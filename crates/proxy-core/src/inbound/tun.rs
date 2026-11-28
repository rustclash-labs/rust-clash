use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Buf, BytesMut};
use ipnet::Ipv4Net;
use parking_lot::RwLock;
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{
        Icmpv6DstUnreachable, Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr, IpListenEndpoint,
        IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr,
        TcpPacket, UdpPacket, UdpRepr,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, Semaphore, mpsc, watch},
    task::{AbortHandle, JoinHandle},
};

use crate::{
    addr::{HostName, TargetAddr},
    inbound::{
        sniff::{
            MAX_SNIFF_BYTES, RealIpTlsOverrideGuard, SniffOutcomeWithProto, SniffedProtocol,
            resolve_real_ip_tcp_dial_target, sniff_tcp_protocol,
        },
        udp_nat::UdpNatManager,
    },
    platform::process::SocketTransport,
    router::Router,
    tracker::{SessionResetter, TelemetryHub},
};

pub const TUN_PACKET_QUEUE_CAPACITY: usize = 4096;
const TUN_DEVICE_RX_MAX_PACKETS: usize = 4096;
const TUN_FLOW_STREAM_CAPACITY: usize = 64;
const TUN_TCP_SOCKET_BUF_SIZE: usize = 64 * 1024;
const MAX_TUN_TCP_FLOWS: usize = 2048;
const MAX_HALF_OPEN_SYN_FLOWS: usize = 256;
const MAX_TUN_UDP_INFLIGHT: usize = 512;
const MAX_TUN_UDP_SESSIONS: usize = 512;
const TCP_SYN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const OUTBOUND_CONNECT_HARD_REAP_GRACE: Duration = Duration::from_secs(2);
/// Established TUN TCP idle ceiling (30 minutes).
/// Long-lived mobile and desktop channels — such as domestic push (`:5223`, 3m heartbeat),
/// Telegram MTProto, SSH/WebSockets, and Google FCM (`mtalk.google.com:5228`, 15m Wi-Fi /
/// 28m cellular heartbeat) — routinely stay application-quiet well beyond 120s while both the
/// local `smoltcp` keep-alive (45s/120s) and outbound OS TCP keepalive (45s/15s) verify peer
/// liveness. Retaining a finite 30m ceiling (checked against both monotonic and wall-clock time)
/// still evicts genuinely abandoned post-deep-sleep zombie flows upon wake.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);
/// Under flow-table saturation (`flows.len() >= MAX_TUN_TCP_FLOWS`), evict the single stalest
/// established flow idle beyond this threshold before dropping incoming SYNs.
const TCP_PRESSURE_EVICT_IDLE_AGE: Duration = Duration::from_secs(120);
const TCP_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded handle to interact with the userspace `smoltcp` TUN stack via raw L3 IPv4/IPv6 packets.
/// Uses bounded `mpsc` channels to enforce end-to-end memory limits and backpressure.
pub struct VirtualTunHandle {
    /// Inject an L3 IPv4/IPv6 packet from the host OS / guest app into the TUN stack.
    pub ingress_tx: mpsc::Sender<Vec<u8>>,
    /// Receive L3 IPv4/IPv6 packets emitted by the TUN stack back toward the host OS / guest app.
    pub egress_rx: mpsc::Receiver<Vec<u8>>,
}

struct VirtualIpDevice {
    mtu: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_sender: mpsc::Sender<Vec<u8>>,
}

struct VecRxToken(Vec<u8>);

impl RxToken for VecRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct ChannelTxToken {
    permit: mpsc::OwnedPermit<Vec<u8>>,
}

impl TxToken for ChannelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut pkt = vec![0u8; len];
        let res = f(&mut pkt);
        let _ = self.permit.send(pkt);
        res
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = VecRxToken;
    type TxToken<'a> = ChannelTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_queue.is_empty() {
            return None;
        }
        let Ok(permit) = self.tx_sender.clone().try_reserve_owned() else {
            return None;
        };
        let pkt = self.rx_queue.pop_front()?;
        Some((VecRxToken(pkt), ChannelTxToken { permit }))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        let Ok(permit) = self.tx_sender.clone().try_reserve_owned() else {
            return None;
        };
        Some(ChannelTxToken { permit })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

struct BridgeFlow {
    handle: SocketHandle,
    established: bool,
    remote_connected: Arc<AtomicBool>,
    dial_timeout_notify: Arc<Notify>,
    dial_timeout_notified_at: Option<(Instant, u64)>,
    created_at: Instant,
    created_wall_ms: u64,
    last_active: Instant,
    last_active_wall_ms: u64,
    fin_started_at: Option<Instant>,
    fin_started_wall_ms: Option<u64>,
    pending_tx: BytesMut,
    from_remote_rx: mpsc::Receiver<Vec<u8>>,
    to_remote_tx: Option<mpsc::Sender<Vec<u8>>>,
    _bridge_closed_rx: watch::Receiver<()>,
    remote_eof: bool,
    remote_failed: Arc<AtomicBool>,
    task_abort: AbortHandle,
}

impl BridgeFlow {
    fn is_dial_timed_out(&self, now: Instant, now_wall_ms: u64) -> bool {
        !self.remote_connected.load(Ordering::Acquire)
            && (now.saturating_duration_since(self.created_at) > OUTBOUND_CONNECT_TIMEOUT
                || now_wall_ms.saturating_sub(self.created_wall_ms)
                    > OUTBOUND_CONNECT_TIMEOUT.as_millis() as u64)
    }

    /// Notify `flow_task` once when outbound dialing exceeds `OUTBOUND_CONNECT_TIMEOUT`, recording
    /// the delivery timestamp so `OUTBOUND_CONNECT_HARD_REAP_GRACE` is always granted even after
    /// an Android deep-sleep wall-clock jump.
    fn notify_dial_timeout_if_needed(&mut self, now: Instant, now_wall_ms: u64) -> bool {
        if self.dial_timeout_notified_at.is_none() && self.is_dial_timed_out(now, now_wall_ms) {
            self.dial_timeout_notified_at = Some((now, now_wall_ms));
            self.dial_timeout_notify.notify_one();
            true
        } else {
            false
        }
    }

    fn effective_idle_duration(&self, now: Instant, now_wall_ms: u64) -> Duration {
        let idle_mono = now.saturating_duration_since(self.last_active);
        let idle_wall = Duration::from_millis(now_wall_ms.saturating_sub(self.last_active_wall_ms));
        idle_mono.max(idle_wall)
    }

    fn is_timed_out(&self, now: Instant, now_wall_ms: u64, send_queue_bytes: usize) -> bool {
        let syn_timed_out = !self.established
            && (now.saturating_duration_since(self.created_at) > TCP_SYN_HANDSHAKE_TIMEOUT
                || now_wall_ms.saturating_sub(self.created_wall_ms)
                    > TCP_SYN_HANDSHAKE_TIMEOUT.as_millis() as u64);
        let remote_connected = self.remote_connected.load(Ordering::Acquire);
        // Enforce hard-reap grace relative to when `dial_timeout_notify` was delivered (not
        // `created_wall_ms`) so waking from a >17s Android AP suspend never aborts `flow_task`
        // in the same poll tick before `ConnectionGuard::record_failed()` executes.
        let dial_hard_timed_out = !remote_connected
            && self
                .dial_timeout_notified_at
                .is_some_and(|(notified_mono, notified_wall_ms)| {
                    now.saturating_duration_since(notified_mono) > OUTBOUND_CONNECT_HARD_REAP_GRACE
                        || now_wall_ms.saturating_sub(notified_wall_ms)
                            > OUTBOUND_CONNECT_HARD_REAP_GRACE.as_millis() as u64
                });
        // Apply `TCP_IDLE_TIMEOUT` only after outbound connect succeeds; pending dials are
        // strictly bounded by `notify_dial_timeout_if_needed` + `dial_hard_timed_out` so a long
        // suspend wakeup cannot preempt the 2s `record_failed()` grace window either.
        let idle_timed_out =
            remote_connected && self.effective_idle_duration(now, now_wall_ms) > TCP_IDLE_TIMEOUT;
        let fin_age_exceeded = self
            .fin_started_at
            .is_some_and(|t| now.saturating_duration_since(t) > TCP_HALF_CLOSE_TIMEOUT)
            || self.fin_started_wall_ms.is_some_and(|w| {
                now_wall_ms.saturating_sub(w) > TCP_HALF_CLOSE_TIMEOUT.as_millis() as u64
            });
        let fin_idle_exceeded = now.saturating_duration_since(self.last_active)
            > TCP_HALF_CLOSE_TIMEOUT
            || now_wall_ms.saturating_sub(self.last_active_wall_ms)
                > TCP_HALF_CLOSE_TIMEOUT.as_millis() as u64;
        let fin_timed_out = fin_age_exceeded
            && fin_idle_exceeded
            && self.pending_tx.is_empty()
            && send_queue_bytes == 0;
        syn_timed_out || dial_hard_timed_out || idle_timed_out || fin_timed_out
    }
}

struct TunIdleWakeResetter {
    wake_notify: Arc<Notify>,
}

impl SessionResetter for TunIdleWakeResetter {
    fn reset_sessions(&self) -> usize {
        self.wake_notify.notify_one();
        0
    }

    fn reap_idle_sessions(&self) -> usize {
        self.wake_notify.notify_one();
        0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FourTuple {
    src: SocketAddr,
    dst: SocketAddr,
}

fn fold_min_delay(acc: Option<Duration>, candidate: Duration) -> Option<Duration> {
    Some(match acc {
        Some(prev) => prev.min(candidate),
        None => candidate,
    })
}

fn create_tun_smoltcp_iface(device: &mut VirtualIpDevice, now: SmolInstant) -> Interface {
    let mut iface_cfg = IfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
    iface_cfg.random_seed = rand::random();
    let gw_v4 = Ipv4Address::new(198, 18, 0, 1);
    let gw_v6 = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let mut iface = Interface::new(iface_cfg, device, now);
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(gw_v4), 0));
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(gw_v6), 0));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(gw_v4);
    let _ = iface.routes_mut().add_default_ipv6_route(gw_v6);
    iface
}

/// Self-healing userspace `smoltcp` TCP/IP state owned by the TUN event loop.
/// Isolates unexpected panics inside `smoltcp` via `catch_unwind` and rebuilds the
/// userspace `Interface` + `SocketSet` in-place while keeping the OS TUN session,
/// routes, DNS hijack, and UDP NAT completely alive.
struct TunSmoltcpStack {
    device: VirtualIpDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: HashMap<FourTuple, BridgeFlow>,
    pending_remove_handles: Vec<SocketHandle>,
    panic_recoveries: u64,
}

fn drain_pending_removed_handles(
    sockets: &mut SocketSet<'static>,
    pending_remove_handles: &mut Vec<SocketHandle>,
) {
    for handle in pending_remove_handles.drain(..) {
        sockets.remove(handle);
    }
}

impl TunSmoltcpStack {
    fn new(mtu: usize, egress_tx: mpsc::Sender<Vec<u8>>, now: SmolInstant) -> Self {
        let mut device = VirtualIpDevice {
            mtu: mtu.clamp(1280, 65535),
            rx_queue: VecDeque::with_capacity(512),
            tx_sender: egress_tx,
        };
        let iface = create_tun_smoltcp_iface(&mut device, now);
        Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            flows: HashMap::new(),
            pending_remove_handles: Vec::new(),
            panic_recoveries: 0,
        }
    }

    fn rebuild_after_panic(
        &mut self,
        stage: &str,
        panic_msg: &str,
        now: SmolInstant,
        hub: &TelemetryHub,
    ) {
        self.panic_recoveries = self.panic_recoveries.saturating_add(1);
        let active_flows = self.flows.len();
        let queued_rx = self.device.rx_queue.len();
        let safe_msg = crate::platform::crash_log::sanitize_crash_text(panic_msg);

        tracing::error!(
            stage,
            recovery_count = self.panic_recoveries,
            active_flows,
            queued_rx,
            panic = %safe_msg,
            "Isolated panic in smoltcp TUN stack; rebuilding userspace Interface and SocketSet"
        );
        hub.push_log(
            "error",
            format!(
                "[TUN] Isolated smoltcp panic at {stage} (recovery #{}, active_flows={active_flows}, queued_rx={queued_rx}): {safe_msg}; rebuilt userspace TCP stack",
                self.panic_recoveries
            ),
        );

        for (_, flow) in self.flows.drain() {
            flow.task_abort.abort();
        }
        self.pending_remove_handles.clear();
        self.device.rx_queue.clear();

        let old_sockets = std::mem::replace(&mut self.sockets, SocketSet::new(vec![]));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            drop(old_sockets);
        }));

        let fresh_iface = create_tun_smoltcp_iface(&mut self.device, now);
        let old_iface = std::mem::replace(&mut self.iface, fresh_iface);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            drop(old_iface);
        }));
    }

    fn run_guarded<R, F>(
        &mut self,
        stage: &str,
        now: SmolInstant,
        hub: &TelemetryHub,
        f: F,
    ) -> Option<R>
    where
        F: FnOnce(&mut Self) -> R,
    {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self))) {
            Ok(val) => Some(val),
            Err(payload) => {
                let msg = crate::platform::crash_log::extract_panic_payload(payload.as_ref());
                self.rebuild_after_panic(stage, &msg, now, hub);
                None
            }
        }
    }

    /// Reap any flow whose `smoltcp` TCP socket reverted from `SynReceived` back to
    /// `State::Listen` (e.g. after receiving an in-window TCP `RST` in `SynReceived`,
    /// which clears `tuple = None` per RFC 793). Preserves the Single-Listen Isolation
    /// Invariant so no stale wildcard `Listen` socket can ever survive to hijack a
    /// subsequent client's `SYN`.
    fn reap_reverted_listen_flows(&mut self) {
        let mut reverted_keys = Vec::new();
        for (tuple, flow) in &self.flows {
            if self.sockets.get::<tcp::Socket>(flow.handle).state() == tcp::State::Listen {
                reverted_keys.push(*tuple);
            }
        }
        for tuple in reverted_keys {
            if let Some(flow) = self.flows.remove(&tuple) {
                flow.task_abort.abort();
                self.sockets.remove(flow.handle);
            }
        }
    }

    fn poll_guarded(&mut self, stage: &str, now: SmolInstant, hub: &TelemetryHub) -> bool {
        self.run_guarded(stage, now, hub, |s| {
            let _ = s.iface.poll(now, &mut s.device, &mut s.sockets);
            drain_pending_removed_handles(&mut s.sockets, &mut s.pending_remove_handles);
            s.reap_reverted_listen_flows();
        })
        .is_some()
    }

    fn remove_finished_flows(
        &mut self,
        finished_keys: Vec<FourTuple>,
        now: SmolInstant,
        hub: &TelemetryHub,
    ) -> bool {
        if finished_keys.is_empty() {
            return true;
        }
        self.run_guarded("sockets.remove", now, hub, |s| {
            for k in finished_keys {
                if let Some(flow) = s.flows.remove(&k) {
                    if !flow.established {
                        flow.task_abort.abort();
                    }
                    s.sockets.remove(flow.handle);
                }
            }
        })
        .is_some()
    }
}

struct SingleFlowStep {
    finished: bool,
    reap_before_poll: bool,
    has_backpressured_rx: bool,
    has_more_ready_rx: bool,
}

fn step_single_tun_flow(
    sock: &mut tcp::Socket<'static>,
    flow: &mut BridgeFlow,
    now: Instant,
    now_wall: u64,
) -> SingleFlowStep {
    // A passive-open `smoltcp` socket in `SynReceived` that receives an in-window TCP `RST`
    // reverts back to `State::Listen` with `tuple = None` (RFC 793). It cannot emit an RST
    // on `iface.poll.post`; abort its flow task and reap it BEFORE the next `iface.poll()`
    // so it can never hijack a subsequent client's SYN.
    if sock.state() == tcp::State::Listen {
        flow.task_abort.abort();
        return SingleFlowStep {
            finished: true,
            reap_before_poll: true,
            has_backpressured_rx: false,
            has_more_ready_rx: false,
        };
    }

    // If outbound dial or REJECT rule failed, immediately emit TCP RST and reap!
    if flow.remote_failed.load(Ordering::Acquire) {
        sock.abort();
        return SingleFlowStep {
            finished: true,
            reap_before_poll: false,
            has_backpressured_rx: false,
            has_more_ready_rx: false,
        };
    }

    if matches!(
        sock.state(),
        tcp::State::Established | tcp::State::CloseWait
    ) {
        flow.established = true;
    }

    let mut has_backpressured_rx = false;
    let mut has_more_ready_rx = false;

    // Read client bytes from smoltcp ONLY when `to_remote_tx` has bounded capacity,
    // preserving TCP receive-window backpressure inside `smoltcp`'s 64 KiB RX buffer!
    if sock.can_recv() {
        if let Some(tx) = &flow.to_remote_tx {
            let mut drained_bytes = 0usize;
            while sock.can_recv() && drained_bytes < 32 * 1024 {
                match tx.try_reserve() {
                    Ok(permit) => {
                        let mut chunk = Vec::with_capacity(32 * 1024);
                        let _ = sock.recv(|data| {
                            let take = data.len().min(32 * 1024 - drained_bytes);
                            chunk.extend_from_slice(&data[..take]);
                            (take, ())
                        });
                        if chunk.is_empty() {
                            break;
                        }
                        drained_bytes += chunk.len();
                        flow.last_active = now;
                        flow.last_active_wall_ms = now_wall;
                        permit.send(chunk);
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        has_backpressured_rx = true;
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        sock.abort();
                        return SingleFlowStep {
                            finished: true,
                            reap_before_poll: false,
                            has_backpressured_rx: false,
                            has_more_ready_rx: false,
                        };
                    }
                }
            }
            if sock.can_recv() && tx.capacity() > 0 {
                has_more_ready_rx = true;
            }
        } else {
            while sock.can_recv() {
                let _ = sock.recv(|data| (data.len(), ()));
            }
        }
    }
    if !sock.can_recv() && flow.established && !sock.may_recv() && flow.to_remote_tx.is_some() {
        flow.to_remote_tx.take();
    }

    // Flush any buffered bytes from remote outbound -> smoltcp TX buffer
    if !flow.pending_tx.is_empty() && sock.can_send() {
        let sent = sock.send_slice(&flow.pending_tx).unwrap_or(0);
        if sent > 0 {
            flow.last_active = now;
            flow.last_active_wall_ms = now_wall;
            flow.pending_tx.advance(sent);
        }
    }

    // Read remote outbound bytes -> feed into smoltcp TX buffer
    while flow.pending_tx.is_empty() && sock.can_send() {
        match flow.from_remote_rx.try_recv() {
            Ok(data) => {
                let sent = sock.send_slice(&data).unwrap_or(0);
                if sent > 0 {
                    flow.last_active = now;
                    flow.last_active_wall_ms = now_wall;
                }
                if sent < data.len() {
                    flow.pending_tx.extend_from_slice(&data[sent..]);
                    break;
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                if !flow.remote_eof {
                    flow.remote_eof = true;
                    flow.fin_started_at.get_or_insert(now);
                    flow.fin_started_wall_ms.get_or_insert(now_wall);
                    sock.close();
                }
                break;
            }
        }
    }

    // Signal `flow_task` when outbound connect exceeds 15s (monotonic or wall-clock)
    // so `ConnectionGuard::record_failed` records the exact dial timeout before RST.
    let _ = flow.notify_dial_timeout_if_needed(now, now_wall);

    // Enforce SYN handshake timeout, hard dial backstop, half-close linger timeout,
    // and idle timeout using both monotonic `Instant` and wall-clock epoch ms
    // (for Android deep sleep).
    if flow.is_timed_out(now, now_wall, sock.send_queue()) {
        flow.task_abort.abort();
        sock.abort();
        return SingleFlowStep {
            finished: true,
            reap_before_poll: false,
            has_backpressured_rx,
            has_more_ready_rx,
        };
    }

    let finished = (flow.established && !sock.is_active())
        || sock.state() == tcp::State::Closed
        || sock.state() == tcp::State::TimeWait
        || sock.state() == tcp::State::Listen;

    SingleFlowStep {
        finished,
        reap_before_poll: sock.state() == tcp::State::Listen,
        has_backpressured_rx,
        has_more_ready_rx,
    }
}

fn step_single_tun_flow_guarded<F>(
    tuple: FourTuple,
    flow: &mut BridgeFlow,
    hub: &TelemetryHub,
    f: F,
) -> SingleFlowStep
where
    F: FnOnce(&mut BridgeFlow) -> SingleFlowStep,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(flow))) {
        Ok(step) => step,
        Err(payload) => {
            let msg = crate::platform::crash_log::sanitize_crash_text(
                &crate::platform::crash_log::extract_panic_payload(payload.as_ref()),
            );
            tracing::error!(
                src = %tuple.src,
                dst = %tuple.dst,
                panic = %msg,
                "Isolated panic in single TUN TCP flow; aborting and reaping flow"
            );
            hub.push_log(
                "error",
                format!(
                    "[TUN] Isolated panic in TCP flow {} -> {}: {msg}; resetting flow",
                    tuple.src, tuple.dst
                ),
            );
            flow.task_abort.abort();
            SingleFlowStep {
                finished: true,
                reap_before_poll: true,
                has_backpressured_rx: false,
                has_more_ready_rx: false,
            }
        }
    }
}

/// Spawn the `smoltcp` userspace `any_ip` transparent TUN stack with:
/// - Event-driven `iface.poll_delay()` + `Notify` wakeups (0 Hz idle polling when inactive!)
/// - Bounded ingress/egress/per-flow channels and TCP window backpressure
/// - IPv4 & IPv6 `any:53` Fake-IP DNS hijack
/// - Stateful multi-datagram IPv4 & IPv6 UDP NAT (`UdpNatManager`) for QUIC/HTTP3/WebRTC
/// - TCP half-close, immediate `RST` on outbound/REJECT failure, and SYN/idle/linger timeouts
/// - `catch_unwind` panic isolation around `smoltcp` polling and per-flow handling
pub fn spawn_userspace_tun(
    mtu: usize,
    router: Arc<RwLock<Arc<Router>>>,
    hub: Arc<TelemetryHub>,
    shutdown: watch::Receiver<bool>,
) -> (VirtualTunHandle, JoinHandle<()>) {
    spawn_userspace_tun_with_ipv6(mtu, router, hub, shutdown, Arc::new(AtomicBool::new(true)))
}

/// Spawn the `smoltcp` userspace `any_ip` transparent TUN stack with a live `ipv6_enabled` gate.
/// When `!ipv6_enabled.load(Ordering::Relaxed)`, inbound IPv6 packets are dropped immediately
/// before DNS hijack, UDP NAT, or `smoltcp` `rx_queue` queueing.
pub fn spawn_userspace_tun_with_ipv6(
    mtu: usize,
    router: Arc<RwLock<Arc<Router>>>,
    hub: Arc<TelemetryHub>,
    shutdown: watch::Receiver<bool>,
    ipv6_enabled: Arc<AtomicBool>,
) -> (VirtualTunHandle, JoinHandle<()>) {
    spawn_userspace_tun_with_options(mtu, router, hub, shutdown, ipv6_enabled, false)
}

/// Spawn the `smoltcp` userspace `any_ip` transparent TUN stack with live `ipv6_enabled` gating
/// and optional `drop_self_pid` loop prevention (enabled for real OS TUN sessions so any leaked
/// packet originating from `rust-clash` itself is dropped immediately instead of self-looping).
pub fn spawn_userspace_tun_with_options(
    mtu: usize,
    router: Arc<RwLock<Arc<Router>>>,
    hub: Arc<TelemetryHub>,
    mut shutdown: watch::Receiver<bool>,
    ipv6_enabled: Arc<AtomicBool>,
    drop_self_pid: bool,
) -> (VirtualTunHandle, JoinHandle<()>) {
    let (ingress_tx, mut ingress_rx) = mpsc::channel::<Vec<u8>>(TUN_PACKET_QUEUE_CAPACITY);
    let (egress_tx, egress_rx) = mpsc::channel::<Vec<u8>>(TUN_PACKET_QUEUE_CAPACITY);

    let task = tokio::spawn(async move {
        let boot = Instant::now();
        let now_smol = || SmolInstant::from_micros(boot.elapsed().as_micros() as i64);

        let mut stack = TunSmoltcpStack::new(mtu, egress_tx.clone(), now_smol());
        let udp_sem = Arc::new(Semaphore::new(MAX_TUN_UDP_INFLIGHT));
        let shutting_down = Arc::new(AtomicBool::new(false));
        let wake_notify = Arc::new(Notify::new());
        let _tun_reap_waker: Arc<dyn SessionResetter> = Arc::new(TunIdleWakeResetter {
            wake_notify: Arc::clone(&wake_notify),
        });
        hub.register_session_resetter(Arc::downgrade(&_tun_reap_waker));

        let egress_for_udp = egress_tx.clone();
        let udp_nat = UdpNatManager::new(
            "TUN(smoltcp-UDP)",
            MAX_TUN_UDP_SESSIONS,
            Arc::clone(&hub),
            Arc::new(move |client_src, return_src_target, payload| {
                if let HostName::Ip(src_ip) = return_src_target.host {
                    let reply_src = SocketAddr::new(src_ip, return_src_target.port);
                    if let Some(ip_pkt) = build_ip_udp_packet(reply_src, client_src, &payload) {
                        let _ = egress_for_udp.try_send(ip_pkt);
                    }
                }
            }),
        );

        let mut next_delay: Option<Duration> = None;
        let mut consecutive_zero_delays: u32 = 0;

        loop {
            if *shutdown.borrow() {
                break;
            }

            if next_delay == Some(Duration::ZERO) {
                if stack.device.tx_sender.is_closed() {
                    break;
                }
                if stack.device.tx_sender.capacity() == 0 {
                    consecutive_zero_delays = 0;
                    tokio::select! {
                        biased;
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                        res = stack.device.tx_sender.reserve() => {
                            if res.is_err() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                    }
                } else {
                    consecutive_zero_delays = consecutive_zero_delays.saturating_add(1);
                    tokio::task::yield_now().await;
                    if consecutive_zero_delays >= 32 {
                        consecutive_zero_delays = 0;
                        if *shutdown.borrow() || shutdown.has_changed().is_err() {
                            break;
                        }
                    }
                }
            } else {
                consecutive_zero_delays = 0;
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    maybe_pkt = ingress_rx.recv() => {
                        let Some(pkt) = maybe_pkt else {
                            break;
                        };
                        let ts_in = now_smol();
                        let _ = stack.run_guarded("ingress_packet", ts_in, &hub, |s| {
                            handle_ingress_packet(
                                pkt,
                                &ipv6_enabled,
                                drop_self_pid,
                                &shutting_down,
                                ts_in,
                                s,
                                &egress_tx,
                                &udp_sem,
                                &udp_nat,
                                &wake_notify,
                                &router,
                                &hub,
                            );
                        });
                        for _ in 0..256 {
                            if *shutdown.borrow()
                                || stack.device.rx_queue.len() >= TUN_DEVICE_RX_MAX_PACKETS
                            {
                                break;
                            }
                            match ingress_rx.try_recv() {
                                Ok(more) => {
                                    let ts_more = now_smol();
                                    let ok = stack
                                        .run_guarded("ingress_packet", ts_more, &hub, |s| {
                                            handle_ingress_packet(
                                                more,
                                                &ipv6_enabled,
                                                drop_self_pid,
                                                &shutting_down,
                                                ts_more,
                                                s,
                                                &egress_tx,
                                                &udp_sem,
                                                &udp_nat,
                                                &wake_notify,
                                                &router,
                                                &hub,
                                            );
                                        })
                                        .is_some();
                                    if !ok {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    _ = wake_notify.notified() => {}
                    _ = async {
                        match next_delay {
                            Some(d) => tokio::time::sleep(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {}
                }
            }

            let ts = now_smol();
            if !stack.poll_guarded("iface.poll.pre", ts, &hub) {
                next_delay = None;
                continue;
            }

            let now = Instant::now();
            let now_wall = TelemetryHub::now_ms();
            let mut finished_keys = Vec::new();
            let mut immediate_remove_keys = Vec::new();
            let mut has_backpressured_rx = false;
            let mut has_more_ready_rx = false;

            {
                let sockets = &mut stack.sockets;
                for (tuple, flow) in stack.flows.iter_mut() {
                    let step = step_single_tun_flow_guarded(*tuple, flow, &hub, |flow| {
                        let sock = sockets.get_mut::<tcp::Socket>(flow.handle);
                        step_single_tun_flow(sock, flow, now, now_wall)
                    });
                    has_backpressured_rx |= step.has_backpressured_rx;
                    has_more_ready_rx |= step.has_more_ready_rx;
                    if step.reap_before_poll {
                        immediate_remove_keys.push(*tuple);
                    } else if step.finished {
                        finished_keys.push(*tuple);
                    }
                }
            }

            // Reap any panicked or Listen-reverted socket BEFORE `iface.poll.post` so it
            // cannot fault `smoltcp` or hijack a subsequent SYN.
            if !stack.remove_finished_flows(immediate_remove_keys, now_smol(), &hub) {
                next_delay = None;
                continue;
            }

            // Flush any segments (SYN-ACK, PSH, FIN, or RST from `sock.abort()`) BEFORE removing
            // finished sockets from `SocketSet`, so aborted sockets actually emit their TCP RST!
            let ts_after = now_smol();
            if !stack.poll_guarded("iface.poll.post", ts_after, &hub) {
                next_delay = None;
                continue;
            }

            if !stack.remove_finished_flows(finished_keys, ts_after, &hub) {
                next_delay = None;
                continue;
            }

            // Compute exact event-driven next sleep deadline (`None` = 0 Hz pure idle wait!)
            let Some(computed_delay) =
                stack.run_guarded("schedule_next_delay", ts_after, &hub, |s| {
                    let mut delay = s
                        .iface
                        .poll_delay(ts_after, &s.sockets)
                        .map(|d| Duration::from_micros(d.total_micros()));

                    if !s.device.rx_queue.is_empty() || has_more_ready_rx {
                        return Some(Duration::ZERO);
                    }

                    if has_backpressured_rx {
                        delay = fold_min_delay(delay, Duration::from_millis(5));
                    }
                    let check_now = Instant::now();
                    let check_now_wall = TelemetryHub::now_ms();
                    for flow in s.flows.values() {
                        let remote_connected = flow.remote_connected.load(Ordering::Acquire);
                        if !flow.established || !remote_connected {
                            let (rem_mono, rem_wall) = if !flow.established {
                                (
                                    TCP_SYN_HANDSHAKE_TIMEOUT.saturating_sub(
                                        check_now.saturating_duration_since(flow.created_at),
                                    ),
                                    TCP_SYN_HANDSHAKE_TIMEOUT.saturating_sub(
                                        Duration::from_millis(
                                            check_now_wall.saturating_sub(flow.created_wall_ms),
                                        ),
                                    ),
                                )
                            } else if let Some((notified_mono, notified_wall_ms)) =
                                flow.dial_timeout_notified_at
                            {
                                (
                                    OUTBOUND_CONNECT_HARD_REAP_GRACE.saturating_sub(
                                        check_now.saturating_duration_since(notified_mono),
                                    ),
                                    OUTBOUND_CONNECT_HARD_REAP_GRACE.saturating_sub(
                                        Duration::from_millis(
                                            check_now_wall.saturating_sub(notified_wall_ms),
                                        ),
                                    ),
                                )
                            } else {
                                (
                                    OUTBOUND_CONNECT_TIMEOUT.saturating_sub(
                                        check_now.saturating_duration_since(flow.created_at),
                                    ),
                                    OUTBOUND_CONNECT_TIMEOUT.saturating_sub(Duration::from_millis(
                                        check_now_wall.saturating_sub(flow.created_wall_ms),
                                    )),
                                )
                            };
                            delay = fold_min_delay(
                                delay,
                                rem_mono.min(rem_wall).max(Duration::from_millis(1)),
                            );
                        }
                        if remote_connected {
                            let rem_idle_mono = TCP_IDLE_TIMEOUT.saturating_sub(
                                check_now.saturating_duration_since(flow.last_active),
                            );
                            let rem_idle_wall =
                                TCP_IDLE_TIMEOUT.saturating_sub(Duration::from_millis(
                                    check_now_wall.saturating_sub(flow.last_active_wall_ms),
                                ));
                            delay = fold_min_delay(
                                delay,
                                rem_idle_mono
                                    .min(rem_idle_wall)
                                    .max(Duration::from_millis(1)),
                            );
                        }
                        if let Some(fin_t) = flow.fin_started_at {
                            let sock = s.sockets.get_mut::<tcp::Socket>(flow.handle);
                            if flow.pending_tx.is_empty() && sock.send_queue() == 0 {
                                let mut rem_fin_age = TCP_HALF_CLOSE_TIMEOUT
                                    .saturating_sub(check_now.duration_since(fin_t));
                                if let Some(fin_w) = flow.fin_started_wall_ms {
                                    let rem_fin_wall = TCP_HALF_CLOSE_TIMEOUT.saturating_sub(
                                        Duration::from_millis(check_now_wall.saturating_sub(fin_w)),
                                    );
                                    rem_fin_age = rem_fin_age.min(rem_fin_wall);
                                }
                                let rem_fin_idle_mono = TCP_HALF_CLOSE_TIMEOUT
                                    .saturating_sub(check_now.duration_since(flow.last_active));
                                let rem_fin_idle_wall =
                                    TCP_HALF_CLOSE_TIMEOUT.saturating_sub(Duration::from_millis(
                                        check_now_wall.saturating_sub(flow.last_active_wall_ms),
                                    ));
                                let rem_fin =
                                    rem_fin_age.max(rem_fin_idle_mono.min(rem_fin_idle_wall));
                                delay =
                                    fold_min_delay(delay, rem_fin.max(Duration::from_millis(1)));
                            }
                        }
                    }
                    delay
                })
            else {
                next_delay = None;
                continue;
            };
            next_delay = computed_delay;
        }

        shutting_down.store(true, Ordering::Release);
        udp_sem.close();
        for (_, flow) in stack.flows.drain() {
            flow.task_abort.abort();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                stack.sockets.remove(flow.handle);
            }));
        }
        for handle in stack.pending_remove_handles.drain(..) {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                stack.sockets.remove(handle);
            }));
        }
        let _ = udp_nat.shutdown();
    });

    (
        VirtualTunHandle {
            ingress_tx,
            egress_rx,
        },
        task,
    )
}

/// Returns `true` for L3 IPv4 packets that must never be NAT-forwarded or proxied through a TUN
/// adapter (multicast `224.0.0.0/4` such as mDNS/LLMNR/SSDP, limited broadcast `255.255.255.255`,
/// link-local `169.254.0.0/16`, or unspecified `0.0.0.0`), preventing Windows/OS TUN multicast
/// self-amplification storms.
pub(crate) fn should_drop_tun_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> bool {
    dst.is_multicast()
        || dst.is_broadcast()
        || dst.is_unspecified()
        || dst.is_link_local()
        || src.is_multicast()
        || src.is_broadcast()
        || src.is_unspecified()
}

/// Returns `true` for L3 IPv6 packets that must never be NAT-forwarded or proxied through a TUN
/// adapter (multicast `ff00::/8`, link-local `fe80::/10`, or unspecified `::`).
pub(crate) fn should_drop_tun_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> bool {
    let is_v6_link_local = |ip: Ipv6Addr| (ip.segments()[0] & 0xffc0) == 0xfe80;
    dst.is_multicast()
        || dst.is_unspecified()
        || is_v6_link_local(dst)
        || src.is_multicast()
        || src.is_unspecified()
}

fn is_self_process_socket(transport: SocketTransport, local_addr: SocketAddr) -> bool {
    crate::platform::process::find_local_process_nonblocking(transport, local_addr)
        .is_some_and(|info| info.pid == std::process::id())
}

#[allow(clippy::too_many_arguments)]
fn process_isolated_tcp_syn(
    pkt: Vec<u8>,
    tuple: FourTuple,
    listen_ip: IpAddress,
    fast_reject: bool,
    drop_self_pid: bool,
    now: SmolInstant,
    stack: &mut TunSmoltcpStack,
    wake_notify: &Arc<Notify>,
    router: &Arc<RwLock<Arc<Router>>>,
    hub: &Arc<TelemetryHub>,
) {
    // 1. Drain any queued non-SYN packets first so `rx_queue` is empty and zero
    //    wildcard `Listen` sockets exist before handling this SYN.
    if !stack.device.rx_queue.is_empty() {
        let _ = stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
        drain_pending_removed_handles(&mut stack.sockets, &mut stack.pending_remove_handles);
    }
    // 2. Sweep any flow whose socket reverted from `SynReceived` back to `State::Listen`
    //    (e.g. from an in-window TCP `RST` drained in step 1 or an earlier poll) BEFORE
    //    entering either `fast_reject` or `register_syn_flow`.
    stack.reap_reverted_listen_flows();

    if !stack.device.rx_queue.is_empty() || stack.device.rx_queue.len() >= TUN_DEVICE_RX_MAX_PACKETS
    {
        return;
    }

    if fast_reject {
        // Zero `Listen` sockets exist right now -> `smoltcp` emits immediate `TCP RST|ACK`
        // with zero chance of hijacking an accepted SYN's wildcard `Listen` socket.
        stack.device.rx_queue.push_back(pkt);
        let _ = stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
        drain_pending_removed_handles(&mut stack.sockets, &mut stack.pending_remove_handles);
        stack.reap_reverted_listen_flows();
        if !stack.device.rx_queue.is_empty() {
            let _ = stack.device.rx_queue.pop_back();
        }
        return;
    }

    // Per-SYN Single-Listen Isolation Invariant: create at most ONE wildcard `Listen` socket
    // for this SYN, immediately feed only this SYN into `iface.poll()`, and verify it bound.
    let newly_registered = if !stack.flows.contains_key(&tuple) {
        register_syn_flow(
            tuple,
            listen_ip,
            drop_self_pid,
            &mut stack.sockets,
            &mut stack.flows,
            &mut stack.pending_remove_handles,
            wake_notify,
            router,
            hub,
        )
    } else {
        None
    };

    stack.device.rx_queue.push_back(pkt);
    let _ = stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
    drain_pending_removed_handles(&mut stack.sockets, &mut stack.pending_remove_handles);

    // If concurrent egress saturation prevented `smoltcp` from consuming the SYN, pop it.
    if !stack.device.rx_queue.is_empty() {
        let _ = stack.device.rx_queue.pop_back();
    }

    // If `smoltcp` rejected or did not consume the SYN, tear down the still-`Listen` socket
    // immediately so zero orphan wildcard `Listen` sockets can survive to hijack future SYNs.
    if let Some(handle) = newly_registered
        && stack.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Listen
    {
        if let Some(flow) = stack.flows.remove(&tuple) {
            flow.task_abort.abort();
        }
        stack.sockets.remove(handle);
    }
    stack.reap_reverted_listen_flows();
}

#[allow(clippy::too_many_arguments)]
fn handle_ingress_packet(
    pkt: Vec<u8>,
    ipv6_enabled: &Arc<AtomicBool>,
    drop_self_pid: bool,
    shutting_down: &Arc<AtomicBool>,
    now: SmolInstant,
    stack: &mut TunSmoltcpStack,
    egress_tx: &mpsc::Sender<Vec<u8>>,
    udp_sem: &Arc<Semaphore>,
    udp_nat: &Arc<UdpNatManager>,
    wake_notify: &Arc<Notify>,
    router: &Arc<RwLock<Arc<Router>>>,
    hub: &Arc<TelemetryHub>,
) {
    if pkt.is_empty() {
        return;
    }
    let ip_ver = pkt[0] >> 4;
    match ip_ver {
        4 => {
            let Ok(ip4) = Ipv4Packet::new_checked(&pkt) else {
                return;
            };
            if ip4.frag_offset() != 0 || ip4.more_frags() {
                return;
            }
            let src_v4: Ipv4Addr = ip4.src_addr();
            let dst_v4: Ipv4Addr = ip4.dst_addr();
            if should_drop_tun_ipv4_packet(src_v4, dst_v4) {
                return;
            }
            match ip4.next_header() {
                IpProtocol::Udp => {
                    if let Ok(udp) = UdpPacket::new_checked(ip4.payload())
                        && udp.verify_checksum(&IpAddress::Ipv4(src_v4), &IpAddress::Ipv4(dst_v4))
                    {
                        // Ignore empty 0-byte UDP datagrams (e.g. OS/SDK route reachability probes
                        // like `8.8.8.8:65535`) so they never open pointless proxy UDP NAT tunnels.
                        if udp.payload().is_empty() {
                            return;
                        }
                        let src_port = udp.src_port();
                        let dst_port = udp.dst_port();
                        let dst_sock = SocketAddr::new(IpAddr::V4(dst_v4), dst_port);
                        let hijack_dns = dst_port == 53 && router.read().tun_dns_hijack();
                        let mut is_unmapped_fake = !hijack_dns
                            && router
                                .read()
                                .dns()
                                .is_unmapped_fake_ip(&TargetAddr::from(dst_sock));
                        if is_unmapped_fake
                            && let crate::inbound::sniff::SniffOutcome::Domain(domain) =
                                crate::inbound::sniff::sniff_quic_initial_sni(udp.payload())
                        {
                            let _ = router
                                .read()
                                .dns()
                                .recover_unmapped_fake_ip(dst_v4, &domain);
                            is_unmapped_fake = false;
                        }
                        if !is_unmapped_fake {
                            let payload = udp.payload().to_vec();
                            spawn_tun_udp_handler(
                                SocketAddr::new(IpAddr::V4(src_v4), src_port),
                                dst_sock,
                                payload,
                                drop_self_pid,
                                shutting_down,
                                egress_tx,
                                udp_sem,
                                udp_nat,
                                router,
                            );
                            return;
                        }
                        // Unmapped Fake-IP UDP (non-hijacked, non-QUIC-Initial): fall through to `device.rx_queue` so
                        // `smoltcp` `iface.poll()` immediately emits `ICMPv4 Destination Unreachable (PortUnreachable)`!
                    } else {
                        return;
                    }
                }
                IpProtocol::Tcp => {
                    if let Ok(tcp_pkt) = TcpPacket::new_checked(ip4.payload())
                        && tcp_pkt.syn()
                        && !tcp_pkt.ack()
                        && !tcp_pkt.rst()
                    {
                        if !ip4.verify_checksum()
                            || !tcp_pkt
                                .verify_checksum(&IpAddress::Ipv4(src_v4), &IpAddress::Ipv4(dst_v4))
                        {
                            return;
                        }
                        let tuple = FourTuple {
                            src: SocketAddr::new(IpAddr::V4(src_v4), tcp_pkt.src_port()),
                            dst: SocketAddr::new(IpAddr::V4(dst_v4), tcp_pkt.dst_port()),
                        };
                        process_isolated_tcp_syn(
                            pkt,
                            tuple,
                            IpAddress::Ipv4(dst_v4),
                            false,
                            drop_self_pid,
                            now,
                            stack,
                            wake_notify,
                            router,
                            hub,
                        );
                        return;
                    }
                }
                _ => {}
            }
        }
        6 => {
            if !ipv6_enabled.load(Ordering::Relaxed) {
                return;
            }
            let Ok(ip6) = Ipv6Packet::new_checked(&pkt) else {
                return;
            };
            let src_v6: Ipv6Addr = ip6.src_addr();
            let dst_v6: Ipv6Addr = ip6.dst_addr();
            if should_drop_tun_ipv6_packet(src_v6, dst_v6) {
                return;
            }
            // Mirror `smoltcp::iface::Interface::process_ipv6` by unwrapping a single
            // IPv6 `HopByHop` extension header so crafted HopByHop-wrapped TCP SYNs cannot
            // bypass `process_isolated_tcp_syn` and enter `rx_queue`.
            let (ip6_next_header, ip6_payload) = if ip6.next_header() == IpProtocol::HopByHop {
                let Ok(ext_hdr) = smoltcp::wire::Ipv6ExtHeader::new_checked(ip6.payload()) else {
                    return;
                };
                let Ok(ext_repr) = smoltcp::wire::Ipv6ExtHeaderRepr::parse(&ext_hdr) else {
                    return;
                };
                let Some(rest) = ip6
                    .payload()
                    .get(ext_repr.header_len() + ext_repr.data.len()..)
                else {
                    return;
                };
                (ext_repr.next_header, rest)
            } else {
                (ip6.next_header(), ip6.payload())
            };
            match ip6_next_header {
                IpProtocol::Udp => {
                    let Ok(udp) = UdpPacket::new_checked(ip6_payload) else {
                        return;
                    };
                    if !udp.verify_checksum(&IpAddress::Ipv6(src_v6), &IpAddress::Ipv6(dst_v6)) {
                        return;
                    }
                    // Ignore empty 0-byte UDP datagrams (e.g. OS/SDK route reachability probes
                    // like `[2000::]:65535`) so they never open pointless proxy UDP NAT tunnels.
                    if udp.payload().is_empty() {
                        return;
                    }
                    let src_port = udp.src_port();
                    let dst_port = udp.dst_port();
                    let src_addr = SocketAddr::new(IpAddr::V6(src_v6), src_port);
                    let dst_sock = SocketAddr::new(IpAddr::V6(dst_v6), dst_port);
                    let hijack_dns = dst_port == 53 && router.read().tun_dns_hijack();
                    let mut is_unmapped_fake = !hijack_dns
                        && router
                            .read()
                            .dns()
                            .is_unmapped_fake_ip(&TargetAddr::from(dst_sock));
                    if is_unmapped_fake
                        && let Some(mapped_v4) = dst_v6.to_ipv4_mapped()
                        && let crate::inbound::sniff::SniffOutcome::Domain(domain) =
                            crate::inbound::sniff::sniff_quic_initial_sni(udp.payload())
                    {
                        let _ = router
                            .read()
                            .dns()
                            .recover_unmapped_fake_ip(mapped_v4, &domain);
                        is_unmapped_fake = false;
                    }
                    let fast_reject = !hijack_dns
                        && !is_unmapped_fake
                        && should_fast_reject_unreachable_direct_ipv6_udp(
                            src_addr,
                            dst_v6,
                            dst_port,
                            udp.payload(),
                            router,
                        );
                    if !is_unmapped_fake && !fast_reject {
                        let payload = udp.payload().to_vec();
                        spawn_tun_udp_handler(
                            src_addr,
                            dst_sock,
                            payload,
                            drop_self_pid,
                            shutting_down,
                            egress_tx,
                            udp_sem,
                            udp_nat,
                            router,
                        );
                        return;
                    }
                    // Unreachable global-unicast DIRECT IPv6 UDP or unmapped Fake-IP UDP (non-53):
                    // fall through to `device.rx_queue` so `smoltcp` `iface.poll()` immediately emits
                    // `ICMPv6 Destination Unreachable (PortUnreachable)` back to `egress_tx`!
                }
                IpProtocol::Tcp => {
                    if let Ok(tcp_pkt) = TcpPacket::new_checked(ip6_payload)
                        && tcp_pkt.syn()
                        && !tcp_pkt.ack()
                        && !tcp_pkt.rst()
                    {
                        if !tcp_pkt
                            .verify_checksum(&IpAddress::Ipv6(src_v6), &IpAddress::Ipv6(dst_v6))
                        {
                            return;
                        }
                        let src_addr = SocketAddr::new(IpAddr::V6(src_v6), tcp_pkt.src_port());
                        let dst_port = tcp_pkt.dst_port();
                        let fast_reject = should_fast_reject_unreachable_direct_ipv6(
                            src_addr,
                            dst_v6,
                            dst_port,
                            SocketTransport::Tcp,
                            router,
                        );
                        let tuple = FourTuple {
                            src: src_addr,
                            dst: SocketAddr::new(IpAddr::V6(dst_v6), dst_port),
                        };
                        process_isolated_tcp_syn(
                            pkt,
                            tuple,
                            IpAddress::Ipv6(dst_v6),
                            fast_reject,
                            drop_self_pid,
                            now,
                            stack,
                            wake_notify,
                            router,
                            hub,
                        );
                        return;
                    }
                }
                _ => {}
            }
        }
        _ => return,
    }

    if stack.device.rx_queue.len() < TUN_DEVICE_RX_MAX_PACKETS {
        stack.device.rx_queue.push_back(pkt);
    }
}

fn should_fast_reject_unreachable_direct_ipv6(
    src_addr: SocketAddr,
    dst_v6: Ipv6Addr,
    dst_port: u16,
    transport: SocketTransport,
    router_slot: &RwLock<Arc<Router>>,
) -> bool {
    if !crate::platform::socket_protect::is_global_unicast_ipv6(dst_v6)
        || crate::platform::socket_protect::is_direct_ipv6_reachable()
    {
        return false;
    }
    let current_router = Arc::clone(&router_slot.read());
    if (dst_port == 53 && current_router.tun_dns_hijack())
        || current_router.dns().is_fake_ip(IpAddr::V6(dst_v6))
    {
        return false;
    }
    current_router.will_route_ip_direct(
        src_addr,
        transport,
        SocketAddr::new(IpAddr::V6(dst_v6), dst_port),
    )
}

/// Evaluate whether an IPv6 UDP datagram on an IPv4-only physical network (`!is_direct_ipv6_reachable`)
/// should be fast-rejected via `smoltcp` ICMPv6 `PortUnreachable`.
///
/// When QUIC Initial SNI sniffing extracts a domain:
/// - If the sniffed domain itself synchronously routes `DIRECT` (e.g. `GeoSite(cn) -> DIRECT` for
///   domestic QUIC endpoints like `shquic.weixin.qq.com`), fast-reject immediately regardless of
///   whether the raw IPv6 matched `GeoIP(CN)` so the app falls back to IPv4 on packet #1.
/// - If the sniffed domain routes `PROXY` (or requires async GeoIP resolution), exempt it so
///   `spawn_tun_udp_handler` can route via `PROXY` or perform full async resolution (with an
///   async ICMPv6 `PortUnreachable` safety net if async routing still ends up on `DIRECT`).
fn should_fast_reject_unreachable_direct_ipv6_udp(
    src_addr: SocketAddr,
    dst_v6: Ipv6Addr,
    dst_port: u16,
    udp_payload: &[u8],
    router_slot: &RwLock<Arc<Router>>,
) -> bool {
    if !crate::platform::socket_protect::is_global_unicast_ipv6(dst_v6)
        || crate::platform::socket_protect::is_direct_ipv6_reachable()
    {
        return false;
    }
    let current_router = Arc::clone(&router_slot.read());
    if (dst_port == 53 && current_router.tun_dns_hijack())
        || current_router.dns().is_fake_ip(IpAddr::V6(dst_v6))
    {
        return false;
    }
    if current_router
        .sniffer()
        .should_sniff_real_ip_udp(IpAddr::V6(dst_v6), dst_port)
        && let crate::inbound::sniff::SniffOutcome::Domain(domain) =
            crate::inbound::sniff::sniff_quic_initial_sni(udp_payload)
        && let Ok(domain_target) = TargetAddr::new_domain(domain, dst_port)
    {
        return current_router.will_route_target_direct(
            src_addr,
            SocketTransport::Udp,
            &domain_target,
        );
    }
    current_router.will_route_ip_direct(
        src_addr,
        SocketTransport::Udp,
        SocketAddr::new(IpAddr::V6(dst_v6), dst_port),
    )
}

fn truncate_tun_udp_dns_response(req: &[u8], dns_resp: Vec<u8>) -> Vec<u8> {
    let max_udp = crate::dns::wire::extract_edns0_udp_payload_size(req);
    if dns_resp.len() <= max_udp {
        return dns_resp;
    }
    if let Ok(qp) = crate::dns::wire::DnsQueryPacket::parse(req) {
        return crate::dns::wire::build_truncated_dns_header(req, &qp);
    }
    if dns_resp.len() >= 12 {
        let mut hdr = dns_resp[..12].to_vec();
        hdr[2] |= 0x82; // QR=1, TC=1
        hdr[4..12].fill(0); // QDCOUNT=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        return hdr;
    }
    dns_resp
}

#[allow(clippy::too_many_arguments)]
fn spawn_tun_udp_handler(
    src: SocketAddr,
    dst: SocketAddr,
    payload: Vec<u8>,
    drop_self_pid: bool,
    shutting_down: &Arc<AtomicBool>,
    egress_tx: &mpsc::Sender<Vec<u8>>,
    udp_sem: &Arc<Semaphore>,
    udp_nat: &Arc<UdpNatManager>,
    router: &Arc<RwLock<Arc<Router>>>,
) {
    if shutting_down.load(Ordering::Acquire) {
        return;
    }
    let current_router = Arc::clone(&router.read());
    let hijack_dns = dst.port() == 53 && current_router.tun_dns_hijack();
    let payload = if !hijack_dns {
        let epoch = current_router.epoch();
        match udp_nat.try_send_fast(src, dst, epoch, payload) {
            Ok(()) => return,
            Err(payload) => payload,
        }
    } else {
        payload
    };

    let Ok(permit) = Arc::clone(udp_sem).try_acquire_owned() else {
        return;
    };
    let egress = egress_tx.clone();
    let nat = Arc::clone(udp_nat);
    let shutting_down_task = Arc::clone(shutting_down);

    tokio::spawn(async move {
        let _permit = permit;
        // 1. Prevent any OS-level TUN routing loop caused by our own process's outbound sockets,
        //    including our own outbound UDP `:53` DNS queries before `:53` hijack!
        if drop_self_pid && is_self_process_socket(SocketTransport::Udp, src) {
            tracing::debug!(
                %src,
                %dst,
                "Dropped self-originated UDP packet entering OS TUN to prevent routing loop"
            );
            return;
        }

        // 2. Port 53 (`any:53`) Fake-IP DNS Hijack across both IPv4 and IPv6 when `tun.dns_hijack` is active!
        if hijack_dns {
            if let Ok(dns_resp) = current_router.dns().handle_dns_packet(&payload).await {
                let wire_out = truncate_tun_udp_dns_response(&payload, dns_resp);
                if let Some(ip_pkt) = build_ip_udp_packet(dst, src, &wire_out) {
                    let _ = egress.send(ip_pkt).await;
                }
            }
            return;
        }

        // 3. General non-53 UDP datagram stateful NAT session forwarding (with QUIC Initial SNI sniffing)!
        let route_epoch = current_router.epoch();
        let raw_target = TargetAddr::from(dst);
        let resolved = crate::inbound::udp_nat::route_udp_datagram_with_quic_sniff(
            &current_router,
            src,
            &raw_target,
            &payload,
        )
        .await;
        if shutting_down_task.load(Ordering::Acquire) {
            return;
        }
        // Layer-2 async safety net: if full async routing (e.g. GeoIP resolution on a sniffed
        // QUIC domain) still routed a global-unicast raw IPv6 UDP target to `DIRECT` on an
        // IPv4-only physical link, immediately emit `ICMPv6 Destination Unreachable (PortUnreachable)`
        // instead of opening a doomed `DirectUdpSession` that fails with `ENETUNREACH (os error 101)`.
        if resolved.decision.outbound.exit_category() == "DIRECT"
            && resolved.decision.restored_from_fake_ip.is_none()
            && !crate::platform::socket_protect::is_direct_ipv6_reachable()
            && let (IpAddr::V6(src_v6), Some(IpAddr::V6(dst_v6))) =
                (src.ip(), resolved.dial_target.host.as_ip())
            && crate::platform::socket_protect::is_global_unicast_ipv6(dst_v6)
        {
            if let Some(icmp_pkt) = build_ipv6_udp_port_unreachable_packet(
                src_v6,
                src.port(),
                dst_v6,
                dst.port(),
                &payload,
            ) {
                let _ = egress.send(icmp_pkt).await;
            }
            return;
        }
        nat.send_datagram_with_options(
            src,
            raw_target,
            resolved.decision.restored_from_fake_ip,
            resolved.decision.target,
            resolved.dial_target,
            &resolved.decision.rule_type,
            &resolved.decision.rule_payload,
            resolved.decision.chains,
            resolved.decision.outbound,
            payload,
            route_epoch,
            resolved.sniffed,
        )
        .await;
        if shutting_down_task.load(Ordering::Acquire) {
            let _ = nat.shutdown();
        }
    });
}

/// Pick the single stalest established, remote-connected flow whose effective idle age
/// (monotonic or wall-clock) exceeds `TCP_PRESSURE_EVICT_IDLE_AGE` for LRU eviction when the
/// TUN TCP flow table reaches `MAX_TUN_TCP_FLOWS`.
fn select_pressure_eviction_candidate(
    flows: &HashMap<FourTuple, BridgeFlow>,
    now: Instant,
    now_wall_ms: u64,
) -> Option<FourTuple> {
    flows
        .iter()
        .filter(|(_, f)| f.established && f.remote_connected.load(Ordering::Acquire))
        .filter_map(|(tuple, f)| {
            let idle = f.effective_idle_duration(now, now_wall_ms);
            (idle > TCP_PRESSURE_EVICT_IDLE_AGE).then_some((*tuple, idle))
        })
        .max_by_key(|(_, idle)| *idle)
        .map(|(tuple, _)| tuple)
}

#[allow(clippy::too_many_arguments)]
fn register_syn_flow(
    tuple: FourTuple,
    listen_ip: IpAddress,
    drop_self_pid: bool,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<FourTuple, BridgeFlow>,
    pending_remove_handles: &mut Vec<SocketHandle>,
    wake_notify: &Arc<Notify>,
    router: &Arc<RwLock<Arc<Router>>>,
    hub: &Arc<TelemetryHub>,
) -> Option<SocketHandle> {
    if flows.contains_key(&tuple) {
        return None;
    }
    let now = Instant::now();
    let now_wall = TelemetryHub::now_ms();
    let half_open_count = flows.values().filter(|f| !f.established).count();
    if half_open_count >= MAX_HALF_OPEN_SYN_FLOWS
        && let Some(oldest_tuple) = flows
            .iter()
            .filter(|(_, f)| !f.established)
            .min_by_key(|(_, f)| f.created_at)
            .map(|(k, _)| *k)
        && let Some(evicted) = flows.remove(&oldest_tuple)
    {
        evicted.task_abort.abort();
        let evicted_sock = sockets.get_mut::<tcp::Socket>(evicted.handle);
        evicted_sock.abort();
        // Defer `sockets.remove` until immediately after the next `iface.poll()` emits TCP RST.
        pending_remove_handles.push(evicted.handle);
    }
    if flows.len() >= MAX_TUN_TCP_FLOWS {
        if let Some(evict_tuple) = select_pressure_eviction_candidate(flows, now, now_wall)
            && let Some(evicted) = flows.remove(&evict_tuple)
        {
            evicted.task_abort.abort();
            let evicted_sock = sockets.get_mut::<tcp::Socket>(evicted.handle);
            evicted_sock.abort();
            // Defer `sockets.remove` until immediately after the next `iface.poll()` emits TCP RST.
            pending_remove_handles.push(evicted.handle);
        } else {
            return None;
        }
    }

    let rx_buf = tcp::SocketBuffer::new(vec![0u8; TUN_TCP_SOCKET_BUF_SIZE]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; TUN_TCP_SOCKET_BUF_SIZE]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    sock.set_nagle_enabled(false);
    sock.set_timeout(Some(SmolDuration::from_secs(120)));
    sock.set_keep_alive(Some(SmolDuration::from_secs(45)));
    if sock
        .listen(IpListenEndpoint {
            addr: Some(listen_ip),
            port: tuple.dst.port(),
        })
        .is_err()
    {
        return None;
    }
    let handle = sockets.add(sock);

    let (to_remote_tx, mut to_remote_rx) = mpsc::channel::<Vec<u8>>(TUN_FLOW_STREAM_CAPACITY);
    let (from_remote_tx, from_remote_rx) = mpsc::channel::<Vec<u8>>(TUN_FLOW_STREAM_CAPACITY);
    let (bridge_closed_tx, bridge_closed_rx) = watch::channel(());
    let remote_connected = Arc::new(AtomicBool::new(false));
    let remote_connected_task = Arc::clone(&remote_connected);
    let dial_timeout_notify = Arc::new(Notify::new());
    let dial_timeout_task = Arc::clone(&dial_timeout_notify);
    let remote_failed = Arc::new(AtomicBool::new(false));
    let remote_failed_task = Arc::clone(&remote_failed);
    let wake_task = Arc::clone(wake_notify);
    let flow_created_at = now;
    let flow_created_wall_ms = now_wall;

    let current_router = Arc::clone(&router.read());
    let hub_clone = Arc::clone(hub);
    let flow_task = tokio::spawn(async move {
        // Prevent any OS-level TUN routing loop caused by our own process's outbound TCP sockets,
        // including our own outbound TCP `:53` DNS queries before `:53` hijack!
        if drop_self_pid && is_self_process_socket(SocketTransport::Tcp, tuple.src) {
            tracing::debug!(
                src = %tuple.src,
                dst = %tuple.dst,
                "Aborted self-originated TCP SYN entering OS TUN to prevent routing loop"
            );
            remote_failed_task.store(true, Ordering::Release);
            wake_task.notify_one();
            return;
        }

        // Port 53 (`any:53`) Fake-IP DNS-over-TCP Hijack (RFC 1035 / RFC 7766 2-byte length prefix).
        // Prevents Android/OS virtual VPN DNS (`198.18.0.2:53`) TCP fallback queries from hitting
        // `UNMAPPED-FAKE-IP` when UDP DNS responses are truncated (`TC=1`) or retried over TCP.
        if tuple.dst.port() == 53 && current_router.tun_dns_hijack() {
            remote_connected_task.store(true, Ordering::Release);
            serve_tun_tcp_dns_flow(
                Arc::clone(current_router.dns()),
                to_remote_rx,
                from_remote_tx,
                remote_failed_task,
                wake_task,
            )
            .await;
            return;
        }

        let raw_target = TargetAddr::from(tuple.dst);
        let is_unmapped_fake = current_router.dns().is_unmapped_fake_ip(&raw_target);
        let is_fake = current_router.dns().is_fake_ip(tuple.dst.ip());
        let sniffer_cfg = current_router.sniffer();
        let mut prefetched_first_payload: Option<Vec<u8>> = None;
        let mut sniffed_real_ip: Option<(String, SniffedProtocol)> = None;

        let route_target = if is_unmapped_fake {
            match sniff_tcp_initial_payload(
                &mut to_remote_rx,
                &bridge_closed_tx,
                Duration::from_millis(250),
                true,
                true,
            )
            .await
            {
                TcpSniffResult::BridgeClosed => return,
                TcpSniffResult::Sniffed {
                    domain, payload, ..
                } => {
                    if !payload.is_empty() {
                        prefetched_first_payload = Some(payload);
                    }
                    let fake_v4 = match tuple.dst.ip() {
                        IpAddr::V4(v4) => Some(v4),
                        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                    };
                    if let Some(v4) = fake_v4 {
                        let _ = current_router.dns().recover_unmapped_fake_ip(v4, &domain);
                    }
                    if !current_router.dns().is_unmapped_fake_ip(&raw_target) {
                        raw_target.clone()
                    } else {
                        TargetAddr::new_domain(domain, tuple.dst.port())
                            .unwrap_or_else(|_| raw_target.clone())
                    }
                }
                TcpSniffResult::NoDomain { payload } => {
                    if !payload.is_empty() {
                        prefetched_first_payload = Some(payload);
                    }
                    raw_target.clone()
                }
            }
        } else if !is_fake && sniffer_cfg.should_sniff_real_ip_tcp(tuple.dst.ip(), tuple.dst.port())
        {
            let allow_tls = sniffer_cfg.should_sniff_tls_port(tuple.dst.port());
            let allow_http = sniffer_cfg.should_sniff_http_port(tuple.dst.port());
            match sniff_tcp_initial_payload(
                &mut to_remote_rx,
                &bridge_closed_tx,
                Duration::from_millis(150),
                allow_tls,
                allow_http,
            )
            .await
            {
                TcpSniffResult::BridgeClosed => return,
                TcpSniffResult::Sniffed {
                    domain,
                    protocol,
                    payload,
                } => {
                    if !payload.is_empty() {
                        prefetched_first_payload = Some(payload);
                    }
                    let target = TargetAddr::new_domain(domain.clone(), tuple.dst.port())
                        .unwrap_or_else(|_| raw_target.clone());
                    sniffed_real_ip = Some((domain, protocol));
                    target
                }
                TcpSniffResult::NoDomain { payload } => {
                    if !payload.is_empty() {
                        prefetched_first_payload = Some(payload);
                    }
                    raw_target.clone()
                }
            }
        } else {
            raw_target.clone()
        };

        let decision = tokio::select! {
            biased;
            _ = bridge_closed_tx.closed() => return,
            _ = dial_timeout_task.notified() => {
                remote_failed_task.store(true, Ordering::Release);
                wake_task.notify_one();
                return;
            }
            d = current_router.route_async_with_context(
                Some(tuple.src.ip()),
                Some(tuple.src),
                crate::platform::process::SocketTransport::Tcp,
                &route_target,
            ) => d,
        };

        // For real-IP flows whose domain was sniffed via TLS SNI / HTTP Host:
        // - Always use the sniffed domain for rule matching and connection telemetry.
        // - Override the remote dial destination with the sniffed domain on PROXY outbounds
        //   when `override-destination` is enabled and the domain is not in `skip-domain`
        //   (defeating local poisoned-IP DNS without adding extra DNS lookups on DIRECT),
        //   while guarding pure-IP TLS flows against hijacking Fake-TLS / REALITY / domain-fronting.
        let (dial_target, sniff_override_tracker) = resolve_real_ip_tcp_dial_target(
            &raw_target,
            &decision.target,
            decision.outbound.exit_category(),
            &sniffer_cfg,
            current_router.sniff_override_guard(),
            sniffed_real_ip.as_ref(),
        );

        let conn_guard = hub_clone.register_connection_with_outbound_guard_sniffed(
            "TUN(smoltcp)",
            "tcp",
            Some(tuple.src),
            &decision.target,
            decision.restored_from_fake_ip.map(|ip| ip.to_string()),
            &decision.rule_type,
            &decision.rule_payload,
            decision.chains.clone(),
            decision.outbound.as_ref(),
            sniffed_real_ip.is_some(),
        );
        let conn_entry = Arc::clone(conn_guard.connection());
        let mut sniff_override_guard = sniff_override_tracker.map(|tracker| {
            RealIpTlsOverrideGuard::new(
                Arc::clone(current_router.sniff_override_guard()),
                Arc::clone(&hub_clone),
                Arc::clone(&conn_entry),
                tracker,
            )
        });
        hub_clone.push_log(
            "info",
            format!(
                "[TUN] {} -> {} (raw {}, dial {}) [{}] via {} ({})",
                tuple.src,
                decision.target,
                tuple.dst,
                dial_target,
                decision.rule_type,
                decision.outbound.name(),
                decision.outbound.exit_category()
            ),
        );

        let dial_start = Instant::now();
        let elapsed_mono = flow_created_at.elapsed();
        let elapsed_wall =
            Duration::from_millis(TelemetryHub::now_ms().saturating_sub(flow_created_wall_ms));
        let rem_connect_budget =
            OUTBOUND_CONNECT_TIMEOUT.saturating_sub(elapsed_mono.max(elapsed_wall));
        let make_timeout_err = || {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "outbound dial+handshake to {} via '{}' timed out after {}s",
                    dial_target,
                    decision.outbound.name(),
                    OUTBOUND_CONNECT_TIMEOUT.as_secs()
                ),
            )
        };
        let dial_res = if rem_connect_budget.is_zero() {
            Err(make_timeout_err())
        } else {
            tokio::select! {
                biased;
                _ = conn_entry.closed() => {
                    if let Some(g) = sniff_override_guard.as_mut() {
                        g.disarm();
                    }
                    remote_failed_task.store(true, Ordering::Release);
                    wake_task.notify_one();
                    return;
                }
                _ = bridge_closed_tx.closed() => {
                    if let Some(g) = sniff_override_guard.as_mut() {
                        g.disarm();
                    }
                    return;
                }
                _ = dial_timeout_task.notified() => {
                    Err(make_timeout_err())
                }
                res = tokio::time::timeout(
                    rem_connect_budget,
                    decision.outbound.connect_tcp(&dial_target),
                ) => {
                    match res {
                        Ok(inner) => inner,
                        Err(_) => Err(make_timeout_err()),
                    }
                }
            }
        };

        let outbound = match dial_res {
            Ok(s) => s,
            Err(err) => {
                if let Some(g) = sniff_override_guard.as_mut() {
                    g.mark_dial_failed();
                }
                tracing::debug!(
                    "[TUN] outbound connect failed for {} -> {}: {}",
                    tuple.src,
                    decision.target,
                    err
                );
                conn_guard.record_failed(&err.to_string());
                remote_failed_task.store(true, Ordering::Release);
                wake_task.notify_one();
                return;
            }
        };
        remote_connected_task.store(true, Ordering::Release);
        conn_guard.mark_established();
        if let Some(g) = sniff_override_guard.as_mut() {
            g.mark_established();
        }
        let leaf_outbound = decision.outbound.name();
        if decision.outbound.exit_category() == "PROXY"
            && !matches!(leaf_outbound, "DIRECT" | "REJECT")
        {
            current_router.record_passive_delay_if_stale(
                leaf_outbound,
                dial_start.elapsed().as_millis().max(1) as u64,
                180_000,
            );
        }

        let tracked = conn_guard.into_tracked_stream(outbound);
        let (mut rd, mut wr) = tokio::io::split(tracked);

        let wake_wr = Arc::clone(&wake_task);
        let writer_fut = async move {
            let drain_and_shutdown = async {
                // If an initial payload was prefetched while recovering an unmapped Fake-IP,
                // flush it immediately; otherwise coalesce client-speaks-first payload for up
                // to 15ms for 0-RTT proxy framing before flushing pending proxy headers.
                let mut client_eof = false;
                if let Some(first_chunk) = prefetched_first_payload {
                    if write_payload_batch(&mut wr, &first_chunk, &mut to_remote_rx, &wake_wr)
                        .await
                        .is_err()
                    {
                        return;
                    }
                } else {
                    match tokio::time::timeout(Duration::from_millis(15), to_remote_rx.recv()).await
                    {
                        Ok(Some(first_chunk)) => {
                            if write_payload_batch(
                                &mut wr,
                                &first_chunk,
                                &mut to_remote_rx,
                                &wake_wr,
                            )
                            .await
                            .is_err()
                            {
                                return;
                            }
                        }
                        Ok(None) => {
                            client_eof = true;
                            if wr.flush().await.is_err() {
                                return;
                            }
                        }
                        Err(_) => {
                            if wr.flush().await.is_err() {
                                return;
                            }
                        }
                    }
                }
                if !client_eof {
                    while let Some(first_chunk) = to_remote_rx.recv().await {
                        if write_payload_batch(&mut wr, &first_chunk, &mut to_remote_rx, &wake_wr)
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                let _ = tokio::time::timeout(Duration::from_secs(2), wr.shutdown()).await;
            };
            tokio::select! {
                () = drain_and_shutdown => {}
                () = async {
                    bridge_closed_tx.closed().await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } => {}
            }
        };

        let wake_rd = Arc::clone(&wake_task);
        let mut raw_ip_progress = sniff_override_guard
            .as_ref()
            .and_then(|g| g.raw_ip_progress_handle());
        let reader_fut = async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = tokio::select! {
                    biased;
                    _ = from_remote_tx.closed() => break,
                    res = rd.read(&mut buf) => match res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    },
                };
                if let Some(handle) = raw_ip_progress.take() {
                    handle.confirm_download_received();
                }
                if from_remote_tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
                wake_rd.notify_one();
            }
            drop(from_remote_tx);
            wake_rd.notify_one();
        };

        tokio::select! {
            _ = async { tokio::join!(writer_fut, reader_fut) } => {}
            _ = conn_entry.closed() => {
                if let Some(g) = sniff_override_guard.as_mut() {
                    g.mark_externally_cancelled();
                }
                remote_failed_task.store(true, Ordering::Release);
                wake_task.notify_one();
            }
        }
        if let Some(g) = sniff_override_guard.as_mut() {
            g.finish();
        }
    });

    flows.insert(
        tuple,
        BridgeFlow {
            handle,
            established: false,
            remote_connected,
            dial_timeout_notify,
            dial_timeout_notified_at: None,
            created_at: now,
            created_wall_ms: now_wall,
            last_active: now,
            last_active_wall_ms: now_wall,
            fin_started_at: None,
            fin_started_wall_ms: None,
            pending_tx: BytesMut::new(),
            from_remote_rx,
            to_remote_tx: Some(to_remote_tx),
            _bridge_closed_rx: bridge_closed_rx,
            remote_eof: false,
            remote_failed,
            task_abort: flow_task.abort_handle(),
        },
    );
    Some(handle)
}

enum TcpSniffResult {
    Sniffed {
        domain: String,
        protocol: SniffedProtocol,
        payload: Vec<u8>,
    },
    /// Always returns every byte read from `to_remote_rx` so zero payload bytes are ever lost
    /// when sniffing times out, sees non-TLS/non-HTTP traffic, or hits `MAX_SNIFF_BYTES`.
    NoDomain {
        payload: Vec<u8>,
    },
    BridgeClosed,
}

async fn sniff_tcp_initial_payload(
    to_remote_rx: &mut mpsc::Receiver<Vec<u8>>,
    bridge_closed_tx: &watch::Sender<()>,
    timeout: Duration,
    allow_tls: bool,
    allow_http: bool,
) -> TcpSniffResult {
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let chunk_res = tokio::select! {
            biased;
            _ = bridge_closed_tx.closed() => return TcpSniffResult::BridgeClosed,
            _ = tokio::time::sleep_until(deadline) => return TcpSniffResult::NoDomain { payload: buf },
            recv = to_remote_rx.recv() => recv,
        };
        let Some(chunk) = chunk_res else {
            return TcpSniffResult::NoDomain { payload: buf };
        };
        buf.extend_from_slice(&chunk);
        let sniff_window = &buf[..buf.len().min(MAX_SNIFF_BYTES)];
        match sniff_tcp_protocol(sniff_window, allow_tls, allow_http) {
            SniffOutcomeWithProto::Domain { domain, protocol } => {
                return TcpSniffResult::Sniffed {
                    domain,
                    protocol,
                    payload: buf,
                };
            }
            SniffOutcomeWithProto::NoHostname => {
                return TcpSniffResult::NoDomain { payload: buf };
            }
            SniffOutcomeWithProto::NeedMoreBytes => {
                if buf.len() >= MAX_SNIFF_BYTES {
                    return TcpSniffResult::NoDomain { payload: buf };
                }
            }
        }
    }
}

async fn write_payload_batch<W: AsyncWriteExt + Unpin>(
    wr: &mut W,
    first_chunk: &[u8],
    to_remote_rx: &mut mpsc::Receiver<Vec<u8>>,
    wake_notify: &Notify,
) -> io::Result<()> {
    wr.write_all(first_chunk).await?;
    wake_notify.notify_one();
    while let Ok(more) = to_remote_rx.try_recv() {
        wr.write_all(&more).await?;
        wake_notify.notify_one();
    }
    wr.flush().await
}

async fn serve_tun_tcp_dns_flow(
    dns: Arc<crate::dns::fake_ip::FakeIpDnsEngine>,
    mut to_remote_rx: mpsc::Receiver<Vec<u8>>,
    from_remote_tx: mpsc::Sender<Vec<u8>>,
    remote_failed: Arc<AtomicBool>,
    wake_notify: Arc<Notify>,
) {
    const MAX_TUN_TCP_DNS_BUF: usize = 64 * 1024;
    const MAX_TUN_TCP_DNS_MSG: usize = 16 * 1024;
    const TUN_TCP_DNS_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

    let mut rx_buf = BytesMut::with_capacity(512);
    let mut handled_queries = 0usize;

    'conn: loop {
        while rx_buf.len() >= 2 {
            let msg_len = u16::from_be_bytes([rx_buf[0], rx_buf[1]]) as usize;
            if !(12..=MAX_TUN_TCP_DNS_MSG).contains(&msg_len) {
                remote_failed.store(true, Ordering::Release);
                break 'conn;
            }
            if rx_buf.len() < 2 + msg_len {
                break;
            }
            let _ = rx_buf.split_to(2);
            let query = rx_buf.split_to(msg_len);
            let Ok(resp) = dns.handle_dns_packet(&query).await else {
                break 'conn;
            };
            if resp.len() > u16::MAX as usize {
                break 'conn;
            }
            let mut framed = Vec::with_capacity(2 + resp.len());
            framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            framed.extend_from_slice(&resp);
            if from_remote_tx.send(framed).await.is_err() {
                break 'conn;
            }
            wake_notify.notify_one();
            handled_queries += 1;
            if handled_queries >= 64 {
                break 'conn;
            }
        }

        match tokio::time::timeout(TUN_TCP_DNS_IDLE_TIMEOUT, to_remote_rx.recv()).await {
            Ok(Some(chunk)) => {
                if rx_buf.len() + chunk.len() > MAX_TUN_TCP_DNS_BUF {
                    remote_failed.store(true, Ordering::Release);
                    break;
                }
                rx_buf.extend_from_slice(&chunk);
            }
            Ok(None) | Err(_) => break,
        }
    }

    drop(from_remote_tx);
    wake_notify.notify_one();
}

fn build_ip_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            build_ipv4_udp_packet(s4, src.port(), d4, dst.port(), payload)
        }
        (IpAddr::V6(s6), IpAddr::V6(d6)) => {
            build_ipv6_udp_packet(s6, src.port(), d6, dst.port(), payload)
        }
        _ => None,
    }
}

/// Construct a checksummed IPv4 + UDP packet (used by TUN DNS hijack, general UDP NAT, & packet tests).
pub fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let checksum_caps = ChecksumCapabilities::default();
    let src_v4: Ipv4Address = src_ip;
    let dst_v4: Ipv4Address = dst_ip;
    let udp_repr = UdpRepr { src_port, dst_port };
    let udp_len = udp_repr.header_len() + payload.len();
    let ip_repr = Ipv4Repr {
        src_addr: src_v4,
        dst_addr: dst_v4,
        next_header: IpProtocol::Udp,
        payload_len: udp_len,
        hop_limit: 64,
    };
    let total_len = ip_repr.buffer_len() + udp_len;
    if total_len > 65535 {
        return None;
    }
    let mut bytes = vec![0u8; total_len];
    let mut ip_pkt = Ipv4Packet::new_unchecked(&mut bytes);
    ip_repr.emit(&mut ip_pkt, &checksum_caps);
    let mut udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload_mut());
    udp_repr.emit(
        &mut udp_pkt,
        &IpAddress::Ipv4(src_v4),
        &IpAddress::Ipv4(dst_v4),
        payload.len(),
        |dst| dst.copy_from_slice(payload),
        &checksum_caps,
    );
    Some(bytes)
}

/// Construct a checksummed IPv6 + UDP packet (used by IPv6 TUN DNS hijack, general IPv6 UDP NAT, & tests).
pub fn build_ipv6_udp_packet(
    src_ip: Ipv6Addr,
    src_port: u16,
    dst_ip: Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let checksum_caps = ChecksumCapabilities::default();
    let src_v6: Ipv6Address = src_ip;
    let dst_v6: Ipv6Address = dst_ip;
    let udp_repr = UdpRepr { src_port, dst_port };
    let udp_len = udp_repr.header_len() + payload.len();
    if udp_len > 65535 {
        return None;
    }
    let ip_repr = Ipv6Repr {
        src_addr: src_v6,
        dst_addr: dst_v6,
        next_header: IpProtocol::Udp,
        payload_len: udp_len,
        hop_limit: 64,
    };
    let total_len = ip_repr.buffer_len() + udp_len;
    let mut bytes = vec![0u8; total_len];
    let mut ip_pkt = Ipv6Packet::new_unchecked(&mut bytes);
    ip_repr.emit(&mut ip_pkt);
    let mut udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload_mut());
    udp_repr.emit(
        &mut udp_pkt,
        &IpAddress::Ipv6(src_v6),
        &IpAddress::Ipv6(dst_v6),
        payload.len(),
        |dst| dst.copy_from_slice(payload),
        &checksum_caps,
    );
    Some(bytes)
}

/// Construct a checksummed RFC 4443 `ICMPv6 Destination Unreachable (PortUnreachable)` packet
/// quoting an unreachable client IPv6 UDP datagram (`client_v6:client_port -> remote_v6:remote_port`).
fn build_ipv6_udp_port_unreachable_packet(
    client_v6: Ipv6Addr,
    client_port: u16,
    remote_v6: Ipv6Addr,
    remote_port: u16,
    udp_payload: &[u8],
) -> Option<Vec<u8>> {
    let checksum_caps = ChecksumCapabilities::default();
    let orig_udp_pkt =
        build_ipv6_udp_packet(client_v6, client_port, remote_v6, remote_port, udp_payload)?;
    let orig_ip_pkt = Ipv6Packet::new_checked(&orig_udp_pkt).ok()?;
    let orig_ip_repr = Ipv6Repr::parse(&orig_ip_pkt).ok()?;
    let icmp_repr = Icmpv6Repr::DstUnreachable {
        reason: Icmpv6DstUnreachable::PortUnreachable,
        header: orig_ip_repr,
        data: orig_ip_pkt.payload(),
    };
    let icmp_len = icmp_repr.buffer_len();
    let outer_repr = Ipv6Repr {
        src_addr: remote_v6,
        dst_addr: client_v6,
        next_header: IpProtocol::Icmpv6,
        payload_len: icmp_len,
        hop_limit: 64,
    };
    let mut bytes = vec![0u8; outer_repr.buffer_len() + icmp_len];
    let mut outer_pkt = Ipv6Packet::new_unchecked(&mut bytes);
    outer_repr.emit(&mut outer_pkt);
    let mut icmp_pkt = Icmpv6Packet::new_unchecked(outer_pkt.payload_mut());
    icmp_repr.emit(&remote_v6, &client_v6, &mut icmp_pkt, &checksum_caps);
    Some(bytes)
}

/// RAII guard owning an attached cross-platform OS system TUN interface (`Linux /dev/net/tun`,
/// `Windows Wintun`, or `macOS Darwin utun`), its routing/DNS state, `SocketProtector`, and `RecoveryJournal`.
pub struct OsTunGuard {
    session: parking_lot::Mutex<Option<Box<dyn crate::platform::tun::SystemTunSession>>>,
}

impl OsTunGuard {
    pub fn health(&self) -> Option<crate::platform::tun::TunHealthSnapshot> {
        self.session.lock().as_ref().map(|s| s.health())
    }

    pub fn stop_now(&self) {
        if let Some(mut s) = self.session.lock().take() {
            s.stop();
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_session(
        session: Box<dyn crate::platform::tun::SystemTunSession>,
    ) -> Self {
        Self {
            session: parking_lot::Mutex::new(Some(session)),
        }
    }
}

impl Drop for OsTunGuard {
    fn drop(&mut self) {
        self.stop_now();
    }
}

/// Attach our userspace `VirtualTunHandle` onto a real OS system TUN interface using a full
/// cross-platform `TunLaunchSpec`.
pub fn attach_os_tun_with_spec(
    spec: crate::platform::tun::TunLaunchSpec,
    handle: VirtualTunHandle,
) -> io::Result<OsTunGuard> {
    let session = crate::platform::tun::attach_platform_system_tun(spec, handle)?;
    Ok(OsTunGuard {
        session: parking_lot::Mutex::new(Some(session)),
    })
}

/// Attach our userspace `VirtualTunHandle` onto a real OS system TUN interface with default options.
pub fn attach_os_tun(
    device_name: &str,
    mtu: usize,
    fake_ip_net: Ipv4Net,
    bypass_ips: Vec<IpAddr>,
    handle: VirtualTunHandle,
) -> io::Result<OsTunGuard> {
    let gw_v4 = Ipv4Addr::from(u32::from(fake_ip_net.network()).saturating_add(1));
    let tun_ipv4_cidr = Ipv4Net::new(gw_v4, fake_ip_net.prefix_len()).unwrap_or(fake_ip_net);
    let tun_ipv6_cidr = crate::platform::tun::DEFAULT_TUN_IPV6_CIDR
        .parse()
        .expect("valid default TUN IPv6 CIDR");

    let spec = crate::platform::tun::TunLaunchSpec {
        device_name: device_name.to_string(),
        mtu,
        auto_route: true,
        strict_route: false,
        enable_ipv6: false,
        auto_detect_interface: true,
        dns_hijack: true,
        fake_ip_net,
        tun_ipv4_cidr,
        tun_ipv6_cidr,
        bypass_ips,
        dns_bypass_ips: Vec::new(),
        route_exclude_cidrs: Vec::new(),
        local_dns_addr: None,
        wintun_dll_path: None,
        state_dir: crate::platform::recovery::default_state_dir(),
        dns_engine: None,
        network_change_hook: None,
    };
    attach_os_tun_with_spec(spec, handle)
}

/// Backward-compatible wrapper calling `attach_os_tun` with default Fake-IP range (`198.18.0.0/15`).
pub fn try_attach_linux_os_tun(
    device_name: &str,
    handle: VirtualTunHandle,
) -> io::Result<OsTunGuard> {
    let default_net: Ipv4Net = "198.18.0.0/15".parse().expect("valid CIDR");
    attach_os_tun(device_name, 1500, default_net, Vec::new(), handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bridge_flow_wall_clock_timeout_fires_when_monotonic_clock_freezes() {
        let mut sockets = SocketSet::new(vec![]);
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64]),
            tcp::SocketBuffer::new(vec![0u8; 64]),
        );
        let handle = sockets.add(sock);
        let (_tx, rx) = mpsc::channel(1);
        let (_bridge_closed_tx, bridge_closed_rx) = watch::channel(());
        let noop_task = tokio::spawn(async {});

        let mono_now = Instant::now();
        let base_wall = 1_700_000_000_000u64;
        let mut flow = BridgeFlow {
            handle,
            established: true,
            remote_connected: Arc::new(AtomicBool::new(true)),
            dial_timeout_notify: Arc::new(Notify::new()),
            dial_timeout_notified_at: None,
            created_at: mono_now,
            created_wall_ms: base_wall,
            last_active: mono_now,
            last_active_wall_ms: base_wall,
            fin_started_at: None,
            fin_started_wall_ms: None,
            pending_tx: BytesMut::new(),
            from_remote_rx: rx,
            to_remote_tx: None,
            _bridge_closed_rx: bridge_closed_rx,
            remote_eof: false,
            remote_failed: Arc::new(AtomicBool::new(false)),
            task_abort: noop_task.abort_handle(),
        };

        // Fresh established flow and long-lived push/IM/FCM idle intervals are NOT timed out.
        assert!(!flow.is_timed_out(mono_now, base_wall + 5_000, 0));
        assert!(!flow.is_timed_out(mono_now, base_wall + 309_000, 0));
        assert!(!flow.is_timed_out(mono_now, base_wall + 1_680_000, 0));

        // Monotonic clock froze at `mono_now`, but wall clock advanced 1801s (> 1800s TCP_IDLE_TIMEOUT).
        assert!(flow.is_timed_out(mono_now, base_wall + 1_801_000, 0));

        // Half-closed flow with empty pending_tx & send_queue times out after 10s idle wall-clock advance even if monotonic froze.
        flow.fin_started_at = Some(mono_now);
        flow.fin_started_wall_ms = Some(base_wall);
        assert!(!flow.is_timed_out(mono_now, base_wall + 9_000, 0));
        assert!(flow.is_timed_out(mono_now, base_wall + 11_000, 0));

        // Unestablished SYN flow times out after 15s wall-clock advance even if monotonic froze.
        flow.established = false;
        flow.fin_started_at = None;
        flow.fin_started_wall_ms = None;
        assert!(!flow.is_timed_out(mono_now, base_wall + 14_000, 0));
        assert!(flow.is_timed_out(mono_now, base_wall + 16_000, 0));
    }

    #[tokio::test]
    async fn established_long_lived_tcp_flow_survives_push_and_fcm_idle_intervals_before_reaping() {
        let mut sockets = SocketSet::new(vec![]);
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64]),
            tcp::SocketBuffer::new(vec![0u8; 64]),
        );
        let handle = sockets.add(sock);
        let (_tx, rx) = mpsc::channel(1);
        let (_bridge_closed_tx, bridge_closed_rx) = watch::channel(());
        let noop_task = tokio::spawn(async {});

        let mono_now = Instant::now();
        let base_wall = 1_700_000_000_000u64;
        let flow = BridgeFlow {
            handle,
            established: true,
            remote_connected: Arc::new(AtomicBool::new(true)),
            dial_timeout_notify: Arc::new(Notify::new()),
            dial_timeout_notified_at: None,
            created_at: mono_now,
            created_wall_ms: base_wall,
            last_active: mono_now,
            last_active_wall_ms: base_wall,
            fin_started_at: None,
            fin_started_wall_ms: None,
            pending_tx: BytesMut::new(),
            from_remote_rx: rx,
            to_remote_tx: None,
            _bridge_closed_rx: bridge_closed_rx,
            remote_eof: false,
            remote_failed: Arc::new(AtomicBool::new(false)),
            task_abort: noop_task.abort_handle(),
        };

        // Typical real-world long-lived TCP idle gaps MUST NOT be aborted with RST:
        // - 180s (3m domestic push `:5223` heartbeat)
        // - 300s (5m IM/SSH keepalive)
        // - 1059s (17m39s Telegram background idle)
        // - 1680s (28m cellular FCM `mtalk.google.com:5228` heartbeat)
        // - 1800s exact ceiling boundary
        for secs in [180u64, 300, 1059, 1680, 1800] {
            let t_mono = mono_now + Duration::from_secs(secs);
            let t_wall = base_wall + secs * 1_000;
            assert!(
                !flow.is_timed_out(t_mono, t_wall, 0),
                "established flow must survive {secs}s idle"
            );
        }

        // Once idle exceeds 1800s (by monotonic OR wall-clock time), reaping fires cleanly.
        assert!(flow.is_timed_out(mono_now + Duration::from_secs(1801), base_wall, 0));
        assert!(flow.is_timed_out(mono_now, base_wall + 1_801_000, 0));
    }

    #[tokio::test]
    async fn pressure_eviction_selects_stalest_idle_established_flow_and_spares_recent_or_pending()
    {
        let mut sockets = SocketSet::new(vec![]);
        let make_flow = |sockets: &mut SocketSet<'static>,
                         established: bool,
                         remote_connected: bool,
                         last_active: Instant,
                         last_active_wall_ms: u64| {
            let sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 64]),
                tcp::SocketBuffer::new(vec![0u8; 64]),
            );
            let handle = sockets.add(sock);
            let (_tx, rx) = mpsc::channel(1);
            let (_bridge_closed_tx, bridge_closed_rx) = watch::channel(());
            let noop_task = tokio::spawn(async {});
            BridgeFlow {
                handle,
                established,
                remote_connected: Arc::new(AtomicBool::new(remote_connected)),
                dial_timeout_notify: Arc::new(Notify::new()),
                dial_timeout_notified_at: None,
                created_at: last_active,
                created_wall_ms: last_active_wall_ms,
                last_active,
                last_active_wall_ms,
                fin_started_at: None,
                fin_started_wall_ms: None,
                pending_tx: BytesMut::new(),
                from_remote_rx: rx,
                to_remote_tx: None,
                _bridge_closed_rx: bridge_closed_rx,
                remote_eof: false,
                remote_failed: Arc::new(AtomicBool::new(false)),
                task_abort: noop_task.abort_handle(),
            }
        };

        let base_mono = Instant::now();
        let base_wall = 1_700_000_000_000u64;
        let now = base_mono + Duration::from_secs(600);
        let now_wall = base_wall + 600_000;

        let tuple_recent = FourTuple {
            src: SocketAddr::from(([198, 18, 0, 1], 40001)),
            dst: SocketAddr::from(([1, 1, 1, 1], 443)),
        };
        let tuple_pending = FourTuple {
            src: SocketAddr::from(([198, 18, 0, 1], 40002)),
            dst: SocketAddr::from(([1, 1, 1, 1], 443)),
        };
        let tuple_idle_3m = FourTuple {
            src: SocketAddr::from(([198, 18, 0, 1], 40003)),
            dst: SocketAddr::from(([1, 1, 1, 1], 443)),
        };
        let tuple_idle_wall_15m = FourTuple {
            src: SocketAddr::from(([198, 18, 0, 1], 40004)),
            dst: SocketAddr::from(([1, 1, 1, 1], 443)),
        };

        let mut flows = HashMap::new();
        // Recently active established flow (60s idle <= 120s threshold) and pending dial flow
        // (even with old timestamp) MUST NOT be selected for pressure eviction.
        flows.insert(
            tuple_recent,
            make_flow(
                &mut sockets,
                true,
                true,
                now - Duration::from_secs(60),
                now_wall - 60_000,
            ),
        );
        flows.insert(
            tuple_pending,
            make_flow(&mut sockets, true, false, base_mono, base_wall - 900_000),
        );
        assert_eq!(
            select_pressure_eviction_candidate(&flows, now, now_wall),
            None
        );

        // Add an established flow idle 180s (> 120s) -> becomes evictable.
        flows.insert(
            tuple_idle_3m,
            make_flow(
                &mut sockets,
                true,
                true,
                now - Duration::from_secs(180),
                now_wall - 180_000,
            ),
        );
        assert_eq!(
            select_pressure_eviction_candidate(&flows, now, now_wall),
            Some(tuple_idle_3m)
        );

        // Add another established flow whose monotonic clock barely moved (50s, e.g. post-sleep)
        // but wall clock is 900s stale -> stalest effective idle wins LRU eviction.
        flows.insert(
            tuple_idle_wall_15m,
            make_flow(
                &mut sockets,
                true,
                true,
                now - Duration::from_secs(50),
                now_wall - 900_000,
            ),
        );
        assert_eq!(
            select_pressure_eviction_candidate(&flows, now, now_wall),
            Some(tuple_idle_wall_15m)
        );
    }

    #[tokio::test]
    async fn locally_established_unconnected_outbound_dial_times_out_on_wall_clock() {
        let mut sockets = SocketSet::new(vec![]);
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64]),
            tcp::SocketBuffer::new(vec![0u8; 64]),
        );
        let handle = sockets.add(sock);
        let (_tx, rx) = mpsc::channel(1);
        let (_bridge_closed_tx, bridge_closed_rx) = watch::channel(());
        let noop_task = tokio::spawn(async {});

        let mono_now = Instant::now();
        let base_wall = 1_700_000_000_000u64;
        let remote_connected = Arc::new(AtomicBool::new(false));
        let mut flow = BridgeFlow {
            handle,
            // smoltcp completed local 3-way handshake (<1ms), while outbound dial is still pending.
            established: true,
            remote_connected: Arc::clone(&remote_connected),
            dial_timeout_notify: Arc::new(Notify::new()),
            dial_timeout_notified_at: None,
            created_at: mono_now,
            created_wall_ms: base_wall,
            // Even if client sent TLS ClientHello bytes at +14s, created_wall_ms governs dial budget!
            last_active: mono_now,
            last_active_wall_ms: base_wall + 14_000,
            fin_started_at: None,
            fin_started_wall_ms: None,
            pending_tx: BytesMut::new(),
            from_remote_rx: rx,
            to_remote_tx: None,
            _bridge_closed_rx: bridge_closed_rx,
            remote_eof: false,
            remote_failed: Arc::new(AtomicBool::new(false)),
            task_abort: noop_task.abort_handle(),
        };

        // At 14s wall-clock (monotonic frozen), neither soft dial timeout nor hard reap fires.
        assert!(!flow.notify_dial_timeout_if_needed(mono_now, base_wall + 14_000));
        assert!(!flow.is_timed_out(mono_now, base_wall + 14_000, 0));

        // At 15.5s wall-clock (monotonic frozen during Android Doze/suspend), soft dial timeout
        // fires once so `flow_task` records `outbound dial+handshake ... timed out after 15s`,
        // while hard reap waits for `OUTBOUND_CONNECT_HARD_REAP_GRACE` (2s) after notification.
        assert!(flow.notify_dial_timeout_if_needed(mono_now, base_wall + 15_500));
        assert!(!flow.notify_dial_timeout_if_needed(mono_now, base_wall + 16_000));
        assert!(!flow.is_timed_out(mono_now, base_wall + 15_500, 0));
        assert!(!flow.is_timed_out(mono_now, base_wall + 17_400, 0));

        // At 18s wall-clock (> 2s after notification), hard reap backstop fires if still unconnected.
        assert!(flow.is_timed_out(mono_now, base_wall + 18_000, 0));

        // Once remote_connected flips true, neither dial timeout nor hard dial backstop triggers.
        remote_connected.store(true, Ordering::Release);
        assert!(!flow.is_dial_timed_out(mono_now, base_wall + 18_000));
        assert!(!flow.is_timed_out(mono_now, base_wall + 18_000, 0));
    }

    #[tokio::test]
    async fn deep_sleep_wakeup_preserves_dial_timeout_record_failed_grace_window() {
        let mut sockets = SocketSet::new(vec![]);
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64]),
            tcp::SocketBuffer::new(vec![0u8; 64]),
        );
        let handle = sockets.add(sock);
        let (_tx, rx) = mpsc::channel(1);
        let (_bridge_closed_tx, bridge_closed_rx) = watch::channel(());
        let noop_task = tokio::spawn(async {});

        let mono_now = Instant::now();
        let base_wall = 1_700_000_000_000u64;
        let dial_notify = Arc::new(Notify::new());
        let mut flow = BridgeFlow {
            handle,
            established: true,
            remote_connected: Arc::new(AtomicBool::new(false)),
            dial_timeout_notify: Arc::clone(&dial_notify),
            dial_timeout_notified_at: None,
            created_at: mono_now,
            created_wall_ms: base_wall,
            last_active: mono_now,
            last_active_wall_ms: base_wall,
            fin_started_at: None,
            fin_started_wall_ms: None,
            pending_tx: BytesMut::new(),
            from_remote_rx: rx,
            to_remote_tx: None,
            _bridge_closed_rx: bridge_closed_rx,
            remote_eof: false,
            remote_failed: Arc::new(AtomicBool::new(false)),
            task_abort: noop_task.abort_handle(),
        };

        // Simulate waking from a 31-minute Android AP deep sleep (> 17s hard dial AND > 1800s TCP_IDLE_TIMEOUT)
        // while CLOCK_MONOTONIC stayed frozen at `mono_now`.
        let wakeup_wall = base_wall + 1_860_000;
        assert!(flow.notify_dial_timeout_if_needed(mono_now, wakeup_wall));

        // On the exact wakeup poll tick (and throughout the 2s grace window), `is_timed_out` MUST
        // stay false so `flow_task` is NOT synchronously aborted before calling `record_failed()`.
        assert!(!flow.is_timed_out(mono_now, wakeup_wall, 0));
        assert!(!flow.is_timed_out(
            mono_now + Duration::from_millis(1_900),
            wakeup_wall + 1_900,
            0
        ));

        // The stored notification permit must immediately wake `flow_task`.
        tokio::time::timeout(Duration::from_millis(50), dial_notify.notified())
            .await
            .expect("dial_timeout_notify must wake flow_task on deep-sleep wakeup");

        // If `flow_task` fails to exit within `OUTBOUND_CONNECT_HARD_REAP_GRACE` (2s) after
        // notification (either by monotonic or wall clock), the hard-reap backstop fires.
        assert!(flow.is_timed_out(
            mono_now + Duration::from_millis(2_100),
            wakeup_wall + 500,
            0
        ));
        assert!(flow.is_timed_out(mono_now, wakeup_wall + 2_100, 0));
    }

    #[tokio::test]
    async fn active_half_closed_bridge_flow_is_not_timed_out_until_idle_and_drained() {
        let mut sockets = SocketSet::new(vec![]);
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64]),
            tcp::SocketBuffer::new(vec![0u8; 64]),
        );
        let handle = sockets.add(sock);
        let (_tx, rx) = mpsc::channel(1);
        let (_bridge_closed_tx, bridge_closed_rx) = watch::channel(());
        let noop_task = tokio::spawn(async {});

        let mono_now = Instant::now();
        let base_wall = 1_700_000_000_000u64;
        let mut flow = BridgeFlow {
            handle,
            established: true,
            remote_connected: Arc::new(AtomicBool::new(true)),
            dial_timeout_notify: Arc::new(Notify::new()),
            dial_timeout_notified_at: None,
            created_at: mono_now,
            created_wall_ms: base_wall,
            last_active: mono_now + Duration::from_secs(20),
            last_active_wall_ms: base_wall + 20_000,
            fin_started_at: Some(mono_now),
            fin_started_wall_ms: Some(base_wall),
            pending_tx: BytesMut::new(),
            from_remote_rx: rx,
            to_remote_tx: None,
            _bridge_closed_rx: bridge_closed_rx,
            remote_eof: false,
            remote_failed: Arc::new(AtomicBool::new(false)),
            task_abort: noop_task.abort_handle(),
        };

        // 25s after FIN started (> 10s), but stream transferred bytes 5s ago (< 10s): MUST NOT time out!
        let t_25s = mono_now + Duration::from_secs(25);
        let wall_25s = base_wall + 25_000;
        assert!(!flow.is_timed_out(t_25s, wall_25s, 0));

        // 35s after FIN started and 15s since last_active (> 10s), but smoltcp send_queue still holds un-ACKed bytes: MUST NOT time out!
        let t_35s = mono_now + Duration::from_secs(35);
        let wall_35s = base_wall + 35_000;
        assert!(!flow.is_timed_out(t_35s, wall_35s, 512));

        // Pending outbound buffer non-empty also prevents premature half-close timeout.
        flow.pending_tx.extend_from_slice(b"chunk");
        assert!(!flow.is_timed_out(t_35s, wall_35s, 0));

        // Once idle > 10s AND both pending_tx and smoltcp send_queue are drained, half-close timeout fires.
        flow.pending_tx.clear();
        assert!(flow.is_timed_out(t_35s, wall_35s, 0));
    }

    struct MockProxyOutbound;

    #[async_trait::async_trait]
    impl crate::outbound::OutboundHandler for MockProxyOutbound {
        fn name(&self) -> &str {
            "ProxyNode"
        }

        fn protocol(&self) -> &'static str {
            "MockProxy"
        }

        fn exit_category(&self) -> &'static str {
            "PROXY"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(
            &self,
            _target: &TargetAddr,
        ) -> io::Result<crate::outbound::BoxedStream> {
            let (client_half, server_half) = tokio::io::duplex(256);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(250)).await;
                drop(server_half);
            });
            Ok(Box::new(client_half))
        }
    }

    fn build_ipv6_split_router() -> Arc<RwLock<Arc<Router>>> {
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds.insert("ProxyNode".to_string(), Arc::new(MockProxyOutbound));
        let rules = vec![
            "IP-CIDR6,2409:8c1e::/32,DIRECT".to_string(),
            "MATCH,ProxyNode".to_string(),
        ];
        let router = Arc::new(
            Router::new(crate::config::RunMode::Rule, outbounds, &[], &rules, dns).unwrap(),
        );
        Arc::new(RwLock::new(router))
    }

    fn build_ipv4_tcp_packet(
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
        control: smoltcp::wire::TcpControl,
        seq: i32,
        ack: Option<i32>,
        payload: &[u8],
    ) -> Vec<u8> {
        let checksum_caps = ChecksumCapabilities::default();
        let (src_ip, src_port) = src;
        let (dst_ip, dst_port) = dst;
        let src_v4: Ipv4Address = src_ip;
        let dst_v4: Ipv4Address = dst_ip;
        let is_syn = control == smoltcp::wire::TcpControl::Syn;
        let tcp_repr = smoltcp::wire::TcpRepr {
            src_port,
            dst_port,
            control,
            seq_number: smoltcp::wire::TcpSeqNumber(seq),
            ack_number: ack.map(smoltcp::wire::TcpSeqNumber),
            window_len: 65535,
            window_scale: None,
            max_seg_size: is_syn.then_some(1440),
            sack_permitted: is_syn,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let tcp_len = tcp_repr.buffer_len();
        let ip_repr = Ipv4Repr {
            src_addr: src_v4,
            dst_addr: dst_v4,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_len,
            hop_limit: 64,
        };
        let mut bytes = vec![0u8; ip_repr.buffer_len() + tcp_len];
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut bytes);
        ip_repr.emit(&mut ip_pkt, &checksum_caps);
        let mut tcp_pkt = TcpPacket::new_unchecked(ip_pkt.payload_mut());
        tcp_repr.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv4(src_v4),
            &IpAddress::Ipv4(dst_v4),
            &checksum_caps,
        );
        bytes
    }

    fn build_ipv6_tcp_syn_packet(
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
    ) -> Vec<u8> {
        let checksum_caps = ChecksumCapabilities::default();
        let src_v6: Ipv6Address = src_ip;
        let dst_v6: Ipv6Address = dst_ip;
        let tcp_repr = smoltcp::wire::TcpRepr {
            src_port,
            dst_port,
            control: smoltcp::wire::TcpControl::Syn,
            seq_number: smoltcp::wire::TcpSeqNumber(1000),
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            max_seg_size: Some(1440),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let tcp_len = tcp_repr.buffer_len();
        let ip_repr = Ipv6Repr {
            src_addr: src_v6,
            dst_addr: dst_v6,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_len,
            hop_limit: 64,
        };
        let mut bytes = vec![0u8; ip_repr.buffer_len() + tcp_len];
        let mut ip_pkt = Ipv6Packet::new_unchecked(&mut bytes);
        ip_repr.emit(&mut ip_pkt);
        let mut tcp_pkt = TcpPacket::new_unchecked(ip_pkt.payload_mut());
        tcp_repr.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv6(src_v6),
            &IpAddress::Ipv6(dst_v6),
            &checksum_caps,
        );
        bytes
    }

    #[tokio::test]
    async fn tun_client_tcp_rst_immediately_closes_flow_task_and_unregisters_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let (payload_tx, payload_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let (_keep_alive_tx, keep_alive_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            let _ = payload_tx.send(buf[..n].to_vec());
            // Hold the upstream TcpStream open without sending bytes or EOF.
            let _ = keep_alive_rx.await;
        });

        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let dst_ip = dns.assign_fake_ip("localhost");
        let rules = vec!["MATCH,DIRECT".to_string()];
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Direct,
                HashMap::new(),
                &[],
                &rules,
                dns,
            )
            .unwrap(),
        );
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mut vtun, _tun_task) =
            spawn_userspace_tun(1500, router_slot, Arc::clone(&hub), shutdown_rx);

        let client = (Ipv4Addr::new(198, 18, 0, 10), 54001u16);
        let dst = (dst_ip, server_port);

        // 1. 3-way TCP handshake over virtual TUN stack
        let syn_pkt = build_ipv4_tcp_packet(
            client,
            dst,
            smoltcp::wire::TcpControl::Syn,
            10_000,
            None,
            &[],
        );
        vtun.ingress_tx.send(syn_pkt).await.unwrap();

        let syn_ack_raw = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected IPv4 TCP SYN-ACK")
            .expect("egress packet");
        let ip4_sa = Ipv4Packet::new_checked(&syn_ack_raw).unwrap();
        let tcp_sa = TcpPacket::new_checked(ip4_sa.payload()).unwrap();
        assert!(tcp_sa.syn() && tcp_sa.ack() && !tcp_sa.rst());
        assert_eq!(tcp_sa.ack_number().0, 10_001);
        let server_next_seq = tcp_sa.seq_number().0.wrapping_add(1);

        let ack_pkt = build_ipv4_tcp_packet(
            client,
            dst,
            smoltcp::wire::TcpControl::None,
            10_001,
            Some(server_next_seq),
            &[],
        );
        vtun.ingress_tx.send(ack_pkt).await.unwrap();

        // 2. Send client payload and verify upstream TcpListener received it while holding stream open
        let payload = b"hello-rst-leak-test";
        let data_pkt = build_ipv4_tcp_packet(
            client,
            dst,
            smoltcp::wire::TcpControl::Psh,
            10_001,
            Some(server_next_seq),
            payload,
        );
        vtun.ingress_tx.send(data_pkt).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), payload_rx)
            .await
            .expect("upstream server should receive client payload")
            .expect("payload oneshot");
        assert_eq!(received, payload);
        assert_eq!(hub.active_connection_count(), 1);

        // 3. Inject client TCP RST (`SO_LINGER(0)`) matching exact next client seq_number
        let client_next_seq = 10_001i32.wrapping_add(payload.len() as i32);
        let rst_pkt = build_ipv4_tcp_packet(
            client,
            dst,
            smoltcp::wire::TcpControl::Rst,
            client_next_seq,
            Some(server_next_seq),
            &[],
        );
        vtun.ingress_tx.send(rst_pkt).await.unwrap();

        // 4. `flow_task` must exit immediately via `from_remote_tx.closed()` and drop `TrackedStream`
        tokio::time::timeout(Duration::from_millis(500), async {
            while hub.active_connection_count() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("active_connection_count must drop to 0 within 500ms after client TCP RST");

        let _ = shutdown_tx.send(true);
        drop(_keep_alive_tx);
        let _ = server_task.await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tun_fast_rejects_unreachable_direct_ipv6_tcp_syn_without_affecting_proxy_ipv6() {
        let _ipv6_guard = crate::platform::socket_protect::lock_ipv6_reachability_for_test();
        crate::platform::socket_protect::set_os_underlying_ipv6_available(Some(false));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let router_slot = build_ipv6_split_router();
        let hub = Arc::new(TelemetryHub::new());
        let (mut vtun, _tun_task) =
            spawn_userspace_tun(1500, router_slot, Arc::clone(&hub), shutdown_rx);

        let client_v6: Ipv6Addr = "fd00::2".parse().unwrap();
        let direct_v6: Ipv6Addr = "2409:8c1e:75b0:1123::101".parse().unwrap();
        let proxy_v6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();

        // 1. DIRECT-routed global unicast IPv6 SYN gets immediate smoltcp TCP RST|ACK with 0 failed connections!
        let syn_direct = build_ipv6_tcp_syn_packet(client_v6, 51001, direct_v6, 443);
        vtun.ingress_tx.send(syn_direct).await.unwrap();

        let rst_pkt = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected immediate IPv6 TCP RST")
            .expect("egress packet");
        let ip6_rst = Ipv6Packet::new_checked(&rst_pkt).unwrap();
        assert_eq!(ip6_rst.src_addr(), direct_v6);
        assert_eq!(ip6_rst.dst_addr(), client_v6);
        assert_eq!(ip6_rst.next_header(), IpProtocol::Tcp);
        let tcp_rst = TcpPacket::new_checked(ip6_rst.payload()).unwrap();
        assert!(tcp_rst.rst() && !tcp_rst.syn());
        assert_eq!(hub.failed_connections_total(), 0);
        assert_eq!(hub.total_connections(), 0);

        // 2. PROXY-routed global unicast IPv6 SYN is NOT fast-rejected and still receives TCP SYN-ACK!
        let syn_proxy = build_ipv6_tcp_syn_packet(client_v6, 51002, proxy_v6, 443);
        vtun.ingress_tx.send(syn_proxy).await.unwrap();

        let syn_ack_pkt = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected IPv6 TCP SYN-ACK for PROXY-routed target")
            .expect("egress packet");
        let ip6_sa = Ipv6Packet::new_checked(&syn_ack_pkt).unwrap();
        assert_eq!(ip6_sa.src_addr(), proxy_v6);
        assert_eq!(ip6_sa.dst_addr(), client_v6);
        assert_eq!(ip6_sa.next_header(), IpProtocol::Tcp);
        let tcp_sa = TcpPacket::new_checked(ip6_sa.payload()).unwrap();
        assert!(tcp_sa.syn() && tcp_sa.ack() && !tcp_sa.rst());

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tun_fast_rejects_unreachable_direct_ipv6_udp_while_preserving_dns_hijack() {
        let _ipv6_guard = crate::platform::socket_protect::lock_ipv6_reachability_for_test();
        crate::platform::socket_protect::set_os_underlying_ipv6_available(Some(false));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let router_slot = build_ipv6_split_router();
        let hub = Arc::new(TelemetryHub::new());
        let (mut vtun, _tun_task) = spawn_userspace_tun(1500, router_slot, hub, shutdown_rx);

        let client_v6: Ipv6Addr = "fd00::2".parse().unwrap();
        let direct_v6: Ipv6Addr = "2409:8c1e:75b0:1123::101".parse().unwrap();
        let dns_v6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();

        // 1. Non-53 IPv6 UDP datagram to DIRECT target gets immediate ICMPv6 Port Unreachable!
        let quic_pkt = build_ipv6_udp_packet(client_v6, 52001, direct_v6, 443, b"quic-chlo")
            .expect("valid IPv6 UDP packet");
        vtun.ingress_tx.send(quic_pkt).await.unwrap();

        let icmp_pkt = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected immediate ICMPv6 Destination Unreachable")
            .expect("egress packet");
        let ip6_icmp = Ipv6Packet::new_checked(&icmp_pkt).unwrap();
        assert_eq!(ip6_icmp.dst_addr(), client_v6);
        assert_eq!(ip6_icmp.next_header(), IpProtocol::Icmpv6);
        let icmp6 = smoltcp::wire::Icmpv6Packet::new_checked(ip6_icmp.payload()).unwrap();
        assert_eq!(
            icmp6.msg_type(),
            smoltcp::wire::Icmpv6Message::DstUnreachable
        );
        assert_eq!(
            smoltcp::wire::Icmpv6DstUnreachable::from(icmp6.msg_code()),
            smoltcp::wire::Icmpv6DstUnreachable::PortUnreachable
        );

        // 2. IPv6 :53 DNS query still receives a hijacked UDP :53 DNS reply!
        let dns_query =
            crate::dns::wire::build_dns_query(0x4242, "example.com", crate::dns::wire::QTYPE_A);
        let dns_pkt = build_ipv6_udp_packet(client_v6, 52002, dns_v6, 53, &dns_query)
            .expect("valid IPv6 DNS UDP packet");
        vtun.ingress_tx.send(dns_pkt).await.unwrap();

        let dns_reply = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected hijacked IPv6 :53 DNS reply")
            .expect("egress packet");
        let ip6_dns = Ipv6Packet::new_checked(&dns_reply).unwrap();
        assert_eq!(ip6_dns.src_addr(), dns_v6);
        assert_eq!(ip6_dns.dst_addr(), client_v6);
        assert_eq!(ip6_dns.next_header(), IpProtocol::Udp);
        let udp_dns = UdpPacket::new_checked(ip6_dns.payload()).unwrap();
        assert_eq!(udp_dns.src_port(), 53);
        assert_eq!(udp_dns.dst_port(), 52002);
        let answers = crate::dns::wire::extract_ip_answers(udp_dns.payload()).unwrap();
        assert!(!answers.is_empty());

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn congested_egress_channel_obeys_shutdown_without_spinning() {
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec!["MATCH,DIRECT".to_string()];
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Direct,
                HashMap::new(),
                &[],
                &rules,
                dns,
            )
            .unwrap(),
        );
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (vtun, tun_task) = spawn_userspace_tun(1500, router_slot, hub, shutdown_rx);

        // Flood unsolicited TCP ACK segments without reading `vtun.egress_rx` so `smoltcp` fills
        // `egress_tx` with RST replies (`capacity() == 0`) while residual packets remain queued in
        // `device.rx_queue` (`next_delay == Some(Duration::ZERO)`).
        let dst = (Ipv4Addr::new(198, 18, 0, 99), 8080u16);
        for i in 0..(TUN_PACKET_QUEUE_CAPACITY + 64) {
            let src_port = 20_000u16.wrapping_add((i % 30_000) as u16);
            let pkt = build_ipv4_tcp_packet(
                (Ipv4Addr::new(198, 18, 0, 10), src_port),
                dst,
                smoltcp::wire::TcpControl::None,
                100,
                Some(200),
                &[],
            );
            if i < TUN_PACKET_QUEUE_CAPACITY {
                vtun.ingress_tx.send(pkt).await.unwrap();
                if i % 256 == 255 {
                    tokio::task::yield_now().await;
                }
            } else {
                let _ = vtun.ingress_tx.try_send(pkt);
            }
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(vtun.egress_rx.len(), TUN_PACKET_QUEUE_CAPACITY);

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_millis(500), tun_task)
            .await
            .expect("TUN task must exit promptly on shutdown even when egress_tx is full")
            .expect("TUN task panicked");
    }

    #[tokio::test]
    async fn spawn_userspace_tun_with_ipv6_live_gate_and_udp_nat_shutdown_cleanup() {
        let udp_sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp_sink.local_addr().unwrap().port();

        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec!["MATCH,DIRECT".to_string()];
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Direct,
                HashMap::new(),
                &[],
                &rules,
                dns,
            )
            .unwrap(),
        );
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let ipv6_enabled = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mut vtun, tun_task) = spawn_userspace_tun_with_ipv6(
            1500,
            router_slot,
            Arc::clone(&hub),
            shutdown_rx,
            Arc::clone(&ipv6_enabled),
        );

        let client_v6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dns_v6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let dns_query =
            crate::dns::wire::build_dns_query(0x5151, "example.org", crate::dns::wire::QTYPE_A);
        let dns_pkt = build_ipv6_udp_packet(client_v6, 53010, dns_v6, 53, &dns_query)
            .expect("valid IPv6 DNS UDP packet");

        // 1. With `ipv6_enabled == false`, inbound IPv6 packets are dropped before DNS hijack / NAT / smoltcp.
        vtun.ingress_tx.send(dns_pkt.clone()).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), vtun.egress_rx.recv())
                .await
                .is_err(),
            "IPv6 DNS packet must be dropped while ipv6_enabled is false"
        );

        // 2. Live-enabling `ipv6_enabled` immediately restores IPv6 packet processing.
        ipv6_enabled.store(true, Ordering::Relaxed);
        vtun.ingress_tx.send(dns_pkt).await.unwrap();
        let dns_reply = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected hijacked IPv6 :53 DNS reply once ipv6_enabled is true")
            .expect("egress packet");
        let ip6_dns = Ipv6Packet::new_checked(&dns_reply).unwrap();
        assert_eq!(ip6_dns.src_addr(), dns_v6);
        assert_eq!(ip6_dns.dst_addr(), client_v6);

        // 3. Establish an active UDP NAT session and verify TUN shutdown cleans up `udp_nat` sessions.
        let udp_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(198, 18, 0, 10),
            53011,
            Ipv4Addr::LOCALHOST,
            udp_port,
            b"ping-cleanup",
        )
        .expect("valid IPv4 UDP packet");
        vtun.ingress_tx.send(udp_pkt).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), udp_sink.recv_from(&mut buf))
            .await
            .expect("UDP sink should receive forwarded datagram")
            .unwrap();
        assert_eq!(&buf[..n], b"ping-cleanup");
        assert_eq!(hub.active_connection_count(), 1);

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), tun_task)
            .await
            .expect("TUN task should exit on shutdown")
            .unwrap();

        tokio::time::timeout(Duration::from_millis(500), async {
            while hub.active_connection_count() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect(
            "TUN shutdown must reset all UdpNatManager sessions so active_connection_count == 0",
        );
    }

    #[tokio::test]
    async fn tun_recovers_unmapped_fake_ip_via_tls_sni_and_fast_rejects_unmapped_udp() {
        struct CaptureDomainOutbound {
            tx: mpsc::UnboundedSender<(String, Vec<u8>)>,
        }

        #[async_trait::async_trait]
        impl crate::outbound::OutboundHandler for CaptureDomainOutbound {
            fn name(&self) -> &str {
                "CaptureProxy"
            }

            fn protocol(&self) -> &'static str {
                "MockProxy"
            }

            fn exit_category(&self) -> &'static str {
                "PROXY"
            }

            fn udp_supported(&self) -> bool {
                true
            }

            async fn connect_tcp(
                &self,
                target: &TargetAddr,
            ) -> io::Result<crate::outbound::BoxedStream> {
                let (client_half, mut server_half) = tokio::io::duplex(2048);
                let target_str = target.to_string();
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = server_half.read(&mut buf).await.unwrap_or(0);
                    let _ = tx.send((target_str, buf[..n].to_vec()));
                    let _ = server_half.shutdown().await;
                });
                Ok(Box::new(client_half))
            }
        }

        let (captured_tx, mut captured_rx) = mpsc::unbounded_channel();
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds.insert(
            "CaptureProxy".to_string(),
            Arc::new(CaptureDomainOutbound { tx: captured_tx }),
        );
        let rules = vec!["MATCH,CaptureProxy".to_string()];
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                outbounds,
                &[],
                &rules,
                Arc::clone(&dns),
            )
            .unwrap(),
        );
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mut vtun, tun_task) =
            spawn_userspace_tun(1500, router_slot, Arc::clone(&hub), shutdown_rx);

        let client_ip = Ipv4Addr::new(198, 18, 0, 10);

        // 1. Unmapped Fake-IP UDP (non-53) triggers immediate ICMPv4 PortUnreachable with zero failed conns
        let unmapped_udp_ip = Ipv4Addr::new(198, 18, 9, 98);
        let udp_pkt = build_ipv4_udp_packet(client_ip, 54001, unmapped_udp_ip, 443, b"quic-stale")
            .expect("valid IPv4 UDP packet");
        vtun.ingress_tx.send(udp_pkt).await.unwrap();

        let icmp_pkt = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected immediate ICMPv4 Destination Unreachable")
            .expect("egress packet");
        let ip4_icmp = Ipv4Packet::new_checked(&icmp_pkt).unwrap();
        assert_eq!(ip4_icmp.dst_addr(), client_ip);
        assert_eq!(ip4_icmp.next_header(), IpProtocol::Icmp);
        let icmp4 = smoltcp::wire::Icmpv4Packet::new_checked(ip4_icmp.payload()).unwrap();
        assert_eq!(
            icmp4.msg_type(),
            smoltcp::wire::Icmpv4Message::DstUnreachable
        );
        assert_eq!(
            smoltcp::wire::Icmpv4DstUnreachable::from(icmp4.msg_code()),
            smoltcp::wire::Icmpv4DstUnreachable::PortUnreachable
        );
        assert_eq!(hub.failed_connections_total(), 0);

        // 2. Unmapped Fake-IP TCP carrying TLS ClientHello recovers SNI & forwards full ClientHello
        let stale_tcp_ip = Ipv4Addr::new(198, 18, 9, 99);
        assert!(dns.lookup_domain(IpAddr::V4(stale_tcp_ip)).is_none());

        let syn = build_ipv4_tcp_packet(
            (client_ip, 54002),
            (stale_tcp_ip, 443),
            smoltcp::wire::TcpControl::Syn,
            1000,
            None,
            &[],
        );
        vtun.ingress_tx.send(syn).await.unwrap();

        let syn_ack_raw = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected SYN-ACK")
            .expect("egress SYN-ACK");
        let ip4_sa = Ipv4Packet::new_checked(&syn_ack_raw).unwrap();
        let tcp_sa = TcpPacket::new_checked(ip4_sa.payload()).unwrap();
        assert!(tcp_sa.syn() && tcp_sa.ack());
        let srv_ack = tcp_sa.seq_number().0.wrapping_add(1);

        let ack = build_ipv4_tcp_packet(
            (client_ip, 54002),
            (stale_tcp_ip, 443),
            smoltcp::wire::TcpControl::None,
            1001,
            Some(srv_ack),
            &[],
        );
        vtun.ingress_tx.send(ack).await.unwrap();

        let chlo =
            crate::inbound::sniff::test_helpers::build_tls_client_hello("recovered.example.com");
        let data_pkt = build_ipv4_tcp_packet(
            (client_ip, 54002),
            (stale_tcp_ip, 443),
            smoltcp::wire::TcpControl::Psh,
            1001,
            Some(srv_ack),
            &chlo,
        );
        vtun.ingress_tx.send(data_pkt).await.unwrap();

        let (routed_target, forwarded_bytes) =
            tokio::time::timeout(Duration::from_secs(2), captured_rx.recv())
                .await
                .expect("expected recovered SNI flow to reach outbound")
                .expect("captured payload");
        assert_eq!(routed_target, "recovered.example.com:443");
        assert_eq!(forwarded_bytes, chlo);
        assert_eq!(
            dns.lookup_domain(IpAddr::V4(stale_tcp_ip)).as_deref(),
            Some("recovered.example.com")
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
    }

    #[tokio::test]
    async fn recover_unmapped_fake_ip_preserves_coalesced_payload_beyond_max_sniff_bytes() {
        let dns = Arc::new(crate::dns::fake_ip::FakeIpDnsEngine::new(&Default::default()).unwrap());
        let rules = vec!["MATCH,DIRECT".to_string()];
        let router = Router::new(
            crate::config::RunMode::Rule,
            HashMap::new(),
            &[],
            &rules,
            Arc::clone(&dns),
        )
        .unwrap();

        let (tx, mut rx) = mpsc::channel(4);
        let (closed_tx, _closed_rx) = watch::channel(());

        // Coalesce an HTTP request whose body extends well past `MAX_SNIFF_BYTES` (16 KiB -> 24 KiB)
        let mut big_req =
            b"POST /upload HTTP/1.1\r\nHost: coalesced.example.com\r\nContent-Length: 24576\r\n\r\n"
                .to_vec();
        big_req.extend(vec![b'X'; 24576]);
        let expected_len = big_req.len();
        tx.send(big_req.clone()).await.unwrap();

        let _ = router;
        match sniff_tcp_initial_payload(&mut rx, &closed_tx, Duration::from_millis(250), true, true)
            .await
        {
            TcpSniffResult::Sniffed {
                domain, payload, ..
            } => {
                assert_eq!(domain, "coalesced.example.com");
                assert_eq!(payload.len(), expected_len);
                assert_eq!(payload, big_req);
            }
            _ => panic!("expected Sniffed outcome without truncating coalesced payload"),
        }
    }

    #[tokio::test]
    async fn tun_drops_ipv4_and_ipv6_multicast_broadcast_and_link_local_packets() {
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec!["MATCH,DIRECT".to_string()];
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Direct,
                HashMap::new(),
                &[],
                &rules,
                dns,
            )
            .unwrap(),
        );
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let ipv6_enabled = Arc::new(AtomicBool::new(true));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mut vtun, tun_task) = spawn_userspace_tun_with_options(
            1500,
            router_slot,
            Arc::clone(&hub),
            shutdown_rx,
            ipv6_enabled,
            true,
        );

        let src_v4 = Ipv4Addr::new(198, 18, 0, 1);
        let noisy_v4 = [
            // mDNS, LLMNR, SSDP/UPnP, limited broadcast, link-local
            (Ipv4Addr::new(224, 0, 0, 251), 5353u16),
            (Ipv4Addr::new(224, 0, 0, 252), 5355u16),
            (Ipv4Addr::new(239, 255, 255, 250), 1900u16),
            (Ipv4Addr::BROADCAST, 67u16),
            (Ipv4Addr::new(169, 254, 10, 20), 137u16),
            (Ipv4Addr::UNSPECIFIED, 5353u16),
        ];
        for (idx, (dst_ip, dst_port)) in noisy_v4.into_iter().enumerate() {
            assert!(should_drop_tun_ipv4_packet(src_v4, dst_ip));
            let pkt = build_ipv4_udp_packet(
                src_v4,
                55000 + idx as u16,
                dst_ip,
                dst_port,
                b"multicast-loop-probe",
            )
            .expect("valid v4 udp packet");
            vtun.ingress_tx.send(pkt).await.unwrap();
        }

        let src_v6: Ipv6Addr = "fd00::1".parse().unwrap();
        let noisy_v6 = [
            ("ff02::fb".parse::<Ipv6Addr>().unwrap(), 5353u16),
            ("ff02::1:3".parse::<Ipv6Addr>().unwrap(), 5355u16),
            ("ff02::c".parse::<Ipv6Addr>().unwrap(), 1900u16),
            ("fe80::1".parse::<Ipv6Addr>().unwrap(), 5353u16),
            (Ipv6Addr::UNSPECIFIED, 5353u16),
        ];
        for (idx, (dst_ip, dst_port)) in noisy_v6.into_iter().enumerate() {
            assert!(should_drop_tun_ipv6_packet(src_v6, dst_ip));
            let pkt = build_ipv6_udp_packet(
                src_v6,
                56000 + idx as u16,
                dst_ip,
                dst_port,
                b"multicast-v6-probe",
            )
            .expect("valid v6 udp packet");
            vtun.ingress_tx.send(pkt).await.unwrap();
        }

        // Valid Fake-IP and LAN unicast destinations must NOT be dropped.
        assert!(!should_drop_tun_ipv4_packet(
            src_v4,
            Ipv4Addr::new(198, 18, 0, 50)
        ));
        assert!(!should_drop_tun_ipv4_packet(
            src_v4,
            Ipv4Addr::new(10, 21, 220, 1)
        ));
        assert!(!should_drop_tun_ipv6_packet(
            src_v6,
            "2606:4700:4700::1111".parse().unwrap()
        ));

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            hub.total_connections(),
            0,
            "multicast/broadcast/link-local TUN packets must never create connections or NAT sessions"
        );
        assert_eq!(hub.active_connection_count(), 0);
        assert!(
            vtun.egress_rx.try_recv().is_err(),
            "dropped multicast/broadcast packets must emit zero egress packets"
        );

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), tun_task)
            .await
            .expect("TUN task must exit promptly on shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn tun_self_pid_guard_drops_looped_udp_from_own_process() {
        let own_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let own_src = own_sock.local_addr().unwrap();
        if !is_self_process_socket(SocketTransport::Udp, own_src) {
            // Skip assertion only on restricted sandboxes where OS socket tables are hidden.
            return;
        }

        let udp_sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst_port = udp_sink.local_addr().unwrap().port();
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec!["MATCH,DIRECT".to_string()];
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Direct,
                HashMap::new(),
                &[],
                &rules,
                dns,
            )
            .unwrap(),
        );
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (vtun, tun_task) = spawn_userspace_tun_with_options(
            1500,
            router_slot,
            Arc::clone(&hub),
            shutdown_rx,
            Arc::new(AtomicBool::new(true)),
            true,
        );

        let IpAddr::V4(src_ip) = own_src.ip() else {
            unreachable!()
        };
        let pkt = build_ipv4_udp_packet(
            src_ip,
            own_src.port(),
            Ipv4Addr::LOCALHOST,
            dst_port,
            b"self-loop-must-drop",
        )
        .expect("valid v4 udp packet");
        vtun.ingress_tx.send(pkt).await.unwrap();

        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(120), udp_sink.recv_from(&mut buf))
                .await
                .is_err(),
            "self-PID UDP packet entering OS TUN must be dropped instead of looping back to outbound"
        );
        assert_eq!(hub.total_connections(), 0);

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
    }

    struct CaptureProxyOutbound {
        name: String,
        last_target: Arc<parking_lot::Mutex<Option<TargetAddr>>>,
        captured_tx: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<Vec<u8>>>>>,
        expected_len: usize,
        reply: &'static [u8],
    }

    #[async_trait::async_trait]
    impl crate::outbound::OutboundHandler for CaptureProxyOutbound {
        fn name(&self) -> &str {
            &self.name
        }

        fn protocol(&self) -> &'static str {
            "mock-proxy"
        }

        async fn connect_tcp(
            &self,
            target: &TargetAddr,
        ) -> io::Result<crate::outbound::BoxedStream> {
            *self.last_target.lock() = Some(target.clone());
            let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
            let tx_slot = Arc::clone(&self.captured_tx);
            let expected_len = self.expected_len;
            let reply = self.reply;
            tokio::spawn(async move {
                let mut received = Vec::with_capacity(expected_len);
                let mut chunk = [0u8; 4096];
                while received.len() < expected_len {
                    match server_side.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => received.extend_from_slice(&chunk[..n]),
                    }
                }
                if let Some(tx) = tx_slot.lock().take() {
                    let _ = tx.send(received);
                }
                let _ = server_side.write_all(reply).await;
                let _ = server_side.shutdown().await;
            });
            Ok(Box::new(client_side))
        }
    }

    #[tokio::test]
    async fn tun_real_ip_sniffs_two_segment_pq_client_hello_acks_first_segment_and_overrides_proxy_target()
     {
        let pq_hello =
            crate::inbound::sniff::test_helpers::build_pq_tls_client_hello("linux.do", 1950);
        assert!(
            pq_hello.len() > 2000,
            "simulated Chrome PQ ClientHello must span 2 TCP segments (> 1460B), got {}",
            pq_hello.len()
        );
        let seg1 = &pq_hello[..1460];
        let seg2 = &pq_hello[1460..];
        assert!(!seg2.is_empty());

        let last_target = Arc::new(parking_lot::Mutex::new(None));
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let proxy = Arc::new(CaptureProxyOutbound {
            name: "MOCK-PROXY".to_string(),
            last_target: Arc::clone(&last_target),
            captured_tx: Arc::new(parking_lot::Mutex::new(Some(captured_tx))),
            expected_len: pq_hello.len(),
            reply: b"SERVER-HELLO-OK",
        });

        let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds.insert("MOCK-PROXY".to_string(), proxy);
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        // Poisoned real IP `31.13.73.1:443` can ONLY match `DOMAIN-SUFFIX,linux.do,MOCK-PROXY`
        // if real-IP SNI sniffing succeeds; otherwise `MATCH,REJECT` would drop it!
        let rules = vec![
            "DOMAIN-SUFFIX,linux.do,MOCK-PROXY".to_string(),
            "MATCH,REJECT".to_string(),
        ];
        let router = Arc::new(
            Router::new(crate::config::RunMode::Rule, outbounds, &[], &rules, dns).unwrap(),
        );
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mut vtun, tun_task) =
            spawn_userspace_tun(1500, router_slot, Arc::clone(&hub), shutdown_rx);

        let client = (Ipv4Addr::new(198, 18, 0, 20), 55443u16);
        let poisoned_dst = (Ipv4Addr::new(31, 13, 73, 1), 443u16);

        // 1. 3-way TCP handshake to poisoned public IP
        let syn_pkt = build_ipv4_tcp_packet(
            client,
            poisoned_dst,
            smoltcp::wire::TcpControl::Syn,
            20_000,
            None,
            &[],
        );
        vtun.ingress_tx.send(syn_pkt).await.unwrap();
        let syn_ack_raw = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected SYN-ACK")
            .expect("egress packet");
        let ip4_sa = Ipv4Packet::new_checked(&syn_ack_raw).unwrap();
        let tcp_sa = TcpPacket::new_checked(ip4_sa.payload()).unwrap();
        assert!(tcp_sa.syn() && tcp_sa.ack());
        let server_next_seq = tcp_sa.seq_number().0.wrapping_add(1);

        let ack_pkt = build_ipv4_tcp_packet(
            client,
            poisoned_dst,
            smoltcp::wire::TcpControl::None,
            20_001,
            Some(server_next_seq),
            &[],
        );
        vtun.ingress_tx.send(ack_pkt).await.unwrap();

        // 2. Send Segment 1 (1460B) ONLY — sniffer returns NeedMoreBytes; verify smoltcp
        //    still drives the stack and emits an ACK so Chrome can send Segment 2 without deadlock!
        let pkt1 = build_ipv4_tcp_packet(
            client,
            poisoned_dst,
            smoltcp::wire::TcpControl::None,
            20_001,
            Some(server_next_seq),
            seg1,
        );
        vtun.ingress_tx.send(pkt1).await.unwrap();

        let ack1_raw = tokio::time::timeout(Duration::from_millis(500), vtun.egress_rx.recv())
            .await
            .expect("smoltcp must ACK segment 1 while sniffer awaits segment 2")
            .expect("egress ACK packet");
        let ip4_a1 = Ipv4Packet::new_checked(&ack1_raw).unwrap();
        let tcp_a1 = TcpPacket::new_checked(ip4_a1.payload()).unwrap();
        assert!(tcp_a1.ack() && !tcp_a1.rst());
        assert_eq!(
            tcp_a1.ack_number().0,
            20_001 + seg1.len() as i32,
            "smoltcp ACK must advance past segment 1"
        );

        // 3. Send Segment 2 (remaining bytes completing the ~2060B PQ ClientHello)
        let pkt2 = build_ipv4_tcp_packet(
            client,
            poisoned_dst,
            smoltcp::wire::TcpControl::Psh,
            20_001 + seg1.len() as i32,
            Some(server_next_seq),
            seg2,
        );
        vtun.ingress_tx.send(pkt2).await.unwrap();

        // 4. Verify outbound dialed `linux.do:443` (overriding poisoned `31.13.73.1:443`)
        //    and received the complete, unmodified ~2060B ClientHello payload!
        let captured = tokio::time::timeout(Duration::from_secs(2), captured_rx)
            .await
            .expect("proxy outbound must receive full ClientHello")
            .unwrap();
        assert_eq!(captured, pq_hello);
        assert_eq!(
            last_target.lock().as_ref().map(|t| t.to_string()),
            Some("linux.do:443".to_string()),
            "PROXY outbound must receive sniffed SNI domain instead of poisoned real IP"
        );

        // 5. Verify server reply flows back through smoltcp (download > 0)
        let mut received_reply = Vec::new();
        let reply_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while received_reply.len() < b"SERVER-HELLO-OK".len()
            && tokio::time::Instant::now() < reply_deadline
        {
            if let Ok(Some(pkt)) =
                tokio::time::timeout(Duration::from_millis(400), vtun.egress_rx.recv()).await
                && let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                && let Ok(tcp) = TcpPacket::new_checked(ip4.payload())
                && !tcp.payload().is_empty()
            {
                received_reply.extend_from_slice(tcp.payload());
            }
        }
        assert_eq!(received_reply, b"SERVER-HELLO-OK");

        let diags = hub.diagnostics_snapshot(10);
        assert!(
            diags.iter().any(|d| d.metadata.host == "linux.do"
                && d.rule == "DomainSuffix"
                && d.rule_payload == "linux.do"),
            "TelemetryHub must record sniffed domain and DomainSuffix rule match, got: {diags:?}"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
    }

    #[tokio::test]
    async fn tun_real_ip_sniff_preserves_non_tls_bytes_and_respects_skip_domain() {
        // Case A: Non-TLS bytes on port 443 must exit sniff immediately and forward 100% losslessly.
        let non_tls = b"SSH-2.0-OpenSSH_9.6\r\n";
        let last_target_a = Arc::new(parking_lot::Mutex::new(None));
        let (cap_tx_a, cap_rx_a) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let proxy_a = Arc::new(CaptureProxyOutbound {
            name: "MOCK-PROXY".to_string(),
            last_target: Arc::clone(&last_target_a),
            captured_tx: Arc::new(parking_lot::Mutex::new(Some(cap_tx_a))),
            expected_len: non_tls.len(),
            reply: b"SSH-OK",
        });
        let mut outbounds_a: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds_a.insert("MOCK-PROXY".to_string(), proxy_a);
        let dns_a = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules_a = vec!["MATCH,MOCK-PROXY".to_string()];
        let router_a = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                outbounds_a,
                &[],
                &rules_a,
                dns_a,
            )
            .unwrap(),
        );
        let hub_a = Arc::new(TelemetryHub::new());
        let (sd_tx_a, sd_rx_a) = watch::channel(false);
        let (mut vtun_a, task_a) =
            spawn_userspace_tun(1500, Arc::new(RwLock::new(router_a)), hub_a, sd_rx_a);

        let client_a = (Ipv4Addr::new(198, 18, 0, 21), 55444u16);
        let dst_a = (Ipv4Addr::new(93, 184, 216, 34), 443u16);
        vtun_a
            .ingress_tx
            .send(build_ipv4_tcp_packet(
                client_a,
                dst_a,
                smoltcp::wire::TcpControl::Syn,
                30_000,
                None,
                &[],
            ))
            .await
            .unwrap();
        let sa_raw = tokio::time::timeout(Duration::from_secs(2), vtun_a.egress_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let sseq_a = TcpPacket::new_checked(Ipv4Packet::new_checked(&sa_raw).unwrap().payload())
            .unwrap()
            .seq_number()
            .0
            .wrapping_add(1);
        vtun_a
            .ingress_tx
            .send(build_ipv4_tcp_packet(
                client_a,
                dst_a,
                smoltcp::wire::TcpControl::Psh,
                30_001,
                Some(sseq_a),
                non_tls,
            ))
            .await
            .unwrap();

        let got_a = tokio::time::timeout(Duration::from_secs(2), cap_rx_a)
            .await
            .expect("non-TLS payload must be forwarded losslessly")
            .unwrap();
        assert_eq!(got_a, non_tls);
        assert_eq!(
            last_target_a.lock().as_ref().map(|t| t.to_string()),
            Some("93.184.216.34:443".to_string())
        );
        let _ = sd_tx_a.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task_a).await;

        // Case B: `skip-domain` still uses sniffed domain for rule matching, but dials raw IP!
        let hello_b = crate::inbound::sniff::test_helpers::build_tls_client_hello("push.apple.com");
        let last_target_b = Arc::new(parking_lot::Mutex::new(None));
        let (cap_tx_b, cap_rx_b) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let proxy_b = Arc::new(CaptureProxyOutbound {
            name: "MOCK-PROXY".to_string(),
            last_target: Arc::clone(&last_target_b),
            captured_tx: Arc::new(parking_lot::Mutex::new(Some(cap_tx_b))),
            expected_len: hello_b.len(),
            reply: b"OK",
        });
        let mut outbounds_b: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds_b.insert("MOCK-PROXY".to_string(), proxy_b);
        let dns_b = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules_b = vec![
            "DOMAIN-SUFFIX,apple.com,MOCK-PROXY".to_string(),
            "MATCH,REJECT".to_string(),
        ];
        let router_b = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                outbounds_b,
                &[],
                &rules_b,
                dns_b,
            )
            .unwrap(),
        );
        let sniffer = crate::config::SnifferConfig {
            skip_domain: vec!["+.push.apple.com".to_string()],
            ..Default::default()
        };
        router_b.set_sniffer(sniffer);

        let hub_b = Arc::new(TelemetryHub::new());
        let (sd_tx_b, sd_rx_b) = watch::channel(false);
        let (mut vtun_b, task_b) =
            spawn_userspace_tun(1500, Arc::new(RwLock::new(router_b)), hub_b, sd_rx_b);

        let client_b = (Ipv4Addr::new(198, 18, 0, 22), 55445u16);
        let dst_b = (Ipv4Addr::new(17, 57, 144, 5), 443u16);
        vtun_b
            .ingress_tx
            .send(build_ipv4_tcp_packet(
                client_b,
                dst_b,
                smoltcp::wire::TcpControl::Syn,
                40_000,
                None,
                &[],
            ))
            .await
            .unwrap();
        let sa_b = tokio::time::timeout(Duration::from_secs(2), vtun_b.egress_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let sseq_b = TcpPacket::new_checked(Ipv4Packet::new_checked(&sa_b).unwrap().payload())
            .unwrap()
            .seq_number()
            .0
            .wrapping_add(1);
        vtun_b
            .ingress_tx
            .send(build_ipv4_tcp_packet(
                client_b,
                dst_b,
                smoltcp::wire::TcpControl::Psh,
                40_001,
                Some(sseq_b),
                &hello_b,
            ))
            .await
            .unwrap();

        let got_b = tokio::time::timeout(Duration::from_secs(2), cap_rx_b)
            .await
            .expect("skip-domain TLS payload must still route and forward")
            .unwrap();
        assert_eq!(got_b, hello_b);
        assert_eq!(
            last_target_b.lock().as_ref().map(|t| t.to_string()),
            Some("17.57.144.5:443".to_string()),
            "skip-domain must keep raw IP as dial target while matching DOMAIN-SUFFIX rule"
        );
        let _ = sd_tx_b.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task_b).await;
    }

    #[tokio::test]
    async fn tun_smoltcp_stack_panic_isolation_recovers_and_logs_without_aborting() {
        let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(64);
        let hub = Arc::new(TelemetryHub::new());
        let mut stack = TunSmoltcpStack::new(1500, egress_tx, SmolInstant::from_millis(0));

        // Seed an active TCP socket, BridgeFlow with a live dummy task, and queued ingress packet
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TUN_TCP_SOCKET_BUF_SIZE]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TUN_TCP_SOCKET_BUF_SIZE]);
        let handle = stack.sockets.add(tcp::Socket::new(rx_buf, tx_buf));
        let dummy_task = tokio::spawn(std::future::pending::<()>());
        let dummy_abort = dummy_task.abort_handle();
        let (to_tx, _to_rx) = mpsc::channel::<Vec<u8>>(4);
        let (_from_tx, from_rx) = mpsc::channel::<Vec<u8>>(4);
        let (_closed_tx, closed_rx) = watch::channel(());
        let tuple = FourTuple {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40001),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 10)), 443),
        };
        let now = Instant::now();
        let now_wall = TelemetryHub::now_ms();
        stack.flows.insert(
            tuple,
            BridgeFlow {
                handle,
                established: true,
                remote_connected: Arc::new(AtomicBool::new(true)),
                dial_timeout_notify: Arc::new(Notify::new()),
                dial_timeout_notified_at: None,
                created_at: now,
                created_wall_ms: now_wall,
                last_active: now,
                last_active_wall_ms: now_wall,
                fin_started_at: None,
                fin_started_wall_ms: None,
                pending_tx: BytesMut::new(),
                from_remote_rx: from_rx,
                to_remote_tx: Some(to_tx),
                _bridge_closed_rx: closed_rx,
                remote_eof: false,
                remote_failed: Arc::new(AtomicBool::new(false)),
                task_abort: dummy_abort,
            },
        );
        stack.device.rx_queue.push_back(vec![0x45; 40]);

        // Inject a smoltcp-style panic inside the guarded boundary
        let res: Option<()> =
            stack.run_guarded("iface.poll.pre", SmolInstant::from_millis(10), &hub, |_| {
                panic!("attempt to subtract sequence numbers with underflow");
            });

        assert!(
            res.is_none(),
            "run_guarded must catch injected panic and return None instead of terminating"
        );
        assert_eq!(stack.panic_recoveries, 1);
        assert!(
            stack.flows.is_empty(),
            "active flows must be drained on stack rebuild"
        );
        assert!(
            stack.device.rx_queue.is_empty(),
            "queued ingress packets must be cleared on stack rebuild"
        );
        assert!(
            dummy_task.await.unwrap_err().is_cancelled(),
            "orphaned flow task must be aborted during stack rebuild"
        );

        let logs = hub.recent_logs();
        assert!(
            logs.iter().any(|entry| {
                entry.level == "error"
                    && entry.payload.contains("iface.poll.pre")
                    && entry
                        .payload
                        .contains("attempt to subtract sequence numbers with underflow")
            }),
            "TelemetryHub must record diagnostic error log for caught smoltcp panic: {logs:?}"
        );

        // Verify the rebuilt Interface + SocketSet handles a fresh TCP SYN cleanly
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TUN_TCP_SOCKET_BUF_SIZE]),
            tcp::SocketBuffer::new(vec![0u8; TUN_TCP_SOCKET_BUF_SIZE]),
        );
        sock.listen(IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(Ipv4Addr::new(93, 184, 216, 34))),
            port: 443,
        })
        .unwrap();
        let _fresh_handle = stack.sockets.add(sock);
        stack.device.rx_queue.push_back(build_ipv4_tcp_packet(
            (Ipv4Addr::new(10, 0, 0, 2), 51234),
            (Ipv4Addr::new(93, 184, 216, 34), 443),
            smoltcp::wire::TcpControl::Syn,
            1000,
            None,
            &[],
        ));
        assert!(stack.poll_guarded(
            "iface.poll.post_recovery",
            SmolInstant::from_millis(20),
            &hub
        ));

        let syn_ack = egress_rx
            .try_recv()
            .expect("rebuilt smoltcp Interface must emit SYN-ACK for subsequent TCP connections");
        let ip4 = Ipv4Packet::new_checked(&syn_ack).unwrap();
        let tcp_pkt = TcpPacket::new_checked(ip4.payload()).unwrap();
        assert!(tcp_pkt.syn() && tcp_pkt.ack());
    }

    #[tokio::test]
    async fn tun_single_flow_panic_isolation_records_redacted_error_and_reaps_faulty_flow() {
        let hub = Arc::new(TelemetryHub::new());
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 4096]),
            tcp::SocketBuffer::new(vec![0u8; 4096]),
        ));
        let flow_task = tokio::spawn(std::future::pending::<()>());
        let (to_tx, _to_rx) = mpsc::channel::<Vec<u8>>(4);
        let (_from_tx, from_rx) = mpsc::channel::<Vec<u8>>(4);
        let (_closed_tx, closed_rx) = watch::channel(());
        let now = Instant::now();
        let now_wall = TelemetryHub::now_ms();
        let mut flow = BridgeFlow {
            handle,
            established: true,
            remote_connected: Arc::new(AtomicBool::new(true)),
            dial_timeout_notify: Arc::new(Notify::new()),
            dial_timeout_notified_at: None,
            created_at: now,
            created_wall_ms: now_wall,
            last_active: now,
            last_active_wall_ms: now_wall,
            fin_started_at: None,
            fin_started_wall_ms: None,
            pending_tx: BytesMut::new(),
            from_remote_rx: from_rx,
            to_remote_tx: Some(to_tx),
            _bridge_closed_rx: closed_rx,
            remote_eof: false,
            remote_failed: Arc::new(AtomicBool::new(false)),
            task_abort: flow_task.abort_handle(),
        };
        let tuple = FourTuple {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 42222),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        };

        let step = step_single_tun_flow_guarded(tuple, &mut flow, &hub, |_| {
            panic!("simulated flow panic with token=SUPERSECRET123");
        });

        assert!(
            step.finished,
            "panicked flow must be marked finished for reaping"
        );
        assert!(
            flow_task.await.unwrap_err().is_cancelled(),
            "panicked flow task must be aborted"
        );
        let logs = hub.recent_logs();
        let err_log = logs
            .iter()
            .find(|e| e.level == "error" && e.payload.contains("Isolated panic in TCP flow"))
            .expect("error log must be recorded for isolated single-flow panic");
        assert!(
            !err_log.payload.contains("SUPERSECRET123"),
            "panic diagnostic log must redact sensitive tokens: {}",
            err_log.payload
        );
    }

    #[test]
    fn smoltcp_64kib_window_scale_odd_bytes_and_zero_window_fin_never_underflows() {
        let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(256);
        let hub = Arc::new(TelemetryHub::new());
        let mut stack = TunSmoltcpStack::new(1500, egress_tx, SmolInstant::from_millis(0));

        let client = (Ipv4Addr::new(10, 0, 0, 2), 55111u16);
        let server = (Ipv4Addr::new(93, 184, 216, 34), 443u16);

        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TUN_TCP_SOCKET_BUF_SIZE]),
            tcp::SocketBuffer::new(vec![0u8; TUN_TCP_SOCKET_BUF_SIZE]),
        );
        sock.set_nagle_enabled(false);
        sock.listen(IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(server.0)),
            port: server.1,
        })
        .unwrap();
        let handle = stack.sockets.add(sock);

        let build_scaled_tcp = |control: smoltcp::wire::TcpControl,
                                seq: i32,
                                ack: Option<i32>,
                                window_scale: Option<u8>,
                                payload: &[u8]| {
            let caps = ChecksumCapabilities::default();
            let is_syn = control == smoltcp::wire::TcpControl::Syn;
            let tcp_repr = smoltcp::wire::TcpRepr {
                src_port: client.1,
                dst_port: server.1,
                control,
                seq_number: smoltcp::wire::TcpSeqNumber(seq),
                ack_number: ack.map(smoltcp::wire::TcpSeqNumber),
                window_len: 65535,
                window_scale,
                max_seg_size: is_syn.then_some(1460),
                sack_permitted: is_syn,
                sack_ranges: [None, None, None],
                timestamp: None,
                payload,
            };
            let ip_repr = Ipv4Repr {
                src_addr: client.0,
                dst_addr: server.0,
                next_header: IpProtocol::Tcp,
                payload_len: tcp_repr.buffer_len(),
                hop_limit: 64,
            };
            let mut buf = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
            let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt, &caps);
            let mut tcp_pkt = TcpPacket::new_unchecked(ip_pkt.payload_mut());
            tcp_repr.emit(
                &mut tcp_pkt,
                &IpAddress::Ipv4(client.0),
                &IpAddress::Ipv4(server.0),
                &caps,
            );
            buf
        };

        // 1. Handshake with RFC 1323 window scaling (so 64 KiB socket negotiates remote_win_shift = 1)
        let mut t_ms = 1i64;
        stack.device.rx_queue.push_back(build_scaled_tcp(
            smoltcp::wire::TcpControl::Syn,
            10_000,
            None,
            Some(7),
            &[],
        ));
        assert!(stack.poll_guarded("syn", SmolInstant::from_millis(t_ms), &hub));
        let sa = egress_rx.try_recv().expect("SYN-ACK expected");
        let server_seq = TcpPacket::new_checked(Ipv4Packet::new_checked(&sa).unwrap().payload())
            .unwrap()
            .seq_number()
            .0
            .wrapping_add(1);

        t_ms += 1;
        stack.device.rx_queue.push_back(build_scaled_tcp(
            smoltcp::wire::TcpControl::None,
            10_001,
            Some(server_seq),
            None,
            &[],
        ));
        assert!(stack.poll_guarded("ack", SmolInstant::from_millis(t_ms), &hub));

        // 2. Fill the 64 KiB RX buffer with odd-sized chunks (inducing 2-byte window-scale rounding)
        //    plus partial reads during delayed ACK and overshoot bytes past advertised right edge.
        let mut client_seq = 10_001i32;
        let odd_chunk = vec![0xABu8; 1459];
        for i in 0..45 {
            t_ms += 1;
            stack.device.rx_queue.push_back(build_scaled_tcp(
                smoltcp::wire::TcpControl::Psh,
                client_seq,
                Some(server_seq),
                None,
                &odd_chunk,
            ));
            assert!(
                stack.poll_guarded("odd_upload", SmolInstant::from_millis(t_ms), &hub),
                "iteration {i} must never panic"
            );
            client_seq = client_seq.wrapping_add(odd_chunk.len() as i32);
            while egress_rx.try_recv().is_ok() {}

            // Halfway through, drain a single odd byte while delayed ACK is armed (reproduces #1048/#1079)
            if i == 22 {
                let s = stack.sockets.get_mut::<tcp::Socket>(handle);
                let _ = s.recv(|d| (d.len().min(1), ()));
            }
        }

        // 3. Push past the 64 KiB edge (out-of-window data) and then send FIN at zero-window edge
        let overshoot = vec![0xCDu8; 512];
        t_ms += 1;
        stack.device.rx_queue.push_back(build_scaled_tcp(
            smoltcp::wire::TcpControl::Psh,
            client_seq,
            Some(server_seq),
            None,
            &overshoot,
        ));
        assert!(stack.poll_guarded("overshoot", SmolInstant::from_millis(t_ms), &hub));

        // Send a FIN right at the current RX right edge while RX buffer is saturated
        let rx_queued = stack.sockets.get::<tcp::Socket>(handle).recv_queue();
        let fin_seq = 10_001i32.wrapping_add(1).wrapping_add(rx_queued as i32);
        t_ms += 20;
        stack.device.rx_queue.push_back(build_scaled_tcp(
            smoltcp::wire::TcpControl::Fin,
            fin_seq,
            Some(server_seq),
            None,
            &[],
        ));
        assert!(stack.poll_guarded("zero_window_fin", SmolInstant::from_millis(t_ms), &hub));
        assert_eq!(
            stack.panic_recoveries, 0,
            "smoltcp 0.14 must handle 64 KiB scaled window, odd chunks, overshoot, and zero-window FIN with zero panics"
        );
    }

    struct HangingMockOutbound;

    #[async_trait::async_trait]
    impl crate::outbound::OutboundHandler for HangingMockOutbound {
        fn name(&self) -> &str {
            "hanging-mock"
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        async fn connect_tcp(
            &self,
            _target: &TargetAddr,
        ) -> io::Result<crate::outbound::BoxedStream> {
            std::future::pending().await
        }
    }

    struct GatedFailingOutbound {
        gate: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl crate::outbound::OutboundHandler for GatedFailingOutbound {
        fn name(&self) -> &str {
            "gated-fail"
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        async fn connect_tcp(
            &self,
            _target: &TargetAddr,
        ) -> io::Result<crate::outbound::BoxedStream> {
            self.gate.notified().await;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "simulated outbound failure",
            ))
        }
    }

    #[tokio::test]
    async fn tun_emits_tcp_rst_on_reject_rule_failing_dial_and_half_open_eviction() {
        // Part A1: Flow routed to `REJECT` emits TCP RST on `egress_rx`.
        {
            let dns = Arc::new(
                crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
            );
            let router = Arc::new(
                Router::new(
                    crate::config::RunMode::Rule,
                    HashMap::new(),
                    &[],
                    &["MATCH,REJECT".to_string()],
                    dns,
                )
                .unwrap(),
            );
            let hub = Arc::new(TelemetryHub::new());
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (mut vtun, tun_task) =
                spawn_userspace_tun(1500, Arc::new(RwLock::new(router)), hub, shutdown_rx);

            // Non-sniffed port 8080 so flow_task immediately hits REJECT without sniff delay.
            let client = (Ipv4Addr::new(198, 18, 0, 30), 55001u16);
            let dst = (Ipv4Addr::new(93, 184, 216, 34), 8080u16);
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::Syn,
                    1000,
                    None,
                    &[],
                ))
                .await
                .unwrap();

            let mut saw_rst = false;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while tokio::time::Instant::now() < deadline {
                let Ok(Some(pkt)) =
                    tokio::time::timeout(Duration::from_millis(200), vtun.egress_rx.recv()).await
                else {
                    break;
                };
                let ip4 = Ipv4Packet::new_checked(&pkt).unwrap();
                let tcp = TcpPacket::new_checked(ip4.payload()).unwrap();
                if tcp.rst() {
                    assert_eq!(ip4.src_addr(), dst.0);
                    assert_eq!(ip4.dst_addr(), client.0);
                    assert_eq!(tcp.src_port(), dst.1);
                    assert_eq!(tcp.dst_port(), client.1);
                    saw_rst = true;
                    break;
                }
            }
            assert!(
                saw_rst,
                "TUN REJECT rule must emit an actual TCP RST packet on egress_rx"
            );

            let _ = shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
        }

        // Part A2: Established TCP flow whose outbound dial fails emits TCP RST on `egress_rx`.
        {
            let fail_gate = Arc::new(Notify::new());
            let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
            outbounds.insert(
                "gated-fail".to_string(),
                Arc::new(GatedFailingOutbound {
                    gate: Arc::clone(&fail_gate),
                }),
            );
            let dns = Arc::new(
                crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
            );
            let router = Arc::new(
                Router::new(
                    crate::config::RunMode::Rule,
                    outbounds,
                    &[],
                    &["MATCH,gated-fail".to_string()],
                    dns,
                )
                .unwrap(),
            );
            let hub = Arc::new(TelemetryHub::new());
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (mut vtun, tun_task) =
                spawn_userspace_tun(1500, Arc::new(RwLock::new(router)), hub, shutdown_rx);

            let client = (Ipv4Addr::new(198, 18, 0, 31), 55002u16);
            let dst = (Ipv4Addr::new(93, 184, 216, 34), 8080u16);
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::Syn,
                    2000,
                    None,
                    &[],
                ))
                .await
                .unwrap();

            let sa_raw = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let tcp_sa =
                TcpPacket::new_checked(Ipv4Packet::new_checked(&sa_raw).unwrap().payload())
                    .unwrap();
            assert!(tcp_sa.syn() && tcp_sa.ack());
            let server_next_seq = tcp_sa.seq_number().0.wrapping_add(1);

            // Complete 3-way handshake to reach `Established`, then trigger outbound dial failure.
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::None,
                    2001,
                    Some(server_next_seq),
                    &[],
                ))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            fail_gate.notify_one();

            let rst_raw = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                .await
                .expect("established flow failing dial must emit TCP RST")
                .expect("egress RST packet");
            let ip4_rst = Ipv4Packet::new_checked(&rst_raw).unwrap();
            let tcp_rst = TcpPacket::new_checked(ip4_rst.payload()).unwrap();
            assert!(
                tcp_rst.rst(),
                "expected TCP RST after outbound dial failure, got syn={} ack={} fin={} rst={}",
                tcp_rst.syn(),
                tcp_rst.ack(),
                tcp_rst.fin(),
                tcp_rst.rst()
            );

            let _ = shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
        }

        // Part B: Half-open eviction in `register_syn_flow` defers socket removal past poll so
        // the evicted flow emits TCP RST before its handle is removed.
        {
            let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
            outbounds.insert("hanging-mock".to_string(), Arc::new(HangingMockOutbound));
            let dns = Arc::new(
                crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
            );
            let router = Arc::new(
                Router::new(
                    crate::config::RunMode::Rule,
                    outbounds,
                    &[],
                    &["MATCH,hanging-mock".to_string()],
                    dns,
                )
                .unwrap(),
            );
            let hub = Arc::new(TelemetryHub::new());
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (mut vtun, tun_task) =
                spawn_userspace_tun(1500, Arc::new(RwLock::new(router)), hub, shutdown_rx);

            let dst = (Ipv4Addr::new(93, 184, 216, 34), 8080u16);
            let base_port = 40_000u16;
            for i in 0..MAX_HALF_OPEN_SYN_FLOWS {
                let client = (Ipv4Addr::new(198, 18, 0, 32), base_port + i as u16);
                vtun.ingress_tx
                    .send(build_ipv4_tcp_packet(
                        client,
                        dst,
                        smoltcp::wire::TcpControl::Syn,
                        10_000 + i as i32,
                        None,
                        &[],
                    ))
                    .await
                    .unwrap();
                let sa = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                    .await
                    .expect("expected SYN-ACK for half-open flow")
                    .expect("egress SYN-ACK");
                let tcp_sa =
                    TcpPacket::new_checked(Ipv4Packet::new_checked(&sa).unwrap().payload())
                        .unwrap();
                assert!(tcp_sa.syn() && tcp_sa.ack());
            }

            // 257th SYN triggers half-open eviction of oldest flow (`base_port`)!
            let new_port = base_port + MAX_HALF_OPEN_SYN_FLOWS as u16;
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    (Ipv4Addr::new(198, 18, 0, 32), new_port),
                    dst,
                    smoltcp::wire::TcpControl::Syn,
                    20_000,
                    None,
                    &[],
                ))
                .await
                .unwrap();

            let mut saw_evicted_rst = false;
            let mut saw_new_syn_ack = false;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while (!saw_evicted_rst || !saw_new_syn_ack) && tokio::time::Instant::now() < deadline {
                let Ok(Some(pkt)) =
                    tokio::time::timeout(Duration::from_millis(200), vtun.egress_rx.recv()).await
                else {
                    break;
                };
                let ip4 = Ipv4Packet::new_checked(&pkt).unwrap();
                let tcp = TcpPacket::new_checked(ip4.payload()).unwrap();
                if tcp.rst() && tcp.dst_port() == base_port {
                    saw_evicted_rst = true;
                } else if tcp.syn() && tcp.ack() && tcp.dst_port() == new_port {
                    saw_new_syn_ack = true;
                }
            }
            assert!(
                saw_evicted_rst,
                "half-open flow eviction must emit TCP RST for evicted client port {base_port}"
            );
            assert!(
                saw_new_syn_ack,
                "newly admitted SYN (port {new_port}) must still receive SYN-ACK"
            );

            let _ = shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tun_syn_isolation_prevents_slot_reuse_collision_bad_checksum_orphans_and_ipv6_hijack()
    {
        // Part A: Bad-checksum SYNs leave 0 orphan Listen sockets, and back-to-back SYNs to the
        // same `(dst_ip, dst_port)` after freeing an earlier SocketSet slot bind strictly to
        // their own 4-tuple flows without order reversal.
        {
            let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(64);
            let hub = Arc::new(TelemetryHub::new());
            let mut stack =
                TunSmoltcpStack::new(1500, egress_tx.clone(), SmolInstant::from_millis(0));

            // Create slot 0 and slot 1, then remove slot 0 so `SocketSet` has a free slot BEFORE
            // existing sockets (classic slot-reuse order-reversal setup).
            let slot0 = stack.sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 1024]),
                tcp::SocketBuffer::new(vec![0u8; 1024]),
            ));
            let _slot1 = stack.sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 1024]),
                tcp::SocketBuffer::new(vec![0u8; 1024]),
            ));
            stack.sockets.remove(slot0);

            let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
            outbounds.insert("hanging-mock".to_string(), Arc::new(HangingMockOutbound));
            let dns = Arc::new(
                crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
            );
            let router = Arc::new(RwLock::new(Arc::new(
                Router::new(
                    crate::config::RunMode::Rule,
                    outbounds,
                    &[],
                    &["MATCH,hanging-mock".to_string()],
                    dns,
                )
                .unwrap(),
            )));
            let ipv6_enabled = Arc::new(AtomicBool::new(true));
            let shutting_down = Arc::new(AtomicBool::new(false));
            let udp_sem = Arc::new(Semaphore::new(8));
            let udp_nat =
                UdpNatManager::new("test-tun", 16, Arc::clone(&hub), Arc::new(|_, _, _| {}));
            let wake_notify = Arc::new(Notify::new());

            let dst = (Ipv4Addr::new(93, 184, 216, 34), 443u16);
            let src1 = (Ipv4Addr::new(198, 18, 0, 41), 51001u16);
            let src2 = (Ipv4Addr::new(198, 18, 0, 42), 51002u16);

            // 1. Corrupt TCP checksum SYN -> must NOT register a flow or orphan Listen socket!
            let mut bad_tcp_csum_syn = build_ipv4_tcp_packet(
                (Ipv4Addr::new(198, 18, 0, 40), 51000),
                dst,
                smoltcp::wire::TcpControl::Syn,
                100,
                None,
                &[],
            );
            let last_idx = bad_tcp_csum_syn.len() - 1;
            bad_tcp_csum_syn[last_idx] ^= 0xff;
            handle_ingress_packet(
                bad_tcp_csum_syn,
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(1),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );
            assert!(
                stack.flows.is_empty(),
                "bad-TCP-checksum SYN must not register any BridgeFlow"
            );

            // 2. Corrupt IPv4 header checksum SYN -> must NOT register a flow or orphan Listen socket!
            let mut bad_ip_csum_syn = build_ipv4_tcp_packet(
                (Ipv4Addr::new(198, 18, 0, 40), 51009),
                dst,
                smoltcp::wire::TcpControl::Syn,
                101,
                None,
                &[],
            );
            bad_ip_csum_syn[10] ^= 0xff; // IPv4 header checksum byte
            handle_ingress_packet(
                bad_ip_csum_syn,
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(2),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );
            assert!(
                stack.flows.is_empty(),
                "bad-IPv4-checksum SYN must not register any BridgeFlow"
            );
            let listen_count_after_bad = stack
                .sockets
                .iter()
                .filter(|(_, s)| {
                    matches!(s, smoltcp::socket::Socket::Tcp(t) if t.state() == tcp::State::Listen)
                })
                .count();
            assert_eq!(
                listen_count_after_bad, 0,
                "bad-checksum SYNs must leave 0 orphan Listen sockets"
            );

            // 3. Two valid SYNs back-to-back to the EXACT SAME `(dst_ip, dst_port)` in one batch!
            handle_ingress_packet(
                build_ipv4_tcp_packet(src1, dst, smoltcp::wire::TcpControl::Syn, 1000, None, &[]),
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(3),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );
            handle_ingress_packet(
                build_ipv4_tcp_packet(src2, dst, smoltcp::wire::TcpControl::Syn, 2000, None, &[]),
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(4),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );

            let tuple1 = FourTuple {
                src: SocketAddr::new(IpAddr::V4(src1.0), src1.1),
                dst: SocketAddr::new(IpAddr::V4(dst.0), dst.1),
            };
            let tuple2 = FourTuple {
                src: SocketAddr::new(IpAddr::V4(src2.0), src2.1),
                dst: SocketAddr::new(IpAddr::V4(dst.0), dst.1),
            };
            let sock1 = stack
                .sockets
                .get::<tcp::Socket>(stack.flows[&tuple1].handle);
            let sock2 = stack
                .sockets
                .get::<tcp::Socket>(stack.flows[&tuple2].handle);
            assert_eq!(sock1.state(), tcp::State::SynReceived);
            assert_eq!(sock2.state(), tcp::State::SynReceived);
            assert_eq!(
                sock1.remote_endpoint(),
                Some(smoltcp::wire::IpEndpoint::new(
                    IpAddress::Ipv4(src1.0),
                    src1.1
                )),
                "tuple1 flow must be bound strictly to src1"
            );
            assert_eq!(
                sock2.remote_endpoint(),
                Some(smoltcp::wire::IpEndpoint::new(
                    IpAddress::Ipv4(src2.0),
                    src2.1
                )),
                "tuple2 flow must be bound strictly to src2"
            );
            let remaining_listen = stack
                .sockets
                .iter()
                .filter(|(_, s)| {
                    matches!(s, smoltcp::socket::Socket::Tcp(t) if t.state() == tcp::State::Listen)
                })
                .count();
            assert_eq!(remaining_listen, 0);

            let mut syn_ack_ports = Vec::new();
            while let Ok(pkt) = egress_rx.try_recv() {
                let ip4 = Ipv4Packet::new_checked(&pkt).unwrap();
                let tcp = TcpPacket::new_checked(ip4.payload()).unwrap();
                if tcp.syn() && tcp.ack() {
                    syn_ack_ports.push(tcp.dst_port());
                }
            }
            assert_eq!(syn_ack_ports, vec![src1.1, src2.1]);

            for (_, flow) in stack.flows.drain() {
                flow.task_abort.abort();
            }
            let _ = udp_nat.shutdown();
        }

        // Part B: Fast-reject IPv6 SYN and accepted IPv6 SYN sharing the SAME `(dst_v6, dst_port)`
        // back-to-back in one ingress batch must NEVER cross-wire!
        {
            let _ipv6_guard = crate::platform::socket_protect::lock_ipv6_reachability_for_test();
            crate::platform::socket_protect::set_os_underlying_ipv6_available(Some(false));

            let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(64);
            let hub = Arc::new(TelemetryHub::new());
            let mut stack =
                TunSmoltcpStack::new(1500, egress_tx.clone(), SmolInstant::from_millis(0));

            let dns = Arc::new(
                crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
            );
            let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
            outbounds.insert("ProxyNode".to_string(), Arc::new(HangingMockOutbound));
            // Same global-unicast IPv6 destination `2409:8c1e::1:443`:
            // - `fd00::10` matches `SRC-IP-CIDR` -> DIRECT (fast-rejected when IPv6 unreachable)
            // - `fd00::20` matches `MATCH,ProxyNode` -> PROXY (accepted)
            let rules = vec![
                "SRC-IP-CIDR,fd00::10/128,DIRECT".to_string(),
                "MATCH,ProxyNode".to_string(),
            ];
            let router = Arc::new(RwLock::new(Arc::new(
                Router::new(crate::config::RunMode::Rule, outbounds, &[], &rules, dns).unwrap(),
            )));
            let ipv6_enabled = Arc::new(AtomicBool::new(true));
            let shutting_down = Arc::new(AtomicBool::new(false));
            let udp_sem = Arc::new(Semaphore::new(8));
            let udp_nat =
                UdpNatManager::new("test-tun-v6", 16, Arc::clone(&hub), Arc::new(|_, _, _| {}));
            let wake_notify = Arc::new(Notify::new());

            let direct_client: Ipv6Addr = "fd00::10".parse().unwrap();
            let proxy_client: Ipv6Addr = "fd00::20".parse().unwrap();
            let shared_dst: Ipv6Addr = "2409:8c1e::1".parse().unwrap();

            // Send accepted PROXY SYN first, then fast-reject DIRECT SYN immediately after.
            handle_ingress_packet(
                build_ipv6_tcp_syn_packet(proxy_client, 52001, shared_dst, 443),
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(10),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );
            handle_ingress_packet(
                build_ipv6_tcp_syn_packet(direct_client, 52002, shared_dst, 443),
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(11),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );

            assert_eq!(stack.flows.len(), 1);
            let proxy_tuple = FourTuple {
                src: SocketAddr::new(IpAddr::V6(proxy_client), 52001),
                dst: SocketAddr::new(IpAddr::V6(shared_dst), 443),
            };
            let proxy_sock = stack
                .sockets
                .get::<tcp::Socket>(stack.flows[&proxy_tuple].handle);
            assert_eq!(
                proxy_sock.remote_endpoint(),
                Some(smoltcp::wire::IpEndpoint::new(
                    IpAddress::Ipv6(proxy_client),
                    52001
                )),
                "accepted IPv6 SYN socket must remain strictly bound to proxy_client"
            );

            let mut proxy_got_syn_ack = false;
            let mut direct_got_rst = false;
            while let Ok(pkt) = egress_rx.try_recv() {
                let ip6 = Ipv6Packet::new_checked(&pkt).unwrap();
                let tcp = TcpPacket::new_checked(ip6.payload()).unwrap();
                if ip6.dst_addr() == proxy_client && tcp.syn() && tcp.ack() && !tcp.rst() {
                    proxy_got_syn_ack = true;
                } else if ip6.dst_addr() == direct_client && tcp.rst() && !tcp.syn() {
                    direct_got_rst = true;
                }
            }
            assert!(proxy_got_syn_ack, "proxy_client must receive SYN-ACK");
            assert!(
                direct_got_rst,
                "fast-rejected direct_client must receive immediate RST|ACK without hijacking proxy_client's socket"
            );

            for (_, flow) in stack.flows.drain() {
                flow.task_abort.abort();
            }
            let _ = udp_nat.shutdown();
        }
    }

    struct RecordingTcpOutbound {
        name: &'static str,
        connects: Arc<std::sync::atomic::AtomicUsize>,
        received: Arc<parking_lot::Mutex<Vec<u8>>>,
        data_notify: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl crate::outbound::OutboundHandler for RecordingTcpOutbound {
        fn name(&self) -> &str {
            self.name
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        async fn connect_tcp(
            &self,
            _target: &TargetAddr,
        ) -> io::Result<crate::outbound::BoxedStream> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            let (client_side, mut server_side) = tokio::io::duplex(16 * 1024);
            let received = Arc::clone(&self.received);
            let notify = Arc::clone(&self.data_notify);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = server_side.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    received.lock().extend_from_slice(&buf[..n]);
                    notify.notify_waiters();
                }
            });
            Ok(Box::new(client_side))
        }
    }

    fn build_ipv6_tcp_packet(
        src: (Ipv6Addr, u16),
        dst: (Ipv6Addr, u16),
        control: smoltcp::wire::TcpControl,
        seq: i32,
        ack: Option<i32>,
        payload: &[u8],
    ) -> Vec<u8> {
        let checksum_caps = ChecksumCapabilities::default();
        let is_syn = control == smoltcp::wire::TcpControl::Syn;
        let tcp_repr = smoltcp::wire::TcpRepr {
            src_port: src.1,
            dst_port: dst.1,
            control,
            seq_number: smoltcp::wire::TcpSeqNumber(seq),
            ack_number: ack.map(smoltcp::wire::TcpSeqNumber),
            window_len: 65535,
            window_scale: is_syn.then_some(7),
            max_seg_size: is_syn.then_some(1440),
            sack_permitted: is_syn,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let tcp_len = tcp_repr.buffer_len();
        let ip_repr = Ipv6Repr {
            src_addr: src.0,
            dst_addr: dst.0,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_len,
            hop_limit: 64,
        };
        let mut bytes = vec![0u8; ip_repr.buffer_len() + tcp_len];
        let mut ip_pkt = Ipv6Packet::new_unchecked(&mut bytes);
        ip_repr.emit(&mut ip_pkt);
        let mut tcp_pkt = TcpPacket::new_unchecked(ip_pkt.payload_mut());
        tcp_repr.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv6(src.0),
            &IpAddress::Ipv6(dst.0),
            &checksum_caps,
        );
        bytes
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tun_syn_received_rst_reaps_reverted_listen_socket_preventing_hijack() {
        // Direct unit check: `step_single_tun_flow` immediately flags any `State::Listen`
        // reverted socket as `finished && reap_before_poll` and aborts its flow task.
        {
            let mut sockets = SocketSet::new(vec![]);
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 4096]),
                tcp::SocketBuffer::new(vec![0u8; 4096]),
            );
            sock.listen(IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(Ipv4Addr::new(93, 184, 216, 34))),
                port: 443,
            })
            .unwrap();
            let handle = sockets.add(sock);
            let flow_task = tokio::spawn(std::future::pending::<()>());
            let (to_tx, _to_rx) = mpsc::channel::<Vec<u8>>(4);
            let (_from_tx, from_rx) = mpsc::channel::<Vec<u8>>(4);
            let (_closed_tx, closed_rx) = watch::channel(());
            let now = Instant::now();
            let now_wall = TelemetryHub::now_ms();
            let mut flow = BridgeFlow {
                handle,
                established: false,
                remote_connected: Arc::new(AtomicBool::new(false)),
                dial_timeout_notify: Arc::new(Notify::new()),
                dial_timeout_notified_at: None,
                created_at: now,
                created_wall_ms: now_wall,
                last_active: now,
                last_active_wall_ms: now_wall,
                fin_started_at: None,
                fin_started_wall_ms: None,
                pending_tx: BytesMut::new(),
                from_remote_rx: from_rx,
                to_remote_tx: Some(to_tx),
                _bridge_closed_rx: closed_rx,
                remote_eof: false,
                remote_failed: Arc::new(AtomicBool::new(false)),
                task_abort: flow_task.abort_handle(),
            };
            let step = step_single_tun_flow(
                sockets.get_mut::<tcp::Socket>(handle),
                &mut flow,
                now,
                now_wall,
            );
            assert!(
                step.finished,
                "reverted Listen socket must be marked finished"
            );
            assert!(
                step.reap_before_poll,
                "reverted Listen socket must be reaped BEFORE iface.poll.post"
            );
            assert!(
                flow_task.await.unwrap_err().is_cancelled(),
                "reverted Listen socket flow_task must be aborted immediately"
            );
        }

        // Case A (across polls): Client A (`198.18.0.10` -> `outbound-a`) sends SYN -> gets
        // SYN-ACK -> sends RST (`seq = syn_seq + 1`). Then Client B (`198.18.0.20` -> `outbound-b`)
        // sends SYN + ACK + `b"SECRET-FROM-CLIENT-B"` to the exact same `(dst_ip, dst_port)`.
        // `outbound-b` must receive `b"SECRET-FROM-CLIENT-B"` and `outbound-a` must receive 0
        // connections and 0 bytes!
        {
            let a_connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let a_received = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
            let a_notify = Arc::new(Notify::new());
            let b_connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let b_received = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
            let b_notify = Arc::new(Notify::new());

            let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
            outbounds.insert(
                "outbound-a".to_string(),
                Arc::new(RecordingTcpOutbound {
                    name: "outbound-a",
                    connects: Arc::clone(&a_connects),
                    received: Arc::clone(&a_received),
                    data_notify: Arc::clone(&a_notify),
                }),
            );
            outbounds.insert(
                "outbound-b".to_string(),
                Arc::new(RecordingTcpOutbound {
                    name: "outbound-b",
                    connects: Arc::clone(&b_connects),
                    received: Arc::clone(&b_received),
                    data_notify: Arc::clone(&b_notify),
                }),
            );
            let dns = Arc::new(
                crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
            );
            let router = Arc::new(
                Router::new(
                    crate::config::RunMode::Rule,
                    outbounds,
                    &[],
                    &[
                        "SRC-IP-CIDR,198.18.0.10/32,outbound-a".to_string(),
                        "SRC-IP-CIDR,198.18.0.20/32,outbound-b".to_string(),
                        "MATCH,REJECT".to_string(),
                    ],
                    dns,
                )
                .unwrap(),
            );
            let hub = Arc::new(TelemetryHub::new());
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (mut vtun, tun_task) =
                spawn_userspace_tun(1500, Arc::new(RwLock::new(router)), hub, shutdown_rx);

            let client_a = (Ipv4Addr::new(198, 18, 0, 10), 40001u16);
            let client_b = (Ipv4Addr::new(198, 18, 0, 20), 40002u16);
            let shared_dst = (Ipv4Addr::new(93, 184, 216, 34), 443u16);

            // 1. Client A sends SYN -> receives SYN-ACK -> sends RST (`seq = 1001`).
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client_a,
                    shared_dst,
                    smoltcp::wire::TcpControl::Syn,
                    1000,
                    None,
                    &[],
                ))
                .await
                .unwrap();
            let sa_a = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                .await
                .expect("Client A must receive SYN-ACK")
                .expect("egress SYN-ACK for Client A");
            let tcp_sa_a =
                TcpPacket::new_checked(Ipv4Packet::new_checked(&sa_a).unwrap().payload()).unwrap();
            assert!(tcp_sa_a.syn() && tcp_sa_a.ack() && tcp_sa_a.dst_port() == client_a.1);

            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client_a,
                    shared_dst,
                    smoltcp::wire::TcpControl::Rst,
                    1001,
                    None,
                    &[],
                ))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;

            // 2. Client B connects to the exact same `(dst_ip, dst_port)` and sends secret payload.
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client_b,
                    shared_dst,
                    smoltcp::wire::TcpControl::Syn,
                    2000,
                    None,
                    &[],
                ))
                .await
                .unwrap();
            let sa_b = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                .await
                .expect("Client B must receive SYN-ACK")
                .expect("egress SYN-ACK for Client B");
            let tcp_sa_b =
                TcpPacket::new_checked(Ipv4Packet::new_checked(&sa_b).unwrap().payload()).unwrap();
            assert!(tcp_sa_b.syn() && tcp_sa_b.ack() && tcp_sa_b.dst_port() == client_b.1);
            let server_b_ack = tcp_sa_b.seq_number().0.wrapping_add(1);

            let secret = b"SECRET-FROM-CLIENT-B";
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client_b,
                    shared_dst,
                    smoltcp::wire::TcpControl::None,
                    2001,
                    Some(server_b_ack),
                    secret,
                ))
                .await
                .unwrap();

            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if b_received.lock().as_slice() == secret {
                        break;
                    }
                    b_notify.notified().await;
                }
            })
            .await
            .expect("outbound-b must receive Client B's secret payload");

            // Wait past the 150ms sniff window to confirm flow_task_A was aborted and never dialed.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                b_connects.load(Ordering::SeqCst),
                1,
                "outbound-b must receive exactly 1 connection"
            );
            assert_eq!(b_received.lock().as_slice(), secret);
            assert_eq!(
                a_connects.load(Ordering::SeqCst),
                0,
                "Case A: aborted Client A flow must NOT hijack Client B or dial outbound-a"
            );
            assert!(
                a_received.lock().is_empty(),
                "Case A: outbound-a must receive 0 bytes"
            );

            let _ = shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
        }

        // Case B (intra-batch): `RST_A` followed immediately in the SAME ingress burst by `SYN_B`
        // (while `RST_A` is still queued in `stack.device.rx_queue`) must reap Client A's reverted
        // `Listen` socket before registering Client B, routing Client B strictly to `outbound-b`.
        {
            let a_connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let a_received = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
            let a_notify = Arc::new(Notify::new());
            let b_connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let b_received = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
            let b_notify = Arc::new(Notify::new());

            let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
            outbounds.insert(
                "outbound-a".to_string(),
                Arc::new(RecordingTcpOutbound {
                    name: "outbound-a",
                    connects: Arc::clone(&a_connects),
                    received: Arc::clone(&a_received),
                    data_notify: Arc::clone(&a_notify),
                }),
            );
            outbounds.insert(
                "outbound-b".to_string(),
                Arc::new(RecordingTcpOutbound {
                    name: "outbound-b",
                    connects: Arc::clone(&b_connects),
                    received: Arc::clone(&b_received),
                    data_notify: Arc::clone(&b_notify),
                }),
            );
            let dns = Arc::new(
                crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
            );
            let router = Arc::new(RwLock::new(Arc::new(
                Router::new(
                    crate::config::RunMode::Rule,
                    outbounds,
                    &[],
                    &[
                        "SRC-IP-CIDR,198.18.0.10/32,outbound-a".to_string(),
                        "SRC-IP-CIDR,198.18.0.20/32,outbound-b".to_string(),
                        "MATCH,REJECT".to_string(),
                    ],
                    dns,
                )
                .unwrap(),
            )));
            let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(64);
            let hub = Arc::new(TelemetryHub::new());
            let mut stack =
                TunSmoltcpStack::new(1500, egress_tx.clone(), SmolInstant::from_millis(0));
            let ipv6_enabled = Arc::new(AtomicBool::new(true));
            let shutting_down = Arc::new(AtomicBool::new(false));
            let udp_sem = Arc::new(Semaphore::new(8));
            let udp_nat = UdpNatManager::new(
                "test-tun-intra-batch",
                16,
                Arc::clone(&hub),
                Arc::new(|_, _, _| {}),
            );
            let wake_notify = Arc::new(Notify::new());

            let client_a = (Ipv4Addr::new(198, 18, 0, 10), 41001u16);
            let client_b = (Ipv4Addr::new(198, 18, 0, 20), 41002u16);
            let shared_dst = (Ipv4Addr::new(93, 184, 216, 34), 443u16);

            // Feed SYN_A, RST_A (queued in rx_queue), and SYN_B back-to-back in ONE burst!
            handle_ingress_packet(
                build_ipv4_tcp_packet(
                    client_a,
                    shared_dst,
                    smoltcp::wire::TcpControl::Syn,
                    1000,
                    None,
                    &[],
                ),
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(1),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );
            handle_ingress_packet(
                build_ipv4_tcp_packet(
                    client_a,
                    shared_dst,
                    smoltcp::wire::TcpControl::Rst,
                    1001,
                    None,
                    &[],
                ),
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(2),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );
            assert_eq!(
                stack.device.rx_queue.len(),
                1,
                "RST_A must be queued in rx_queue right before intra-batch SYN_B arrives"
            );
            handle_ingress_packet(
                build_ipv4_tcp_packet(
                    client_b,
                    shared_dst,
                    smoltcp::wire::TcpControl::Syn,
                    2000,
                    None,
                    &[],
                ),
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(3),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );

            let tuple_a = FourTuple {
                src: SocketAddr::new(IpAddr::V4(client_a.0), client_a.1),
                dst: SocketAddr::new(IpAddr::V4(shared_dst.0), shared_dst.1),
            };
            let tuple_b = FourTuple {
                src: SocketAddr::new(IpAddr::V4(client_b.0), client_b.1),
                dst: SocketAddr::new(IpAddr::V4(shared_dst.0), shared_dst.1),
            };
            assert!(
                !stack.flows.contains_key(&tuple_a),
                "Case B: Client A reverted Listen flow must be reaped before SYN_B"
            );
            assert!(
                stack.flows.contains_key(&tuple_b),
                "Case B: Client B must own its own freshly registered flow"
            );
            let sock_b = stack
                .sockets
                .get::<tcp::Socket>(stack.flows[&tuple_b].handle);
            assert_eq!(sock_b.state(), tcp::State::SynReceived);
            assert_eq!(
                sock_b.remote_endpoint(),
                Some(smoltcp::wire::IpEndpoint::new(
                    IpAddress::Ipv4(client_b.0),
                    client_b.1
                )),
                "Case B: Client B socket must be strictly bound to client_b"
            );
            let remaining_listen = stack
                .sockets
                .iter()
                .filter(|(_, s)| {
                    matches!(s, smoltcp::socket::Socket::Tcp(t) if t.state() == tcp::State::Listen)
                })
                .count();
            assert_eq!(remaining_listen, 0);

            // Extract SYN-ACK for Client B, send ACK + payload, and bridge into flow_task_B.
            let mut server_b_ack = None;
            while let Ok(pkt) = egress_rx.try_recv() {
                let ip4 = Ipv4Packet::new_checked(&pkt).unwrap();
                let tcp = TcpPacket::new_checked(ip4.payload()).unwrap();
                if tcp.syn() && tcp.ack() && tcp.dst_port() == client_b.1 {
                    server_b_ack = Some(tcp.seq_number().0.wrapping_add(1));
                }
            }
            let server_b_ack = server_b_ack.expect("Client B must receive SYN-ACK");
            let secret = b"SECRET-FROM-CLIENT-B";
            handle_ingress_packet(
                build_ipv4_tcp_packet(
                    client_b,
                    shared_dst,
                    smoltcp::wire::TcpControl::None,
                    2001,
                    Some(server_b_ack),
                    secret,
                ),
                &ipv6_enabled,
                false,
                &shutting_down,
                SmolInstant::from_millis(4),
                &mut stack,
                &egress_tx,
                &udp_sem,
                &udp_nat,
                &wake_notify,
                &router,
                &hub,
            );
            assert!(stack.poll_guarded("case_b.poll", SmolInstant::from_millis(5), &hub));
            {
                let flow_b = stack.flows.get_mut(&tuple_b).unwrap();
                let sock_b_mut = stack.sockets.get_mut::<tcp::Socket>(flow_b.handle);
                let _ = step_single_tun_flow(
                    sock_b_mut,
                    flow_b,
                    Instant::now(),
                    TelemetryHub::now_ms(),
                );
            }

            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if b_received.lock().as_slice() == secret {
                        break;
                    }
                    b_notify.notified().await;
                }
            })
            .await
            .expect("Case B: outbound-b must receive Client B's payload");

            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(b_connects.load(Ordering::SeqCst), 1);
            assert_eq!(b_received.lock().as_slice(), secret);
            assert_eq!(
                a_connects.load(Ordering::SeqCst),
                0,
                "Case B: outbound-a must receive 0 connections (0 hijack)"
            );
            assert!(a_received.lock().is_empty());

            for (_, flow) in stack.flows.drain() {
                flow.task_abort.abort();
            }
            let _ = udp_nat.shutdown();
        }

        // Case C (IPv6 `fast_reject` after `SynReceived` + `RST`, both intra-batch and across
        // polls): Client A (`fd00::10` -> `outbound-a`) sends IPv6 SYN -> SYN-ACK -> RST,
        // followed by Client B (`fd00::20` -> `DIRECT`, `fast_reject == true`) sending IPv6 SYN
        // to the same `(dst_v6, 443)` -> Client B must receive `RST|ACK` and `outbound-a` must
        // get 0 connections and 0 bytes!
        {
            let _ipv6_guard = crate::platform::socket_protect::lock_ipv6_reachability_for_test();
            crate::platform::socket_protect::set_os_underlying_ipv6_available(Some(false));

            let client_a_v6: Ipv6Addr = "fd00::10".parse().unwrap();
            let client_b_v6: Ipv6Addr = "fd00::20".parse().unwrap();
            let shared_dst_v6: Ipv6Addr = "2409:8c1e::1".parse().unwrap();

            // C1: Intra-batch IPv6 RST_A immediately followed by fast_reject SYN_B.
            {
                let a_connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let a_received = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
                let a_notify = Arc::new(Notify::new());
                let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
                outbounds.insert(
                    "outbound-a".to_string(),
                    Arc::new(RecordingTcpOutbound {
                        name: "outbound-a",
                        connects: Arc::clone(&a_connects),
                        received: Arc::clone(&a_received),
                        data_notify: Arc::clone(&a_notify),
                    }),
                );
                let dns = Arc::new(
                    crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
                );
                let router = Arc::new(RwLock::new(Arc::new(
                    Router::new(
                        crate::config::RunMode::Rule,
                        outbounds,
                        &[],
                        &[
                            "SRC-IP-CIDR,fd00::10/128,outbound-a".to_string(),
                            "SRC-IP-CIDR,fd00::20/128,DIRECT".to_string(),
                            "MATCH,REJECT".to_string(),
                        ],
                        dns,
                    )
                    .unwrap(),
                )));
                let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(64);
                let hub = Arc::new(TelemetryHub::new());
                let mut stack =
                    TunSmoltcpStack::new(1500, egress_tx.clone(), SmolInstant::from_millis(0));
                let ipv6_enabled = Arc::new(AtomicBool::new(true));
                let shutting_down = Arc::new(AtomicBool::new(false));
                let udp_sem = Arc::new(Semaphore::new(8));
                let udp_nat = UdpNatManager::new(
                    "test-tun-v6-rst-intra",
                    16,
                    Arc::clone(&hub),
                    Arc::new(|_, _, _| {}),
                );
                let wake_notify = Arc::new(Notify::new());

                handle_ingress_packet(
                    build_ipv6_tcp_packet(
                        (client_a_v6, 53001),
                        (shared_dst_v6, 443),
                        smoltcp::wire::TcpControl::Syn,
                        1000,
                        None,
                        &[],
                    ),
                    &ipv6_enabled,
                    false,
                    &shutting_down,
                    SmolInstant::from_millis(10),
                    &mut stack,
                    &egress_tx,
                    &udp_sem,
                    &udp_nat,
                    &wake_notify,
                    &router,
                    &hub,
                );
                handle_ingress_packet(
                    build_ipv6_tcp_packet(
                        (client_a_v6, 53001),
                        (shared_dst_v6, 443),
                        smoltcp::wire::TcpControl::Rst,
                        1001,
                        None,
                        &[],
                    ),
                    &ipv6_enabled,
                    false,
                    &shutting_down,
                    SmolInstant::from_millis(11),
                    &mut stack,
                    &egress_tx,
                    &udp_sem,
                    &udp_nat,
                    &wake_notify,
                    &router,
                    &hub,
                );
                handle_ingress_packet(
                    build_ipv6_tcp_packet(
                        (client_b_v6, 53002),
                        (shared_dst_v6, 443),
                        smoltcp::wire::TcpControl::Syn,
                        2000,
                        None,
                        &[],
                    ),
                    &ipv6_enabled,
                    false,
                    &shutting_down,
                    SmolInstant::from_millis(12),
                    &mut stack,
                    &egress_tx,
                    &udp_sem,
                    &udp_nat,
                    &wake_notify,
                    &router,
                    &hub,
                );

                assert!(
                    stack.flows.is_empty(),
                    "Case C1: Client A flow must be reaped and fast-rejected Client B must not register any flow"
                );
                let mut client_b_got_rst_ack = false;
                while let Ok(pkt) = egress_rx.try_recv() {
                    let ip6 = Ipv6Packet::new_checked(&pkt).unwrap();
                    let tcp = TcpPacket::new_checked(ip6.payload()).unwrap();
                    if ip6.dst_addr() == client_b_v6
                        && tcp.dst_port() == 53002
                        && tcp.rst()
                        && tcp.ack()
                        && !tcp.syn()
                    {
                        client_b_got_rst_ack = true;
                    }
                }
                assert!(
                    client_b_got_rst_ack,
                    "Case C1: fast-rejected IPv6 Client B must receive RST|ACK after Client A RST"
                );

                tokio::time::sleep(Duration::from_millis(200)).await;
                assert_eq!(a_connects.load(Ordering::SeqCst), 0);
                assert!(a_received.lock().is_empty());
                let _ = udp_nat.shutdown();
            }

            // C2: Across polls via full `spawn_userspace_tun`.
            {
                let a_connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let a_received = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
                let a_notify = Arc::new(Notify::new());
                let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
                outbounds.insert(
                    "outbound-a".to_string(),
                    Arc::new(RecordingTcpOutbound {
                        name: "outbound-a",
                        connects: Arc::clone(&a_connects),
                        received: Arc::clone(&a_received),
                        data_notify: Arc::clone(&a_notify),
                    }),
                );
                let dns = Arc::new(
                    crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
                );
                let router = Arc::new(
                    Router::new(
                        crate::config::RunMode::Rule,
                        outbounds,
                        &[],
                        &[
                            "SRC-IP-CIDR,fd00::10/128,outbound-a".to_string(),
                            "SRC-IP-CIDR,fd00::20/128,DIRECT".to_string(),
                            "MATCH,REJECT".to_string(),
                        ],
                        dns,
                    )
                    .unwrap(),
                );
                let hub = Arc::new(TelemetryHub::new());
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let (mut vtun, tun_task) =
                    spawn_userspace_tun(1500, Arc::new(RwLock::new(router)), hub, shutdown_rx);

                vtun.ingress_tx
                    .send(build_ipv6_tcp_packet(
                        (client_a_v6, 54001),
                        (shared_dst_v6, 443),
                        smoltcp::wire::TcpControl::Syn,
                        1000,
                        None,
                        &[],
                    ))
                    .await
                    .unwrap();
                let sa_a = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                    .await
                    .expect("Case C2: Client A must receive SYN-ACK")
                    .expect("egress IPv6 SYN-ACK");
                let tcp_sa_a =
                    TcpPacket::new_checked(Ipv6Packet::new_checked(&sa_a).unwrap().payload())
                        .unwrap();
                assert!(tcp_sa_a.syn() && tcp_sa_a.ack());

                vtun.ingress_tx
                    .send(build_ipv6_tcp_packet(
                        (client_a_v6, 54001),
                        (shared_dst_v6, 443),
                        smoltcp::wire::TcpControl::Rst,
                        1001,
                        None,
                        &[],
                    ))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;

                vtun.ingress_tx
                    .send(build_ipv6_tcp_packet(
                        (client_b_v6, 54002),
                        (shared_dst_v6, 443),
                        smoltcp::wire::TcpControl::Syn,
                        2000,
                        None,
                        &[],
                    ))
                    .await
                    .unwrap();
                let resp_b = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                    .await
                    .expect("Case C2: fast-rejected IPv6 Client B must receive RST|ACK")
                    .expect("egress IPv6 RST|ACK");
                let ip6_b = Ipv6Packet::new_checked(&resp_b).unwrap();
                let tcp_b = TcpPacket::new_checked(ip6_b.payload()).unwrap();
                assert_eq!(ip6_b.dst_addr(), client_b_v6);
                assert_eq!(tcp_b.dst_port(), 54002);
                assert!(
                    tcp_b.rst() && tcp_b.ack() && !tcp_b.syn(),
                    "Case C2: expected RST|ACK for fast-rejected IPv6 Client B, got syn={} ack={} rst={}",
                    tcp_b.syn(),
                    tcp_b.ack(),
                    tcp_b.rst()
                );

                tokio::time::sleep(Duration::from_millis(200)).await;
                assert_eq!(
                    a_connects.load(Ordering::SeqCst),
                    0,
                    "Case C2: outbound-a must receive 0 connections (0 hijack)"
                );
                assert!(a_received.lock().is_empty());

                let _ = shutdown_tx.send(true);
                let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
            }
        }
    }

    #[tokio::test]
    async fn tun_self_pid_guard_drops_own_process_dns_port_53_before_hijack() {
        let own_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let own_udp_src = own_udp.local_addr().unwrap();
        if !is_self_process_socket(SocketTransport::Udp, own_udp_src) {
            // Skip only on restricted sandboxes where OS socket tables are hidden.
            return;
        }

        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec!["MATCH,DIRECT".to_string()];
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                HashMap::new(),
                &[],
                &rules,
                Arc::clone(&dns),
            )
            .unwrap(),
        );
        assert!(router.tun_dns_hijack());
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mut vtun, tun_task) = spawn_userspace_tun_with_options(
            1500,
            router_slot,
            Arc::clone(&hub),
            shutdown_rx,
            Arc::new(AtomicBool::new(true)),
            true,
        );

        // 1. Self-originated UDP `:53` query entering OS TUN with `drop_self_pid = true` MUST be
        //    dropped BEFORE DNS hijack (no DNS reply emitted, no Fake-IP assigned).
        let IpAddr::V4(own_ip) = own_udp_src.ip() else {
            unreachable!()
        };
        let self_dns_query = crate::dns::wire::build_dns_query(
            0x4242,
            "self-loop.example.com",
            crate::dns::wire::QTYPE_A,
        );
        let self_pkt = build_ipv4_udp_packet(
            own_ip,
            own_udp_src.port(),
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            &self_dns_query,
        )
        .expect("valid v4 udp dns packet");
        vtun.ingress_tx.send(self_pkt).await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(150), vtun.egress_rx.recv())
                .await
                .is_err(),
            "self-PID UDP :53 query must be dropped before DNS hijack instead of emitting a reply"
        );
        assert_eq!(
            dns.lookup_ip("self-loop.example.com"),
            None,
            "self-PID UDP :53 query must never enter FakeIpDnsEngine"
        );

        // 2. Non-self guest UDP `:53` query on the SAME `drop_self_pid = true` TUN MUST still be
        //    hijacked cleanly and receive a Fake-IP DNS reply.
        let guest_ip = Ipv4Addr::new(198, 18, 0, 55);
        let guest_port = 44444;
        let guest_dns_query = crate::dns::wire::build_dns_query(
            0x4343,
            "guest-app.example.com",
            crate::dns::wire::QTYPE_A,
        );
        let guest_pkt = build_ipv4_udp_packet(
            guest_ip,
            guest_port,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            &guest_dns_query,
        )
        .expect("valid guest v4 udp dns packet");
        vtun.ingress_tx.send(guest_pkt).await.unwrap();

        let egress_pkt = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("guest UDP :53 query must be hijacked and receive a DNS reply")
            .expect("egress packet");
        let ip4 = Ipv4Packet::new_checked(&egress_pkt).unwrap();
        let udp = UdpPacket::new_checked(ip4.payload()).unwrap();
        assert_eq!(ip4.src_addr(), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(ip4.dst_addr(), guest_ip);
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), guest_port);
        let meta = crate::dns::wire::extract_dns_response_meta(udp.payload()).unwrap();
        assert_eq!(meta.rcode, 0);
        assert!(dns.lookup_ip("guest-app.example.com").is_some());

        // 3. Sister TCP `:53` check: self-originated TCP SYN to `:53` must abort with RST instead
        //    of being hijacked into `serve_tun_tcp_dns_flow`.
        let own_tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let own_tcp_src = own_tcp.local_addr().unwrap();
        if is_self_process_socket(SocketTransport::Tcp, own_tcp_src) {
            let IpAddr::V4(own_tcp_ip) = own_tcp_src.ip() else {
                unreachable!()
            };
            let syn_pkt = build_ipv4_tcp_packet(
                (own_tcp_ip, own_tcp_src.port()),
                (Ipv4Addr::new(8, 8, 8, 8), 53),
                smoltcp::wire::TcpControl::Syn,
                1000,
                None,
                &[],
            );
            vtun.ingress_tx.send(syn_pkt).await.unwrap();

            let mut saw_rst = false;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while tokio::time::Instant::now() < deadline {
                let Ok(Some(pkt)) =
                    tokio::time::timeout(Duration::from_millis(300), vtun.egress_rx.recv()).await
                else {
                    break;
                };
                if let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                    && ip4.next_header() == IpProtocol::Tcp
                    && let Ok(tcp) = TcpPacket::new_checked(ip4.payload())
                    && tcp.dst_port() == own_tcp_src.port()
                    && tcp.rst()
                {
                    saw_rst = true;
                    break;
                }
            }
            assert!(
                saw_rst,
                "self-PID TCP :53 SYN must be aborted with RST before TCP DNS hijack"
            );
        }

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
    }

    #[tokio::test]
    async fn tun_udp_dns_hijack_truncates_by_rfc1035_and_edns0_payload_size() {
        // Mock upstream UDP DNS server returning a ~715-byte TXT response (3 * 220B TXT records)
        // for `med-*.txt.example` and a ~1400-byte TXT response (6 * 220B TXT records) for
        // `big.txt.example`.
        let upstream_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, peer)) = upstream_sock.recv_from(&mut buf).await {
                let req = &buf[..n];
                let Ok(qp) = crate::dns::wire::DnsQueryPacket::parse(req) else {
                    continue;
                };
                let count = if qp.question.name == "big.txt.example" {
                    6
                } else {
                    3
                };
                let txt_chunk = "x".repeat(220);
                let answers: Vec<crate::dns::wire::DnsAnswerData> = (0..count)
                    .map(|_| crate::dns::wire::DnsAnswerData::Txt(txt_chunk.clone()))
                    .collect();
                let resp = qp.build_response(req, 0, 60, &answers);
                let _ = upstream_sock.send_to(&resp, peer).await;
            }
        });

        let dns_cfg = crate::config::DnsConfig {
            nameserver: vec![upstream_addr.to_string()],
            fallback: vec![],
            default_nameserver: vec![],
            ..crate::config::DnsConfig::default()
        };
        let dns = Arc::new(crate::dns::FakeIpDnsEngine::new(&dns_cfg).unwrap());
        let rules = vec!["MATCH,DIRECT".to_string()];
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                HashMap::new(),
                &[],
                &rules,
                Arc::clone(&dns),
            )
            .unwrap(),
        );
        assert!(router.tun_dns_hijack());
        let router_slot = Arc::new(RwLock::new(router));
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mut vtun, tun_task) = spawn_userspace_tun(1500, router_slot, hub, shutdown_rx);

        let append_edns0_opt = |mut pkt: Vec<u8>, udp_size: u16| -> Vec<u8> {
            pkt[10] = 0;
            pkt[11] = 1; // ARCOUNT = 1
            pkt.push(0); // root owner name
            pkt.extend_from_slice(&crate::dns::wire::QTYPE_OPT.to_be_bytes());
            pkt.extend_from_slice(&udp_size.to_be_bytes());
            pkt.extend_from_slice(&0u32.to_be_bytes()); // extended RCODE / flags
            pkt.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0
            pkt
        };

        let client_v4 = Ipv4Addr::new(198, 18, 0, 77);
        let dns_v4 = Ipv4Addr::new(8, 8, 8, 8);

        async fn send_v4_dns(
            vtun: &mut VirtualTunHandle,
            client_v4: Ipv4Addr,
            dns_v4: Ipv4Addr,
            port: u16,
            query: &[u8],
        ) -> Vec<u8> {
            let pkt = build_ipv4_udp_packet(client_v4, port, dns_v4, 53, query)
                .expect("valid v4 udp dns packet");
            vtun.ingress_tx.send(pkt).await.unwrap();
            let egress = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                .await
                .expect("expected hijacked TUN UDP :53 reply")
                .expect("egress packet");
            let ip4 = Ipv4Packet::new_checked(&egress).unwrap();
            let udp = UdpPacket::new_checked(ip4.payload()).unwrap();
            assert_eq!(ip4.src_addr(), dns_v4);
            assert_eq!(ip4.dst_addr(), client_v4);
            assert_eq!(udp.src_port(), 53);
            assert_eq!(udp.dst_port(), port);
            udp.payload().to_vec()
        }

        // 1. Non-EDNS0 UDP :53 query for ~715B TXT response -> MUST return TC=1 (<= 512 bytes).
        let q_plain = crate::dns::wire::build_dns_query(
            0x5101,
            "med-plain.txt.example",
            crate::dns::wire::QTYPE_TXT,
        );
        let resp_plain = send_v4_dns(&mut vtun, client_v4, dns_v4, 51001, &q_plain).await;
        let meta_plain = crate::dns::wire::extract_dns_response_meta(&resp_plain).unwrap();
        assert_eq!(u16::from_be_bytes([resp_plain[0], resp_plain[1]]), 0x5101);
        assert!(
            meta_plain.truncated,
            "non-EDNS0 TUN UDP :53 query must receive TC=1 when reply > 512B (got {}B)",
            resp_plain.len()
        );
        assert!(
            resp_plain.len() <= 512,
            "truncated non-EDNS0 reply must be <= 512B (got {}B)",
            resp_plain.len()
        );
        assert_eq!(meta_plain.ancount, 0);

        // 2. EDNS0(600B) UDP :53 query for ~715B TXT response -> MUST return TC=1 (<= 600 bytes).
        let q_600 = append_edns0_opt(
            crate::dns::wire::build_dns_query(
                0x5102,
                "med-600.txt.example",
                crate::dns::wire::QTYPE_TXT,
            ),
            600,
        );
        let resp_600 = send_v4_dns(&mut vtun, client_v4, dns_v4, 51002, &q_600).await;
        let meta_600 = crate::dns::wire::extract_dns_response_meta(&resp_600).unwrap();
        assert_eq!(u16::from_be_bytes([resp_600[0], resp_600[1]]), 0x5102);
        assert!(
            meta_600.truncated,
            "EDNS0(600B) TUN UDP :53 query must receive TC=1 when reply > 600B (got {}B)",
            resp_600.len()
        );
        assert!(
            resp_600.len() <= 600,
            "truncated EDNS0(600B) reply must be <= 600B (got {}B)",
            resp_600.len()
        );
        assert_eq!(meta_600.ancount, 0);

        // 3. EDNS0(1232B) UDP :53 query for ~715B TXT response -> MUST pass through untruncated!
        let q_1232 = append_edns0_opt(
            crate::dns::wire::build_dns_query(
                0x5103,
                "med-1232.txt.example",
                crate::dns::wire::QTYPE_TXT,
            ),
            1232,
        );
        let resp_1232 = send_v4_dns(&mut vtun, client_v4, dns_v4, 51003, &q_1232).await;
        let meta_1232 = crate::dns::wire::extract_dns_response_meta(&resp_1232).unwrap();
        assert_eq!(u16::from_be_bytes([resp_1232[0], resp_1232[1]]), 0x5103);
        assert!(
            !meta_1232.truncated,
            "EDNS0(1232B) TUN UDP :53 query must NOT truncate a ~715B reply (got {}B)",
            resp_1232.len()
        );
        assert!(
            resp_1232.len() > 650 && resp_1232.len() <= 1232,
            "expected full ~715B TXT response, got {}B",
            resp_1232.len()
        );
        assert_eq!(meta_1232.ancount, 3);

        // 4. Cache-hit parity: re-querying `med-plain.txt.example` with EDNS0(1232B) returns the
        //    full cached untruncated reply, while re-querying `med-1232.txt.example` without EDNS0
        //    returns TC=1.
        let q_cached_1232 = append_edns0_opt(
            crate::dns::wire::build_dns_query(
                0x5104,
                "med-plain.txt.example",
                crate::dns::wire::QTYPE_TXT,
            ),
            1232,
        );
        let resp_cached_1232 =
            send_v4_dns(&mut vtun, client_v4, dns_v4, 51004, &q_cached_1232).await;
        let meta_cached_1232 =
            crate::dns::wire::extract_dns_response_meta(&resp_cached_1232).unwrap();
        assert!(!meta_cached_1232.truncated);
        assert!(resp_cached_1232.len() > 650 && resp_cached_1232.len() <= 1232);
        assert_eq!(meta_cached_1232.ancount, 3);

        let q_cached_plain = crate::dns::wire::build_dns_query(
            0x5105,
            "med-1232.txt.example",
            crate::dns::wire::QTYPE_TXT,
        );
        let resp_cached_plain =
            send_v4_dns(&mut vtun, client_v4, dns_v4, 51005, &q_cached_plain).await;
        let meta_cached_plain =
            crate::dns::wire::extract_dns_response_meta(&resp_cached_plain).unwrap();
        assert!(meta_cached_plain.truncated);
        assert!(resp_cached_plain.len() <= 512);
        assert_eq!(meta_cached_plain.ancount, 0);

        // 5. EDNS0(4096B) clamped to 1232B for ~1400B TXT response -> MUST return TC=1.
        let q_4096 = append_edns0_opt(
            crate::dns::wire::build_dns_query(
                0x5106,
                "big.txt.example",
                crate::dns::wire::QTYPE_TXT,
            ),
            4096,
        );
        let resp_4096 = send_v4_dns(&mut vtun, client_v4, dns_v4, 51006, &q_4096).await;
        let meta_4096 = crate::dns::wire::extract_dns_response_meta(&resp_4096).unwrap();
        assert!(
            meta_4096.truncated,
            "EDNS0(4096B) clamped to 1232B must return TC=1 for ~1400B reply (got {}B)",
            resp_4096.len()
        );
        assert!(resp_4096.len() <= 512);
        assert_eq!(meta_4096.ancount, 0);

        // 6. IPv6 TUN UDP :53 hijack follows the exact same RFC 1035 / EDNS0 truncation policy.
        let client_v6: Ipv6Addr = "fd00::77".parse().unwrap();
        let dns_v6: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let q_v6_plain = crate::dns::wire::build_dns_query(
            0x5107,
            "med-v6.txt.example",
            crate::dns::wire::QTYPE_TXT,
        );
        let pkt_v6_plain = build_ipv6_udp_packet(client_v6, 51007, dns_v6, 53, &q_v6_plain)
            .expect("valid v6 udp dns packet");
        vtun.ingress_tx.send(pkt_v6_plain).await.unwrap();
        let egress_v6 = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("expected hijacked IPv6 TUN UDP :53 reply")
            .expect("egress v6 packet");
        let ip6 = Ipv6Packet::new_checked(&egress_v6).unwrap();
        let udp6 = UdpPacket::new_checked(ip6.payload()).unwrap();
        assert_eq!(ip6.src_addr(), dns_v6);
        assert_eq!(ip6.dst_addr(), client_v6);
        assert_eq!(udp6.src_port(), 53);
        assert_eq!(udp6.dst_port(), 51007);
        let meta_v6_plain = crate::dns::wire::extract_dns_response_meta(udp6.payload()).unwrap();
        assert!(meta_v6_plain.truncated);
        assert!(udp6.payload().len() <= 512);
        assert_eq!(meta_v6_plain.ancount, 0);

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), tun_task).await;
        upstream_task.abort();
    }

    #[test]
    fn truncate_tun_udp_dns_response_unparseable_query_uses_12_byte_tc_fallback() {
        // Unparseable query (QDCOUNT=0) with an oversized (>512B) response MUST fall back to a
        // 12-byte QR=1|TC=1 zeroed-counts header rather than emitting the oversized UDP payload.
        let unparseable_req = [
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut oversized_resp = vec![0x55u8; 700];
        oversized_resp[0] = 0xAB;
        oversized_resp[1] = 0xCD;
        oversized_resp[2] = 0x01; // QR=0, TC=0, RD=1
        oversized_resp[3] = 0x80; // RA=1
        oversized_resp[4..12].copy_from_slice(&[0, 1, 0, 3, 0, 2, 0, 1]);

        let out = truncate_tun_udp_dns_response(&unparseable_req, oversized_resp);
        assert_eq!(out.len(), 12);
        assert_eq!(&out[0..2], &[0xAB, 0xCD]);
        assert_eq!(out[2] & 0x82, 0x82, "QR=1 and TC=1 must both be set");
        assert_eq!(out[3], 0x80);
        assert_eq!(
            &out[4..12],
            &[0u8; 8],
            "QDCOUNT, ANCOUNT, NSCOUNT, and ARCOUNT must be zeroed"
        );

        // Exact boundary checks for non-EDNS0 (512B) and EDNS0(600B).
        let plain_q = crate::dns::wire::build_dns_query(
            0x1234,
            "edge.example.com",
            crate::dns::wire::QTYPE_TXT,
        );
        let resp_512 = vec![0u8; 512];
        assert_eq!(
            truncate_tun_udp_dns_response(&plain_q, resp_512.clone()).len(),
            512
        );
        let resp_513 = vec![0u8; 513];
        let trunc_513 = truncate_tun_udp_dns_response(&plain_q, resp_513);
        assert_eq!(trunc_513[2] & 0x82, 0x82);
        assert!(trunc_513.len() <= 512);

        let mut edns_600_q = plain_q;
        edns_600_q[10] = 0;
        edns_600_q[11] = 1;
        edns_600_q.push(0);
        edns_600_q.extend_from_slice(&crate::dns::wire::QTYPE_OPT.to_be_bytes());
        edns_600_q.extend_from_slice(&600u16.to_be_bytes());
        edns_600_q.extend_from_slice(&0u32.to_be_bytes());
        edns_600_q.extend_from_slice(&0u16.to_be_bytes());

        assert_eq!(
            truncate_tun_udp_dns_response(&edns_600_q, vec![0u8; 600]).len(),
            600
        );
        let trunc_601 = truncate_tun_udp_dns_response(&edns_600_q, vec![0u8; 601]);
        assert_eq!(trunc_601[2] & 0x82, 0x82);
        assert!(trunc_601.len() <= 512);
    }

    #[tokio::test]
    async fn tun_real_ip_camouflage_sni_loop_auto_bypasses_to_raw_ip_after_three_short_closes() {
        use std::sync::atomic::AtomicUsize;

        struct RecordingShortReplyProxy {
            dialed_targets: Arc<parking_lot::Mutex<Vec<String>>>,
            reply_len: usize,
        }

        #[async_trait::async_trait]
        impl crate::outbound::OutboundHandler for RecordingShortReplyProxy {
            fn name(&self) -> &str {
                "MOCK-PROXY"
            }
            fn protocol(&self) -> &'static str {
                "MockProxy"
            }
            async fn connect_tcp(
                &self,
                target: &TargetAddr,
            ) -> io::Result<crate::outbound::BoxedStream> {
                self.dialed_targets.lock().push(target.to_string());
                let (client_half, mut server_half) = tokio::io::duplex(16 * 1024);
                let reply = vec![0x16u8; self.reply_len];
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = server_half.read(&mut buf).await;
                    let _ = server_half.write_all(&reply).await;
                    let _ = server_half.shutdown().await;
                });
                Ok(Box::new(client_half))
            }
        }

        let dialed_targets = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let proxy = Arc::new(RecordingShortReplyProxy {
            dialed_targets: Arc::clone(&dialed_targets),
            reply_len: 4096,
        });
        let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds.insert("MOCK-PROXY".to_string(), proxy);
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec![
            "DOMAIN-SUFFIX,google.com,MOCK-PROXY".to_string(),
            "MATCH,MOCK-PROXY".to_string(),
        ];
        let router = Arc::new(
            Router::new(crate::config::RunMode::Rule, outbounds, &[], &rules, dns).unwrap(),
        );
        let hub = Arc::new(TelemetryHub::new());
        let (sd_tx, sd_rx) = watch::channel(false);
        let (mut vtun, task) = spawn_userspace_tun(
            1500,
            Arc::new(RwLock::new(Arc::clone(&router))),
            Arc::clone(&hub),
            sd_rx,
        );

        let hello = crate::inbound::sniff::test_helpers::build_tls_client_hello("www.google.com");
        let raw_ip = Ipv4Addr::new(194, 221, 250, 50);
        let seq_counter = AtomicUsize::new(0);

        // Run 4 short-lived connections to 194.221.250.50:443 with decoy SNI `www.google.com`.
        for idx in 0..4u16 {
            let client = (Ipv4Addr::new(198, 18, 0, 55), 52_000 + idx);
            let dst = (raw_ip, 443u16);
            let isn = 10_000i32 + (seq_counter.fetch_add(1, Ordering::Relaxed) as i32) * 50_000;

            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::Syn,
                    isn,
                    None,
                    &[],
                ))
                .await
                .unwrap();

            // Wait for SYN-ACK
            let mut sseq = None;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while tokio::time::Instant::now() < deadline {
                if let Ok(Some(pkt)) =
                    tokio::time::timeout(Duration::from_millis(200), vtun.egress_rx.recv()).await
                    && let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                    && let Ok(tcp) = TcpPacket::new_checked(ip4.payload())
                    && tcp.dst_port() == client.1
                    && tcp.syn()
                    && tcp.ack()
                {
                    sseq = Some(tcp.seq_number().0.wrapping_add(1));
                    break;
                }
            }
            let sseq = sseq.expect("expected SYN-ACK for camouflage TLS flow");

            // Send ClientHello (PSH|ACK)
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::Psh,
                    isn + 1,
                    Some(sseq),
                    &hello,
                ))
                .await
                .unwrap();

            // Wait until we receive the mock server's reply or FIN, then send client FIN|ACK.
            let mut rx_bytes = 0usize;
            let mut peer_seq = sseq;
            let reply_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while rx_bytes < 4096 && tokio::time::Instant::now() < reply_deadline {
                if let Ok(Some(pkt)) =
                    tokio::time::timeout(Duration::from_millis(200), vtun.egress_rx.recv()).await
                    && let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                    && let Ok(tcp) = TcpPacket::new_checked(ip4.payload())
                    && tcp.dst_port() == client.1
                {
                    let plen = tcp.payload().len();
                    if plen > 0 {
                        rx_bytes += plen;
                        peer_seq = tcp.seq_number().0.wrapping_add(plen as i32);
                    }
                    if tcp.fin() {
                        peer_seq = peer_seq.wrapping_add(1);
                        break;
                    }
                }
            }
            assert!(
                rx_bytes > 0,
                "attempt #{idx} must receive server reply bytes"
            );

            // Client immediately aborts/closes (simulating Fake-TLS HMAC rejection).
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::Fin,
                    isn + 1 + hello.len() as i32,
                    Some(peer_seq),
                    &[],
                ))
                .await
                .unwrap();

            // Give flow_task a brief moment to record outcome in SniffOverrideGuard before next attempt.
            let settle_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while hub.active_connection_count() > 0 && tokio::time::Instant::now() < settle_deadline
            {
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let dialed = dialed_targets.lock().clone();
        assert_eq!(
            dialed,
            vec![
                "www.google.com:443",
                "www.google.com:443",
                "www.google.com:443",
                "194.221.250.50:443",
            ],
            "after 3 rapid short closes under override, 4th attempt must auto-bypass to raw IP dial"
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn tun_drops_empty_zero_byte_ipv4_and_ipv6_udp_probes_without_opening_outbound_sessions()
    {
        use std::sync::atomic::AtomicUsize;

        struct CountingUdpProxy {
            opened_sessions: Arc<AtomicUsize>,
            sent_targets: Arc<parking_lot::Mutex<Vec<String>>>,
            non_empty_tx: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<String>>>>,
        }

        struct CountingUdpSession {
            sent_targets: Arc<parking_lot::Mutex<Vec<String>>>,
            non_empty_tx: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<String>>>>,
        }

        #[async_trait::async_trait]
        impl crate::outbound::OutboundUdpSession for CountingUdpSession {
            async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
                let target_s = format!("{target}({}B)", data.len());
                self.sent_targets.lock().push(target_s.clone());
                if !data.is_empty()
                    && let Some(tx) = self.non_empty_tx.lock().take()
                {
                    let _ = tx.send(target_s);
                }
                Ok(())
            }

            async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
                std::future::pending().await
            }
        }

        #[async_trait::async_trait]
        impl crate::outbound::OutboundHandler for CountingUdpProxy {
            fn name(&self) -> &str {
                "MOCK-UDP-PROXY"
            }
            fn protocol(&self) -> &'static str {
                "MockProxy"
            }
            fn udp_supported(&self) -> bool {
                true
            }
            async fn connect_tcp(
                &self,
                _target: &TargetAddr,
            ) -> io::Result<crate::outbound::BoxedStream> {
                Err(io::Error::other("unused"))
            }
            async fn open_udp_session(
                &self,
            ) -> io::Result<Box<dyn crate::outbound::OutboundUdpSession>> {
                self.opened_sessions.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(CountingUdpSession {
                    sent_targets: Arc::clone(&self.sent_targets),
                    non_empty_tx: Arc::clone(&self.non_empty_tx),
                }))
            }
        }

        let opened_sessions = Arc::new(AtomicUsize::new(0));
        let sent_targets = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (barrier_tx, barrier_rx) = tokio::sync::oneshot::channel();
        let proxy = Arc::new(CountingUdpProxy {
            opened_sessions: Arc::clone(&opened_sessions),
            sent_targets: Arc::clone(&sent_targets),
            non_empty_tx: Arc::new(parking_lot::Mutex::new(Some(barrier_tx))),
        });
        let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds.insert("MOCK-UDP-PROXY".to_string(), proxy);
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec!["MATCH,MOCK-UDP-PROXY".to_string()];
        let router = Arc::new(
            Router::new(crate::config::RunMode::Rule, outbounds, &[], &rules, dns).unwrap(),
        );
        let hub = Arc::new(TelemetryHub::new());
        let (sd_tx, sd_rx) = watch::channel(false);
        let (vtun, task) =
            spawn_userspace_tun(1500, Arc::new(RwLock::new(router)), Arc::clone(&hub), sd_rx);

        // 1. Send 0-byte IPv4 probe `8.8.8.8:65535` and 0-byte IPv6 probe `[2000::]:65535`.
        let empty_v4 = build_ipv4_udp_packet(
            Ipv4Addr::new(198, 18, 0, 1),
            49_001,
            Ipv4Addr::new(8, 8, 8, 8),
            65535,
            &[],
        )
        .unwrap();
        let empty_v6 = build_ipv6_udp_packet(
            "fdfe:dcba:9876::1".parse().unwrap(),
            49_002,
            "2000::".parse().unwrap(),
            65535,
            &[],
        )
        .unwrap();
        vtun.ingress_tx.send(empty_v4).await.unwrap();
        vtun.ingress_tx.send(empty_v6).await.unwrap();

        // 2. Send a real non-empty UDP datagram afterwards as a synchronization barrier.
        let real_v4 = build_ipv4_udp_packet(
            Ipv4Addr::new(198, 18, 0, 1),
            49_003,
            Ipv4Addr::new(1, 1, 1, 1),
            443,
            b"hello-udp",
        )
        .unwrap();
        vtun.ingress_tx.send(real_v4).await.unwrap();

        let got = tokio::time::timeout(Duration::from_secs(2), barrier_rx)
            .await
            .expect("non-empty UDP barrier packet must be forwarded")
            .unwrap();
        assert_eq!(got, "1.1.1.1:443(9B)");
        assert_eq!(
            opened_sessions.load(Ordering::SeqCst),
            1,
            "0-byte IPv4/IPv6 UDP probes must be dropped without opening outbound UDP sessions"
        );
        assert_eq!(*sent_targets.lock(), vec!["1.1.1.1:443(9B)".to_string()]);
        assert_eq!(hub.total_connections(), 1);

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tun_fast_rejects_unreachable_direct_ipv6_quic_initial_while_proxying_proxy_sni() {
        use std::sync::atomic::AtomicUsize;

        struct RecordingUdpSession {
            sent_targets: Arc<parking_lot::Mutex<Vec<String>>>,
            notify_tx: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<String>>>>,
        }

        #[async_trait::async_trait]
        impl crate::outbound::OutboundUdpSession for RecordingUdpSession {
            async fn send_to(&self, _payload: &[u8], target: &TargetAddr) -> io::Result<()> {
                let entry = target.to_string();
                self.sent_targets.lock().push(entry.clone());
                if let Some(tx) = self.notify_tx.lock().take() {
                    let _ = tx.send(entry);
                }
                Ok(())
            }
            async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
                std::future::pending().await
            }
        }

        struct RecordingUdpProxy {
            opened_sessions: Arc<AtomicUsize>,
            sent_targets: Arc<parking_lot::Mutex<Vec<String>>>,
            notify_tx: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<String>>>>,
        }

        #[async_trait::async_trait]
        impl crate::outbound::OutboundHandler for RecordingUdpProxy {
            fn name(&self) -> &str {
                "MOCK-PROXY"
            }
            fn protocol(&self) -> &'static str {
                "MockProxy"
            }
            fn udp_supported(&self) -> bool {
                true
            }
            async fn connect_tcp(
                &self,
                _target: &TargetAddr,
            ) -> io::Result<crate::outbound::BoxedStream> {
                Err(io::Error::other("unused"))
            }
            async fn open_udp_session(
                &self,
            ) -> io::Result<Box<dyn crate::outbound::OutboundUdpSession>> {
                self.opened_sessions.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(RecordingUdpSession {
                    sent_targets: Arc::clone(&self.sent_targets),
                    notify_tx: Arc::clone(&self.notify_tx),
                }))
            }
        }

        let _ipv6_guard = crate::platform::socket_protect::lock_ipv6_reachability_for_test();
        crate::platform::socket_protect::set_os_underlying_ipv6_available(Some(false));

        let opened_sessions = Arc::new(AtomicUsize::new(0));
        let sent_targets = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (proxy_tx, proxy_rx) = tokio::sync::oneshot::channel();
        let proxy = Arc::new(RecordingUdpProxy {
            opened_sessions: Arc::clone(&opened_sessions),
            sent_targets: Arc::clone(&sent_targets),
            notify_tx: Arc::new(parking_lot::Mutex::new(Some(proxy_tx))),
        });

        let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds.insert("MOCK-PROXY".to_string(), proxy);
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec![
            "DOMAIN-SUFFIX,weixin.qq.com,DIRECT".to_string(),
            "DOMAIN-SUFFIX,google.com,MOCK-PROXY".to_string(),
            "IP-CIDR6,2409::/16,DIRECT,no-resolve".to_string(),
            "MATCH,MOCK-PROXY".to_string(),
        ];
        let router = Arc::new(
            Router::new(crate::config::RunMode::Rule, outbounds, &[], &rules, dns).unwrap(),
        );
        let hub = Arc::new(TelemetryHub::new());
        let (sd_tx, sd_rx) = watch::channel(false);
        let (mut vtun, task) =
            spawn_userspace_tun(1500, Arc::new(RwLock::new(router)), Arc::clone(&hub), sd_rx);

        let client_v6: Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let cn_v6: Ipv6Addr = "2409:8c1e:75b0:1123::101".parse().unwrap();
        let non_cn_v6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        // 1. Real RFC 9001 QUIC Initial with domestic SNI (`shquic.weixin.qq.com -> DIRECT`) on
        //    both a CN IPv6 and a non-CN IPv6 MUST be fast-rejected via ICMPv6 PortUnreachable
        //    with ZERO failed connections (`os error 101`) instead of opening a doomed DIRECT session.
        let wechat_quic = crate::inbound::sniff::test_helpers::build_quic_initial_packet(
            crate::inbound::sniff::QUIC_VERSION_1,
            &dcid,
            "shquic.weixin.qq.com",
        );
        for (src_port, dst_v6) in [(54_001u16, cn_v6), (54_002u16, non_cn_v6)] {
            let pkt = build_ipv6_udp_packet(client_v6, src_port, dst_v6, 443, &wechat_quic)
                .expect("valid IPv6 QUIC packet");
            vtun.ingress_tx.send(pkt).await.unwrap();
            let icmp_pkt = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
                .await
                .expect("expected immediate ICMPv6 PortUnreachable for DIRECT IPv6 QUIC")
                .expect("egress packet");
            let ip6_icmp = Ipv6Packet::new_checked(&icmp_pkt).unwrap();
            assert_eq!(ip6_icmp.dst_addr(), client_v6);
            assert_eq!(ip6_icmp.next_header(), IpProtocol::Icmpv6);
            let icmp6 = Icmpv6Packet::new_checked(ip6_icmp.payload()).unwrap();
            assert_eq!(
                icmp6.msg_type(),
                smoltcp::wire::Icmpv6Message::DstUnreachable
            );
            assert_eq!(
                Icmpv6DstUnreachable::from(icmp6.msg_code()),
                Icmpv6DstUnreachable::PortUnreachable
            );
        }
        assert_eq!(hub.failed_connections_total(), 0);
        assert_eq!(hub.total_connections(), 0);

        // 2. Real RFC 9001 QUIC Initial to the same CN IPv6 carrying a PROXY SNI (`www.google.com`)
        //    MUST NOT be fast-rejected and MUST forward through `MOCK-PROXY`.
        let google_quic = crate::inbound::sniff::test_helpers::build_quic_initial_packet(
            crate::inbound::sniff::QUIC_VERSION_1,
            &dcid,
            "www.google.com",
        );
        let pkt_proxy = build_ipv6_udp_packet(client_v6, 54_003, cn_v6, 443, &google_quic)
            .expect("valid IPv6 QUIC packet");
        vtun.ingress_tx.send(pkt_proxy).await.unwrap();

        let dialed = tokio::time::timeout(Duration::from_secs(2), proxy_rx)
            .await
            .expect("PROXY-routed IPv6 QUIC SNI must bypass fast-reject and reach MOCK-PROXY")
            .unwrap();
        assert_eq!(dialed, "www.google.com:443");
        assert_eq!(opened_sessions.load(Ordering::SeqCst), 1);
        assert_eq!(hub.failed_connections_total(), 0);

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn tun_real_ip_long_lived_probe_confirms_bypass_immediately_on_first_response_byte() {
        use std::sync::atomic::AtomicUsize;

        struct HoldOpenProbeProxy {
            dialed_targets: Arc<parking_lot::Mutex<Vec<String>>>,
            hold_open_raw_ip: Ipv4Addr,
            release_rx: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>,
        }

        #[async_trait::async_trait]
        impl crate::outbound::OutboundHandler for HoldOpenProbeProxy {
            fn name(&self) -> &str {
                "MOCK-PROXY"
            }
            fn protocol(&self) -> &'static str {
                "MockProxy"
            }
            async fn connect_tcp(
                &self,
                target: &TargetAddr,
            ) -> io::Result<crate::outbound::BoxedStream> {
                let label = target.to_string();
                self.dialed_targets.lock().push(label.clone());
                let (client_half, mut server_half) = tokio::io::duplex(16 * 1024);
                let is_raw = target.host.as_ip() == Some(IpAddr::V4(self.hold_open_raw_ip));
                let hold_rx = if is_raw {
                    self.release_rx.lock().take()
                } else {
                    None
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = server_half.read(&mut buf).await;
                    let _ = server_half.write_all(&[0x16u8; 2048]).await;
                    let _ = server_half.flush().await;
                    if let Some(rx) = hold_rx {
                        let _ = rx.await;
                    }
                    let _ = server_half.shutdown().await;
                });
                Ok(Box::new(client_half))
            }
        }

        let raw_ip = Ipv4Addr::new(194, 221, 250, 51);
        let dialed_targets = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let proxy = Arc::new(HoldOpenProbeProxy {
            dialed_targets: Arc::clone(&dialed_targets),
            hold_open_raw_ip: raw_ip,
            release_rx: Arc::new(parking_lot::Mutex::new(Some(release_rx))),
        });
        let mut outbounds: HashMap<String, crate::outbound::DynOutbound> = HashMap::new();
        outbounds.insert("MOCK-PROXY".to_string(), proxy);
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let rules = vec![
            "DOMAIN-SUFFIX,google.com,MOCK-PROXY".to_string(),
            "MATCH,MOCK-PROXY".to_string(),
        ];
        let router = Arc::new(
            Router::new(crate::config::RunMode::Rule, outbounds, &[], &rules, dns).unwrap(),
        );
        let hub = Arc::new(TelemetryHub::new());
        let (sd_tx, sd_rx) = watch::channel(false);
        let (mut vtun, task) = spawn_userspace_tun(
            1500,
            Arc::new(RwLock::new(Arc::clone(&router))),
            Arc::clone(&hub),
            sd_rx,
        );

        let hello = crate::inbound::sniff::test_helpers::build_tls_client_hello("www.google.com");
        let seq_counter = AtomicUsize::new(0);

        // 1. Trigger 3 rapid short closes under override so guard enters `ProbingRawIp`.
        for idx in 0..3u16 {
            let client = (Ipv4Addr::new(198, 18, 0, 56), 53_000 + idx);
            let dst = (raw_ip, 443u16);
            let isn = 20_000i32 + (seq_counter.fetch_add(1, Ordering::Relaxed) as i32) * 50_000;
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::Syn,
                    isn,
                    None,
                    &[],
                ))
                .await
                .unwrap();
            let syn_ack = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let pkt = vtun.egress_rx.recv().await.unwrap();
                    if let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                        && let Ok(tcp) = TcpPacket::new_checked(ip4.payload())
                        && tcp.dst_port() == client.1
                        && tcp.syn()
                        && tcp.ack()
                    {
                        return tcp.seq_number().0;
                    }
                }
            })
            .await
            .expect("SYN-ACK");
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::None,
                    isn + 1,
                    Some(syn_ack.wrapping_add(1)),
                    &hello,
                ))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let pkt = vtun.egress_rx.recv().await.unwrap();
                    if let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                        && let Ok(tcp) = TcpPacket::new_checked(ip4.payload())
                        && tcp.dst_port() == client.1
                        && !tcp.payload().is_empty()
                    {
                        break;
                    }
                }
            })
            .await
            .expect("server reply");
            vtun.ingress_tx
                .send(build_ipv4_tcp_packet(
                    client,
                    dst,
                    smoltcp::wire::TcpControl::Rst,
                    isn + 1 + hello.len() as i32,
                    Some(syn_ack.wrapping_add(1)),
                    &[],
                ))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
        }

        // 2. Open the 4th connection (raw-IP probe) and KEEP IT OPEN (never send RST/FIN).
        let probe_client = (Ipv4Addr::new(198, 18, 0, 56), 53_100);
        let dst = (raw_ip, 443u16);
        let isn = 400_000i32;
        vtun.ingress_tx
            .send(build_ipv4_tcp_packet(
                probe_client,
                dst,
                smoltcp::wire::TcpControl::Syn,
                isn,
                None,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let pkt = vtun.egress_rx.recv().await.unwrap();
                if let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                    && let Ok(tcp) = TcpPacket::new_checked(ip4.payload())
                    && tcp.dst_port() == probe_client.1
                    && tcp.syn()
                    && tcp.ack()
                {
                    return tcp.seq_number().0;
                }
            }
        })
        .await
        .expect("probe SYN-ACK");
        vtun.ingress_tx
            .send(build_ipv4_tcp_packet(
                probe_client,
                dst,
                smoltcp::wire::TcpControl::None,
                isn + 1,
                Some(syn_ack.wrapping_add(1)),
                &hello,
            ))
            .await
            .unwrap();

        // Wait for the server's first response bytes while the probe stream stays OPEN.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let pkt = vtun.egress_rx.recv().await.unwrap();
                if let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                    && let Ok(tcp) = TcpPacket::new_checked(ip4.payload())
                    && tcp.dst_port() == probe_client.1
                    && !tcp.payload().is_empty()
                {
                    break;
                }
            }
        })
        .await
        .expect("probe response bytes");

        // Guard MUST already have confirmed `BypassActive` and emitted the success log BEFORE close!
        let confirmed_while_open = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let logs = hub.recent_logs();
                if logs.iter().any(|e| {
                    e.payload
                        .contains("Raw IP dial succeeded for 194.221.250.51:443")
                }) {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            confirmed_while_open,
            "long-lived raw-IP probe must confirm BypassActive immediately on first received byte before closing"
        );
        assert_eq!(
            dialed_targets.lock().last().map(String::as_str),
            Some("194.221.250.51:443")
        );

        let _ = release_tx.send(());
        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
}
