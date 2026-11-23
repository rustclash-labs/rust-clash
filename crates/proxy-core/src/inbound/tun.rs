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
        IpAddress, IpCidr, IpListenEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr,
        Ipv6Address, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket, UdpRepr,
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
        sniff::{MAX_SNIFF_BYTES, SniffOutcomeWithProto, SniffedProtocol, sniff_tcp_protocol},
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
    panic_recoveries: u64,
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

    fn poll_guarded(&mut self, stage: &str, now: SmolInstant, hub: &TelemetryHub) -> bool {
        self.run_guarded(stage, now, hub, |s| {
            let _ = s.iface.poll(now, &mut s.device, &mut s.sockets);
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
    has_backpressured_rx: bool,
    has_more_ready_rx: bool,
}

fn step_single_tun_flow(
    sock: &mut tcp::Socket<'static>,
    flow: &mut BridgeFlow,
    now: Instant,
    now_wall: u64,
) -> SingleFlowStep {
    // If outbound dial or REJECT rule failed, immediately emit TCP RST and reap!
    if flow.remote_failed.load(Ordering::Acquire) {
        sock.abort();
        return SingleFlowStep {
            finished: true,
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
            has_backpressured_rx,
            has_more_ready_rx,
        };
    }

    let finished = (flow.established && !sock.is_active())
        || sock.state() == tcp::State::Closed
        || sock.state() == tcp::State::TimeWait;

    SingleFlowStep {
        finished,
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
                                &mut s.device,
                                &mut s.sockets,
                                &mut s.flows,
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
                                                &mut s.device,
                                                &mut s.sockets,
                                                &mut s.flows,
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
                    if step.finished {
                        finished_keys.push(*tuple);
                    }
                }
            }

            if !stack.remove_finished_flows(finished_keys, now_smol(), &hub) {
                next_delay = None;
                continue;
            }

            // Flush any segments (SYN-ACK, PSH, FIN, or RST) queued above immediately!
            let ts_after = now_smol();
            if !stack.poll_guarded("iface.poll.post", ts_after, &hub) {
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
fn handle_ingress_packet(
    pkt: Vec<u8>,
    ipv6_enabled: &Arc<AtomicBool>,
    drop_self_pid: bool,
    shutting_down: &Arc<AtomicBool>,
    device: &mut VirtualIpDevice,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<FourTuple, BridgeFlow>,
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
                    {
                        let tuple = FourTuple {
                            src: SocketAddr::new(IpAddr::V4(src_v4), tcp_pkt.src_port()),
                            dst: SocketAddr::new(IpAddr::V4(dst_v4), tcp_pkt.dst_port()),
                        };
                        register_syn_flow(
                            tuple,
                            IpAddress::Ipv4(dst_v4),
                            drop_self_pid,
                            sockets,
                            flows,
                            wake_notify,
                            router,
                            hub,
                        );
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
            match ip6.next_header() {
                IpProtocol::Udp => {
                    let Ok(udp) = UdpPacket::new_checked(ip6.payload()) else {
                        return;
                    };
                    if !udp.verify_checksum(&IpAddress::Ipv6(src_v6), &IpAddress::Ipv6(dst_v6)) {
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
                        && should_fast_reject_unreachable_direct_ipv6(
                            src_addr,
                            dst_v6,
                            dst_port,
                            SocketTransport::Udp,
                            router,
                        )
                        && !(router
                            .read()
                            .sniffer()
                            .should_sniff_real_ip_udp(IpAddr::V6(dst_v6), dst_port)
                            && matches!(
                                crate::inbound::sniff::sniff_quic_initial_sni(udp.payload()),
                                crate::inbound::sniff::SniffOutcome::Domain(_)
                            ));
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
                    if let Ok(tcp_pkt) = TcpPacket::new_checked(ip6.payload())
                        && tcp_pkt.syn()
                        && !tcp_pkt.ack()
                    {
                        let src_addr = SocketAddr::new(IpAddr::V6(src_v6), tcp_pkt.src_port());
                        let dst_port = tcp_pkt.dst_port();
                        if !should_fast_reject_unreachable_direct_ipv6(
                            src_addr,
                            dst_v6,
                            dst_port,
                            SocketTransport::Tcp,
                            router,
                        ) {
                            let tuple = FourTuple {
                                src: src_addr,
                                dst: SocketAddr::new(IpAddr::V6(dst_v6), dst_port),
                            };
                            register_syn_flow(
                                tuple,
                                IpAddress::Ipv6(dst_v6),
                                drop_self_pid,
                                sockets,
                                flows,
                                wake_notify,
                                router,
                                hub,
                            );
                        }
                        // When `should_fast_reject_unreachable_direct_ipv6` is `true`, skip
                        // `register_syn_flow` and fall through to `device.rx_queue` so `smoltcp`
                        // `iface.poll()` immediately emits `TCP RST|ACK` with zero socket allocation
                        // and zero `TelemetryHub` failed-connection noise!
                    }
                }
                _ => {}
            }
        }
        _ => return,
    }

    if device.rx_queue.len() < TUN_DEVICE_RX_MAX_PACKETS {
        device.rx_queue.push_back(pkt);
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
        // 1. Port 53 (`any:53`) Fake-IP DNS Hijack across both IPv4 and IPv6 when `tun.dns_hijack` is active!
        if hijack_dns {
            const MAX_TUN_UDP_DNS_PAYLOAD: usize = 1232;
            if let Ok(dns_resp) = current_router.dns().handle_dns_packet(&payload).await {
                let wire_out = if dns_resp.len() > MAX_TUN_UDP_DNS_PAYLOAD {
                    if let Ok(qp) = crate::dns::wire::DnsQueryPacket::parse(&payload) {
                        crate::dns::wire::build_truncated_dns_header(&payload, &qp)
                    } else {
                        dns_resp
                    }
                } else {
                    dns_resp
                };
                if let Some(ip_pkt) = build_ip_udp_packet(dst, src, &wire_out) {
                    let _ = egress.send(ip_pkt).await;
                }
            }
            return;
        }

        // 2. Prevent any OS-level TUN routing loop caused by our own process's outbound sockets.
        if drop_self_pid && is_self_process_socket(SocketTransport::Udp, src) {
            tracing::debug!(
                %src,
                %dst,
                "Dropped self-originated UDP packet entering OS TUN to prevent routing loop"
            );
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
    wake_notify: &Arc<Notify>,
    router: &Arc<RwLock<Arc<Router>>>,
    hub: &Arc<TelemetryHub>,
) {
    if flows.contains_key(&tuple) {
        return;
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
        sockets.remove(evicted.handle);
    }
    if flows.len() >= MAX_TUN_TCP_FLOWS {
        if let Some(evict_tuple) = select_pressure_eviction_candidate(flows, now, now_wall)
            && let Some(evicted) = flows.remove(&evict_tuple)
        {
            evicted.task_abort.abort();
            let evicted_sock = sockets.get_mut::<tcp::Socket>(evicted.handle);
            evicted_sock.abort();
            sockets.remove(evicted.handle);
        } else {
            return;
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
        return;
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

        // Prevent any OS-level TUN routing loop caused by our own process's outbound TCP sockets.
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
        //   (defeating local poisoned-IP DNS without adding extra DNS lookups on DIRECT).
        let dial_target = if let Some((ref domain, proto)) = sniffed_real_ip {
            if decision.outbound.exit_category() == "PROXY"
                && sniffer_cfg.should_override_destination(proto, domain)
            {
                decision.target.clone()
            } else {
                raw_target.clone()
            }
        } else {
            decision.target.clone()
        };

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
                    remote_failed_task.store(true, Ordering::Release);
                    wake_task.notify_one();
                    return;
                }
                _ = bridge_closed_tx.closed() => {
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
                remote_failed_task.store(true, Ordering::Release);
                wake_task.notify_one();
            }
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
}
