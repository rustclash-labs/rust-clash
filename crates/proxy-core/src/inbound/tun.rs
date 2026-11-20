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
        sniff::{MAX_SNIFF_BYTES, SniffOutcome, sniff_client_hello_or_http_host},
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
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
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
    dial_timeout_notified: bool,
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
            && (now.duration_since(self.created_at) > OUTBOUND_CONNECT_TIMEOUT
                || now_wall_ms.saturating_sub(self.created_wall_ms)
                    > OUTBOUND_CONNECT_TIMEOUT.as_millis() as u64)
    }

    fn is_timed_out(&self, now: Instant, now_wall_ms: u64, send_queue_bytes: usize) -> bool {
        let syn_timed_out = !self.established
            && (now.duration_since(self.created_at) > TCP_SYN_HANDSHAKE_TIMEOUT
                || now_wall_ms.saturating_sub(self.created_wall_ms)
                    > TCP_SYN_HANDSHAKE_TIMEOUT.as_millis() as u64);
        let hard_dial_limit = OUTBOUND_CONNECT_TIMEOUT + OUTBOUND_CONNECT_HARD_REAP_GRACE;
        let dial_hard_timed_out = !self.remote_connected.load(Ordering::Acquire)
            && (now.duration_since(self.created_at) > hard_dial_limit
                || now_wall_ms.saturating_sub(self.created_wall_ms)
                    > hard_dial_limit.as_millis() as u64);
        let idle_timed_out = now.duration_since(self.last_active) > TCP_IDLE_TIMEOUT
            || now_wall_ms.saturating_sub(self.last_active_wall_ms)
                > TCP_IDLE_TIMEOUT.as_millis() as u64;
        let fin_age_exceeded = self
            .fin_started_at
            .is_some_and(|t| now.duration_since(t) > TCP_HALF_CLOSE_TIMEOUT)
            || self.fin_started_wall_ms.is_some_and(|w| {
                now_wall_ms.saturating_sub(w) > TCP_HALF_CLOSE_TIMEOUT.as_millis() as u64
            });
        let fin_idle_exceeded = now.duration_since(self.last_active) > TCP_HALF_CLOSE_TIMEOUT
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

/// Spawn the `smoltcp` userspace `any_ip` transparent TUN stack with:
/// - Event-driven `iface.poll_delay()` + `Notify` wakeups (0 Hz idle polling when inactive!)
/// - Bounded ingress/egress/per-flow channels and TCP window backpressure
/// - IPv4 & IPv6 `any:53` Fake-IP DNS hijack
/// - Stateful multi-datagram IPv4 & IPv6 UDP NAT (`UdpNatManager`) for QUIC/HTTP3/WebRTC
/// - TCP half-close, immediate `RST` on outbound/REJECT failure, and SYN/idle/linger timeouts
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
        let mut device = VirtualIpDevice {
            mtu: mtu.clamp(1280, 65535),
            rx_queue: VecDeque::with_capacity(512),
            tx_sender: egress_tx.clone(),
        };

        let mut iface_cfg = IfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
        iface_cfg.random_seed = rand::random();
        let boot = Instant::now();
        let now_smol = || SmolInstant::from_micros(boot.elapsed().as_micros() as i64);

        let gw_v4 = Ipv4Address::new(198, 18, 0, 1);
        let gw_v6 = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let mut iface = Interface::new(iface_cfg, &mut device, now_smol());
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(gw_v4), 0));
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(gw_v6), 0));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(gw_v4);
        let _ = iface.routes_mut().add_default_ipv6_route(gw_v6);

        let mut sockets = SocketSet::new(vec![]);
        let mut flows: HashMap<FourTuple, BridgeFlow> = HashMap::new();
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
                if device.tx_sender.is_closed() {
                    break;
                }
                if device.tx_sender.capacity() == 0 {
                    consecutive_zero_delays = 0;
                    tokio::select! {
                        biased;
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                        res = device.tx_sender.reserve() => {
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
                        handle_ingress_packet(
                            pkt,
                            &ipv6_enabled,
                            drop_self_pid,
                            &shutting_down,
                            &mut device,
                            &mut sockets,
                            &mut flows,
                            &egress_tx,
                            &udp_sem,
                            &udp_nat,
                            &wake_notify,
                            &router,
                            &hub,
                        );
                        for _ in 0..256 {
                            if *shutdown.borrow() || device.rx_queue.len() >= TUN_DEVICE_RX_MAX_PACKETS {
                                break;
                            }
                            match ingress_rx.try_recv() {
                                Ok(more) => handle_ingress_packet(
                                    more,
                                    &ipv6_enabled,
                                    drop_self_pid,
                                    &shutting_down,
                                    &mut device,
                                    &mut sockets,
                                    &mut flows,
                                    &egress_tx,
                                    &udp_sem,
                                    &udp_nat,
                                    &wake_notify,
                                    &router,
                                    &hub,
                                ),
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
            let _ = iface.poll(ts, &mut device, &mut sockets);

            let now = Instant::now();
            let now_wall = TelemetryHub::now_ms();
            let mut finished_keys = Vec::new();
            let mut has_backpressured_rx = false;
            let mut has_more_ready_rx = false;

            for (tuple, flow) in flows.iter_mut() {
                let sock = sockets.get_mut::<tcp::Socket>(flow.handle);

                // If outbound dial or REJECT rule failed, immediately emit TCP RST and reap!
                if flow.remote_failed.load(Ordering::Acquire) {
                    sock.abort();
                    finished_keys.push(*tuple);
                    continue;
                }

                if matches!(
                    sock.state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    flow.established = true;
                }

                // Read client bytes from smoltcp ONLY when `to_remote_tx` has bounded capacity,
                // preserving TCP receive-window backpressure inside `smoltcp`'s 64 KiB RX buffer!
                if sock.can_recv() {
                    if let Some(tx) = &flow.to_remote_tx {
                        let mut aborted = false;
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
                                    finished_keys.push(*tuple);
                                    aborted = true;
                                    break;
                                }
                            }
                        }
                        if aborted {
                            continue;
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
                if !sock.can_recv()
                    && flow.established
                    && !sock.may_recv()
                    && flow.to_remote_tx.is_some()
                {
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
                if flow.is_dial_timed_out(now, now_wall) && !flow.dial_timeout_notified {
                    flow.dial_timeout_notified = true;
                    flow.dial_timeout_notify.notify_one();
                }

                // Enforce SYN handshake timeout, hard dial backstop, half-close linger timeout,
                // and idle timeout using both monotonic `Instant` and wall-clock epoch ms
                // (for Android deep sleep).
                if flow.is_timed_out(now, now_wall, sock.send_queue()) {
                    flow.task_abort.abort();
                    sock.abort();
                    finished_keys.push(*tuple);
                    continue;
                }

                if (flow.established && !sock.is_active())
                    || sock.state() == tcp::State::Closed
                    || sock.state() == tcp::State::TimeWait
                {
                    finished_keys.push(*tuple);
                }
            }

            for k in finished_keys {
                if let Some(flow) = flows.remove(&k) {
                    if !flow.established {
                        flow.task_abort.abort();
                    }
                    sockets.remove(flow.handle);
                }
            }

            // Flush any segments (SYN-ACK, PSH, FIN, or RST) queued above immediately!
            let ts_after = now_smol();
            let _ = iface.poll(ts_after, &mut device, &mut sockets);

            // Compute exact event-driven next sleep deadline (`None` = 0 Hz pure idle wait!)
            next_delay = iface
                .poll_delay(ts_after, &sockets)
                .map(|d| Duration::from_micros(d.total_micros()));

            if !device.rx_queue.is_empty() || has_more_ready_rx {
                next_delay = Some(Duration::ZERO);
            } else {
                if has_backpressured_rx {
                    next_delay = fold_min_delay(next_delay, Duration::from_millis(5));
                }
                let check_now = Instant::now();
                let check_now_wall = TelemetryHub::now_ms();
                for flow in flows.values() {
                    if !flow.established || !flow.remote_connected.load(Ordering::Acquire) {
                        let limit = if !flow.established {
                            TCP_SYN_HANDSHAKE_TIMEOUT
                        } else if !flow.dial_timeout_notified {
                            OUTBOUND_CONNECT_TIMEOUT
                        } else {
                            OUTBOUND_CONNECT_TIMEOUT + OUTBOUND_CONNECT_HARD_REAP_GRACE
                        };
                        let rem_mono =
                            limit.saturating_sub(check_now.duration_since(flow.created_at));
                        let rem_wall = limit.saturating_sub(Duration::from_millis(
                            check_now_wall.saturating_sub(flow.created_wall_ms),
                        ));
                        next_delay = fold_min_delay(
                            next_delay,
                            rem_mono.min(rem_wall).max(Duration::from_millis(1)),
                        );
                    }
                    let rem_idle_mono =
                        TCP_IDLE_TIMEOUT.saturating_sub(check_now.duration_since(flow.last_active));
                    let rem_idle_wall = TCP_IDLE_TIMEOUT.saturating_sub(Duration::from_millis(
                        check_now_wall.saturating_sub(flow.last_active_wall_ms),
                    ));
                    next_delay = fold_min_delay(
                        next_delay,
                        rem_idle_mono
                            .min(rem_idle_wall)
                            .max(Duration::from_millis(1)),
                    );
                    if let Some(fin_t) = flow.fin_started_at {
                        let sock = sockets.get_mut::<tcp::Socket>(flow.handle);
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
                            let rem_fin = rem_fin_age.max(rem_fin_idle_mono.min(rem_fin_idle_wall));
                            next_delay =
                                fold_min_delay(next_delay, rem_fin.max(Duration::from_millis(1)));
                        }
                    }
                }
            }
        }

        shutting_down.store(true, Ordering::Release);
        udp_sem.close();
        for (_, flow) in flows.drain() {
            flow.task_abort.abort();
            sockets.remove(flow.handle);
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
                        let is_unmapped_fake = !hijack_dns
                            && router
                                .read()
                                .dns()
                                .is_unmapped_fake_ip(&TargetAddr::from(dst_sock));
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
                        // Unmapped Fake-IP UDP (non-hijacked): fall through to `device.rx_queue` so
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
                    let is_unmapped_fake = !hijack_dns
                        && router
                            .read()
                            .dns()
                            .is_unmapped_fake_ip(&TargetAddr::from(dst_sock));
                    if !is_unmapped_fake
                        && (hijack_dns
                            || !should_fast_reject_unreachable_direct_ipv6(
                                src_addr,
                                dst_v6,
                                dst_port,
                                SocketTransport::Udp,
                                router,
                            ))
                    {
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

        // 3. General non-53 UDP datagram stateful NAT session forwarding!
        let route_epoch = current_router.epoch();
        let raw_target = TargetAddr::from(dst);
        let decision = current_router
            .route_async_with_context(
                Some(src.ip()),
                Some(src),
                crate::platform::process::SocketTransport::Udp,
                &raw_target,
            )
            .await;
        if shutting_down_task.load(Ordering::Acquire) {
            return;
        }
        nat.send_datagram_with_epoch(
            src,
            raw_target,
            decision.restored_from_fake_ip,
            decision.target,
            &decision.rule_type,
            &decision.rule_payload,
            decision.chains,
            decision.outbound,
            payload,
            route_epoch,
        )
        .await;
        if shutting_down_task.load(Ordering::Acquire) {
            let _ = nat.shutdown();
        }
    });
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
        return;
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
    let now = Instant::now();
    let now_wall = TelemetryHub::now_ms();
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
        let mut prefetched_first_payload: Option<Vec<u8>> = None;
        let route_target = if current_router.dns().is_unmapped_fake_ip(&raw_target) {
            match recover_unmapped_fake_ip_tcp(
                tuple.dst,
                &current_router,
                &mut to_remote_rx,
                &bridge_closed_tx,
            )
            .await
            {
                UnmappedFakeIpRecovery::BridgeClosed => return,
                UnmappedFakeIpRecovery::Recovered { domain, payload } => {
                    prefetched_first_payload = Some(payload);
                    if !current_router.dns().is_unmapped_fake_ip(&raw_target) {
                        raw_target.clone()
                    } else {
                        TargetAddr::new_domain(domain, tuple.dst.port())
                            .unwrap_or_else(|_| raw_target.clone())
                    }
                }
                UnmappedFakeIpRecovery::Failed => raw_target.clone(),
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
        let conn_guard = hub_clone.register_connection_with_outbound_guard(
            "TUN(smoltcp)",
            "tcp",
            Some(tuple.src),
            &decision.target,
            decision.restored_from_fake_ip.map(|ip| ip.to_string()),
            &decision.rule_type,
            &decision.rule_payload,
            decision.chains.clone(),
            decision.outbound.as_ref(),
        );
        let conn_entry = Arc::clone(conn_guard.connection());
        hub_clone.push_log(
            "info",
            format!(
                "[TUN] {} -> {} (raw {}) [{}] via {} ({})",
                tuple.src,
                decision.target,
                tuple.dst,
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
                    decision.target,
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
                    decision.outbound.connect_tcp(&decision.target),
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

        let writer_fut = async move {
            let drain_and_shutdown = async {
                // If an initial payload was prefetched while recovering an unmapped Fake-IP,
                // flush it immediately; otherwise coalesce client-speaks-first payload for up
                // to 15ms for 0-RTT proxy framing before flushing pending proxy headers.
                let mut client_eof = false;
                if let Some(first_chunk) = prefetched_first_payload {
                    if write_payload_batch(&mut wr, &first_chunk, &mut to_remote_rx)
                        .await
                        .is_err()
                    {
                        return;
                    }
                } else {
                    match tokio::time::timeout(Duration::from_millis(15), to_remote_rx.recv()).await
                    {
                        Ok(Some(first_chunk)) => {
                            if write_payload_batch(&mut wr, &first_chunk, &mut to_remote_rx)
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
                        if write_payload_batch(&mut wr, &first_chunk, &mut to_remote_rx)
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
            dial_timeout_notified: false,
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

enum UnmappedFakeIpRecovery {
    Recovered { domain: String, payload: Vec<u8> },
    Failed,
    BridgeClosed,
}

async fn recover_unmapped_fake_ip_tcp(
    dst: SocketAddr,
    router: &Router,
    to_remote_rx: &mut mpsc::Receiver<Vec<u8>>,
    bridge_closed_tx: &watch::Sender<()>,
) -> UnmappedFakeIpRecovery {
    const UNMAPPED_SNIFF_TIMEOUT: Duration = Duration::from_millis(250);
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + UNMAPPED_SNIFF_TIMEOUT;

    loop {
        let chunk_res = tokio::select! {
            biased;
            _ = bridge_closed_tx.closed() => return UnmappedFakeIpRecovery::BridgeClosed,
            _ = tokio::time::sleep_until(deadline) => return UnmappedFakeIpRecovery::Failed,
            recv = to_remote_rx.recv() => recv,
        };
        let Some(chunk) = chunk_res else {
            return UnmappedFakeIpRecovery::Failed;
        };
        buf.extend_from_slice(&chunk);
        let sniff_window = &buf[..buf.len().min(MAX_SNIFF_BYTES)];
        match sniff_client_hello_or_http_host(sniff_window) {
            SniffOutcome::Domain(domain) => {
                let fake_v4 = match dst.ip() {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                };
                if let Some(v4) = fake_v4 {
                    let _ = router.dns().recover_unmapped_fake_ip(v4, &domain);
                }
                return UnmappedFakeIpRecovery::Recovered {
                    domain,
                    payload: buf,
                };
            }
            SniffOutcome::NoHostname => return UnmappedFakeIpRecovery::Failed,
            SniffOutcome::NeedMoreBytes => {
                if buf.len() >= MAX_SNIFF_BYTES {
                    return UnmappedFakeIpRecovery::Failed;
                }
            }
        }
    }
}

async fn write_payload_batch<W: AsyncWriteExt + Unpin>(
    wr: &mut W,
    first_chunk: &[u8],
    to_remote_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    wr.write_all(first_chunk).await?;
    while let Ok(more) = to_remote_rx.try_recv() {
        wr.write_all(&more).await?;
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
        fake_ip_net,
        tun_ipv4_cidr,
        tun_ipv6_cidr,
        bypass_ips,
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
            dial_timeout_notified: false,
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

        // Fresh established flow is not timed out.
        assert!(!flow.is_timed_out(mono_now, base_wall + 5_000, 0));

        // Monotonic clock froze at `mono_now`, but wall clock advanced 309s (> 120s TCP_IDLE_TIMEOUT).
        assert!(flow.is_timed_out(mono_now, base_wall + 309_000, 0));

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
        let flow = BridgeFlow {
            handle,
            // smoltcp completed local 3-way handshake (<1ms), while outbound dial is still pending.
            established: true,
            remote_connected: Arc::clone(&remote_connected),
            dial_timeout_notify: Arc::new(Notify::new()),
            dial_timeout_notified: false,
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
        assert!(!flow.is_dial_timed_out(mono_now, base_wall + 14_000));
        assert!(!flow.is_timed_out(mono_now, base_wall + 14_000, 0));

        // At 15.5s wall-clock (monotonic frozen during Android Doze/suspend), soft dial timeout
        // fires so `flow_task` records `outbound dial+handshake ... timed out after 15s`.
        assert!(flow.is_dial_timed_out(mono_now, base_wall + 15_500));
        assert!(!flow.is_timed_out(mono_now, base_wall + 15_500, 0));

        // At 18s wall-clock (> 15s + 2s grace), hard reap backstop also fires if still unconnected.
        assert!(flow.is_timed_out(mono_now, base_wall + 18_000, 0));

        // Once remote_connected flips true, neither dial timeout nor hard dial backstop triggers.
        remote_connected.store(true, Ordering::Release);
        assert!(!flow.is_dial_timed_out(mono_now, base_wall + 18_000));
        assert!(!flow.is_timed_out(mono_now, base_wall + 18_000, 0));
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
            dial_timeout_notified: false,
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

        let dst: SocketAddr = "198.18.9.77:80".parse().unwrap();
        match recover_unmapped_fake_ip_tcp(dst, &router, &mut rx, &closed_tx).await {
            UnmappedFakeIpRecovery::Recovered { domain, payload } => {
                assert_eq!(domain, "coalesced.example.com");
                assert_eq!(payload.len(), expected_len);
                assert_eq!(payload, big_req);
            }
            _ => panic!("expected Recovered outcome without truncating coalesced payload"),
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
}
