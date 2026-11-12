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
    task::JoinHandle,
};

use crate::{
    addr::{HostName, TargetAddr},
    inbound::udp_nat::UdpNatManager,
    router::Router,
    tracker::{TelemetryHub, TrackedStream},
};

pub const TUN_PACKET_QUEUE_CAPACITY: usize = 4096;
const TUN_DEVICE_RX_MAX_PACKETS: usize = 4096;
const TUN_FLOW_STREAM_CAPACITY: usize = 256;
const MAX_TUN_TCP_FLOWS: usize = 2048;
const MAX_TUN_UDP_INFLIGHT: usize = 512;
const MAX_TUN_UDP_SESSIONS: usize = 512;
const TCP_SYN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

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
    tx: mpsc::Sender<Vec<u8>>,
}

impl TxToken for ChannelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut pkt = vec![0u8; len];
        let res = f(&mut pkt);
        let _ = self.tx.try_send(pkt);
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
        if self.tx_sender.capacity() == 0 {
            return None;
        }
        let pkt = self.rx_queue.pop_front()?;
        Some((
            VecRxToken(pkt),
            ChannelTxToken {
                tx: self.tx_sender.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx_sender.capacity() == 0 {
            return None;
        }
        Some(ChannelTxToken {
            tx: self.tx_sender.clone(),
        })
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
    created_at: Instant,
    last_active: Instant,
    fin_started_at: Option<Instant>,
    pending_tx: BytesMut,
    from_remote_rx: mpsc::Receiver<Vec<u8>>,
    to_remote_tx: Option<mpsc::Sender<Vec<u8>>>,
    remote_eof: bool,
    remote_failed: Arc<AtomicBool>,
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
    mut shutdown: watch::Receiver<bool>,
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
        let wake_notify = Arc::new(Notify::new());

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

        loop {
            if next_delay == Some(Duration::ZERO) {
                tokio::task::yield_now().await;
            } else {
                tokio::select! {
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
                            if device.rx_queue.len() >= TUN_DEVICE_RX_MAX_PACKETS {
                                break;
                            }
                            match ingress_rx.try_recv() {
                                Ok(more) => handle_ingress_packet(
                                    more,
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
                // preserving TCP receive-window backpressure inside `smoltcp`'s 256 KiB RX buffer!
                if sock.can_recv() {
                    if let Some(tx) = &flow.to_remote_tx {
                        let mut aborted = false;
                        let mut drained_bytes = 0usize;
                        while sock.can_recv() && drained_bytes < 64 * 1024 {
                            match tx.try_reserve() {
                                Ok(permit) => {
                                    let mut chunk = Vec::with_capacity(32 * 1024);
                                    let _ = sock.recv(|data| {
                                        let take = data.len().min(64 * 1024 - drained_bytes);
                                        chunk.extend_from_slice(&data[..take]);
                                        (take, ())
                                    });
                                    if chunk.is_empty() {
                                        break;
                                    }
                                    drained_bytes += chunk.len();
                                    flow.last_active = now;
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
                    flow.fin_started_at.get_or_insert(now);
                }

                // Flush any buffered bytes from remote outbound -> smoltcp TX buffer
                if !flow.pending_tx.is_empty() && sock.can_send() {
                    let sent = sock.send_slice(&flow.pending_tx).unwrap_or(0);
                    if sent > 0 {
                        flow.last_active = now;
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
                                sock.close();
                            }
                            break;
                        }
                    }
                }

                // Enforce SYN handshake timeout, half-close linger timeout, and idle timeout
                let syn_timed_out = !flow.established
                    && now.duration_since(flow.created_at) > TCP_SYN_HANDSHAKE_TIMEOUT;
                let idle_timed_out = now.duration_since(flow.last_active) > TCP_IDLE_TIMEOUT;
                let fin_timed_out = flow
                    .fin_started_at
                    .is_some_and(|t| now.duration_since(t) > TCP_HALF_CLOSE_TIMEOUT)
                    && flow.pending_tx.is_empty();

                if syn_timed_out || idle_timed_out || fin_timed_out {
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
                for flow in flows.values() {
                    if !flow.established {
                        let rem = TCP_SYN_HANDSHAKE_TIMEOUT
                            .saturating_sub(check_now.duration_since(flow.created_at));
                        next_delay = fold_min_delay(next_delay, rem.max(Duration::from_millis(1)));
                    }
                    let rem_idle =
                        TCP_IDLE_TIMEOUT.saturating_sub(check_now.duration_since(flow.last_active));
                    next_delay = fold_min_delay(next_delay, rem_idle.max(Duration::from_millis(1)));
                    if let Some(fin_t) = flow.fin_started_at {
                        let rem_fin =
                            TCP_HALF_CLOSE_TIMEOUT.saturating_sub(check_now.duration_since(fin_t));
                        next_delay =
                            fold_min_delay(next_delay, rem_fin.max(Duration::from_millis(1)));
                    }
                }
            }
        }
    });

    (
        VirtualTunHandle {
            ingress_tx,
            egress_rx,
        },
        task,
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_ingress_packet(
    pkt: Vec<u8>,
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
            let src_v4: Ipv4Addr = ip4.src_addr();
            let dst_v4: Ipv4Addr = ip4.dst_addr();
            match ip4.next_header() {
                IpProtocol::Udp => {
                    if let Ok(udp) = UdpPacket::new_checked(ip4.payload()) {
                        let src_port = udp.src_port();
                        let dst_port = udp.dst_port();
                        let payload = udp.payload().to_vec();
                        spawn_tun_udp_handler(
                            SocketAddr::new(IpAddr::V4(src_v4), src_port),
                            SocketAddr::new(IpAddr::V4(dst_v4), dst_port),
                            payload,
                            egress_tx,
                            udp_sem,
                            udp_nat,
                            router,
                        );
                    }
                    return;
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
            let Ok(ip6) = Ipv6Packet::new_checked(&pkt) else {
                return;
            };
            let src_v6: Ipv6Addr = ip6.src_addr();
            let dst_v6: Ipv6Addr = ip6.dst_addr();
            match ip6.next_header() {
                IpProtocol::Udp => {
                    if let Ok(udp) = UdpPacket::new_checked(ip6.payload()) {
                        let src_port = udp.src_port();
                        let dst_port = udp.dst_port();
                        let payload = udp.payload().to_vec();
                        spawn_tun_udp_handler(
                            SocketAddr::new(IpAddr::V6(src_v6), src_port),
                            SocketAddr::new(IpAddr::V6(dst_v6), dst_port),
                            payload,
                            egress_tx,
                            udp_sem,
                            udp_nat,
                            router,
                        );
                    }
                    return;
                }
                IpProtocol::Tcp => {
                    if let Ok(tcp_pkt) = TcpPacket::new_checked(ip6.payload())
                        && tcp_pkt.syn()
                        && !tcp_pkt.ack()
                    {
                        let tuple = FourTuple {
                            src: SocketAddr::new(IpAddr::V6(src_v6), tcp_pkt.src_port()),
                            dst: SocketAddr::new(IpAddr::V6(dst_v6), tcp_pkt.dst_port()),
                        };
                        register_syn_flow(
                            tuple,
                            IpAddress::Ipv6(dst_v6),
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
        _ => return,
    }

    if device.rx_queue.len() < TUN_DEVICE_RX_MAX_PACKETS {
        device.rx_queue.push_back(pkt);
    }
}

fn spawn_tun_udp_handler(
    src: SocketAddr,
    dst: SocketAddr,
    payload: Vec<u8>,
    egress_tx: &mpsc::Sender<Vec<u8>>,
    udp_sem: &Arc<Semaphore>,
    udp_nat: &Arc<UdpNatManager>,
    router: &Arc<RwLock<Arc<Router>>>,
) {
    let Ok(permit) = Arc::clone(udp_sem).try_acquire_owned() else {
        return;
    };
    let current_router = Arc::clone(&router.read());
    let egress = egress_tx.clone();
    let nat = Arc::clone(udp_nat);

    tokio::spawn(async move {
        let _permit = permit;
        // 1. Port 53 (`any:53`) Fake-IP DNS Hijack across both IPv4 and IPv6!
        if dst.port() == 53 {
            if let Ok(dns_resp) = current_router.dns().handle_dns_packet(&payload).await
                && let Some(ip_pkt) = build_ip_udp_packet(dst, src, &dns_resp)
            {
                let _ = egress.send(ip_pkt).await;
            }
            return;
        }

        // 2. General non-53 UDP datagram stateful NAT session forwarding!
        let raw_target = TargetAddr::from(dst);
        let decision = current_router
            .route_async_with_context(
                Some(src.ip()),
                Some(src),
                crate::platform::process::SocketTransport::Udp,
                &raw_target,
            )
            .await;
        nat.send_datagram(
            src,
            raw_target,
            decision.restored_from_fake_ip,
            decision.target,
            &decision.rule_type,
            &decision.rule_payload,
            decision.chains,
            decision.outbound,
            payload,
        )
        .await;
    });
}

fn register_syn_flow(
    tuple: FourTuple,
    listen_ip: IpAddress,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<FourTuple, BridgeFlow>,
    wake_notify: &Arc<Notify>,
    router: &Arc<RwLock<Arc<Router>>>,
    hub: &Arc<TelemetryHub>,
) {
    if flows.contains_key(&tuple) || flows.len() >= MAX_TUN_TCP_FLOWS {
        return;
    }
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; 256 * 1024]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; 256 * 1024]);
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
    let remote_failed = Arc::new(AtomicBool::new(false));
    let remote_failed_task = Arc::clone(&remote_failed);
    let wake_task = Arc::clone(wake_notify);
    let now = Instant::now();

    flows.insert(
        tuple,
        BridgeFlow {
            handle,
            established: false,
            created_at: now,
            last_active: now,
            fin_started_at: None,
            pending_tx: BytesMut::new(),
            from_remote_rx,
            to_remote_tx: Some(to_remote_tx),
            remote_eof: false,
            remote_failed,
        },
    );

    let current_router = Arc::clone(&router.read());
    let hub_clone = Arc::clone(hub);
    tokio::spawn(async move {
        // Port 53 (`any:53`) Fake-IP DNS-over-TCP Hijack (RFC 1035 / RFC 7766 2-byte length prefix).
        // Prevents Android/OS virtual VPN DNS (`198.18.0.2:53`) TCP fallback queries from hitting
        // `UNMAPPED-FAKE-IP` when UDP DNS responses are truncated (`TC=1`) or retried over TCP.
        if tuple.dst.port() == 53 {
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
        let decision = current_router
            .route_async_with_context(
                Some(tuple.src.ip()),
                Some(tuple.src),
                crate::platform::process::SocketTransport::Tcp,
                &raw_target,
            )
            .await;
        let conn_entry = hub_clone.register_connection_with_outbound(
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

        let outbound = match decision.outbound.connect_tcp(&decision.target).await {
            Ok(s) => s,
            Err(err) => {
                tracing::debug!(
                    "[TUN] outbound connect failed for {} -> {}: {}",
                    tuple.src,
                    decision.target,
                    err
                );
                remote_failed_task.store(true, Ordering::Release);
                wake_task.notify_one();
                hub_clone.record_connection_failed(&conn_entry.id, &err.to_string());
                return;
            }
        };
        conn_entry.mark_established();

        let tracked = TrackedStream::new(outbound, Arc::clone(&hub_clone), Arc::clone(&conn_entry));
        let (mut rd, mut wr) = tokio::io::split(tracked);

        let writer_fut = async move {
            while let Some(first_chunk) = to_remote_rx.recv().await {
                if wr.write_all(&first_chunk).await.is_err() {
                    break;
                }
                let mut write_failed = false;
                while let Ok(more) = to_remote_rx.try_recv() {
                    if wr.write_all(&more).await.is_err() {
                        write_failed = true;
                        break;
                    }
                }
                if write_failed || wr.flush().await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        };

        let wake_rd = Arc::clone(&wake_task);
        let reader_fut = async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if from_remote_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                        wake_rd.notify_one();
                    }
                }
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
