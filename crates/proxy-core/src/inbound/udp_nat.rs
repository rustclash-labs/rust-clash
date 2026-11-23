use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, watch};

use crate::{
    addr::{HostName, TargetAddr},
    outbound::DynOutbound,
    tracker::{ActiveConnection, SessionResetter, TelemetryHub},
};

const UDP_SESSION_QUEUE_CAPACITY: usize = 256;
const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const ONE_SHOT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(12);
const NTP_PORT: u16 = 123;
const MAX_UDP_DESTS_PER_SESSION: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
enum PortFakeMapping {
    Unique(TargetAddr),
    Ambiguous,
}

#[derive(Default)]
struct ReverseTargetMap {
    fake_ip_pinned_v4: Option<Ipv4Addr>,
    target_to_raw: HashMap<TargetAddr, TargetAddr>,
    port_to_fake_raw: HashMap<u16, PortFakeMapping>,
    raw_ip_ports: HashSet<u16>,
    last_raw_dst: Option<TargetAddr>,
}

impl ReverseTargetMap {
    fn with_fake_ip_pin(fake_ip_pinned_v4: Option<Ipv4Addr>) -> Self {
        Self {
            fake_ip_pinned_v4,
            ..Self::default()
        }
    }

    fn has_outbound(&self, target: &TargetAddr, raw_dst: &TargetAddr, was_fake_ip: bool) -> bool {
        if self.target_to_raw.get(target) != Some(raw_dst) {
            return false;
        }
        if was_fake_ip || matches!(target.host, HostName::Domain(_)) {
            if self.last_raw_dst.as_ref() != Some(raw_dst) {
                return false;
            }
            match self.port_to_fake_raw.get(&target.port) {
                Some(PortFakeMapping::Unique(existing)) => existing == raw_dst,
                Some(PortFakeMapping::Ambiguous) => true,
                None => false,
            }
        } else {
            self.raw_ip_ports.contains(&target.port)
                || self.raw_ip_ports.len() >= MAX_UDP_DESTS_PER_SESSION
        }
    }

    fn record_outbound(&mut self, target: &TargetAddr, raw_dst: &TargetAddr, was_fake_ip: bool) {
        if self.target_to_raw.contains_key(target)
            || self.target_to_raw.len() < MAX_UDP_DESTS_PER_SESSION
        {
            self.target_to_raw.insert(target.clone(), raw_dst.clone());
        }
        if was_fake_ip || matches!(target.host, HostName::Domain(_)) {
            let collides_with_raw_ip = self.raw_ip_ports.contains(&target.port);
            if let Some(mapping) = self.port_to_fake_raw.get_mut(&target.port) {
                if let PortFakeMapping::Unique(existing) = mapping
                    && (existing != raw_dst || collides_with_raw_ip)
                {
                    *mapping = PortFakeMapping::Ambiguous;
                }
            } else if self.port_to_fake_raw.len() < MAX_UDP_DESTS_PER_SESSION {
                let entry = if collides_with_raw_ip {
                    PortFakeMapping::Ambiguous
                } else {
                    PortFakeMapping::Unique(raw_dst.clone())
                };
                self.port_to_fake_raw.insert(target.port, entry);
            }
            self.last_raw_dst = Some(raw_dst.clone());
        } else {
            if self.raw_ip_ports.contains(&target.port)
                || self.raw_ip_ports.len() < MAX_UDP_DESTS_PER_SESSION
            {
                self.raw_ip_ports.insert(target.port);
            }
            if let Some(mapping) = self.port_to_fake_raw.get_mut(&target.port)
                && let PortFakeMapping::Unique(existing) = mapping
                && existing != raw_dst
            {
                *mapping = PortFakeMapping::Ambiguous;
            }
        }
    }

    fn map_return_source(&self, remote_src: &TargetAddr) -> TargetAddr {
        if let Some(raw) = self.target_to_raw.get(remote_src) {
            return raw.clone();
        }
        if let Some(pinned_v4) = self.fake_ip_pinned_v4 {
            let port = if remote_src.port != 0 {
                remote_src.port
            } else {
                self.last_raw_dst.as_ref().map(|d| d.port).unwrap_or(0)
            };
            return TargetAddr::from(SocketAddr::new(IpAddr::V4(pinned_v4), port));
        }
        match self.port_to_fake_raw.get(&remote_src.port) {
            Some(PortFakeMapping::Unique(fake_raw)) => return fake_raw.clone(),
            Some(PortFakeMapping::Ambiguous) => return remote_src.clone(),
            None => {}
        }
        if matches!(remote_src.host, HostName::Ip(_)) {
            return remote_src.clone();
        }
        self.last_raw_dst
            .clone()
            .unwrap_or_else(|| remote_src.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct NatSessionKey {
    client_src: SocketAddr,
    outbound_name: String,
    fake_ip_scope: Option<Ipv4Addr>,
}

#[derive(Clone, Debug)]
struct CachedUdpRoute {
    outbound_name: String,
    fake_ip_scope: Option<Ipv4Addr>,
    resolved_target: TargetAddr,
    was_fake_ip: bool,
    router_epoch: u64,
}

struct NatSessionEntry {
    tx: mpsc::Sender<(TargetAddr, Vec<u8>)>,
    reverse_map: Arc<RwLock<ReverseTargetMap>>,
    conn_entry: Arc<ActiveConnection>,
    last_active_ms: Arc<AtomicU64>,
    last_active_wall_ms: Arc<AtomicU64>,
    idle_timeout_ms: Arc<AtomicU64>,
}

/// Callback invoked whenever an `OutboundUdpSession` yields a response datagram back toward the client.
/// Parameters: `(client_src, effective_return_target, payload)`.
pub type UdpReplySink = Arc<dyn Fn(SocketAddr, TargetAddr, Vec<u8>) + Send + Sync>;

fn cleanup_weak_session_maps(
    sessions_weak: &Weak<DashMap<NatSessionKey, NatSessionEntry>>,
    fast_routes_weak: &Weak<DashMap<(SocketAddr, SocketAddr), CachedUdpRoute>>,
    key: &NatSessionKey,
    conn_entry: &Arc<ActiveConnection>,
) {
    if let Some(sessions_map) = sessions_weak.upgrade()
        && sessions_map
            .remove_if(key, |_, v| Arc::ptr_eq(&v.conn_entry, conn_entry))
            .is_some()
        && let Some(fast_routes_map) = fast_routes_weak.upgrade()
    {
        fast_routes_map.retain(|rk, rv| {
            !(rk.0 == key.client_src
                && rv.outbound_name == key.outbound_name
                && rv.fake_ip_scope == key.fake_ip_scope)
        });
    }
}

async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow_and_update() {
        return;
    }
    let _ = rx.changed().await;
}

/// Outcome of routing an initial UDP datagram with optional QUIC Initial SNI sniffing.
pub struct ResolvedUdpRoute {
    pub decision: crate::router::RouteDecision,
    pub dial_target: TargetAddr,
    pub sniffed: bool,
}

/// Route a UDP datagram via `router`, applying RFC 9001/9369 QUIC Initial SNI sniffing on:
/// 1. Unmapped Fake-IP destinations (recovering the Fake-IP mapping when SNI is present), and
/// 2. Real IP destinations matching `SnifferConfig::should_sniff_real_ip_udp(ip, port)`.
///
/// When a real-IP destination is sniffed, the recovered domain participates in rule matching and
/// connection telemetry (`sniffed = true`), and overrides `dial_target` ONLY when the matched
/// outbound is `PROXY` and `SnifferConfig::should_override_destination(Quic, domain)` allows it
/// (`DIRECT` and `skip-domain` preserve the raw destination IP).
pub async fn route_udp_datagram_with_quic_sniff(
    router: &crate::router::Router,
    client_src: SocketAddr,
    raw_dst: &TargetAddr,
    payload: &[u8],
) -> ResolvedUdpRoute {
    use crate::inbound::sniff::{SniffOutcome, SniffedProtocol, sniff_quic_initial_sni};

    let sniffer_cfg = router.sniffer();
    let mut sniffed_real_ip: Option<String> = None;

    let route_target = if let Some(dst_ip) = raw_dst.host.as_ip() {
        let is_unmapped_fake = router.dns().is_unmapped_fake_ip(raw_dst);
        let is_fake = router.dns().is_fake_ip(dst_ip);
        if is_unmapped_fake {
            match sniff_quic_initial_sni(payload) {
                SniffOutcome::Domain(domain) => {
                    let fake_v4 = match dst_ip {
                        IpAddr::V4(v4) => Some(v4),
                        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                    };
                    if let Some(v4) = fake_v4 {
                        let _ = router.dns().recover_unmapped_fake_ip(v4, &domain);
                    }
                    if !router.dns().is_unmapped_fake_ip(raw_dst) {
                        raw_dst.clone()
                    } else {
                        TargetAddr::new_domain(domain, raw_dst.port)
                            .unwrap_or_else(|_| raw_dst.clone())
                    }
                }
                SniffOutcome::NeedMoreBytes | SniffOutcome::NoHostname => raw_dst.clone(),
            }
        } else if !is_fake && sniffer_cfg.should_sniff_real_ip_udp(dst_ip, raw_dst.port) {
            match sniff_quic_initial_sni(payload) {
                SniffOutcome::Domain(domain) => {
                    let target = TargetAddr::new_domain(domain.clone(), raw_dst.port)
                        .unwrap_or_else(|_| raw_dst.clone());
                    sniffed_real_ip = Some(domain);
                    target
                }
                SniffOutcome::NeedMoreBytes | SniffOutcome::NoHostname => raw_dst.clone(),
            }
        } else {
            raw_dst.clone()
        }
    } else {
        raw_dst.clone()
    };

    let decision = router
        .route_async_with_context(
            Some(client_src.ip()),
            Some(client_src),
            crate::platform::process::SocketTransport::Udp,
            &route_target,
        )
        .await;

    let dial_target = if let Some(ref domain) = sniffed_real_ip {
        if decision.outbound.exit_category() == "PROXY"
            && sniffer_cfg.should_override_destination(SniffedProtocol::Quic, domain)
        {
            decision.target.clone()
        } else {
            raw_dst.clone()
        }
    } else {
        decision.target.clone()
    };

    ResolvedUdpRoute {
        decision,
        dial_target,
        sniffed: sniffed_real_ip.is_some(),
    }
}

/// Stateful multi-datagram UDP NAT manager shared by TUN and SOCKS5 `UDP ASSOCIATE`.
/// Maintains persistent `OutboundUdpSession`s per `(client_src, outbound)` (and per Fake-IP on proxy
/// outbounds) so QUIC/HTTP3, gaming, and STUN/WebRTC flows preserve NAT port bindings and return addresses.
pub struct UdpNatManager {
    inbound_label: &'static str,
    max_sessions: usize,
    idle_timeout: Duration,
    boot: Instant,
    closed: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    evict_lock: Mutex<()>,
    fast_route_evict_lock: Mutex<u64>,
    sessions: Arc<DashMap<NatSessionKey, NatSessionEntry>>,
    fast_routes: Arc<DashMap<(SocketAddr, SocketAddr), CachedUdpRoute>>,
    hub: Arc<TelemetryHub>,
    reply_sink: UdpReplySink,
}

impl Drop for UdpNatManager {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl SessionResetter for UdpNatManager {
    fn reset_sessions(&self) -> usize {
        self.reset_all_sessions()
    }

    fn reap_idle_sessions(&self) -> usize {
        UdpNatManager::reap_idle_sessions(self)
    }
}

impl UdpNatManager {
    pub fn new(
        inbound_label: &'static str,
        max_sessions: usize,
        hub: Arc<TelemetryHub>,
        reply_sink: UdpReplySink,
    ) -> Arc<Self> {
        Self::with_idle_timeout(
            inbound_label,
            max_sessions,
            DEFAULT_UDP_IDLE_TIMEOUT,
            hub,
            reply_sink,
        )
    }

    pub fn with_idle_timeout(
        inbound_label: &'static str,
        max_sessions: usize,
        idle_timeout: Duration,
        hub: Arc<TelemetryHub>,
        reply_sink: UdpReplySink,
    ) -> Arc<Self> {
        let (shutdown_tx, _) = watch::channel(false);
        let mgr = Arc::new(Self {
            inbound_label,
            max_sessions: max_sessions.max(16),
            idle_timeout,
            boot: Instant::now(),
            closed: AtomicBool::new(false),
            shutdown_tx,
            evict_lock: Mutex::new(()),
            fast_route_evict_lock: Mutex::new(0),
            sessions: Arc::new(DashMap::new()),
            fast_routes: Arc::new(DashMap::new()),
            hub: Arc::clone(&hub),
            reply_sink,
        });
        let weak: Weak<dyn SessionResetter> = Arc::downgrade(&mgr) as Weak<dyn SessionResetter>;
        hub.register_session_resetter(weak);
        mgr
    }

    fn session_idle_timeout(&self, dst_port: u16) -> Duration {
        if self.idle_timeout == DEFAULT_UDP_IDLE_TIMEOUT && dst_port == NTP_PORT {
            ONE_SHOT_UDP_IDLE_TIMEOUT
        } else {
            self.idle_timeout
        }
    }

    fn now_ms(&self) -> u64 {
        self.boot.elapsed().as_millis() as u64
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Permanently shut down this `UdpNatManager`, rejecting any late-arriving datagrams and
    /// immediately terminating all active per-session tasks, sockets, and `TelemetryHub` entries.
    pub fn shutdown(&self) -> usize {
        self.closed.store(true, Ordering::Release);
        let _ = self.shutdown_tx.send(true);
        self.reset_all_sessions()
    }

    /// Synchronously evict and close every cached UDP NAT session (e.g. on Wi-Fi <-> Cellular handoff).
    pub fn reset_all_sessions(&self) -> usize {
        self.fast_routes.clear();
        let keys: Vec<NatSessionKey> = self.sessions.iter().map(|e| e.key().clone()).collect();
        let mut count = 0;
        for key in keys {
            if let Some((_, entry)) = self.sessions.remove(&key) {
                entry.conn_entry.request_close();
                self.hub.unregister_connection(&entry.conn_entry.id);
                drop(entry.tx);
                count += 1;
            }
        }
        count
    }

    /// Reap sessions whose monotonic or wall-clock idle age has reached or exceeded
    /// `idle_timeout_ms` (e.g. across Android/Linux deep sleep where `CLOCK_MONOTONIC` freezes).
    pub fn reap_idle_sessions(&self) -> usize {
        let now_wall = TelemetryHub::now_ms();
        let now_mono = self.now_ms();
        let mut evicted: Vec<(NatSessionKey, Arc<ActiveConnection>)> = Vec::new();
        self.sessions.retain(|key, entry| {
            let timeout_ms = entry.idle_timeout_ms.load(Ordering::Relaxed);
            let mono_idle = now_mono.saturating_sub(entry.last_active_ms.load(Ordering::Relaxed));
            let wall_idle =
                now_wall.saturating_sub(entry.last_active_wall_ms.load(Ordering::Relaxed));
            let keep = !entry.tx.is_closed()
                && !entry.conn_entry.is_closed()
                && mono_idle < timeout_ms
                && wall_idle < timeout_ms;
            if !keep {
                evicted.push((key.clone(), Arc::clone(&entry.conn_entry)));
            }
            keep
        });
        if evicted.is_empty() {
            return 0;
        }
        for (ek, conn_entry) in &evicted {
            self.fast_routes.retain(|rk, rv| {
                !(rk.0 == ek.client_src
                    && rv.outbound_name == ek.outbound_name
                    && rv.fake_ip_scope == ek.fake_ip_scope)
            });
            conn_entry.request_close();
            self.hub.unregister_connection(&conn_entry.id);
        }
        evicted.len()
    }

    #[allow(clippy::too_many_arguments)]
    fn cache_fast_route(
        &self,
        client_src: SocketAddr,
        raw_dst: &TargetAddr,
        outbound_name: &str,
        fake_ip_scope: Option<Ipv4Addr>,
        resolved_target: &TargetAddr,
        was_fake_ip: bool,
        router_epoch: u64,
    ) {
        if router_epoch == 0 {
            return;
        }
        let HostName::Ip(dst_ip) = raw_dst.host else {
            return;
        };
        let cap = self.max_sessions.saturating_mul(4);
        if cap == 0 {
            return;
        }
        let route_key = (client_src, SocketAddr::new(dst_ip, raw_dst.port));
        let cached = CachedUdpRoute {
            outbound_name: outbound_name.to_string(),
            fake_ip_scope,
            resolved_target: resolved_target.clone(),
            was_fake_ip,
            router_epoch,
        };

        // Fast path: updating an existing same-epoch cached route in place never grows
        // `fast_routes` and avoids eviction-lock contention on hot flows.
        if let Some(mut existing) = self.fast_routes.get_mut(&route_key)
            && existing.router_epoch == router_epoch
        {
            *existing = cached;
            return;
        }

        // Serialize new-key admission and capacity eviction under `fast_route_evict_lock`
        // (never acquired while holding any DashMap guard and never held across `.await`)
        // so concurrent threads cannot race on the same victim and overflow `cap`.
        // The mutex stores `single_epoch`: non-zero `E` means every entry currently in
        // `fast_routes` has `router_epoch == E`; `0` means empty or potentially mixed epochs.
        let mut single_epoch = self.fast_route_evict_lock.lock();
        if self.fast_routes.is_empty() {
            *single_epoch = router_epoch;
        }
        if self.fast_routes.len() >= cap && !self.fast_routes.contains_key(&route_key) {
            if *single_epoch != router_epoch {
                self.fast_routes
                    .retain(|_, v| v.router_epoch == router_epoch);
                *single_epoch = router_epoch;
            }
            while self.fast_routes.len() >= cap {
                // Compute victim in an inner scope so the DashMap shard read guard is
                // explicitly dropped before calling `remove(&victim)` (avoids Rust 2024
                // temporary-lifetime self-deadlock on the same shard).
                let victim = { self.fast_routes.iter().next().map(|e| *e.key()) };
                let Some(victim) = victim else {
                    break;
                };
                self.fast_routes.remove(&victim);
            }
        } else if *single_epoch != router_epoch {
            *single_epoch = 0;
        }
        self.fast_routes.insert(route_key, cached);
    }

    /// O(1) synchronous zero-spawn fast path for established UDP flows when `router_epoch` is unchanged.
    /// Returns `Ok(())` on fast-path hit, or `Err(payload)` (returning the original buffer with zero
    /// extra allocation) on fast-path miss so the caller can perform full async routing.
    pub fn try_send_fast(
        &self,
        client_src: SocketAddr,
        raw_dst: SocketAddr,
        router_epoch: u64,
        payload: Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        if self.closed.load(Ordering::Acquire) || router_epoch == 0 {
            return Err(payload);
        }
        let cached = match self.fast_routes.get(&(client_src, raw_dst)) {
            Some(entry) => entry.clone(),
            None => return Err(payload),
        };
        if router_epoch != cached.router_epoch {
            self.fast_routes.remove_if(&(client_src, raw_dst), |_, v| {
                v.router_epoch != router_epoch
            });
            return Err(payload);
        }

        let key = NatSessionKey {
            client_src,
            outbound_name: cached.outbound_name,
            fake_ip_scope: cached.fake_ip_scope,
        };
        let Some(entry) = self.sessions.get(&key) else {
            return Err(payload);
        };
        if entry.tx.is_closed() || entry.conn_entry.is_closed() {
            return Err(payload);
        }

        let raw_target = TargetAddr::from(raw_dst);
        let needs_map_update = !entry.reverse_map.read().has_outbound(
            &cached.resolved_target,
            &raw_target,
            cached.was_fake_ip,
        );
        if needs_map_update {
            entry.reverse_map.write().record_outbound(
                &cached.resolved_target,
                &raw_target,
                cached.was_fake_ip,
            );
        }

        let pkt_timeout_ms = (self
            .session_idle_timeout(cached.resolved_target.port)
            .as_millis() as u64)
            .max(1);
        entry
            .idle_timeout_ms
            .fetch_max(pkt_timeout_ms, Ordering::Relaxed);

        let payload_len = payload.len();
        match entry.tx.try_send((cached.resolved_target, payload)) {
            Ok(()) => {
                entry.last_active_ms.store(self.now_ms(), Ordering::Relaxed);
                entry
                    .last_active_wall_ms
                    .store(TelemetryHub::now_ms(), Ordering::Relaxed);
                self.hub.record_upload(&entry.conn_entry, payload_len);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                entry.last_active_ms.store(self.now_ms(), Ordering::Relaxed);
                entry
                    .last_active_wall_ms
                    .store(TelemetryHub::now_ms(), Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed((_, returned_payload))) => Err(returned_payload),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_datagram(
        self: &Arc<Self>,
        client_src: SocketAddr,
        raw_dst: TargetAddr,
        restored_from_fake_ip: Option<Ipv4Addr>,
        target: TargetAddr,
        rule_type: &str,
        rule_payload: &str,
        chains: Vec<String>,
        outbound: DynOutbound,
        payload: Vec<u8>,
    ) {
        self.send_datagram_with_epoch(
            client_src,
            raw_dst,
            restored_from_fake_ip,
            target,
            rule_type,
            rule_payload,
            chains,
            outbound,
            payload,
            0,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_datagram_with_epoch(
        &self,
        client_src: SocketAddr,
        raw_dst: TargetAddr,
        restored_from_fake_ip: Option<Ipv4Addr>,
        target: TargetAddr,
        rule_type: &str,
        rule_payload: &str,
        chains: Vec<String>,
        outbound: DynOutbound,
        payload: Vec<u8>,
        router_epoch: u64,
    ) {
        self.send_datagram_with_options(
            client_src,
            raw_dst,
            restored_from_fake_ip,
            target.clone(),
            target,
            rule_type,
            rule_payload,
            chains,
            outbound,
            payload,
            router_epoch,
            false,
        )
        .await;
    }

    /// Send a UDP datagram through the stateful NAT table with separate `telemetry_target`
    /// (for connection metadata/diagnostics, e.g. sniffed QUIC SNI domain) and `dial_target`
    /// (for outbound forwarding, e.g. raw IP on `DIRECT`/`skip-domain` or sniffed domain on `PROXY`).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_datagram_with_options(
        &self,
        client_src: SocketAddr,
        raw_dst: TargetAddr,
        restored_from_fake_ip: Option<Ipv4Addr>,
        telemetry_target: TargetAddr,
        dial_target: TargetAddr,
        rule_type: &str,
        rule_payload: &str,
        chains: Vec<String>,
        outbound: DynOutbound,
        payload: Vec<u8>,
        router_epoch: u64,
        sniffed: bool,
    ) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if !outbound.udp_supported() {
            let reason = match outbound.exit_category() {
                "REJECT" => "blocked by REJECT rule",
                "ERROR" if outbound.name() == "UNMAPPED-FAKE-IP" => {
                    "target is an unmapped or expired Fake-IP; please re-resolve DNS"
                }
                "ERROR" => "routing chain resolution error",
                _ => "selected outbound does not support UDP relay",
            };
            self.hub.record_instant_failed_diagnostic_sniffed(
                self.inbound_label,
                "udp",
                Some(client_src),
                &telemetry_target,
                restored_from_fake_ip.map(|ip| ip.to_string()),
                rule_type,
                rule_payload,
                chains,
                outbound.as_ref(),
                reason,
                sniffed,
            );
            return;
        }

        // Scope Fake-IP UDP sessions per Fake-IP across both proxy and `DIRECT` outbounds so
        // concurrent QUIC `:443` flows to distinct Fake-IP domains sharing a CDN Anycast IP never
        // collide on `peer_to_domain` or return addresses, while keeping non-Fake-IP `DIRECT`
        // sessions (`restored_from_fake_ip == None`) unscoped to preserve full-cone NAT on one socket.
        let fake_ip_scope = restored_from_fake_ip;
        let key = NatSessionKey {
            client_src,
            outbound_name: outbound.name().to_string(),
            fake_ip_scope,
        };
        let now_ms = self.now_ms();
        let now_wall_ms = TelemetryHub::now_ms();
        let was_fake_ip = restored_from_fake_ip.is_some();
        let session_timeout = self.session_idle_timeout(dial_target.port);
        let pkt_idle_timeout_ms = (session_timeout.as_millis() as u64).max(1);

        // Fast-path check before potentially running capacity eviction.
        if let Some(existing) = self.sessions.get(&key)
            && !existing.tx.is_closed()
            && !existing.conn_entry.is_closed()
        {
            existing.last_active_ms.store(now_ms, Ordering::Relaxed);
            existing
                .last_active_wall_ms
                .store(now_wall_ms, Ordering::Relaxed);
            existing
                .idle_timeout_ms
                .fetch_max(pkt_idle_timeout_ms, Ordering::Relaxed);
            let needs_map_update =
                !existing
                    .reverse_map
                    .read()
                    .has_outbound(&dial_target, &raw_dst, was_fake_ip);
            if needs_map_update {
                existing
                    .reverse_map
                    .write()
                    .record_outbound(&dial_target, &raw_dst, was_fake_ip);
            }
            let payload_len = payload.len();
            if existing.tx.try_send((dial_target.clone(), payload)).is_ok() {
                self.hub.record_upload(&existing.conn_entry, payload_len);
            }
            drop(existing);
            self.cache_fast_route(
                client_src,
                &raw_dst,
                outbound.name(),
                fake_ip_scope,
                &dial_target,
                was_fake_ip,
                router_epoch,
            );
            return;
        }

        // Serialize slow-path eviction + slot claim under `evict_lock` (never held across `.await`)
        // so concurrent UDP bursts cannot race past `max_sessions` by evicting the same oldest key.
        let (rx, conn_entry, reverse_map, last_active_ms, last_active_wall_ms, idle_timeout_ms) = {
            let _evict_guard = self.evict_lock.lock();

            if self.sessions.len() >= self.max_sessions && !self.sessions.contains_key(&key) {
                let _ = self.reap_idle_sessions();
                while self.sessions.len() >= self.max_sessions {
                    let Some(oldest_key) = self
                        .sessions
                        .iter()
                        .min_by_key(|entry| entry.value().last_active_ms.load(Ordering::Relaxed))
                        .map(|entry| entry.key().clone())
                    else {
                        break;
                    };
                    if let Some((_, evicted)) = self.sessions.remove(&oldest_key) {
                        evicted.conn_entry.request_close();
                        self.hub.unregister_connection(&evicted.conn_entry.id);
                        self.fast_routes.retain(|rk, rv| {
                            !(rk.0 == oldest_key.client_src
                                && rv.outbound_name == oldest_key.outbound_name
                                && rv.fake_ip_scope == oldest_key.fake_ip_scope)
                        });
                    } else {
                        break;
                    }
                }
            }

            // Synchronously claim or join the session slot BEFORE any `.await` (`open_udp_session`),
            // preventing concurrent QUIC Initial bursts from opening N parallel upstream sessions!
            match self.sessions.entry(key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                    if !occ.get().tx.is_closed() && !occ.get().conn_entry.is_closed() {
                        occ.get().last_active_ms.store(now_ms, Ordering::Relaxed);
                        occ.get()
                            .last_active_wall_ms
                            .store(now_wall_ms, Ordering::Relaxed);
                        occ.get()
                            .idle_timeout_ms
                            .fetch_max(pkt_idle_timeout_ms, Ordering::Relaxed);
                        occ.get().reverse_map.write().record_outbound(
                            &dial_target,
                            &raw_dst,
                            was_fake_ip,
                        );
                        let payload_len = payload.len();
                        if occ
                            .get()
                            .tx
                            .try_send((dial_target.clone(), payload))
                            .is_ok()
                        {
                            self.hub.record_upload(&occ.get().conn_entry, payload_len);
                        }
                        drop(occ);
                        drop(_evict_guard);
                        self.cache_fast_route(
                            client_src,
                            &raw_dst,
                            outbound.name(),
                            fake_ip_scope,
                            &dial_target,
                            was_fake_ip,
                            router_epoch,
                        );
                        return;
                    }
                    let conn_entry = self.hub.register_connection_with_outbound_sniffed(
                        self.inbound_label,
                        "udp",
                        Some(client_src),
                        &telemetry_target,
                        restored_from_fake_ip.map(|ip| ip.to_string()),
                        rule_type,
                        rule_payload,
                        chains.clone(),
                        outbound.as_ref(),
                        sniffed,
                    );
                    let reverse_map = Arc::new(RwLock::new(ReverseTargetMap::with_fake_ip_pin(
                        fake_ip_scope,
                    )));
                    reverse_map
                        .write()
                        .record_outbound(&dial_target, &raw_dst, was_fake_ip);
                    let last_active_ms = Arc::new(AtomicU64::new(now_ms));
                    let last_active_wall_ms = Arc::new(AtomicU64::new(now_wall_ms));
                    let idle_timeout_ms = Arc::new(AtomicU64::new(pkt_idle_timeout_ms));
                    let (tx, rx) =
                        mpsc::channel::<(TargetAddr, Vec<u8>)>(UDP_SESSION_QUEUE_CAPACITY);
                    let payload_len = payload.len();
                    if tx.try_send((dial_target.clone(), payload)).is_ok() {
                        self.hub.record_upload(&conn_entry, payload_len);
                    }
                    let evicted = occ.insert(NatSessionEntry {
                        tx,
                        reverse_map: Arc::clone(&reverse_map),
                        conn_entry: Arc::clone(&conn_entry),
                        last_active_ms: Arc::clone(&last_active_ms),
                        last_active_wall_ms: Arc::clone(&last_active_wall_ms),
                        idle_timeout_ms: Arc::clone(&idle_timeout_ms),
                    });
                    evicted.conn_entry.request_close();
                    self.hub.unregister_connection(&evicted.conn_entry.id);
                    (
                        rx,
                        conn_entry,
                        reverse_map,
                        last_active_ms,
                        last_active_wall_ms,
                        idle_timeout_ms,
                    )
                }
                dashmap::mapref::entry::Entry::Vacant(vac) => {
                    let conn_entry = self.hub.register_connection_with_outbound_sniffed(
                        self.inbound_label,
                        "udp",
                        Some(client_src),
                        &telemetry_target,
                        restored_from_fake_ip.map(|ip| ip.to_string()),
                        rule_type,
                        rule_payload,
                        chains.clone(),
                        outbound.as_ref(),
                        sniffed,
                    );
                    let reverse_map = Arc::new(RwLock::new(ReverseTargetMap::with_fake_ip_pin(
                        fake_ip_scope,
                    )));
                    reverse_map
                        .write()
                        .record_outbound(&dial_target, &raw_dst, was_fake_ip);
                    let last_active_ms = Arc::new(AtomicU64::new(now_ms));
                    let last_active_wall_ms = Arc::new(AtomicU64::new(now_wall_ms));
                    let idle_timeout_ms = Arc::new(AtomicU64::new(pkt_idle_timeout_ms));
                    let (tx, rx) =
                        mpsc::channel::<(TargetAddr, Vec<u8>)>(UDP_SESSION_QUEUE_CAPACITY);
                    let payload_len = payload.len();
                    if tx.try_send((dial_target.clone(), payload)).is_ok() {
                        self.hub.record_upload(&conn_entry, payload_len);
                    }
                    vac.insert(NatSessionEntry {
                        tx,
                        reverse_map: Arc::clone(&reverse_map),
                        conn_entry: Arc::clone(&conn_entry),
                        last_active_ms: Arc::clone(&last_active_ms),
                        last_active_wall_ms: Arc::clone(&last_active_wall_ms),
                        idle_timeout_ms: Arc::clone(&idle_timeout_ms),
                    });
                    (
                        rx,
                        conn_entry,
                        reverse_map,
                        last_active_ms,
                        last_active_wall_ms,
                        idle_timeout_ms,
                    )
                }
            }
        };

        if self.closed.load(Ordering::Acquire) {
            if self
                .sessions
                .remove_if(&key, |_, v| Arc::ptr_eq(&v.conn_entry, &conn_entry))
                .is_some()
            {
                self.fast_routes.clear();
            }
            conn_entry.request_close();
            self.hub.unregister_connection(&conn_entry.id);
            return;
        }

        self.cache_fast_route(
            client_src,
            &raw_dst,
            outbound.name(),
            fake_ip_scope,
            &dial_target,
            was_fake_ip,
            router_epoch,
        );
        let target = telemetry_target;

        let inbound_label = self.inbound_label;
        let hub_clone = Arc::clone(&self.hub);
        let sessions_weak = Arc::downgrade(&self.sessions);
        let fast_routes_weak = Arc::downgrade(&self.fast_routes);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let sink = Arc::clone(&self.reply_sink);
        let boot = self.boot;

        tokio::spawn(async move {
            let mut rx = rx;
            let session = tokio::select! {
                biased;
                _ = conn_entry.closed() => {
                    cleanup_weak_session_maps(&sessions_weak, &fast_routes_weak, &key, &conn_entry);
                    hub_clone.unregister_connection(&conn_entry.id);
                    return;
                }
                _ = wait_for_shutdown(&mut shutdown_rx) => {
                    conn_entry.request_close();
                    cleanup_weak_session_maps(&sessions_weak, &fast_routes_weak, &key, &conn_entry);
                    hub_clone.unregister_connection(&conn_entry.id);
                    return;
                }
                res = tokio::time::timeout(Duration::from_secs(10), outbound.open_udp_session()) => {
                    match res {
                        Ok(Ok(s)) => Arc::new(s),
                        Ok(Err(err)) => {
                            tracing::debug!(
                                "[{}] open_udp_session on '{}' failed for {} -> {}: {}",
                                inbound_label,
                                outbound.name(),
                                client_src,
                                target,
                                err
                            );
                            cleanup_weak_session_maps(&sessions_weak, &fast_routes_weak, &key, &conn_entry);
                            hub_clone.record_connection_failed(&conn_entry.id, &err.to_string());
                            return;
                        }
                        Err(_) => {
                            let msg = "open_udp_session timed out after 10s";
                            tracing::debug!(
                                "[{}] {} on '{}' for {} -> {}",
                                inbound_label,
                                msg,
                                outbound.name(),
                                client_src,
                                target
                            );
                            cleanup_weak_session_maps(&sessions_weak, &fast_routes_weak, &key, &conn_entry);
                            hub_clone.record_connection_failed(&conn_entry.id, msg);
                            return;
                        }
                    }
                }
            };

            // Wait for and transmit the first queued datagram BEFORE marking the connection
            // established so lazy UDP outbounds (VLESS, Trojan, SS, AnyTLS) measure true dial RTT
            // instead of `hs=0ms` and report first-packet dial failures as `failed` (not `zeroRxClosed`).
            enum FirstPacketOutcome {
                Sent,
                Failed(std::io::Error),
                ClosedOrIdle,
            }

            let first_outcome = tokio::select! {
                biased;
                _ = conn_entry.closed() => FirstPacketOutcome::ClosedOrIdle,
                _ = wait_for_shutdown(&mut shutdown_rx) => FirstPacketOutcome::ClosedOrIdle,
                res = tokio::time::timeout(session_timeout, async {
                    let mut last_transient_err: Option<std::io::Error> = None;
                    loop {
                        let recv_res = if last_transient_err.is_some() {
                            match rx.try_recv() {
                                Ok(item) => Some(item),
                                Err(_) => return Err(last_transient_err.take().unwrap()),
                            }
                        } else {
                            rx.recv().await
                        };
                        let Some((first_dst, first_data)) = recv_res else {
                            return match last_transient_err {
                                Some(err) => Err(err),
                                None => Ok(false),
                            };
                        };
                        last_active_ms.store(boot.elapsed().as_millis() as u64, Ordering::Relaxed);
                        last_active_wall_ms.store(TelemetryHub::now_ms(), Ordering::Relaxed);
                        match session.send_to(&first_data, &first_dst).await {
                            Ok(()) => return Ok(true),
                            Err(err) if session.is_target_transient_error(&err) => {
                                tracing::debug!(
                                    "[{}] transient initial UDP send_to error on '{}' for {} -> {}: {}",
                                    inbound_label,
                                    outbound.name(),
                                    client_src,
                                    first_dst,
                                    err
                                );
                                last_transient_err = Some(err);
                            }
                            Err(err) => return Err(err),
                        }
                    }
                }) => {
                    match res {
                        Ok(Ok(true)) => FirstPacketOutcome::Sent,
                        Ok(Ok(false)) | Err(_) => FirstPacketOutcome::ClosedOrIdle,
                        Ok(Err(err)) => FirstPacketOutcome::Failed(err),
                    }
                }
            };

            match first_outcome {
                FirstPacketOutcome::Sent => {
                    conn_entry.mark_established();
                }
                FirstPacketOutcome::Failed(err) => {
                    tracing::debug!(
                        "[{}] first UDP send_to on '{}' failed for {} -> {}: {}",
                        inbound_label,
                        outbound.name(),
                        client_src,
                        target,
                        err
                    );
                    cleanup_weak_session_maps(&sessions_weak, &fast_routes_weak, &key, &conn_entry);
                    hub_clone.record_connection_failed(&conn_entry.id, &err.to_string());
                    return;
                }
                FirstPacketOutcome::ClosedOrIdle => {
                    conn_entry.request_close();
                    cleanup_weak_session_maps(&sessions_weak, &fast_routes_weak, &key, &conn_entry);
                    hub_clone.unregister_connection(&conn_entry.id);
                    return;
                }
            }

            let session_rx = Arc::clone(&session);
            let writer_last = Arc::clone(&last_active_ms);
            let writer_last_wall = Arc::clone(&last_active_wall_ms);
            let outbound_name_log = outbound.name().to_string();
            let writer = async move {
                while let Some((dst, data)) = rx.recv().await {
                    writer_last.store(boot.elapsed().as_millis() as u64, Ordering::Relaxed);
                    writer_last_wall.store(TelemetryHub::now_ms(), Ordering::Relaxed);
                    if let Err(err) = session.send_to(&data, &dst).await {
                        if session.is_target_transient_error(&err) {
                            tracing::debug!(
                                "[{}] ignoring transient UDP send_to error on '{}' for {} -> {}: {}",
                                inbound_label,
                                outbound_name_log,
                                client_src,
                                dst,
                                err
                            );
                            continue;
                        }
                        break;
                    }
                }
            };

            let conn_dl = Arc::clone(&conn_entry);
            let hub_dl = Arc::clone(&hub_clone);
            let rev_dl = Arc::clone(&reverse_map);
            let reader_last = Arc::clone(&last_active_ms);
            let reader_last_wall = Arc::clone(&last_active_wall_ms);
            let shutdown_rx_reader = shutdown_rx.clone();
            let reader = async move {
                loop {
                    if conn_dl.is_closed() || *shutdown_rx_reader.borrow() {
                        break;
                    }
                    match session_rx.recv_from().await {
                        Ok((resp, remote_src)) => {
                            if conn_dl.is_closed() || *shutdown_rx_reader.borrow() {
                                break;
                            }
                            reader_last.store(boot.elapsed().as_millis() as u64, Ordering::Relaxed);
                            reader_last_wall.store(TelemetryHub::now_ms(), Ordering::Relaxed);
                            hub_dl.record_download(&conn_dl, resp.len());
                            let eff_target = rev_dl.read().map_return_source(&remote_src);
                            sink(client_src, eff_target, resp);
                        }
                        Err(_) => break,
                    }
                }
            };

            // Monitor monotonic and wall-clock idle expiry in an independent future so active
            // sessions with refreshed `last_active_ms` never cancel `session_rx.recv_from()`.
            let idle_last = Arc::clone(&last_active_ms);
            let idle_last_wall = Arc::clone(&last_active_wall_ms);
            let idle_timeout = Arc::clone(&idle_timeout_ms);
            let idle_watchdog = async move {
                loop {
                    let timeout_ms = idle_timeout.load(Ordering::Relaxed);
                    let now_mono = boot.elapsed().as_millis() as u64;
                    let now_wall = TelemetryHub::now_ms();
                    let mono_idle = now_mono.saturating_sub(idle_last.load(Ordering::Relaxed));
                    let wall_idle = now_wall.saturating_sub(idle_last_wall.load(Ordering::Relaxed));
                    if mono_idle >= timeout_ms || wall_idle >= timeout_ms {
                        break;
                    }
                    let sleep_ms = (timeout_ms - mono_idle).min(timeout_ms - wall_idle).max(1);
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                }
            };

            tokio::select! {
                biased;
                _ = conn_entry.closed() => {}
                _ = wait_for_shutdown(&mut shutdown_rx) => {}
                _ = writer => {}
                _ = reader => {}
                _ = idle_watchdog => {}
            }

            conn_entry.request_close();
            cleanup_weak_session_maps(&sessions_weak, &fast_routes_weak, &key, &conn_entry);
            hub_clone.unregister_connection(&conn_entry.id);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Mutex as AsyncMutex;

    use crate::outbound::{BoxedStream, OutboundHandler, OutboundUdpSession};

    struct SlowMockUdpSession {
        sent: Arc<AsyncMutex<Vec<Vec<u8>>>>,
        closed_rx: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl OutboundUdpSession for SlowMockUdpSession {
        async fn send_to(&self, payload: &[u8], _target: &TargetAddr) -> std::io::Result<()> {
            self.sent.lock().await.push(payload.to_vec());
            Ok(())
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, TargetAddr)> {
            self.closed_rx.notified().await;
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ))
        }
    }

    struct SlowMockUdpOutbound {
        open_calls: Arc<AtomicUsize>,
        sent: Arc<AsyncMutex<Vec<Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl OutboundHandler for SlowMockUdpOutbound {
        fn name(&self) -> &str {
            "mock-quic-node"
        }

        fn protocol(&self) -> &'static str {
            "hysteria2"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> std::io::Result<BoxedStream> {
            Err(std::io::Error::other("unused"))
        }

        async fn open_udp_session(&self) -> std::io::Result<Box<dyn OutboundUdpSession>> {
            self.open_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(40)).await;
            Ok(Box::new(SlowMockUdpSession {
                sent: Arc::clone(&self.sent),
                closed_rx: tokio::sync::Notify::new(),
            }))
        }
    }

    #[tokio::test]
    async fn concurrent_quic_initial_burst_opens_single_session_and_preserves_order() {
        let hub = Arc::new(TelemetryHub::new());
        let mgr = UdpNatManager::new("test-udp", 64, Arc::clone(&hub), Arc::new(|_, _, _| {}));
        let open_calls = Arc::new(AtomicUsize::new(0));
        let sent = Arc::new(AsyncMutex::new(Vec::new()));
        let outbound: DynOutbound = Arc::new(SlowMockUdpOutbound {
            open_calls: Arc::clone(&open_calls),
            sent: Arc::clone(&sent),
        });

        let src: SocketAddr = "198.18.0.2:54321".parse().unwrap();
        let dst = TargetAddr::new_domain("quic.example.com", 443).unwrap();

        let mut handles = Vec::new();
        for seq in 0u8..8 {
            let m = Arc::clone(&mgr);
            let ob = Arc::clone(&outbound);
            let d = dst.clone();
            handles.push(tokio::spawn(async move {
                m.send_datagram(
                    src,
                    d.clone(),
                    None,
                    d,
                    "MATCH",
                    "",
                    vec!["mock-quic-node".into()],
                    ob,
                    vec![seq],
                )
                .await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        for _ in 0..150 {
            if sent.lock().await.len() >= 8 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            open_calls.load(Ordering::SeqCst),
            1,
            "concurrent QUIC initial burst must open exactly 1 upstream UDP session"
        );
        let delivered = sent.lock().await.clone();
        assert_eq!(
            delivered.len(),
            8,
            "all 8 burst datagrams must be delivered"
        );
        mgr.reset_all_sessions();
    }

    #[test]
    fn reverse_target_map_caps_entries_and_avoids_ambiguous_fake_ip_port_spoofing() {
        let mut map = ReverseTargetMap::default();
        let fake_a: TargetAddr = "198.18.0.10:443".parse().unwrap();
        let fake_b: TargetAddr = "198.18.0.11:443".parse().unwrap();
        let dom_a = TargetAddr::new_domain("a.example.com", 443).unwrap();
        let dom_b = TargetAddr::new_domain("b.example.com", 443).unwrap();
        let resolved_ip_a: TargetAddr = "93.184.216.34:443".parse().unwrap();

        // Single Fake-IP on :443 maps resolved IP response back to fake_a.
        map.record_outbound(&dom_a, &fake_a, true);
        assert_eq!(map.map_return_source(&resolved_ip_a), fake_a);

        // Second distinct Fake-IP sharing :443 marks :443 ambiguous instead of spoofing fake_b.
        map.record_outbound(&dom_b, &fake_b, true);
        assert_eq!(map.map_return_source(&dom_a), fake_a);
        assert_eq!(map.map_return_source(&dom_b), fake_b);
        assert_eq!(map.map_return_source(&resolved_ip_a), resolved_ip_a);

        // Flooding > MAX_UDP_DESTS_PER_SESSION destinations stays bounded.
        for i in 0..700u16 {
            let t = TargetAddr::new_domain(format!("host-{i}.example.com"), 1000 + i).unwrap();
            let raw: TargetAddr = format!(
                "198.18.{}.{}:{}",
                (i >> 8) as u8,
                (i & 0xff) as u8,
                1000 + i
            )
            .parse()
            .unwrap();
            map.record_outbound(&t, &raw, true);
        }
        assert!(map.target_to_raw.len() <= MAX_UDP_DESTS_PER_SESSION);
        assert!(map.port_to_fake_raw.len() <= MAX_UDP_DESTS_PER_SESSION);
    }

    #[tokio::test]
    async fn fast_path_populates_on_first_packet_and_invalidates_on_epoch_bump() {
        let hub = Arc::new(TelemetryHub::new());
        let mgr = UdpNatManager::new("test-udp", 64, Arc::clone(&hub), Arc::new(|_, _, _| {}));
        let open_calls = Arc::new(AtomicUsize::new(0));
        let sent = Arc::new(AsyncMutex::new(Vec::new()));
        let outbound: DynOutbound = Arc::new(SlowMockUdpOutbound {
            open_calls: Arc::clone(&open_calls),
            sent: Arc::clone(&sent),
        });

        let src: SocketAddr = "198.18.0.2:54321".parse().unwrap();
        let raw_dst_sock: SocketAddr = "198.18.0.50:443".parse().unwrap();
        let raw_dst = TargetAddr::from(raw_dst_sock);
        let resolved_dst = TargetAddr::new_domain("quic.example.com", 443).unwrap();

        // Fast path misses before first routed packet populates `fast_routes`.
        assert_eq!(
            mgr.try_send_fast(src, raw_dst_sock, 1, vec![0]),
            Err(vec![0])
        );

        mgr.send_datagram_with_epoch(
            src,
            raw_dst,
            Some("198.18.0.50".parse().unwrap()),
            resolved_dst,
            "MATCH",
            "",
            vec!["mock-quic-node".into()],
            Arc::clone(&outbound),
            vec![1],
            1,
        )
        .await;

        // Subsequent packets on the same epoch hit the O(1) zero-spawn fast path.
        assert_eq!(mgr.try_send_fast(src, raw_dst_sock, 1, vec![2]), Ok(()));
        assert_eq!(mgr.try_send_fast(src, raw_dst_sock, 1, vec![3]), Ok(()));

        // Epoch 0 disables fast path without evicting epoch 1.
        assert_eq!(
            mgr.try_send_fast(src, raw_dst_sock, 0, vec![99]),
            Err(vec![99])
        );
        assert_eq!(mgr.try_send_fast(src, raw_dst_sock, 1, vec![4]), Ok(()));

        for _ in 0..150 {
            if sent.lock().await.len() >= 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            sent.lock().await.clone(),
            vec![vec![1], vec![2], vec![3], vec![4]]
        );

        // Bumping router_epoch invalidates the cached route and returns original payload.
        assert_eq!(
            mgr.try_send_fast(src, raw_dst_sock, 2, vec![5]),
            Err(vec![5])
        );
        assert_eq!(
            mgr.try_send_fast(src, raw_dst_sock, 1, vec![6]),
            Err(vec![6])
        );
        mgr.reset_all_sessions();
    }

    struct FailingFirstSendUdpSession;

    #[async_trait::async_trait]
    impl OutboundUdpSession for FailingFirstSendUdpSession {
        async fn send_to(&self, _payload: &[u8], _target: &TargetAddr) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "upstream dial refused",
            ))
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, TargetAddr)> {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ))
        }
    }

    struct LazyFailingUdpOutbound;

    #[async_trait::async_trait]
    impl OutboundHandler for LazyFailingUdpOutbound {
        fn name(&self) -> &str {
            "lazy-vless-node"
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> std::io::Result<BoxedStream> {
            Err(std::io::Error::other("unused"))
        }

        async fn open_udp_session(&self) -> std::io::Result<Box<dyn OutboundUdpSession>> {
            Ok(Box::new(FailingFirstSendUdpSession))
        }
    }

    #[tokio::test]
    async fn lazy_udp_session_first_send_to_error_records_failed_not_zero_rx() {
        let hub = Arc::new(TelemetryHub::new());
        let mgr = UdpNatManager::new("test-udp", 64, Arc::clone(&hub), Arc::new(|_, _, _| {}));
        let outbound: DynOutbound = Arc::new(LazyFailingUdpOutbound);

        let src: SocketAddr = "198.18.0.2:54322".parse().unwrap();
        let raw_dst_sock: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let raw_dst = TargetAddr::from(raw_dst_sock);

        mgr.send_datagram_with_epoch(
            src,
            raw_dst.clone(),
            None,
            raw_dst,
            "MATCH",
            "",
            vec!["lazy-vless-node".into()],
            outbound,
            vec![0xaa, 0xbb],
            7,
        )
        .await;

        for _ in 0..100 {
            if hub.failed_connections_total() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(hub.failed_connections_total(), 1);
        assert_eq!(hub.zero_rx_closed_total(), 0);
        assert_eq!(hub.established_connections_total(), 0);
        assert_eq!(hub.active_connection_count(), 0);
        assert!(mgr.try_send_fast(src, raw_dst_sock, 7, vec![0xcc]).is_err());

        let diags = hub.diagnostics_snapshot(10);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].status, "failed");
        assert!(diags[0].connect_duration_ms.is_none());
    }

    #[tokio::test]
    async fn ntp_port_uses_short_idle_timeout_while_quic_uses_60s_and_custom_timeout_wins() {
        let hub = Arc::new(TelemetryHub::new());
        let mgr = UdpNatManager::new("test-udp", 64, Arc::clone(&hub), Arc::new(|_, _, _| {}));
        let outbound: DynOutbound = Arc::new(SlowMockUdpOutbound {
            open_calls: Arc::new(AtomicUsize::new(0)),
            sent: Arc::new(AsyncMutex::new(Vec::new())),
        });

        let src_ntp: SocketAddr = "198.18.0.2:55123".parse().unwrap();
        let dst_ntp: TargetAddr = "162.159.200.1:123".parse().unwrap();
        mgr.send_datagram(
            src_ntp,
            dst_ntp.clone(),
            None,
            dst_ntp.clone(),
            "MATCH",
            "",
            vec!["mock-quic-node".into()],
            Arc::clone(&outbound),
            vec![0x1b],
        )
        .await;

        let src_quic: SocketAddr = "198.18.0.2:55443".parse().unwrap();
        let dst_quic = TargetAddr::new_domain("quic.example.com", 443).unwrap();
        mgr.send_datagram(
            src_quic,
            dst_quic.clone(),
            None,
            dst_quic,
            "MATCH",
            "",
            vec!["mock-quic-node".into()],
            Arc::clone(&outbound),
            vec![0xc0],
        )
        .await;

        let key_ntp = NatSessionKey {
            client_src: src_ntp,
            outbound_name: "mock-quic-node".into(),
            fake_ip_scope: None,
        };
        let key_quic = NatSessionKey {
            client_src: src_quic,
            outbound_name: "mock-quic-node".into(),
            fake_ip_scope: None,
        };
        assert_eq!(
            mgr.sessions
                .get(&key_ntp)
                .unwrap()
                .idle_timeout_ms
                .load(Ordering::Relaxed),
            12_000
        );
        assert_eq!(
            mgr.sessions
                .get(&key_quic)
                .unwrap()
                .idle_timeout_ms
                .load(Ordering::Relaxed),
            60_000
        );

        // Sending a :443 datagram from `src_ntp` upgrades the shared session's idle timeout to 60s.
        mgr.send_datagram(
            src_ntp,
            TargetAddr::new_domain("upgrade.example.com", 443).unwrap(),
            None,
            TargetAddr::new_domain("upgrade.example.com", 443).unwrap(),
            "MATCH",
            "",
            vec!["mock-quic-node".into()],
            Arc::clone(&outbound),
            vec![0xc0],
        )
        .await;
        assert_eq!(
            mgr.sessions
                .get(&key_ntp)
                .unwrap()
                .idle_timeout_ms
                .load(Ordering::Relaxed),
            60_000
        );

        let custom_mgr = UdpNatManager::with_idle_timeout(
            "test-custom-udp",
            64,
            Duration::from_millis(200),
            Arc::clone(&hub),
            Arc::new(|_, _, _| {}),
        );
        custom_mgr
            .send_datagram(
                src_ntp,
                dst_ntp.clone(),
                None,
                dst_ntp,
                "MATCH",
                "",
                vec!["mock-quic-node".into()],
                outbound,
                vec![0x1b],
            )
            .await;
        assert_eq!(
            custom_mgr
                .sessions
                .get(&key_ntp)
                .unwrap()
                .idle_timeout_ms
                .load(Ordering::Relaxed),
            200
        );

        mgr.reset_all_sessions();
        custom_mgr.reset_all_sessions();
    }

    #[tokio::test]
    async fn reap_idle_sessions_evicts_wall_clock_expired_sessions_when_monotonic_freezes() {
        let hub = Arc::new(TelemetryHub::new());
        let mgr = UdpNatManager::new("test-udp", 64, Arc::clone(&hub), Arc::new(|_, _, _| {}));
        let sent = Arc::new(AsyncMutex::new(Vec::new()));
        let outbound: DynOutbound = Arc::new(SlowMockUdpOutbound {
            open_calls: Arc::new(AtomicUsize::new(0)),
            sent: Arc::clone(&sent),
        });

        let src_ntp: SocketAddr = "198.18.0.2:56123".parse().unwrap();
        let ntp_sock: SocketAddr = "162.159.200.1:123".parse().unwrap();
        let dst_ntp = TargetAddr::from(ntp_sock);

        let src_quic: SocketAddr = "198.18.0.2:56443".parse().unwrap();
        let quic_sock: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let dst_quic = TargetAddr::from(quic_sock);

        mgr.send_datagram_with_epoch(
            src_ntp,
            dst_ntp.clone(),
            None,
            dst_ntp,
            "MATCH",
            "",
            vec!["mock-quic-node".into()],
            Arc::clone(&outbound),
            vec![0x1b],
            1,
        )
        .await;
        mgr.send_datagram_with_epoch(
            src_quic,
            dst_quic.clone(),
            None,
            dst_quic,
            "MATCH",
            "",
            vec!["mock-quic-node".into()],
            outbound,
            vec![0xc0],
            1,
        )
        .await;

        for _ in 0..150 {
            if sent.lock().await.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(mgr.active_session_count(), 2);
        assert_eq!(hub.active_connection_count(), 2);

        // Simulate 309s Android SCREEN_OFF deep sleep: monotonic `boot.elapsed()` barely advanced,
        // while wall-clock `last_active_wall_ms` on the NTP session is 309s old.
        let key_ntp = NatSessionKey {
            client_src: src_ntp,
            outbound_name: "mock-quic-node".into(),
            fake_ip_scope: None,
        };
        let key_quic = NatSessionKey {
            client_src: src_quic,
            outbound_name: "mock-quic-node".into(),
            fake_ip_scope: None,
        };
        mgr.sessions
            .get(&key_ntp)
            .unwrap()
            .last_active_wall_ms
            .store(
                TelemetryHub::now_ms().saturating_sub(309_000),
                Ordering::Relaxed,
            );

        assert_eq!(hub.reap_idle_sessions(), 1);
        assert_eq!(mgr.active_session_count(), 1);
        assert_eq!(hub.active_connection_count(), 1);
        assert!(mgr.try_send_fast(src_ntp, ntp_sock, 1, vec![0x99]).is_err());
        assert_eq!(
            mgr.try_send_fast(src_quic, quic_sock, 1, vec![0x42]),
            Ok(())
        );

        // Now backdate the remaining :443 session past its 60s timeout as well.
        mgr.sessions
            .get(&key_quic)
            .unwrap()
            .last_active_wall_ms
            .store(
                TelemetryHub::now_ms().saturating_sub(309_000),
                Ordering::Relaxed,
            );
        assert_eq!(hub.reap_idle_sessions(), 1);
        assert_eq!(mgr.active_session_count(), 0);
        assert_eq!(hub.active_connection_count(), 0);
    }

    struct OriginEchoProxySession {
        rx: AsyncMutex<mpsc::Receiver<(Vec<u8>, TargetAddr)>>,
        tx: mpsc::Sender<(Vec<u8>, TargetAddr)>,
    }

    #[async_trait::async_trait]
    impl OutboundUdpSession for OriginEchoProxySession {
        async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> std::io::Result<()> {
            // Simulate a remote proxy resolving domain targets to IPv4 or IPv6 origin addresses!
            let origin_src = match &target.host {
                HostName::Domain(d) if d == "a.example.com" => {
                    "93.184.216.34:443".parse::<TargetAddr>().unwrap()
                }
                HostName::Domain(d) if d == "b.example.com" => {
                    "[2606:4700::6810:84e5]:443".parse::<TargetAddr>().unwrap()
                }
                _ => target.clone(),
            };
            let _ = self.tx.send((payload.to_vec(), origin_src)).await;
            Ok(())
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, TargetAddr)> {
            self.rx.lock().await.recv().await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "mock closed")
            })
        }
    }

    struct OriginEchoProxyOutbound;

    #[async_trait::async_trait]
    impl OutboundHandler for OriginEchoProxyOutbound {
        fn name(&self) -> &str {
            "vless-proxy"
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> std::io::Result<BoxedStream> {
            Err(std::io::Error::other("unused"))
        }

        async fn open_udp_session(&self) -> std::io::Result<Box<dyn OutboundUdpSession>> {
            let (tx, rx) = mpsc::channel(16);
            Ok(Box::new(OriginEchoProxySession {
                rx: AsyncMutex::new(rx),
                tx,
            }))
        }
    }

    type CapturedReplies = Vec<(SocketAddr, TargetAddr, Vec<u8>)>;
    type DeliveredDatagrams = Vec<(TargetAddr, Vec<u8>)>;

    #[tokio::test]
    async fn concurrent_fake_ip_quic_flows_on_same_client_port_preserve_exact_fake_ip_even_for_ipv6_origin()
     {
        let hub = Arc::new(TelemetryHub::new());
        let replies: Arc<parking_lot::Mutex<CapturedReplies>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let replies_sink = Arc::clone(&replies);
        let mgr = UdpNatManager::new(
            "test-udp",
            64,
            Arc::clone(&hub),
            Arc::new(move |c, eff, data| {
                replies_sink.lock().push((c, eff, data));
            }),
        );
        let outbound: DynOutbound = Arc::new(OriginEchoProxyOutbound);

        let client_src: SocketAddr = "198.18.0.2:59001".parse().unwrap();
        let fake_a_v4: Ipv4Addr = "198.18.0.10".parse().unwrap();
        let fake_b_v4: Ipv4Addr = "198.18.0.11".parse().unwrap();
        let raw_a: TargetAddr = "198.18.0.10:443".parse().unwrap();
        let raw_b: TargetAddr = "198.18.0.11:443".parse().unwrap();
        let dom_a = TargetAddr::new_domain("a.example.com", 443).unwrap();
        let dom_b = TargetAddr::new_domain("b.example.com", 443).unwrap();

        mgr.send_datagram_with_epoch(
            client_src,
            raw_a.clone(),
            Some(fake_a_v4),
            dom_a,
            "MATCH",
            "",
            vec!["vless-proxy".into()],
            Arc::clone(&outbound),
            vec![0xa1],
            1,
        )
        .await;
        mgr.send_datagram_with_epoch(
            client_src,
            raw_b.clone(),
            Some(fake_b_v4),
            dom_b,
            "MATCH",
            "",
            vec!["vless-proxy".into()],
            outbound,
            vec![0xb2],
            1,
        )
        .await;

        for _ in 0..100 {
            if replies.lock().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let got = replies.lock().clone();
        assert_eq!(got.len(), 2);
        assert!(got.contains(&(client_src, raw_a, vec![0xa1])));
        assert!(got.contains(&(client_src, raw_b, vec![0xb2])));
        mgr.reset_all_sessions();
    }

    struct TransientDirectMockSession {
        delivered: Arc<AsyncMutex<DeliveredDatagrams>>,
        closed: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl OutboundUdpSession for TransientDirectMockSession {
        fn is_target_transient_error(&self, err: &std::io::Error) -> bool {
            err.kind() == std::io::ErrorKind::HostUnreachable
        }

        async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> std::io::Result<()> {
            if matches!(&target.host, HostName::Domain(d) if d == "nodata.example.com") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::HostUnreachable,
                    "cached NODATA for nodata.example.com",
                ));
            }
            self.delivered
                .lock()
                .await
                .push((target.clone(), payload.to_vec()));
            Ok(())
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, TargetAddr)> {
            self.closed.notified().await;
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ))
        }
    }

    struct TransientDirectMockOutbound {
        delivered: Arc<AsyncMutex<DeliveredDatagrams>>,
    }

    #[async_trait::async_trait]
    impl OutboundHandler for TransientDirectMockOutbound {
        fn name(&self) -> &str {
            "DIRECT"
        }

        fn protocol(&self) -> &'static str {
            "direct"
        }

        fn exit_category(&self) -> &'static str {
            "DIRECT"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> std::io::Result<BoxedStream> {
            Err(std::io::Error::other("unused"))
        }

        async fn open_udp_session(&self) -> std::io::Result<Box<dyn OutboundUdpSession>> {
            Ok(Box::new(TransientDirectMockSession {
                delivered: Arc::clone(&self.delivered),
                closed: tokio::sync::Notify::new(),
            }))
        }
    }

    #[tokio::test]
    async fn shared_direct_udp_session_survives_transient_target_dns_errors() {
        let hub = Arc::new(TelemetryHub::new());
        let mgr = UdpNatManager::new("test-udp", 64, Arc::clone(&hub), Arc::new(|_, _, _| {}));
        let delivered = Arc::new(AsyncMutex::new(Vec::new()));
        let outbound: DynOutbound = Arc::new(TransientDirectMockOutbound {
            delivered: Arc::clone(&delivered),
        });

        let src: SocketAddr = "198.18.0.2:60123".parse().unwrap();
        let ok_target = TargetAddr::new_domain("ok.example.com", 443).unwrap();
        let bad_target = TargetAddr::new_domain("nodata.example.com", 443).unwrap();

        mgr.send_datagram(
            src,
            ok_target.clone(),
            None,
            ok_target.clone(),
            "MATCH",
            "",
            vec!["DIRECT".into()],
            Arc::clone(&outbound),
            vec![1],
        )
        .await;
        for _ in 0..100 {
            if delivered.lock().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Now send to a NODATA target on the same shared `(src, DIRECT)` non-Fake-IP session followed by another good packet!
        mgr.send_datagram(
            src,
            bad_target.clone(),
            None,
            bad_target,
            "MATCH",
            "",
            vec!["DIRECT".into()],
            Arc::clone(&outbound),
            vec![2],
        )
        .await;
        mgr.send_datagram(
            src,
            ok_target.clone(),
            None,
            ok_target.clone(),
            "MATCH",
            "",
            vec!["DIRECT".into()],
            outbound,
            vec![3],
        )
        .await;

        for _ in 0..100 {
            if delivered.lock().await.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let got = delivered.lock().await.clone();
        assert_eq!(
            got,
            vec![(ok_target.clone(), vec![1]), (ok_target, vec![3])]
        );
        assert_eq!(mgr.active_session_count(), 1);
        mgr.reset_all_sessions();
    }

    struct AnycastDirectMockSession {
        rx: AsyncMutex<mpsc::Receiver<(Vec<u8>, TargetAddr)>>,
        tx: mpsc::Sender<(Vec<u8>, TargetAddr)>,
        last_domain: parking_lot::Mutex<Option<TargetAddr>>,
    }

    #[async_trait::async_trait]
    impl OutboundUdpSession for AnycastDirectMockSession {
        async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> std::io::Result<()> {
            // Mirror `DirectUdpSession::peer_to_domain`: a single socket overwrites `last_domain`
            // when two domains resolve to the same Anycast IP `104.16.1.1:443`!
            *self.last_domain.lock() = Some(target.clone());
            let mapped = self
                .last_domain
                .lock()
                .clone()
                .unwrap_or_else(|| "104.16.1.1:443".parse().unwrap());
            let _ = self.tx.send((payload.to_vec(), mapped)).await;
            Ok(())
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, TargetAddr)> {
            self.rx.lock().await.recv().await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "mock closed")
            })
        }
    }

    struct AnycastDirectMockOutbound;

    #[async_trait::async_trait]
    impl OutboundHandler for AnycastDirectMockOutbound {
        fn name(&self) -> &str {
            "DIRECT"
        }

        fn protocol(&self) -> &'static str {
            "direct"
        }

        fn exit_category(&self) -> &'static str {
            "DIRECT"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> std::io::Result<BoxedStream> {
            Err(std::io::Error::other("unused"))
        }

        async fn open_udp_session(&self) -> std::io::Result<Box<dyn OutboundUdpSession>> {
            let (tx, rx) = mpsc::channel(16);
            Ok(Box::new(AnycastDirectMockSession {
                rx: AsyncMutex::new(rx),
                tx,
                last_domain: parking_lot::Mutex::new(None),
            }))
        }
    }

    #[tokio::test]
    async fn concurrent_direct_fake_ip_quic_flows_on_same_anycast_ip_never_crosstalk() {
        let hub = Arc::new(TelemetryHub::new());
        let replies: Arc<parking_lot::Mutex<CapturedReplies>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let replies_sink = Arc::clone(&replies);
        let mgr = UdpNatManager::new(
            "test-direct-fakeip",
            64,
            Arc::clone(&hub),
            Arc::new(move |c, eff, data| {
                replies_sink.lock().push((c, eff, data));
            }),
        );
        let outbound: DynOutbound = Arc::new(AnycastDirectMockOutbound);

        let client_src: SocketAddr = "198.18.0.2:61001".parse().unwrap();
        let fake_a: Ipv4Addr = "198.18.0.30".parse().unwrap();
        let fake_b: Ipv4Addr = "198.18.0.31".parse().unwrap();
        let raw_a: TargetAddr = "198.18.0.30:443".parse().unwrap();
        let raw_b: TargetAddr = "198.18.0.31:443".parse().unwrap();
        let dom_a = TargetAddr::new_domain("cdn-a.cn", 443).unwrap();
        let dom_b = TargetAddr::new_domain("cdn-b.cn", 443).unwrap();

        mgr.send_datagram_with_epoch(
            client_src,
            raw_a.clone(),
            Some(fake_a),
            dom_a,
            "GEOSITE",
            "cn",
            vec!["DIRECT".into()],
            Arc::clone(&outbound),
            vec![0x11],
            1,
        )
        .await;
        mgr.send_datagram_with_epoch(
            client_src,
            raw_b.clone(),
            Some(fake_b),
            dom_b,
            "GEOSITE",
            "cn",
            vec!["DIRECT".into()],
            outbound,
            vec![0x22],
            1,
        )
        .await;

        for _ in 0..100 {
            if replies.lock().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(mgr.active_session_count(), 2);
        let got = replies.lock().clone();
        assert!(got.contains(&(client_src, raw_a, vec![0x11])));
        assert!(got.contains(&(client_src, raw_b, vec![0x22])));
        mgr.reset_all_sessions();
    }

    struct FloodingUdpSession {
        dropped: Arc<AtomicBool>,
    }

    impl Drop for FloodingUdpSession {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[async_trait::async_trait]
    impl OutboundUdpSession for FloodingUdpSession {
        async fn send_to(&self, _payload: &[u8], _target: &TargetAddr) -> std::io::Result<()> {
            Ok(())
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, TargetAddr)> {
            tokio::task::yield_now().await;
            Ok((vec![0xAB; 32], "93.184.216.34:443".parse().unwrap()))
        }
    }

    struct FloodingUdpOutbound {
        dropped: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl OutboundHandler for FloodingUdpOutbound {
        fn name(&self) -> &str {
            "flood-node"
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> std::io::Result<BoxedStream> {
            Err(std::io::Error::other("unused"))
        }

        async fn open_udp_session(&self) -> std::io::Result<Box<dyn OutboundUdpSession>> {
            Ok(Box::new(FloodingUdpSession {
                dropped: Arc::clone(&self.dropped),
            }))
        }
    }

    #[tokio::test]
    async fn drop_and_shutdown_break_self_retaining_cycle_during_udp_flood() {
        let hub = Arc::new(TelemetryHub::new());
        let rx_packets = Arc::new(AtomicUsize::new(0));
        let rx_clone = Arc::clone(&rx_packets);
        let session_dropped = Arc::new(AtomicBool::new(false));
        let outbound: DynOutbound = Arc::new(FloodingUdpOutbound {
            dropped: Arc::clone(&session_dropped),
        });

        let mgr = UdpNatManager::new(
            "test-flood",
            64,
            Arc::clone(&hub),
            Arc::new(move |_, _, _| {
                rx_clone.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let sessions_weak = Arc::downgrade(&mgr.sessions);
        let src: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let dst: TargetAddr = "93.184.216.34:443".parse().unwrap();

        mgr.send_datagram(
            src,
            dst.clone(),
            None,
            dst.clone(),
            "MATCH",
            "",
            vec!["flood-node".into()],
            Arc::clone(&outbound),
            vec![1, 2, 3],
        )
        .await;

        // Wait until the flooded reader loop is actively delivering packets
        for _ in 0..200 {
            if rx_packets.load(Ordering::Relaxed) >= 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(rx_packets.load(Ordering::Relaxed) >= 5);
        assert_eq!(hub.active_connection_count(), 1);

        // Dropping the sole Arc<UdpNatManager> (without calling reset_all_sessions manually)
        // MUST immediately exit the flooded session task, close TelemetryHub, and free the session map!
        drop(mgr);

        tokio::time::timeout(Duration::from_millis(250), async {
            while !session_dropped.load(Ordering::Acquire)
                || hub.active_connection_count() != 0
                || sessions_weak.strong_count() != 0
            {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("flooded UDP session and DashMap must be freed within milliseconds on Drop");

        // Also verify explicit shutdown() gates late send_datagram_with_epoch calls against zombie sessions
        let mgr2 = UdpNatManager::new(
            "test-shutdown-gate",
            64,
            Arc::clone(&hub),
            Arc::new(|_, _, _| {}),
        );
        mgr2.shutdown();
        assert!(mgr2.is_closed());
        mgr2.send_datagram_with_epoch(
            src,
            dst.clone(),
            None,
            dst,
            "MATCH",
            "",
            vec!["flood-node".into()],
            outbound,
            vec![9, 9],
            1,
        )
        .await;
        assert_eq!(mgr2.active_session_count(), 0);
        assert_eq!(hub.active_connection_count(), 0);
    }

    #[tokio::test]
    async fn udp_nat_strictly_enforces_max_sessions_under_concurrent_burst() {
        let hub = Arc::new(TelemetryHub::new());
        let mgr = UdpNatManager::new(
            "test-cap-burst",
            32,
            Arc::clone(&hub),
            Arc::new(|_, _, _| {}),
        );
        let open_calls = Arc::new(AtomicUsize::new(0));
        let sent = Arc::new(AsyncMutex::new(Vec::new()));
        let outbound: DynOutbound = Arc::new(SlowMockUdpOutbound { open_calls, sent });

        let dst = TargetAddr::from("1.1.1.1:443".parse::<SocketAddr>().unwrap());
        let mut tasks = Vec::new();
        for port in 40000u16..40180u16 {
            let m = Arc::clone(&mgr);
            let ob = Arc::clone(&outbound);
            let d = dst.clone();
            tasks.push(tokio::spawn(async move {
                let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), port);
                m.send_datagram_with_epoch(
                    src,
                    d.clone(),
                    None,
                    d,
                    "MATCH",
                    "",
                    vec!["mock-quic-node".into()],
                    ob,
                    vec![1, 2, 3],
                    1,
                )
                .await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        assert!(
            mgr.active_session_count() <= 32,
            "UDP NAT session count ({}) must never exceed max_sessions (32) under concurrent burst",
            mgr.active_session_count()
        );
        assert!(
            hub.active_connection_count() <= 32,
            "TelemetryHub active connections ({}) must stay bounded by max_sessions (32)",
            hub.active_connection_count()
        );

        mgr.shutdown();
        assert_eq!(mgr.active_session_count(), 0);
        assert_eq!(hub.active_connection_count(), 0);
    }

    type SentDatagrams = Arc<AsyncMutex<Vec<(TargetAddr, Vec<u8>)>>>;

    struct RecordingTargetUdpSession {
        sent: SentDatagrams,
        reply_rx: AsyncMutex<mpsc::Receiver<(TargetAddr, Vec<u8>)>>,
        reply_tx: mpsc::Sender<(TargetAddr, Vec<u8>)>,
    }

    #[async_trait::async_trait]
    impl crate::outbound::OutboundUdpSession for RecordingTargetUdpSession {
        async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> std::io::Result<()> {
            self.sent
                .lock()
                .await
                .push((target.clone(), payload.to_vec()));
            let _ = self
                .reply_tx
                .try_send((target.clone(), b"quic-ack".to_vec()));
            Ok(())
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, TargetAddr)> {
            let (target, payload) = self
                .reply_rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed"))?;
            Ok((payload, target))
        }
    }

    struct RecordingUdpOutbound {
        name: &'static str,
        category: &'static str,
        sent: SentDatagrams,
    }

    #[async_trait::async_trait]
    impl crate::outbound::OutboundHandler for RecordingUdpOutbound {
        fn name(&self) -> &str {
            self.name
        }
        fn protocol(&self) -> &'static str {
            if self.category == "DIRECT" {
                "direct"
            } else {
                "vless"
            }
        }
        fn exit_category(&self) -> &'static str {
            self.category
        }
        async fn connect_tcp(
            &self,
            _target: &TargetAddr,
        ) -> std::io::Result<crate::outbound::BoxedStream> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "udp only",
            ))
        }
        fn udp_supported(&self) -> bool {
            true
        }
        async fn open_udp_session(
            &self,
        ) -> std::io::Result<Box<dyn crate::outbound::OutboundUdpSession>> {
            let (reply_tx, reply_rx) = mpsc::channel(16);
            Ok(Box::new(RecordingTargetUdpSession {
                sent: Arc::clone(&self.sent),
                reply_rx: AsyncMutex::new(reply_rx),
                reply_tx,
            }))
        }
    }

    #[tokio::test]
    async fn quic_sni_sniffing_routes_overrides_proxy_preserves_direct_and_recovers_fake_ip() {
        use crate::inbound::sniff::{
            QUIC_VERSION_1, QUIC_VERSION_2, test_helpers::build_quic_initial_packet,
        };

        let proxy_sent = Arc::new(AsyncMutex::new(Vec::new()));
        let direct_sent = Arc::new(AsyncMutex::new(Vec::new()));
        let fallback_sent = Arc::new(AsyncMutex::new(Vec::new()));

        let mut outbounds: HashMap<String, DynOutbound> = HashMap::new();
        outbounds.insert(
            "proxy-quic".to_string(),
            Arc::new(RecordingUdpOutbound {
                name: "proxy-quic",
                category: "PROXY",
                sent: Arc::clone(&proxy_sent),
            }),
        );
        outbounds.insert(
            "direct-mock".to_string(),
            Arc::new(RecordingUdpOutbound {
                name: "direct-mock",
                category: "DIRECT",
                sent: Arc::clone(&direct_sent),
            }),
        );
        outbounds.insert(
            "fallback".to_string(),
            Arc::new(RecordingUdpOutbound {
                name: "fallback",
                category: "PROXY",
                sent: Arc::clone(&fallback_sent),
            }),
        );

        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let router = Arc::new(
            crate::router::Router::new(
                crate::config::RunMode::Rule,
                outbounds,
                &[],
                &[
                    "DOMAIN-SUFFIX,direct.quic.test,direct-mock".to_string(),
                    "DOMAIN-SUFFIX,builtin-direct.quic.test,DIRECT".to_string(),
                    "DOMAIN-SUFFIX,quic.test,proxy-quic".to_string(),
                    "MATCH,fallback".to_string(),
                ],
                Arc::clone(&dns),
            )
            .unwrap(),
        );
        let mut sniffer = crate::config::SnifferConfig::default();
        sniffer.skip_domain.push("skip.quic.test".to_string());
        router.set_sniffer(sniffer);

        let hub = Arc::new(TelemetryHub::new());
        let replies = Arc::new(Mutex::new(Vec::<(SocketAddr, TargetAddr, Vec<u8>)>::new()));
        let replies_sink = Arc::clone(&replies);
        let mgr = UdpNatManager::new(
            "TUN(smoltcp)",
            64,
            Arc::clone(&hub),
            Arc::new(move |src, ret_target, payload| {
                replies_sink.lock().push((src, ret_target, payload));
            }),
        );

        let epoch = router.epoch();

        // 1. Real-IP QUIC v1 Initial (UDP 443) -> sniffed SNI routes to `proxy-quic`,
        //    overrides dial target to domain, sets `metadata.sniffed == true`, maps reply back to real IP,
        //    and caches fast route for follow-up Short-Header QUIC packets.
        let src1: SocketAddr = "198.18.0.1:51001".parse().unwrap();
        let raw_dst1_sock: SocketAddr = "104.16.132.229:443".parse().unwrap();
        let raw_dst1 = TargetAddr::from(raw_dst1_sock);
        let quic_v1 = build_quic_initial_packet(
            QUIC_VERSION_1,
            b"\x83\x94\xc8\xf0\x3e\x51\x57\x08",
            "edge.quic.test",
        );
        let res1 = route_udp_datagram_with_quic_sniff(&router, src1, &raw_dst1, &quic_v1).await;
        assert!(res1.sniffed);
        assert_eq!(res1.decision.outbound.name(), "proxy-quic");
        assert_eq!(res1.decision.rule_type, "DomainSuffix");
        assert_eq!(
            res1.dial_target,
            TargetAddr::new_domain("edge.quic.test", 443).unwrap()
        );
        mgr.send_datagram_with_options(
            src1,
            raw_dst1.clone(),
            res1.decision.restored_from_fake_ip,
            res1.decision.target,
            res1.dial_target,
            &res1.decision.rule_type,
            &res1.decision.rule_payload,
            res1.decision.chains,
            res1.decision.outbound,
            quic_v1,
            epoch,
            res1.sniffed,
        )
        .await;
        // Follow-up QUIC Short Header packet hits O(1) fast path using cached domain dial target!
        let short_hdr_pkt = vec![0x43, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(
            mgr.try_send_fast(src1, raw_dst1_sock, epoch, short_hdr_pkt.clone()),
            Ok(())
        );

        // 2. Real-IP QUIC v2 Initial matching `DIRECT`-category rule -> keeps raw IP as dial target!
        let src2: SocketAddr = "198.18.0.1:51002".parse().unwrap();
        let raw_dst2: TargetAddr = "93.184.216.34:443".parse().unwrap();
        let quic_direct = build_quic_initial_packet(
            QUIC_VERSION_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
            "api.direct.quic.test",
        );
        let res2 = route_udp_datagram_with_quic_sniff(&router, src2, &raw_dst2, &quic_direct).await;
        assert!(res2.sniffed);
        assert_eq!(res2.decision.outbound.name(), "direct-mock");
        assert_eq!(
            res2.decision.target,
            TargetAddr::new_domain("api.direct.quic.test", 443).unwrap()
        );
        assert_eq!(
            res2.dial_target, raw_dst2,
            "DIRECT outbound must retain original IP as dial target"
        );
        // Also verify built-in `DIRECT` outbound preserves raw IP without overriding dial target.
        let quic_builtin_direct = build_quic_initial_packet(
            QUIC_VERSION_1,
            b"\x11\x22\x33\x44\x55\x66\x77\x88",
            "api.builtin-direct.quic.test",
        );
        let res2_builtin =
            route_udp_datagram_with_quic_sniff(&router, src2, &raw_dst2, &quic_builtin_direct)
                .await;
        assert!(res2_builtin.sniffed);
        assert_eq!(res2_builtin.decision.outbound.name(), "DIRECT");
        assert_eq!(res2_builtin.dial_target, raw_dst2);
        mgr.send_datagram_with_options(
            src2,
            raw_dst2.clone(),
            res2.decision.restored_from_fake_ip,
            res2.decision.target,
            res2.dial_target,
            &res2.decision.rule_type,
            &res2.decision.rule_payload,
            res2.decision.chains,
            res2.decision.outbound,
            quic_direct,
            epoch,
            res2.sniffed,
        )
        .await;

        // 3. Real-IP QUIC v1 Initial hitting `skip-domain` -> matches domain rule to `proxy-quic`,
        //    but preserves original IP as dial target!
        let src3: SocketAddr = "198.18.0.1:51003".parse().unwrap();
        let raw_dst3: TargetAddr = "104.16.133.229:443".parse().unwrap();
        let quic_skip = build_quic_initial_packet(
            QUIC_VERSION_1,
            b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11",
            "skip.quic.test",
        );
        let res3 = route_udp_datagram_with_quic_sniff(&router, src3, &raw_dst3, &quic_skip).await;
        assert!(res3.sniffed);
        assert_eq!(res3.decision.outbound.name(), "proxy-quic");
        assert_eq!(
            res3.dial_target, raw_dst3,
            "skip-domain must preserve original IP without overriding dial target"
        );

        // 4. Unmapped Fake-IP (`198.18.9.9:443`) with QUIC v1 Initial -> recovers Fake-IP mapping!
        let src4: SocketAddr = "198.18.0.1:51004".parse().unwrap();
        let unmapped_fake: TargetAddr = "198.18.9.9:443".parse().unwrap();
        assert!(dns.is_unmapped_fake_ip(&unmapped_fake));
        let quic_fake = build_quic_initial_packet(
            QUIC_VERSION_1,
            b"\x10\x20\x30\x40\x50\x60\x70\x80",
            "recovered.quic.test",
        );
        let res4 =
            route_udp_datagram_with_quic_sniff(&router, src4, &unmapped_fake, &quic_fake).await;
        assert!(
            !res4.sniffed,
            "recovered Fake-IP is not a real-IP sniff hit"
        );
        assert_eq!(
            res4.decision.restored_from_fake_ip,
            Some(Ipv4Addr::new(198, 18, 9, 9))
        );
        assert_eq!(res4.decision.outbound.name(), "proxy-quic");
        assert_eq!(
            res4.dial_target,
            TargetAddr::new_domain("recovered.quic.test", 443).unwrap()
        );
        assert_eq!(
            dns.lookup_domain(IpAddr::V4(Ipv4Addr::new(198, 18, 9, 9)))
                .as_deref(),
            Some("recovered.quic.test")
        );

        // 5. Malformed / non-Initial UDP payload on 443 -> fast fallback to raw IP, zero panic.
        let src5: SocketAddr = "198.18.0.1:51005".parse().unwrap();
        let raw_dst5: TargetAddr = "104.16.134.229:443".parse().unwrap();
        for bad in [
            &b""[..],
            &[0x43, 0x01, 0x02],
            &[0xc3, 0x00, 0x00, 0x00, 0x01, 0xff],
        ] {
            let res_bad = route_udp_datagram_with_quic_sniff(&router, src5, &raw_dst5, bad).await;
            assert!(!res_bad.sniffed);
            assert_eq!(res_bad.decision.outbound.name(), "fallback");
            assert_eq!(res_bad.dial_target, raw_dst5);
        }

        // Wait for async UDP NAT workers to deliver packets & replies.
        for _ in 0..100 {
            if proxy_sent.lock().await.len() >= 2
                && !direct_sent.lock().await.is_empty()
                && !replies.lock().is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let ps = proxy_sent.lock().await.clone();
        assert_eq!(ps.len(), 2);
        assert_eq!(
            ps[0].0,
            TargetAddr::new_domain("edge.quic.test", 443).unwrap()
        );
        assert_eq!(
            ps[1].0,
            TargetAddr::new_domain("edge.quic.test", 443).unwrap()
        );
        assert_eq!(ps[1].1, short_hdr_pkt);

        let ds = direct_sent.lock().await.clone();
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].0, raw_dst2);

        // Reply from `proxy-quic` must be reverse-mapped back to original client dst `104.16.132.229:443`!
        assert!(
            replies
                .lock()
                .iter()
                .any(|(c, ret, _)| *c == src1 && *ret == raw_dst1),
            "PROXY reply must reverse-map sniffed domain back to raw_dst1"
        );

        let active = hub.list_connections();
        assert!(
            active
                .iter()
                .any(|c| c.metadata.host == "edge.quic.test" && c.metadata.sniffed),
            "QUIC sniffed real-IP flow must record metadata.sniffed == true"
        );
        assert!(
            active
                .iter()
                .any(|c| c.metadata.host == "api.direct.quic.test" && c.metadata.sniffed),
            "DIRECT QUIC sniffed flow must also record sniffed domain and metadata.sniffed == true"
        );

        mgr.shutdown();
    }

    #[tokio::test]
    async fn cache_fast_route_eviction_does_not_deadlock_at_capacity() {
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, _) = watch::channel(false);
        let mgr_small = Arc::new(UdpNatManager {
            inbound_label: "test-fast-route-cap4",
            max_sessions: 1, // cap = max_sessions * 4 = 4
            idle_timeout: DEFAULT_UDP_IDLE_TIMEOUT,
            boot: Instant::now(),
            closed: AtomicBool::new(false),
            shutdown_tx,
            evict_lock: Mutex::new(()),
            fast_route_evict_lock: Mutex::new(0),
            sessions: Arc::new(DashMap::new()),
            fast_routes: Arc::new(DashMap::new()),
            hub: Arc::clone(&hub),
            reply_sink: Arc::new(|_, _, _| {}),
        });

        let mgr_small_run = Arc::clone(&mgr_small);
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::task::spawn_blocking(move || {
                for i in 0u16..10 {
                    let src: SocketAddr = format!("198.18.0.2:{}", 40_000 + i).parse().unwrap();
                    let dst: TargetAddr = format!("93.184.216.{}:443", 10 + i).parse().unwrap();
                    mgr_small_run.cache_fast_route(src, &dst, "DIRECT", None, &dst, false, 1);
                }
            }),
        )
        .await
        .expect("cache_fast_route must not self-deadlock on DashMap shard eviction")
        .unwrap();
        assert!(
            mgr_small.fast_routes.len() <= 4,
            "fast_routes must remain bounded to cap=4, got {}",
            mgr_small.fast_routes.len()
        );
        assert_eq!(mgr_small.fast_routes.len(), 4);

        // Also exercise the public constructor floor (`max_sessions.max(16)` -> cap = 64).
        let mgr_pub = UdpNatManager::new("test-fast-route-pub", 1, hub, Arc::new(|_, _, _| {}));
        let mgr_pub_run = Arc::clone(&mgr_pub);
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::task::spawn_blocking(move || {
                for i in 0u16..80 {
                    let src: SocketAddr = format!("198.18.0.3:{}", 41_000 + i).parse().unwrap();
                    let dst: TargetAddr = format!("1.1.1.{}:443", 1 + (i % 200)).parse().unwrap();
                    mgr_pub_run.cache_fast_route(src, &dst, "DIRECT", None, &dst, false, 2);
                }
            }),
        )
        .await
        .expect("public UdpNatManager cache_fast_route eviction must not deadlock")
        .unwrap();
        assert!(mgr_pub.fast_routes.len() <= 64);
        assert_eq!(mgr_pub.fast_routes.len(), 64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn cache_fast_route_multithread_stress_stays_bounded_without_deadlock() {
        let hub = Arc::new(TelemetryHub::new());
        let mgr = UdpNatManager::new("test-mt-fast-route", 16, hub, Arc::new(|_, _, _| {}));
        let cap = 16usize * 4; // 64
        let done = Arc::new(AtomicBool::new(false));
        let max_observed = Arc::new(AtomicUsize::new(0));

        // Concurrent observer taking linearizable `fast_routes.len()` snapshots under
        // `fast_route_evict_lock` mid-flight to verify the hard bound holds continuously
        // (not merely at quiescence) without torn cross-shard `DashMap::len()` sums.
        let mgr_obs = Arc::clone(&mgr);
        let done_obs = Arc::clone(&done);
        let max_obs = Arc::clone(&max_observed);
        let observer = tokio::spawn(async move {
            let mut samples = 0usize;
            while !done_obs.load(Ordering::Acquire) {
                let len = {
                    let _guard = mgr_obs.fast_route_evict_lock.lock();
                    mgr_obs.fast_routes.len()
                };
                max_obs.fetch_max(len, Ordering::AcqRel);
                samples += 1;
                tokio::task::yield_now().await;
            }
            samples
        });

        let mut tasks = Vec::with_capacity(16);
        for worker in 0usize..16 {
            let mgr_w = Arc::clone(&mgr);
            tasks.push(tokio::spawn(async move {
                let src: SocketAddr = format!("198.18.0.{}:{}", 10 + worker, 40_000 + worker)
                    .parse()
                    .unwrap();
                for i in 0u32..1000 {
                    let octet3 = ((worker * 4) + ((i / 250) as usize)) as u8;
                    let octet4 = ((i % 250) + 1) as u8;
                    let dst_sock: SocketAddr = format!(
                        "10.{}.{}.{}:{}",
                        worker + 1,
                        octet3,
                        octet4,
                        1000 + (i % 500)
                    )
                    .parse()
                    .unwrap();
                    let dst = TargetAddr::from(dst_sock);
                    mgr_w.cache_fast_route(src, &dst, "DIRECT", None, &dst, false, 1);
                    // Interleave concurrent `try_send_fast` reads on the hot path.
                    let _ = mgr_w.try_send_fast(src, dst_sock, 1, vec![0x42]);
                }
            }));
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            for t in tasks {
                t.await.expect("worker task must not panic");
            }
        })
        .await
        .expect("16-task multi-threaded cache_fast_route + try_send_fast must not deadlock");

        done.store(true, Ordering::Release);
        let samples = observer.await.expect("observer task must not panic");
        assert!(
            samples > 0,
            "observer must record mid-flight linearizable snapshots during concurrent stress"
        );

        let live_cached_routes = mgr.fast_routes.len();
        assert!(
            live_cached_routes <= cap,
            "fast_routes overflowed cap={cap}: observed live_cached_routes={live_cached_routes}"
        );
        assert_eq!(
            live_cached_routes, cap,
            "cache should stay populated up to cap={cap}, got {live_cached_routes}"
        );
        let peak = max_observed.load(Ordering::Acquire);
        assert!(
            peak <= cap,
            "fast_routes transiently exceeded cap={cap} mid-flight: peak={peak}"
        );

        // Verify epoch bump under concurrency clears stale epoch-1 routes and stays bounded.
        let mut epoch2_tasks = Vec::with_capacity(8);
        for worker in 0usize..8 {
            let mgr_w = Arc::clone(&mgr);
            epoch2_tasks.push(tokio::spawn(async move {
                let src: SocketAddr = format!("198.18.1.{}:{}", 10 + worker, 45_000 + worker)
                    .parse()
                    .unwrap();
                for i in 0u32..100 {
                    let dst_sock: SocketAddr =
                        format!("172.16.{}.{}:443", worker + 1, (i % 250) + 1)
                            .parse()
                            .unwrap();
                    let dst = TargetAddr::from(dst_sock);
                    mgr_w.cache_fast_route(src, &dst, "DIRECT", None, &dst, false, 2);
                    let _ = mgr_w.try_send_fast(src, dst_sock, 2, vec![0x24]);
                }
            }));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            for t in epoch2_tasks {
                t.await.expect("epoch2 worker must not panic");
            }
        })
        .await
        .expect("concurrent epoch-2 cache_fast_route must not deadlock");

        assert!(
            mgr.fast_routes.len() <= cap,
            "epoch-2 fast_routes overflowed cap={cap}: got {}",
            mgr.fast_routes.len()
        );
        assert!(
            mgr.fast_routes.iter().all(|e| e.value().router_epoch == 2),
            "stale epoch-1 routes must be evicted once epoch-2 hits capacity"
        );
    }

    struct CancelCountingUdpSession {
        send_count: Arc<AtomicUsize>,
        recv_started: Arc<AtomicUsize>,
        recv_cancellations: Arc<AtomicUsize>,
        recv_gate: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl OutboundUdpSession for CancelCountingUdpSession {
        async fn send_to(&self, _payload: &[u8], _target: &TargetAddr) -> std::io::Result<()> {
            self.send_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, TargetAddr)> {
            struct CancelGuard {
                armed: bool,
                cancellations: Arc<AtomicUsize>,
            }
            impl Drop for CancelGuard {
                fn drop(&mut self) {
                    if self.armed {
                        self.cancellations.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }

            self.recv_started.fetch_add(1, Ordering::SeqCst);
            let mut guard = CancelGuard {
                armed: true,
                cancellations: Arc::clone(&self.recv_cancellations),
            };
            self.recv_gate.notified().await;
            guard.armed = false;
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ))
        }
    }

    struct CancelCountingUdpOutbound {
        send_count: Arc<AtomicUsize>,
        recv_started: Arc<AtomicUsize>,
        recv_cancellations: Arc<AtomicUsize>,
        recv_gate: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl OutboundHandler for CancelCountingUdpOutbound {
        fn name(&self) -> &str {
            "cancel-counting-uot"
        }

        fn protocol(&self) -> &'static str {
            "anytls"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> std::io::Result<BoxedStream> {
            Err(std::io::Error::other("unused"))
        }

        async fn open_udp_session(&self) -> std::io::Result<Box<dyn OutboundUdpSession>> {
            Ok(Box::new(CancelCountingUdpSession {
                send_count: Arc::clone(&self.send_count),
                recv_started: Arc::clone(&self.recv_started),
                recv_cancellations: Arc::clone(&self.recv_cancellations),
                recv_gate: Arc::clone(&self.recv_gate),
            }))
        }
    }

    #[tokio::test]
    async fn udp_nat_active_session_does_not_cancel_recv_from_before_real_idle_expiry() {
        let hub = Arc::new(TelemetryHub::new());
        let idle_timeout = Duration::from_millis(80);
        let mgr = UdpNatManager::with_idle_timeout(
            "test-idle-watchdog",
            16,
            idle_timeout,
            Arc::clone(&hub),
            Arc::new(|_, _, _| {}),
        );

        let send_count = Arc::new(AtomicUsize::new(0));
        let recv_started = Arc::new(AtomicUsize::new(0));
        let recv_cancellations = Arc::new(AtomicUsize::new(0));
        let recv_gate = Arc::new(tokio::sync::Notify::new());
        let outbound: DynOutbound = Arc::new(CancelCountingUdpOutbound {
            send_count: Arc::clone(&send_count),
            recv_started: Arc::clone(&recv_started),
            recv_cancellations: Arc::clone(&recv_cancellations),
            recv_gate: Arc::clone(&recv_gate),
        });

        let src: SocketAddr = "198.18.0.2:57001".parse().unwrap();
        let dst: TargetAddr = "1.1.1.1:443".parse().unwrap();

        mgr.send_datagram(
            src,
            dst.clone(),
            None,
            dst.clone(),
            "MATCH",
            "",
            vec!["cancel-counting-uot".into()],
            Arc::clone(&outbound),
            vec![1],
        )
        .await;

        tokio::time::timeout(Duration::from_secs(1), async {
            while recv_started.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("reader must start awaiting recv_from");

        // Continuously refresh activity well past the 80ms idle timeout (~240ms total).
        for seq in 2u8..=9 {
            tokio::time::sleep(Duration::from_millis(30)).await;
            mgr.send_datagram(
                src,
                dst.clone(),
                None,
                dst.clone(),
                "MATCH",
                "",
                vec!["cancel-counting-uot".into()],
                Arc::clone(&outbound),
                vec![seq],
            )
            .await;
        }

        assert_eq!(
            recv_cancellations.load(Ordering::SeqCst),
            0,
            "active UDP session must NEVER cancel session_rx.recv_from() while activity refreshes idle watchdog"
        );
        assert_eq!(
            recv_started.load(Ordering::SeqCst),
            1,
            "recv_from() must stay continuously pending without restart while active"
        );
        assert_eq!(mgr.active_session_count(), 1);
        assert!(send_count.load(Ordering::SeqCst) >= 8);

        // Once genuinely idle past 80ms, idle_watchdog must cleanly tear down the session.
        tokio::time::timeout(Duration::from_millis(500), async {
            while mgr.active_session_count() != 0 || hub.active_connection_count() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("truly idle UDP session must expire cleanly after idle_timeout");

        assert_eq!(
            recv_cancellations.load(Ordering::SeqCst),
            1,
            "recv_from() should be cancelled exactly once at true idle teardown"
        );
    }
}
