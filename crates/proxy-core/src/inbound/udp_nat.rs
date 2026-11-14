use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;

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
    target_to_raw: HashMap<TargetAddr, TargetAddr>,
    port_to_fake_raw: HashMap<u16, PortFakeMapping>,
    last_raw_dst: Option<TargetAddr>,
}

impl ReverseTargetMap {
    fn has_outbound(&self, target: &TargetAddr, raw_dst: &TargetAddr, was_fake_ip: bool) -> bool {
        if self.target_to_raw.get(target) != Some(raw_dst) {
            return false;
        }
        if self.last_raw_dst.as_ref() != Some(raw_dst) {
            return false;
        }
        if was_fake_ip || matches!(target.host, HostName::Domain(_)) {
            match self.port_to_fake_raw.get(&target.port) {
                Some(PortFakeMapping::Unique(existing)) => existing == raw_dst,
                Some(PortFakeMapping::Ambiguous) => true,
                None => false,
            }
        } else {
            true
        }
    }

    fn record_outbound(&mut self, target: &TargetAddr, raw_dst: &TargetAddr, was_fake_ip: bool) {
        if self.target_to_raw.contains_key(target)
            || self.target_to_raw.len() < MAX_UDP_DESTS_PER_SESSION
        {
            self.target_to_raw.insert(target.clone(), raw_dst.clone());
        }
        if was_fake_ip || matches!(target.host, HostName::Domain(_)) {
            if let Some(mapping) = self.port_to_fake_raw.get_mut(&target.port) {
                if let PortFakeMapping::Unique(existing) = mapping
                    && existing != raw_dst
                {
                    *mapping = PortFakeMapping::Ambiguous;
                }
            } else if self.port_to_fake_raw.len() < MAX_UDP_DESTS_PER_SESSION {
                self.port_to_fake_raw
                    .insert(target.port, PortFakeMapping::Unique(raw_dst.clone()));
            }
        }
        self.last_raw_dst = Some(raw_dst.clone());
    }

    fn map_return_source(&self, remote_src: &TargetAddr) -> TargetAddr {
        if let Some(raw) = self.target_to_raw.get(remote_src) {
            return raw.clone();
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
}

#[derive(Clone, Debug)]
struct CachedUdpRoute {
    outbound_name: String,
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
    idle_timeout_ms: u64,
}

/// Callback invoked whenever an `OutboundUdpSession` yields a response datagram back toward the client.
/// Parameters: `(client_src, effective_return_target, payload)`.
pub type UdpReplySink = Arc<dyn Fn(SocketAddr, TargetAddr, Vec<u8>) + Send + Sync>;

/// Stateful multi-datagram UDP NAT manager shared by TUN and SOCKS5 `UDP ASSOCIATE`.
/// Maintains persistent `OutboundUdpSession`s per `(client_src, outbound)` so QUIC/HTTP3,
/// gaming, and STUN/WebRTC flows preserve NAT port bindings and avoid per-datagram handshakes.
pub struct UdpNatManager {
    inbound_label: &'static str,
    max_sessions: usize,
    idle_timeout: Duration,
    boot: Instant,
    sessions: Arc<DashMap<NatSessionKey, NatSessionEntry>>,
    fast_routes: Arc<DashMap<(SocketAddr, SocketAddr), CachedUdpRoute>>,
    hub: Arc<TelemetryHub>,
    reply_sink: UdpReplySink,
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
        let mgr = Arc::new(Self {
            inbound_label,
            max_sessions: max_sessions.max(16),
            idle_timeout,
            boot: Instant::now(),
            sessions: Arc::new(DashMap::new()),
            fast_routes: Arc::new(DashMap::new()),
            hub: Arc::clone(&hub),
            reply_sink,
        });
        let weak: std::sync::Weak<dyn SessionResetter> =
            Arc::downgrade(&mgr) as std::sync::Weak<dyn SessionResetter>;
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
            let mono_idle = now_mono.saturating_sub(entry.last_active_ms.load(Ordering::Relaxed));
            let wall_idle =
                now_wall.saturating_sub(entry.last_active_wall_ms.load(Ordering::Relaxed));
            let keep = !entry.tx.is_closed()
                && !entry.conn_entry.is_closed()
                && mono_idle < entry.idle_timeout_ms
                && wall_idle < entry.idle_timeout_ms;
            if !keep {
                evicted.push((key.clone(), Arc::clone(&entry.conn_entry)));
            }
            keep
        });
        if evicted.is_empty() {
            return 0;
        }
        for (ek, conn_entry) in &evicted {
            self.fast_routes
                .retain(|rk, rv| !(rk.0 == ek.client_src && rv.outbound_name == ek.outbound_name));
            conn_entry.request_close();
            self.hub.unregister_connection(&conn_entry.id);
        }
        evicted.len()
    }

    fn cache_fast_route(
        &self,
        client_src: SocketAddr,
        raw_dst: &TargetAddr,
        outbound_name: &str,
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
        let route_key = (client_src, SocketAddr::new(dst_ip, raw_dst.port));
        let cap = self.max_sessions.saturating_mul(4);
        if self.fast_routes.len() >= cap && !self.fast_routes.contains_key(&route_key) {
            self.fast_routes
                .retain(|_, v| v.router_epoch == router_epoch);
            if self.fast_routes.len() >= cap
                && let Some(victim) = self.fast_routes.iter().next().map(|e| *e.key())
            {
                self.fast_routes.remove(&victim);
            }
        }
        self.fast_routes.insert(
            route_key,
            CachedUdpRoute {
                outbound_name: outbound_name.to_string(),
                resolved_target: resolved_target.clone(),
                was_fake_ip,
                router_epoch,
            },
        );
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
        if router_epoch == 0 {
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
        restored_from_fake_ip: Option<std::net::Ipv4Addr>,
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
        restored_from_fake_ip: Option<std::net::Ipv4Addr>,
        target: TargetAddr,
        rule_type: &str,
        rule_payload: &str,
        chains: Vec<String>,
        outbound: DynOutbound,
        payload: Vec<u8>,
        router_epoch: u64,
    ) {
        if !outbound.udp_supported() {
            let reason = match outbound.exit_category() {
                "REJECT" => "blocked by REJECT rule",
                "ERROR" => "routing chain resolution error",
                _ => "selected outbound does not support UDP relay",
            };
            self.hub.record_instant_failed_diagnostic(
                self.inbound_label,
                "udp",
                Some(client_src),
                &target,
                restored_from_fake_ip.map(|ip| ip.to_string()),
                rule_type,
                rule_payload,
                chains,
                outbound.as_ref(),
                reason,
            );
            return;
        }

        let key = NatSessionKey {
            client_src,
            outbound_name: outbound.name().to_string(),
        };
        let now_ms = self.now_ms();
        let now_wall_ms = TelemetryHub::now_ms();
        let was_fake_ip = restored_from_fake_ip.is_some();

        // Fast-path check before potentially running capacity eviction.
        if let Some(existing) = self.sessions.get(&key)
            && !existing.tx.is_closed()
            && !existing.conn_entry.is_closed()
        {
            existing.last_active_ms.store(now_ms, Ordering::Relaxed);
            existing
                .last_active_wall_ms
                .store(now_wall_ms, Ordering::Relaxed);
            let needs_map_update =
                !existing
                    .reverse_map
                    .read()
                    .has_outbound(&target, &raw_dst, was_fake_ip);
            if needs_map_update {
                existing
                    .reverse_map
                    .write()
                    .record_outbound(&target, &raw_dst, was_fake_ip);
            }
            self.hub.record_upload(&existing.conn_entry, payload.len());
            let _ = existing.tx.try_send((target.clone(), payload));
            drop(existing);
            self.cache_fast_route(
                client_src,
                &raw_dst,
                outbound.name(),
                &target,
                was_fake_ip,
                router_epoch,
            );
            return;
        }

        if self.sessions.len() >= self.max_sessions {
            let _ = self.reap_idle_sessions();
            if self.sessions.len() >= self.max_sessions {
                let oldest_key = self
                    .sessions
                    .iter()
                    .min_by_key(|entry| entry.value().last_active_ms.load(Ordering::Relaxed))
                    .map(|entry| entry.key().clone());
                if let Some(k) = oldest_key
                    && let Some((_, evicted)) = self.sessions.remove(&k)
                {
                    evicted.conn_entry.request_close();
                    self.hub.unregister_connection(&evicted.conn_entry.id);
                    self.fast_routes.retain(|rk, rv| {
                        !(rk.0 == k.client_src && rv.outbound_name == k.outbound_name)
                    });
                }
            }
        }

        let session_timeout = self.session_idle_timeout(target.port);
        let idle_timeout_ms = (session_timeout.as_millis() as u64).max(1);

        // Synchronously claim or join the session slot BEFORE any `.await` (`open_udp_session`),
        // preventing concurrent QUIC Initial bursts from opening N parallel upstream sessions!
        let (rx, conn_entry, reverse_map, last_active_ms, last_active_wall_ms) = match self
            .sessions
            .entry(key.clone())
        {
            dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                if !occ.get().tx.is_closed() && !occ.get().conn_entry.is_closed() {
                    occ.get().last_active_ms.store(now_ms, Ordering::Relaxed);
                    occ.get()
                        .last_active_wall_ms
                        .store(now_wall_ms, Ordering::Relaxed);
                    occ.get()
                        .reverse_map
                        .write()
                        .record_outbound(&target, &raw_dst, was_fake_ip);
                    self.hub.record_upload(&occ.get().conn_entry, payload.len());
                    let _ = occ.get().tx.try_send((target.clone(), payload));
                    drop(occ);
                    self.cache_fast_route(
                        client_src,
                        &raw_dst,
                        outbound.name(),
                        &target,
                        was_fake_ip,
                        router_epoch,
                    );
                    return;
                }
                let conn_entry = self.hub.register_connection_with_outbound(
                    self.inbound_label,
                    "udp",
                    Some(client_src),
                    &target,
                    restored_from_fake_ip.map(|ip| ip.to_string()),
                    rule_type,
                    rule_payload,
                    chains.clone(),
                    outbound.as_ref(),
                );
                self.hub.record_upload(&conn_entry, payload.len());
                let reverse_map = Arc::new(RwLock::new(ReverseTargetMap::default()));
                reverse_map
                    .write()
                    .record_outbound(&target, &raw_dst, was_fake_ip);
                let last_active_ms = Arc::new(AtomicU64::new(now_ms));
                let last_active_wall_ms = Arc::new(AtomicU64::new(now_wall_ms));
                let (tx, rx) = mpsc::channel::<(TargetAddr, Vec<u8>)>(UDP_SESSION_QUEUE_CAPACITY);
                let _ = tx.try_send((target.clone(), payload));
                let evicted = occ.insert(NatSessionEntry {
                    tx,
                    reverse_map: Arc::clone(&reverse_map),
                    conn_entry: Arc::clone(&conn_entry),
                    last_active_ms: Arc::clone(&last_active_ms),
                    last_active_wall_ms: Arc::clone(&last_active_wall_ms),
                    idle_timeout_ms,
                });
                evicted.conn_entry.request_close();
                self.hub.unregister_connection(&evicted.conn_entry.id);
                (
                    rx,
                    conn_entry,
                    reverse_map,
                    last_active_ms,
                    last_active_wall_ms,
                )
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                let conn_entry = self.hub.register_connection_with_outbound(
                    self.inbound_label,
                    "udp",
                    Some(client_src),
                    &target,
                    restored_from_fake_ip.map(|ip| ip.to_string()),
                    rule_type,
                    rule_payload,
                    chains.clone(),
                    outbound.as_ref(),
                );
                self.hub.record_upload(&conn_entry, payload.len());
                let reverse_map = Arc::new(RwLock::new(ReverseTargetMap::default()));
                reverse_map
                    .write()
                    .record_outbound(&target, &raw_dst, was_fake_ip);
                let last_active_ms = Arc::new(AtomicU64::new(now_ms));
                let last_active_wall_ms = Arc::new(AtomicU64::new(now_wall_ms));
                let (tx, rx) = mpsc::channel::<(TargetAddr, Vec<u8>)>(UDP_SESSION_QUEUE_CAPACITY);
                let _ = tx.try_send((target.clone(), payload));
                vac.insert(NatSessionEntry {
                    tx,
                    reverse_map: Arc::clone(&reverse_map),
                    conn_entry: Arc::clone(&conn_entry),
                    last_active_ms: Arc::clone(&last_active_ms),
                    last_active_wall_ms: Arc::clone(&last_active_wall_ms),
                    idle_timeout_ms,
                });
                (
                    rx,
                    conn_entry,
                    reverse_map,
                    last_active_ms,
                    last_active_wall_ms,
                )
            }
        };

        self.cache_fast_route(
            client_src,
            &raw_dst,
            outbound.name(),
            &target,
            was_fake_ip,
            router_epoch,
        );

        let inbound_label = self.inbound_label;
        let hub_clone = Arc::clone(&self.hub);
        let sessions_map = Arc::clone(&self.sessions);
        let fast_routes_map = Arc::clone(&self.fast_routes);
        let sink = Arc::clone(&self.reply_sink);
        let boot = self.boot;

        tokio::spawn(async move {
            let mut rx = rx;
            let session = tokio::select! {
                biased;
                _ = conn_entry.closed() => {
                    if sessions_map
                        .remove_if(&key, |_, v| Arc::ptr_eq(&v.conn_entry, &conn_entry))
                        .is_some()
                    {
                        fast_routes_map.retain(|rk, rv| {
                            !(rk.0 == key.client_src && rv.outbound_name == key.outbound_name)
                        });
                    }
                    hub_clone.unregister_connection(&conn_entry.id);
                    return;
                }
                res = outbound.open_udp_session() => {
                    match res {
                        Ok(s) => Arc::new(s),
                        Err(err) => {
                            tracing::debug!(
                                "[{}] open_udp_session on '{}' failed for {} -> {}: {}",
                                inbound_label,
                                outbound.name(),
                                client_src,
                                target,
                                err
                            );
                            if sessions_map
                                .remove_if(&key, |_, v| Arc::ptr_eq(&v.conn_entry, &conn_entry))
                                .is_some()
                            {
                                fast_routes_map.retain(|rk, rv| {
                                    !(rk.0 == key.client_src && rv.outbound_name == key.outbound_name)
                                });
                            }
                            hub_clone.record_connection_failed(&conn_entry.id, &err.to_string());
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
                res = tokio::time::timeout(session_timeout, async {
                    let Some((first_dst, first_data)) = rx.recv().await else {
                        return Ok(false);
                    };
                    last_active_ms.store(boot.elapsed().as_millis() as u64, Ordering::Relaxed);
                    last_active_wall_ms.store(TelemetryHub::now_ms(), Ordering::Relaxed);
                    session.send_to(&first_data, &first_dst).await.map(|()| true)
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
                    if sessions_map
                        .remove_if(&key, |_, v| Arc::ptr_eq(&v.conn_entry, &conn_entry))
                        .is_some()
                    {
                        fast_routes_map.retain(|rk, rv| {
                            !(rk.0 == key.client_src && rv.outbound_name == key.outbound_name)
                        });
                    }
                    hub_clone.record_connection_failed(&conn_entry.id, &err.to_string());
                    return;
                }
                FirstPacketOutcome::ClosedOrIdle => {
                    if sessions_map
                        .remove_if(&key, |_, v| Arc::ptr_eq(&v.conn_entry, &conn_entry))
                        .is_some()
                    {
                        fast_routes_map.retain(|rk, rv| {
                            !(rk.0 == key.client_src && rv.outbound_name == key.outbound_name)
                        });
                    }
                    hub_clone.unregister_connection(&conn_entry.id);
                    return;
                }
            }

            let session_rx = Arc::clone(&session);
            let writer_last = Arc::clone(&last_active_ms);
            let writer_last_wall = Arc::clone(&last_active_wall_ms);
            let writer = async move {
                while let Some((dst, data)) = rx.recv().await {
                    writer_last.store(boot.elapsed().as_millis() as u64, Ordering::Relaxed);
                    writer_last_wall.store(TelemetryHub::now_ms(), Ordering::Relaxed);
                    if session.send_to(&data, &dst).await.is_err() {
                        break;
                    }
                }
            };

            let conn_dl = Arc::clone(&conn_entry);
            let hub_dl = Arc::clone(&hub_clone);
            let rev_dl = Arc::clone(&reverse_map);
            let reader_last = Arc::clone(&last_active_ms);
            let reader_last_wall = Arc::clone(&last_active_wall_ms);
            let reader = async move {
                loop {
                    let now_mono = boot.elapsed().as_millis() as u64;
                    let now_wall = TelemetryHub::now_ms();
                    let mono_idle = now_mono.saturating_sub(reader_last.load(Ordering::Relaxed));
                    let wall_idle =
                        now_wall.saturating_sub(reader_last_wall.load(Ordering::Relaxed));
                    if mono_idle >= idle_timeout_ms || wall_idle >= idle_timeout_ms {
                        break;
                    }
                    let sleep_ms = (idle_timeout_ms - mono_idle)
                        .min(idle_timeout_ms - wall_idle)
                        .max(1);
                    match tokio::time::timeout(
                        Duration::from_millis(sleep_ms),
                        session_rx.recv_from(),
                    )
                    .await
                    {
                        Ok(Ok((resp, remote_src))) => {
                            reader_last.store(boot.elapsed().as_millis() as u64, Ordering::Relaxed);
                            reader_last_wall.store(TelemetryHub::now_ms(), Ordering::Relaxed);
                            hub_dl.record_download(&conn_dl, resp.len());
                            let eff_target = rev_dl.read().map_return_source(&remote_src);
                            sink(client_src, eff_target, resp);
                        }
                        Ok(Err(_)) => break,
                        Err(_) => {
                            let now_mono = boot.elapsed().as_millis() as u64;
                            let now_wall = TelemetryHub::now_ms();
                            if now_mono.saturating_sub(reader_last.load(Ordering::Relaxed))
                                >= idle_timeout_ms
                                || now_wall.saturating_sub(reader_last_wall.load(Ordering::Relaxed))
                                    >= idle_timeout_ms
                            {
                                break;
                            }
                        }
                    }
                }
            };

            tokio::select! {
                _ = writer => {}
                _ = reader => {}
                _ = conn_entry.closed() => {}
            }

            if sessions_map
                .remove_if(&key, |_, v| Arc::ptr_eq(&v.conn_entry, &conn_entry))
                .is_some()
            {
                fast_routes_map.retain(|rk, rv| {
                    !(rk.0 == key.client_src && rv.outbound_name == key.outbound_name)
                });
            }
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
        };
        let key_quic = NatSessionKey {
            client_src: src_quic,
            outbound_name: "mock-quic-node".into(),
        };
        assert_eq!(mgr.sessions.get(&key_ntp).unwrap().idle_timeout_ms, 12_000);
        assert_eq!(mgr.sessions.get(&key_quic).unwrap().idle_timeout_ms, 60_000);

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
            custom_mgr.sessions.get(&key_ntp).unwrap().idle_timeout_ms,
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
        };
        let key_quic = NatSessionKey {
            client_src: src_quic,
            outbound_name: "mock-quic-node".into(),
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
}
