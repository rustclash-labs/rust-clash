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

#[derive(Default)]
struct ReverseTargetMap {
    target_to_raw: HashMap<TargetAddr, TargetAddr>,
    port_to_fake_raw: HashMap<u16, TargetAddr>,
    last_raw_dst: Option<TargetAddr>,
}

impl ReverseTargetMap {
    fn record_outbound(&mut self, target: &TargetAddr, raw_dst: &TargetAddr, was_fake_ip: bool) {
        self.target_to_raw.insert(target.clone(), raw_dst.clone());
        if was_fake_ip || matches!(target.host, HostName::Domain(_)) {
            self.port_to_fake_raw.insert(target.port, raw_dst.clone());
        }
        self.last_raw_dst = Some(raw_dst.clone());
    }

    fn map_return_source(&self, remote_src: &TargetAddr) -> TargetAddr {
        if let Some(raw) = self.target_to_raw.get(remote_src) {
            return raw.clone();
        }
        if let Some(fake_raw) = self.port_to_fake_raw.get(&remote_src.port) {
            return fake_raw.clone();
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

struct NatSessionEntry {
    tx: mpsc::Sender<(TargetAddr, Vec<u8>)>,
    reverse_map: Arc<RwLock<ReverseTargetMap>>,
    conn_entry: Arc<ActiveConnection>,
    last_active_ms: Arc<AtomicU64>,
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
    hub: Arc<TelemetryHub>,
    reply_sink: UdpReplySink,
}

impl SessionResetter for UdpNatManager {
    fn reset_sessions(&self) -> usize {
        self.reset_all_sessions()
    }
}

impl UdpNatManager {
    pub fn new(
        inbound_label: &'static str,
        max_sessions: usize,
        hub: Arc<TelemetryHub>,
        reply_sink: UdpReplySink,
    ) -> Arc<Self> {
        let mgr = Arc::new(Self {
            inbound_label,
            max_sessions: max_sessions.max(16),
            idle_timeout: DEFAULT_UDP_IDLE_TIMEOUT,
            boot: Instant::now(),
            sessions: Arc::new(DashMap::new()),
            hub: Arc::clone(&hub),
            reply_sink,
        });
        let weak: std::sync::Weak<dyn SessionResetter> =
            Arc::downgrade(&mgr) as std::sync::Weak<dyn SessionResetter>;
        hub.register_session_resetter(weak);
        mgr
    }

    fn now_ms(&self) -> u64 {
        self.boot.elapsed().as_millis() as u64
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Synchronously evict and close every cached UDP NAT session (e.g. on Wi-Fi <-> Cellular handoff).
    pub fn reset_all_sessions(&self) -> usize {
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
        let was_fake_ip = restored_from_fake_ip.is_some();

        // Fast-path check before potentially running capacity eviction.
        if let Some(existing) = self.sessions.get(&key)
            && !existing.tx.is_closed()
            && !existing.conn_entry.is_closed()
        {
            existing.last_active_ms.store(now_ms, Ordering::Relaxed);
            existing
                .reverse_map
                .write()
                .record_outbound(&target, &raw_dst, was_fake_ip);
            self.hub.record_upload(&existing.conn_entry, payload.len());
            let _ = existing.tx.try_send((target, payload));
            return;
        }

        if self.sessions.len() >= self.max_sessions {
            let idle_ms = self.idle_timeout.as_millis() as u64;
            self.sessions.retain(|_, v| {
                !v.tx.is_closed()
                    && !v.conn_entry.is_closed()
                    && now_ms.saturating_sub(v.last_active_ms.load(Ordering::Relaxed)) < idle_ms
            });
            if self.sessions.len() >= self.max_sessions {
                let oldest_key = self
                    .sessions
                    .iter()
                    .min_by_key(|entry| entry.value().last_active_ms.load(Ordering::Relaxed))
                    .map(|entry| entry.key().clone());
                if let Some(k) = oldest_key {
                    self.sessions.remove(&k);
                }
            }
        }

        // Synchronously claim or join the session slot BEFORE any `.await` (`open_udp_session`),
        // preventing concurrent QUIC Initial bursts from opening N parallel upstream sessions!
        let (rx, conn_entry, reverse_map, last_active_ms) = match self.sessions.entry(key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                if !occ.get().tx.is_closed() && !occ.get().conn_entry.is_closed() {
                    occ.get().last_active_ms.store(now_ms, Ordering::Relaxed);
                    occ.get()
                        .reverse_map
                        .write()
                        .record_outbound(&target, &raw_dst, was_fake_ip);
                    self.hub.record_upload(&occ.get().conn_entry, payload.len());
                    let _ = occ.get().tx.try_send((target, payload));
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
                let (tx, rx) = mpsc::channel::<(TargetAddr, Vec<u8>)>(UDP_SESSION_QUEUE_CAPACITY);
                let _ = tx.try_send((target.clone(), payload));
                occ.insert(NatSessionEntry {
                    tx,
                    reverse_map: Arc::clone(&reverse_map),
                    conn_entry: Arc::clone(&conn_entry),
                    last_active_ms: Arc::clone(&last_active_ms),
                });
                (rx, conn_entry, reverse_map, last_active_ms)
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
                let (tx, rx) = mpsc::channel::<(TargetAddr, Vec<u8>)>(UDP_SESSION_QUEUE_CAPACITY);
                let _ = tx.try_send((target.clone(), payload));
                vac.insert(NatSessionEntry {
                    tx,
                    reverse_map: Arc::clone(&reverse_map),
                    conn_entry: Arc::clone(&conn_entry),
                    last_active_ms: Arc::clone(&last_active_ms),
                });
                (rx, conn_entry, reverse_map, last_active_ms)
            }
        };

        let inbound_label = self.inbound_label;
        let hub_clone = Arc::clone(&self.hub);
        let sessions_map = Arc::clone(&self.sessions);
        let sink = Arc::clone(&self.reply_sink);
        let boot = self.boot;
        let idle_timeout = self.idle_timeout;

        tokio::spawn(async move {
            let mut rx = rx;
            let session = match outbound.open_udp_session().await {
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
                    sessions_map.remove_if(&key, |_, v| Arc::ptr_eq(&v.conn_entry, &conn_entry));
                    hub_clone.record_connection_failed(&conn_entry.id, &err.to_string());
                    return;
                }
            };
            conn_entry.mark_established();

            let session_rx = Arc::clone(&session);
            let writer_last = Arc::clone(&last_active_ms);
            let writer = async move {
                while let Some((dst, data)) = rx.recv().await {
                    writer_last.store(boot.elapsed().as_millis() as u64, Ordering::Relaxed);
                    if session.send_to(&data, &dst).await.is_err() {
                        break;
                    }
                }
            };

            let conn_dl = Arc::clone(&conn_entry);
            let hub_dl = Arc::clone(&hub_clone);
            let rev_dl = Arc::clone(&reverse_map);
            let reader_last = Arc::clone(&last_active_ms);
            let reader = async move {
                while let Ok(Ok((resp, remote_src))) =
                    tokio::time::timeout(idle_timeout, session_rx.recv_from()).await
                {
                    reader_last.store(boot.elapsed().as_millis() as u64, Ordering::Relaxed);
                    hub_dl.record_download(&conn_dl, resp.len());
                    let eff_target = rev_dl.read().map_return_source(&remote_src);
                    sink(client_src, eff_target, resp);
                }
            };

            tokio::select! {
                _ = writer => {}
                _ = reader => {}
                _ = conn_entry.closed() => {}
            }

            sessions_map.remove_if(&key, |_, v| Arc::ptr_eq(&v.conn_entry, &conn_entry));
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
}
