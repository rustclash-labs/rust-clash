use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, broadcast},
};

use crate::{addr::TargetAddr, config::uri::redact_sensitive_text, outbound::OutboundHandler};

const MAX_RECENT_DIAGNOSTICS: usize = 200;

fn log_level_severity(level: &str) -> u8 {
    match level.trim().to_ascii_lowercase().as_str() {
        "debug" | "trace" => 0,
        "info" => 1,
        "warn" | "warning" => 2,
        "err" | "error" => 3,
        "silent" | "off" | "none" => 4,
        _ => 1,
    }
}

/// Hook implemented by stateful session managers (such as `UdpNatManager`) so
/// `TelemetryHub` / `ProxyEngine::notify_network_change()` can synchronously evict
/// sockets bound to a stale network interface.
pub trait SessionResetter: Send + Sync {
    fn reset_sessions(&self) -> usize;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionMetadata {
    pub id: String,
    pub network: String,
    #[serde(rename = "type")]
    pub inbound_type: String,
    pub source: String,
    pub destination_ip: Option<String>,
    pub destination_port: u16,
    pub host: String,
    /// Set when Fake-IP (`198.18.0.0/15`) was automatically restored back to a domain.
    pub fake_ip: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub id: String,
    pub metadata: ConnectionMetadata,
    pub upload: u64,
    pub download: u64,
    pub start_epoch_ms: u64,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    #[serde(default)]
    pub effective_outbound: String,
    #[serde(default)]
    pub effective_protocol: String,
    /// Physical exit category: `"DIRECT"`, `"PROXY"`, `"REJECT"`, or `"ERROR"`.
    #[serde(default)]
    pub exit_type: String,
    #[serde(default)]
    pub remote_endpoint: String,
    /// Lifecycle state: `"connecting"`, `"active"`, `"closed"`, or `"failed"`.
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_epoch_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TrafficPoint {
    pub timestamp_ms: u64,
    pub up: u64,
    pub down: u64,
    pub total_up: u64,
    pub total_down: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp_ms: u64,
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

pub struct ActiveConnection {
    pub id: String,
    pub metadata: ConnectionMetadata,
    pub upload: AtomicU64,
    pub download: AtomicU64,
    pub start_epoch_ms: u64,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub effective_outbound: String,
    pub effective_protocol: String,
    pub exit_type: String,
    pub remote_endpoint: String,
    established: AtomicBool,
    closed: AtomicBool,
    close_notify: Notify,
}

impl ActiveConnection {
    pub fn mark_established(&self) {
        self.established.store(true, Ordering::Release);
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        let status = if self.established.load(Ordering::Acquire) {
            "active"
        } else {
            "connecting"
        };
        ConnectionSnapshot {
            id: self.id.clone(),
            metadata: self.metadata.clone(),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            start_epoch_ms: self.start_epoch_ms,
            chains: self.chains.clone(),
            rule: self.rule.clone(),
            rule_payload: self.rule_payload.clone(),
            effective_outbound: self.effective_outbound.clone(),
            effective_protocol: self.effective_protocol.clone(),
            exit_type: self.exit_type.clone(),
            remote_endpoint: self.remote_endpoint.clone(),
            status: status.to_string(),
            error: None,
            end_epoch_ms: None,
        }
    }

    pub fn request_close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.close_notify.notify_waiters();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub async fn closed(&self) {
        let notified = self.close_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

/// Central telemetry, connection manager, and structured log hub.
pub struct TelemetryHub {
    total_upload: AtomicU64,
    total_download: AtomicU64,
    last_sampled_up: AtomicU64,
    last_sampled_down: AtomicU64,
    sample_ticks: AtomicU64,
    min_log_severity: AtomicU8,
    connections: DashMap<String, Arc<ActiveConnection>>,
    activity_notify: Notify,
    recent_diagnostics: Mutex<VecDeque<ConnectionSnapshot>>,
    session_resetters: Mutex<Vec<Weak<dyn SessionResetter>>>,
    history: Mutex<VecDeque<TrafficPoint>>,
    recent_logs: Mutex<VecDeque<LogEntry>>,
    traffic_tx: broadcast::Sender<TrafficPoint>,
    log_tx: broadcast::Sender<LogEntry>,
}

impl Default for TelemetryHub {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryHub {
    pub fn new() -> Self {
        let (traffic_tx, _) = broadcast::channel(256);
        let (log_tx, _) = broadcast::channel(512);
        Self {
            total_upload: AtomicU64::new(0),
            total_download: AtomicU64::new(0),
            last_sampled_up: AtomicU64::new(0),
            last_sampled_down: AtomicU64::new(0),
            sample_ticks: AtomicU64::new(0),
            min_log_severity: AtomicU8::new(log_level_severity("info")),
            connections: DashMap::new(),
            activity_notify: Notify::new(),
            recent_diagnostics: Mutex::new(VecDeque::with_capacity(MAX_RECENT_DIAGNOSTICS)),
            session_resetters: Mutex::new(Vec::new()),
            history: Mutex::new(VecDeque::with_capacity(120)),
            recent_logs: Mutex::new(VecDeque::with_capacity(300)),
            traffic_tx,
            log_tx,
        }
    }

    pub fn set_log_level(&self, level: &str) {
        self.min_log_severity
            .store(log_level_severity(level), Ordering::Relaxed);
    }

    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn infer_exit_type_from_leaf(leaf: &str) -> &'static str {
        if leaf.eq_ignore_ascii_case("DIRECT") {
            "DIRECT"
        } else if leaf.eq_ignore_ascii_case("REJECT") {
            "REJECT"
        } else if leaf.starts_with("ERROR") {
            "ERROR"
        } else {
            "PROXY"
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_connection(
        &self,
        inbound_type: impl Into<String>,
        network: impl Into<String>,
        source: Option<SocketAddr>,
        target: &TargetAddr,
        fake_ip: Option<String>,
        rule: impl Into<String>,
        rule_payload: impl Into<String>,
        chains: Vec<String>,
    ) -> Arc<ActiveConnection> {
        let leaf = chains
            .first()
            .cloned()
            .unwrap_or_else(|| "REJECT".to_string());
        let exit_type = Self::infer_exit_type_from_leaf(&leaf).to_string();
        let protocol = leaf.to_ascii_lowercase();
        let remote_endpoint = target.to_string();
        self.register_connection_detailed(
            inbound_type,
            network,
            source,
            target,
            fake_ip,
            rule,
            rule_payload,
            chains,
            leaf,
            protocol,
            exit_type,
            remote_endpoint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_connection_with_outbound(
        &self,
        inbound_type: impl Into<String>,
        network: impl Into<String>,
        source: Option<SocketAddr>,
        target: &TargetAddr,
        fake_ip: Option<String>,
        rule: impl Into<String>,
        rule_payload: impl Into<String>,
        chains: Vec<String>,
        outbound: &dyn OutboundHandler,
    ) -> Arc<ActiveConnection> {
        self.register_connection_detailed(
            inbound_type,
            network,
            source,
            target,
            fake_ip,
            rule,
            rule_payload,
            chains,
            outbound.name().to_string(),
            outbound.protocol().to_string(),
            outbound.exit_category().to_string(),
            outbound.remote_endpoint(target),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_connection_detailed(
        &self,
        inbound_type: impl Into<String>,
        network: impl Into<String>,
        source: Option<SocketAddr>,
        target: &TargetAddr,
        fake_ip: Option<String>,
        rule: impl Into<String>,
        rule_payload: impl Into<String>,
        chains: Vec<String>,
        effective_outbound: String,
        effective_protocol: String,
        exit_type: String,
        remote_endpoint: String,
    ) -> Arc<ActiveConnection> {
        let id = uuid::Uuid::new_v4().to_string();
        let metadata = ConnectionMetadata {
            id: id.clone(),
            network: network.into(),
            inbound_type: inbound_type.into(),
            source: source
                .map(|s| s.to_string())
                .unwrap_or_else(|| "tun://local".to_string()),
            destination_ip: target.host.as_ip().map(|ip| ip.to_string()),
            destination_port: target.port,
            host: target.host.to_string(),
            fake_ip,
        };
        let conn = Arc::new(ActiveConnection {
            id: id.clone(),
            metadata,
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            start_epoch_ms: Self::now_ms(),
            chains,
            rule: rule.into(),
            rule_payload: rule_payload.into(),
            effective_outbound,
            effective_protocol,
            exit_type,
            remote_endpoint,
            established: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        });
        self.connections.insert(id, Arc::clone(&conn));
        self.activity_notify.notify_waiters();
        conn
    }

    fn archive_diagnostic(&self, snap: ConnectionSnapshot) {
        let mut ring = self.recent_diagnostics.lock();
        if snap.status == "failed"
            && let Some(back) = ring.back_mut()
            && back.status == "failed"
            && back.metadata.network == snap.metadata.network
            && back.metadata.host == snap.metadata.host
            && back.metadata.destination_port == snap.metadata.destination_port
            && back.effective_outbound == snap.effective_outbound
            && back.error == snap.error
            && snap.start_epoch_ms.saturating_sub(back.start_epoch_ms) < 1_000
        {
            back.end_epoch_ms = snap.end_epoch_ms;
            return;
        }
        if ring.len() >= MAX_RECENT_DIAGNOSTICS {
            ring.pop_front();
        }
        ring.push_back(snap);
    }

    pub fn record_connection_failed(&self, id: &str, raw_reason: &str) {
        let safe_reason = redact_sensitive_text(raw_reason);
        if let Some((_, conn)) = self.connections.remove(id) {
            let mut snap = conn.snapshot();
            snap.status = "failed".to_string();
            snap.error = Some(safe_reason.clone());
            snap.end_epoch_ms = Some(Self::now_ms());
            self.push_log(
                "warn",
                format!(
                    "[DIAG] {}:{} [{}] -> {} ({}) failed: {}",
                    snap.metadata.host,
                    snap.metadata.destination_port,
                    snap.rule,
                    snap.effective_outbound,
                    snap.exit_type,
                    safe_reason
                ),
            );
            self.archive_diagnostic(snap);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_instant_failed_diagnostic(
        &self,
        inbound_type: impl Into<String>,
        network: impl Into<String>,
        source: Option<SocketAddr>,
        target: &TargetAddr,
        fake_ip: Option<String>,
        rule: impl Into<String>,
        rule_payload: impl Into<String>,
        chains: Vec<String>,
        outbound: &dyn OutboundHandler,
        raw_reason: &str,
    ) {
        let now = Self::now_ms();
        let id = uuid::Uuid::new_v4().to_string();
        let safe_reason = redact_sensitive_text(raw_reason);
        let snap = ConnectionSnapshot {
            id: id.clone(),
            metadata: ConnectionMetadata {
                id,
                network: network.into(),
                inbound_type: inbound_type.into(),
                source: source
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "tun://local".to_string()),
                destination_ip: target.host.as_ip().map(|ip| ip.to_string()),
                destination_port: target.port,
                host: target.host.to_string(),
                fake_ip,
            },
            upload: 0,
            download: 0,
            start_epoch_ms: now,
            chains,
            rule: rule.into(),
            rule_payload: rule_payload.into(),
            effective_outbound: outbound.name().to_string(),
            effective_protocol: outbound.protocol().to_string(),
            exit_type: outbound.exit_category().to_string(),
            remote_endpoint: outbound.remote_endpoint(target),
            status: "failed".to_string(),
            error: Some(safe_reason),
            end_epoch_ms: Some(now),
        };
        self.archive_diagnostic(snap);
    }

    pub fn unregister_connection(&self, id: &str) {
        if let Some((_, conn)) = self.connections.remove(id) {
            let mut snap = conn.snapshot();
            snap.status = "closed".to_string();
            snap.end_epoch_ms = Some(Self::now_ms());
            self.archive_diagnostic(snap);
        }
    }

    pub fn close_connection(&self, id: &str) -> bool {
        if let Some((_, conn)) = self.connections.remove(id) {
            conn.request_close();
            let mut snap = conn.snapshot();
            snap.status = "closed".to_string();
            snap.end_epoch_ms = Some(Self::now_ms());
            self.archive_diagnostic(snap);
            true
        } else {
            false
        }
    }

    pub fn close_all_connections(&self) -> usize {
        let keys: Vec<String> = self.connections.iter().map(|e| e.key().clone()).collect();
        let mut count = 0;
        for key in keys {
            if self.close_connection(&key) {
                count += 1;
            }
        }
        count
    }

    /// Close active proxy connections routed through `group_name` whose effective leaf outbound
    /// differs from `new_effective_outbound`, while preserving `DIRECT` connections uninterrupted.
    pub fn close_connections_for_group(
        &self,
        group_name: &str,
        new_effective_outbound: &str,
    ) -> usize {
        let stale_ids: Vec<String> = self
            .connections
            .iter()
            .filter_map(|entry| {
                let conn = entry.value();
                let in_group = conn.chains.iter().any(|c| c == group_name);
                let is_direct = conn.exit_type.eq_ignore_ascii_case("DIRECT")
                    || conn.effective_outbound.eq_ignore_ascii_case("DIRECT");
                if in_group && !is_direct && conn.effective_outbound != new_effective_outbound {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        let mut closed = 0;
        for id in stale_ids {
            if self.close_connection(&id) {
                closed += 1;
            }
        }
        closed
    }

    pub fn activity_notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.activity_notify.notified()
    }

    pub fn sample_tick_count(&self) -> u64 {
        self.sample_ticks.load(Ordering::Relaxed)
    }

    pub fn register_session_resetter(&self, resetter: Weak<dyn SessionResetter>) {
        let mut guard = self.session_resetters.lock();
        guard.retain(|w| w.strong_count() > 0);
        guard.push(resetter);
    }

    /// Synchronously reset all registered `UdpNatManager` tables so sockets bound to a
    /// stale interface are immediately closed and subsequent datagrams open fresh sessions.
    pub fn reset_udp_nat_sessions(&self) -> usize {
        let live: Vec<Arc<dyn SessionResetter>> = {
            let mut guard = self.session_resetters.lock();
            let mut active = Vec::with_capacity(guard.len());
            guard.retain(|w| {
                if let Some(strong) = w.upgrade() {
                    active.push(strong);
                    true
                } else {
                    false
                }
            });
            active
        };
        live.into_iter().map(|r| r.reset_sessions()).sum()
    }

    pub fn active_connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn list_connections(&self) -> Vec<ConnectionSnapshot> {
        let mut list: Vec<ConnectionSnapshot> = self
            .connections
            .iter()
            .map(|entry| entry.value().snapshot())
            .collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.start_epoch_ms));
        list
    }

    /// Return a unified newest-first connection diagnostics feed combining currently active
    /// connections (`connecting` / `active`) with recently closed or failed attempts (`closed` / `failed`).
    pub fn diagnostics_snapshot(&self, limit: usize) -> Vec<ConnectionSnapshot> {
        let cap = limit.clamp(1, 500);
        let mut combined: Vec<ConnectionSnapshot> = self
            .connections
            .iter()
            .map(|entry| entry.value().snapshot())
            .collect();
        {
            let ring = self.recent_diagnostics.lock();
            combined.extend(ring.iter().cloned());
        }
        combined.sort_by_key(|a| std::cmp::Reverse(a.start_epoch_ms));
        if combined.len() > cap {
            combined.truncate(cap);
        }
        combined
    }

    pub fn clear_diagnostics(&self) {
        self.recent_diagnostics.lock().clear();
    }

    pub fn totals(&self) -> (u64, u64) {
        (
            self.total_upload.load(Ordering::Relaxed),
            self.total_download.load(Ordering::Relaxed),
        )
    }

    pub fn record_upload(&self, conn: &ActiveConnection, bytes: usize) {
        let b = bytes as u64;
        conn.upload.fetch_add(b, Ordering::Relaxed);
        self.total_upload.fetch_add(b, Ordering::Relaxed);
    }

    pub fn record_download(&self, conn: &ActiveConnection, bytes: usize) {
        let b = bytes as u64;
        conn.download.fetch_add(b, Ordering::Relaxed);
        self.total_download.fetch_add(b, Ordering::Relaxed);
    }

    /// Sample instantaneous 1-second speed delta and broadcast to `/traffic` subscribers.
    pub fn sample_tick(&self) -> TrafficPoint {
        self.sample_ticks.fetch_add(1, Ordering::Relaxed);
        let total_up = self.total_upload.load(Ordering::Relaxed);
        let total_down = self.total_download.load(Ordering::Relaxed);
        let prev_up = self.last_sampled_up.swap(total_up, Ordering::Relaxed);
        let prev_down = self.last_sampled_down.swap(total_down, Ordering::Relaxed);
        let point = TrafficPoint {
            timestamp_ms: Self::now_ms(),
            up: total_up.saturating_sub(prev_up),
            down: total_down.saturating_sub(prev_down),
            total_up,
            total_down,
        };
        {
            let mut hist = self.history.lock();
            if hist.len() >= 120 {
                hist.pop_front();
            }
            hist.push_back(point);
        }
        let _ = self.traffic_tx.send(point);
        point
    }

    pub fn traffic_history(&self) -> Vec<TrafficPoint> {
        self.history.lock().iter().copied().collect()
    }

    pub fn subscribe_traffic(&self) -> broadcast::Receiver<TrafficPoint> {
        self.traffic_tx.subscribe()
    }

    pub fn push_log(&self, level: impl Into<String>, payload: impl Into<String>) {
        let level_str = level.into();
        if log_level_severity(&level_str) < self.min_log_severity.load(Ordering::Relaxed) {
            return;
        }
        let entry = LogEntry {
            timestamp_ms: Self::now_ms(),
            level: level_str,
            payload: payload.into(),
        };
        {
            let mut logs = self.recent_logs.lock();
            if logs.len() >= 300 {
                logs.pop_front();
            }
            logs.push_back(entry.clone());
        }
        let _ = self.log_tx.send(entry);
    }

    pub fn recent_logs(&self) -> Vec<LogEntry> {
        self.recent_logs.lock().iter().cloned().collect()
    }

    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEntry> {
        self.log_tx.subscribe()
    }
}

/// Stream wrapper that automatically meters upload/download bytes and unregisters on drop.
pub struct TrackedStream<S> {
    inner: S,
    hub: Arc<TelemetryHub>,
    conn: Arc<ActiveConnection>,
}

impl<S> TrackedStream<S> {
    pub fn new(inner: S, hub: Arc<TelemetryHub>, conn: Arc<ActiveConnection>) -> Self {
        Self { inner, hub, conn }
    }
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        self.hub.unregister_connection(&self.conn.id);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.conn.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed by controller",
            )));
        }
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let delta = buf.filled().len().saturating_sub(before);
            if delta > 0 {
                self.hub.record_download(&self.conn, delta);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.conn.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed by controller",
            )));
        }
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res
            && *n > 0
        {
            self.hub.record_upload(&self.conn, *n);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
