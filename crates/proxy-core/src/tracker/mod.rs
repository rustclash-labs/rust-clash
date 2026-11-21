use std::{
    collections::{HashSet, VecDeque},
    io,
    net::SocketAddr,
    ops::Deref,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Instant, SystemTime, UNIX_EPOCH},
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
pub const MAX_DEBUG_DIAGNOSTICS: usize = 3_000;
const MAX_FAILED_DIAGNOSTICS: usize = 300;
const MAX_RECENT_LOGS: usize = 300;
const MAX_DEBUG_LOGS: usize = 1_500;
const MAX_IMPORTANT_LOGS: usize = 500;

/// Format `host` and `port` as `host:port` for IPv4/domains or `[host]:port` for bare IPv6 literals.
pub fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

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

fn is_routine_connection_log(payload: &str) -> bool {
    payload.starts_with("[TUN] ")
        || payload.starts_with("[SOCKS5] ")
        || payload.starts_with("[HTTP-CONNECT] ")
        || payload.starts_with("[HTTP] ")
}

fn is_important_log(level: &str, payload: &str) -> bool {
    let sev = log_level_severity(level);
    if sev == 0 || sev >= 4 {
        return false;
    }
    sev >= 2 || !is_routine_connection_log(payload)
}

fn split_coalesce_suffix(s: &str) -> (&str, u64) {
    if let Some(without_close) = s.strip_suffix(')')
        && let Some((base, count_str)) = without_close.rsplit_once(" (x")
        && !count_str.is_empty()
        && count_str.bytes().all(|b| b.is_ascii_digit())
        && let Ok(count) = count_str.parse::<u64>()
        && count >= 2
    {
        return (base, count);
    }
    (s, 1)
}

fn tun_log_coalesce_key<'a>(level: &str, payload: &'a str) -> Option<(&'a str, &'a str)> {
    if !level.trim().eq_ignore_ascii_case("info") {
        return None;
    }
    let after_tun = payload.strip_prefix("[TUN] ")?;
    let (clean, _) = split_coalesce_suffix(after_tun);
    let (src_part, rest) = clean.split_once(" -> ")?;
    let (proto_prefix, client_addr) = if let Some(addr) = src_part.strip_prefix("TCP ") {
        ("TCP", addr)
    } else if let Some(addr) = src_part.strip_prefix("UDP ") {
        ("UDP", addr)
    } else {
        ("", src_part)
    };
    if client_addr.is_empty()
        || client_addr.bytes().any(|b| b.is_ascii_whitespace())
        || !client_addr.contains(':')
        || rest.is_empty()
        || rest.contains(" failed")
    {
        return None;
    }
    Some((proto_prefix, rest))
}

fn diag_log_coalesce_key<'a>(level: &str, payload: &'a str) -> Option<&'a str> {
    if !matches!(
        level.trim().to_ascii_lowercase().as_str(),
        "warn" | "warning"
    ) {
        return None;
    }
    let after_diag = payload.strip_prefix("[DIAG] ")?;
    let (clean, _) = split_coalesce_suffix(after_diag);
    if clean.is_empty() {
        return None;
    }
    Some(clean)
}

fn default_coalesced_count() -> u64 {
    1
}

/// Hook implemented by stateful session managers (such as `UdpNatManager`) so
/// `TelemetryHub` / `ProxyEngine::notify_network_change()` can synchronously evict
/// sockets bound to a stale network interface.
pub trait SessionResetter: Send + Sync {
    fn reset_sessions(&self) -> usize;

    /// Reap sessions whose wall-clock idle age exceeded their idle timeout
    /// (e.g. across Android/Linux deep suspend where `CLOCK_MONOTONIC` freezes).
    fn reap_idle_sessions(&self) -> usize {
        0
    }
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
    /// Optional local client process executable name (e.g. `curl`, `chrome.exe`) when resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    /// True when a real-IP connection's hostname was recovered via protocol sniffing (TLS SNI / HTTP Host / QUIC SNI).
    #[serde(default)]
    pub sniffed: bool,
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
    /// Outbound TCP/TLS/protocol handshake duration in milliseconds once established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_duration_ms: Option<u64>,
    #[serde(default = "default_coalesced_count")]
    pub coalesced_count: u64,
}

pub type DiagnosticEntry = ConnectionSnapshot;

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
    started_mono: Instant,
    established: AtomicBool,
    connect_duration_ms: AtomicU64,
    closed: AtomicBool,
    close_notify: Notify,
}

impl ActiveConnection {
    pub fn mark_established(&self) {
        if !self.established.swap(true, Ordering::Release) {
            let dur = self.started_mono.elapsed().as_millis() as u64;
            let _ = self.connect_duration_ms.compare_exchange(
                u64::MAX,
                dur,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        let status = if self.established.load(Ordering::Acquire) {
            "active"
        } else {
            "connecting"
        };
        let raw_dur = self.connect_duration_ms.load(Ordering::Acquire);
        let connect_duration_ms = (raw_dur != u64::MAX).then_some(raw_dur);
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
            connect_duration_ms,
            coalesced_count: 1,
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

/// Result of querying diagnostics in a time window, including ring/limit truncation metadata.
#[derive(Debug, Clone)]
pub struct WindowDiagnosticsResult {
    pub entries: Vec<DiagnosticEntry>,
    pub ring_capacity: usize,
    pub ring_evicted_in_window: bool,
    pub limit_truncated: bool,
    pub truncated: bool,
}

/// Central telemetry, connection manager, and structured log hub.
pub struct TelemetryHub {
    started_at_ms: u64,
    total_connections: AtomicU64,
    established_connections_total: AtomicU64,
    failed_connections_total: AtomicU64,
    cancelled_connections_total: AtomicU64,
    zero_rx_closed_total: AtomicU64,
    last_evicted_recent_epoch_ms: AtomicU64,
    total_upload: AtomicU64,
    total_download: AtomicU64,
    last_sampled_up: AtomicU64,
    last_sampled_down: AtomicU64,
    sample_ticks: AtomicU64,
    telemetry_parked: AtomicBool,
    debug_mode: AtomicBool,
    min_log_severity: AtomicU8,
    connections: DashMap<String, Arc<ActiveConnection>>,
    activity_notify: Notify,
    recent_diagnostics: Mutex<VecDeque<ConnectionSnapshot>>,
    failed_diagnostics: Mutex<VecDeque<ConnectionSnapshot>>,
    session_resetters: Mutex<Vec<Weak<dyn SessionResetter>>>,
    history: Mutex<VecDeque<TrafficPoint>>,
    recent_logs: Mutex<VecDeque<LogEntry>>,
    important_logs: Mutex<VecDeque<LogEntry>>,
    traffic_tx: broadcast::Sender<TrafficPoint>,
    log_tx: broadcast::Sender<LogEntry>,
}

impl Default for TelemetryHub {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryHub {
    pub fn format_host_port(host: &str, port: u16) -> String {
        format_host_port(host, port)
    }

    pub fn new() -> Self {
        let (traffic_tx, _) = broadcast::channel(256);
        let (log_tx, _) = broadcast::channel(512);
        Self {
            started_at_ms: Self::now_ms(),
            total_connections: AtomicU64::new(0),
            established_connections_total: AtomicU64::new(0),
            failed_connections_total: AtomicU64::new(0),
            cancelled_connections_total: AtomicU64::new(0),
            zero_rx_closed_total: AtomicU64::new(0),
            last_evicted_recent_epoch_ms: AtomicU64::new(0),
            total_upload: AtomicU64::new(0),
            total_download: AtomicU64::new(0),
            last_sampled_up: AtomicU64::new(0),
            last_sampled_down: AtomicU64::new(0),
            sample_ticks: AtomicU64::new(0),
            telemetry_parked: AtomicBool::new(false),
            debug_mode: AtomicBool::new(false),
            min_log_severity: AtomicU8::new(log_level_severity("info")),
            connections: DashMap::new(),
            activity_notify: Notify::new(),
            recent_diagnostics: Mutex::new(VecDeque::with_capacity(MAX_RECENT_DIAGNOSTICS)),
            failed_diagnostics: Mutex::new(VecDeque::with_capacity(MAX_FAILED_DIAGNOSTICS)),
            session_resetters: Mutex::new(Vec::new()),
            history: Mutex::new(VecDeque::with_capacity(120)),
            recent_logs: Mutex::new(VecDeque::with_capacity(MAX_RECENT_LOGS)),
            important_logs: Mutex::new(VecDeque::with_capacity(MAX_IMPORTANT_LOGS)),
            traffic_tx,
            log_tx,
        }
    }

    pub fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    pub fn uptime_secs(&self) -> u64 {
        Self::now_ms().saturating_sub(self.started_at_ms) / 1000
    }

    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    pub fn established_connections_total(&self) -> u64 {
        self.established_connections_total.load(Ordering::Relaxed)
    }

    pub fn failed_connections_total(&self) -> u64 {
        self.failed_connections_total.load(Ordering::Relaxed)
    }

    pub fn cancelled_connections_total(&self) -> u64 {
        self.cancelled_connections_total.load(Ordering::Relaxed)
    }

    pub fn zero_rx_closed_total(&self) -> u64 {
        self.zero_rx_closed_total.load(Ordering::Relaxed)
    }

    pub fn is_debug_mode(&self) -> bool {
        self.debug_mode.load(Ordering::Acquire)
    }

    pub fn set_debug_mode(&self, enabled: bool) {
        self.debug_mode.store(enabled, Ordering::Release);
        if enabled {
            self.min_log_severity
                .store(log_level_severity("debug"), Ordering::Relaxed);
        } else {
            self.min_log_severity
                .store(log_level_severity("info"), Ordering::Relaxed);
            {
                let mut ring = self.recent_diagnostics.lock();
                while ring.len() > MAX_RECENT_DIAGNOSTICS {
                    if let Some(evicted) = ring.pop_front() {
                        let ts = evicted.end_epoch_ms.unwrap_or(evicted.start_epoch_ms);
                        self.last_evicted_recent_epoch_ms
                            .fetch_max(ts, Ordering::Relaxed);
                    }
                }
            }
            {
                let mut logs = self.recent_logs.lock();
                while logs.len() > MAX_RECENT_LOGS {
                    logs.pop_front();
                }
            }
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

    fn resolve_source_process(network: &str, source: Option<SocketAddr>) -> Option<String> {
        let sa = source?;
        let transport = if network.eq_ignore_ascii_case("udp") {
            crate::platform::process::SocketTransport::Udp
        } else {
            crate::platform::process::SocketTransport::Tcp
        };
        crate::platform::process::find_local_process_nonblocking(transport, sa)
            .map(|info| info.name)
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
            false,
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
        self.register_connection_with_outbound_sniffed(
            inbound_type,
            network,
            source,
            target,
            fake_ip,
            rule,
            rule_payload,
            chains,
            outbound,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_connection_with_outbound_sniffed(
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
        sniffed: bool,
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
            sniffed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_connection_guard(
        self: &Arc<Self>,
        inbound_type: impl Into<String>,
        network: impl Into<String>,
        source: Option<SocketAddr>,
        target: &TargetAddr,
        fake_ip: Option<String>,
        rule: impl Into<String>,
        rule_payload: impl Into<String>,
        chains: Vec<String>,
    ) -> ConnectionGuard {
        let conn = self.register_connection(
            inbound_type,
            network,
            source,
            target,
            fake_ip,
            rule,
            rule_payload,
            chains,
        );
        ConnectionGuard::new(Arc::clone(self), conn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_connection_with_outbound_guard(
        self: &Arc<Self>,
        inbound_type: impl Into<String>,
        network: impl Into<String>,
        source: Option<SocketAddr>,
        target: &TargetAddr,
        fake_ip: Option<String>,
        rule: impl Into<String>,
        rule_payload: impl Into<String>,
        chains: Vec<String>,
        outbound: &dyn OutboundHandler,
    ) -> ConnectionGuard {
        self.register_connection_with_outbound_guard_sniffed(
            inbound_type,
            network,
            source,
            target,
            fake_ip,
            rule,
            rule_payload,
            chains,
            outbound,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_connection_with_outbound_guard_sniffed(
        self: &Arc<Self>,
        inbound_type: impl Into<String>,
        network: impl Into<String>,
        source: Option<SocketAddr>,
        target: &TargetAddr,
        fake_ip: Option<String>,
        rule: impl Into<String>,
        rule_payload: impl Into<String>,
        chains: Vec<String>,
        outbound: &dyn OutboundHandler,
        sniffed: bool,
    ) -> ConnectionGuard {
        let conn = self.register_connection_with_outbound_sniffed(
            inbound_type,
            network,
            source,
            target,
            fake_ip,
            rule,
            rule_payload,
            chains,
            outbound,
            sniffed,
        );
        ConnectionGuard::new(Arc::clone(self), conn)
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
        sniffed: bool,
    ) -> Arc<ActiveConnection> {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        let id = uuid::Uuid::new_v4().to_string();
        let net_str = network.into();
        let process = Self::resolve_source_process(&net_str, source);
        let metadata = ConnectionMetadata {
            id: id.clone(),
            network: net_str,
            inbound_type: inbound_type.into(),
            source: source
                .map(|s| s.to_string())
                .unwrap_or_else(|| "tun://local".to_string()),
            destination_ip: target.host.as_ip().map(|ip| ip.to_string()),
            destination_port: target.port,
            host: target.host.to_string(),
            fake_ip,
            process,
            sniffed,
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
            started_mono: Instant::now(),
            established: AtomicBool::new(false),
            connect_duration_ms: AtomicU64::new(u64::MAX),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        });
        self.connections.insert(id, Arc::clone(&conn));
        self.activity_notify.notify_waiters();
        conn
    }

    fn push_or_coalesce_diagnostic(
        ring: &mut VecDeque<ConnectionSnapshot>,
        snap: ConnectionSnapshot,
        max_cap: usize,
    ) -> Option<u64> {
        let is_unmapped_fake_ip = snap.effective_outbound == "UNMAPPED-FAKE-IP";
        let coalesce_window_ms = if is_unmapped_fake_ip { 10_000 } else { 1_000 };
        if snap.status == "failed"
            && let Some(existing) = ring.iter_mut().rev().take(16).find(|cand| {
                cand.status == "failed"
                    && cand.metadata.network == snap.metadata.network
                    && cand.metadata.host == snap.metadata.host
                    && (is_unmapped_fake_ip
                        || cand.metadata.destination_port == snap.metadata.destination_port)
                    && cand.effective_outbound == snap.effective_outbound
                    && (is_unmapped_fake_ip || cand.error == snap.error)
                    && snap.start_epoch_ms.saturating_sub(cand.start_epoch_ms) < coalesce_window_ms
            })
        {
            existing.end_epoch_ms = snap.end_epoch_ms;
            existing.coalesced_count = existing
                .coalesced_count
                .saturating_add(snap.coalesced_count.max(1));
            return None;
        }
        let mut max_evicted_ts: Option<u64> = None;
        while ring.len() >= max_cap {
            if let Some(evicted) = ring.pop_front() {
                let ts = evicted.end_epoch_ms.unwrap_or(evicted.start_epoch_ms);
                max_evicted_ts = Some(max_evicted_ts.map_or(ts, |prev| prev.max(ts)));
            }
        }
        ring.push_back(snap);
        max_evicted_ts
    }

    fn archive_diagnostic(&self, snap: ConnectionSnapshot) {
        let is_failed = snap.status == "failed";
        if is_failed {
            self.failed_connections_total
                .fetch_add(1, Ordering::Relaxed);
        } else if snap.connect_duration_ms.is_some() {
            self.established_connections_total
                .fetch_add(1, Ordering::Relaxed);
            if snap.download == 0 && snap.upload > 0 {
                self.zero_rx_closed_total.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.cancelled_connections_total
                .fetch_add(1, Ordering::Relaxed);
        }
        let max_cap = if self.is_debug_mode() {
            MAX_DEBUG_DIAGNOSTICS
        } else {
            MAX_RECENT_DIAGNOSTICS
        };
        if is_failed {
            let mut failed_ring = self.failed_diagnostics.lock();
            Self::push_or_coalesce_diagnostic(
                &mut failed_ring,
                snap.clone(),
                MAX_FAILED_DIAGNOSTICS,
            );
        }
        let mut ring = self.recent_diagnostics.lock();
        if let Some(evicted_ts) = Self::push_or_coalesce_diagnostic(&mut ring, snap, max_cap) {
            self.last_evicted_recent_epoch_ms
                .fetch_max(evicted_ts, Ordering::Relaxed);
        }
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
                    "[DIAG] {} [{}] -> {} ({}) failed: {}",
                    format_host_port(&snap.metadata.host, snap.metadata.destination_port),
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
        self.record_instant_failed_diagnostic_sniffed(
            inbound_type,
            network,
            source,
            target,
            fake_ip,
            rule,
            rule_payload,
            chains,
            outbound,
            raw_reason,
            false,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_instant_failed_diagnostic_sniffed(
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
        sniffed: bool,
    ) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        let now = Self::now_ms();
        let id = uuid::Uuid::new_v4().to_string();
        let safe_reason = redact_sensitive_text(raw_reason);
        let net_str = network.into();
        let process = Self::resolve_source_process(&net_str, source);
        let snap = ConnectionSnapshot {
            id: id.clone(),
            metadata: ConnectionMetadata {
                id,
                network: net_str,
                inbound_type: inbound_type.into(),
                source: source
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "tun://local".to_string()),
                destination_ip: target.host.as_ip().map(|ip| ip.to_string()),
                destination_port: target.port,
                host: target.host.to_string(),
                fake_ip,
                process,
                sniffed,
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
            connect_duration_ms: None,
            coalesced_count: 1,
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

    /// Close active proxy connections whose leaf `effective_outbound` was deleted or removed
    /// by a config/profile transition, while preserving `DIRECT` and surviving outbounds.
    pub fn close_connections_missing_outbounds(&self, valid_outbounds: &HashSet<&str>) -> usize {
        let stale_ids: Vec<String> = self
            .connections
            .iter()
            .filter_map(|entry| {
                let conn = entry.value();
                let ob = conn.effective_outbound.as_str();
                let is_builtin =
                    ob.eq_ignore_ascii_case("DIRECT") || ob.eq_ignore_ascii_case("REJECT");
                if !is_builtin && !valid_outbounds.contains(ob) {
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
        self.sample_ticks.load(Ordering::Acquire)
    }

    pub fn is_telemetry_parked(&self) -> bool {
        self.telemetry_parked.load(Ordering::Acquire)
    }

    pub fn set_telemetry_parked(&self, parked: bool) {
        self.telemetry_parked.store(parked, Ordering::Release);
    }

    pub fn has_unsampled_traffic(&self) -> bool {
        self.total_upload.load(Ordering::Acquire) != self.last_sampled_up.load(Ordering::Acquire)
            || self.total_download.load(Ordering::Acquire)
                != self.last_sampled_down.load(Ordering::Acquire)
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

    /// Reap sessions across all registered `SessionResetter`s whose wall-clock or monotonic
    /// idle age exceeded their idle timeout (e.g. across Android/Linux deep suspend).
    pub fn reap_idle_sessions(&self) -> usize {
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
        live.into_iter().map(|r| r.reap_idle_sessions()).sum()
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

    /// Return newest-first failed/errored connection diagnostics pulled directly from the
    /// dedicated `failed_diagnostics` ring (plus any live failed connection), so routine
    /// `active`/`closed` traffic churn never crowds out real failures.
    pub fn failed_diagnostics_snapshot(&self, limit: usize) -> Vec<ConnectionSnapshot> {
        let cap = limit.clamp(1, 500);
        let mut seen = HashSet::new();
        let mut failed: Vec<ConnectionSnapshot> = Vec::new();
        for entry in self.connections.iter() {
            let snap = entry.value().snapshot();
            if (snap.status == "failed" || snap.error.is_some()) && seen.insert(snap.id.clone()) {
                failed.push(snap);
            }
        }
        {
            let ring = self.failed_diagnostics.lock();
            for snap in ring.iter().rev() {
                if (snap.status == "failed" || snap.error.is_some()) && seen.insert(snap.id.clone())
                {
                    failed.push(snap.clone());
                }
            }
        }
        failed.sort_by_key(|a| std::cmp::Reverse(a.start_epoch_ms));
        if failed.len() > cap {
            failed.truncate(cap);
        }
        failed
    }

    /// Return active + archived connection snapshots overlapping `[since_epoch_ms, now]`,
    /// sorted newest-first and capped at `MAX_DEBUG_DIAGNOSTICS`.
    pub fn diagnostics_since(&self, since_epoch_ms: u64, limit: usize) -> Vec<ConnectionSnapshot> {
        self.diagnostics_in_window(since_epoch_ms, u64::MAX, limit)
    }

    /// Return active + archived connection snapshots overlapping `[since_epoch_ms, until_epoch_ms]`,
    /// sorted newest-first and capped at `MAX_DEBUG_DIAGNOSTICS`, while prioritizing `failed_diagnostics`
    /// so high-volume routine `closed` churn never evicts failure root causes within a diagnostic window.
    pub fn diagnostics_in_window(
        &self,
        since_epoch_ms: u64,
        until_epoch_ms: u64,
        limit: usize,
    ) -> Vec<DiagnosticEntry> {
        self.diagnostics_in_window_with_meta(since_epoch_ms, until_epoch_ms, limit)
            .entries
    }

    /// Like [`Self::diagnostics_in_window`], additionally returning exact ring-eviction and
    /// query-cap truncation flags so diagnostic exporters never silently under-report high-volume windows.
    pub fn diagnostics_in_window_with_meta(
        &self,
        since_epoch_ms: u64,
        until_epoch_ms: u64,
        limit: usize,
    ) -> WindowDiagnosticsResult {
        let ring_capacity = if self.is_debug_mode() {
            MAX_DEBUG_DIAGNOSTICS
        } else {
            MAX_RECENT_DIAGNOSTICS
        };
        if since_epoch_ms > until_epoch_ms {
            return WindowDiagnosticsResult {
                entries: Vec::new(),
                ring_capacity,
                ring_evicted_in_window: false,
                limit_truncated: false,
                truncated: false,
            };
        }
        let cap = limit.clamp(1, MAX_DEBUG_DIAGNOSTICS);
        let matches_window = |s: &ConnectionSnapshot| -> bool {
            s.start_epoch_ms <= until_epoch_ms
                && (s.start_epoch_ms >= since_epoch_ms
                    || s.end_epoch_ms.is_none_or(|end| end >= since_epoch_ms))
        };

        let mut seen_ids = HashSet::new();
        let mut limit_truncated = false;
        let mut selected: Vec<DiagnosticEntry> = {
            let failed_ring = self.failed_diagnostics.lock();
            let mut failed_selected = Vec::new();
            for s in failed_ring.iter().rev().filter(|s| matches_window(s)) {
                if !seen_ids.insert(s.id.clone()) {
                    continue;
                }
                if failed_selected.len() < cap {
                    failed_selected.push(s.clone());
                } else {
                    limit_truncated = true;
                    break;
                }
            }
            failed_selected
        };

        let remaining = cap.saturating_sub(selected.len());
        if remaining > 0 {
            let mut others: Vec<DiagnosticEntry> = self
                .connections
                .iter()
                .map(|entry| entry.value().snapshot())
                .filter(|s| matches_window(s) && seen_ids.insert(s.id.clone()))
                .collect();
            {
                let ring = self.recent_diagnostics.lock();
                others.extend(
                    ring.iter()
                        .filter(|s| matches_window(s) && seen_ids.insert(s.id.clone()))
                        .cloned(),
                );
            }
            others.sort_by_key(|a| std::cmp::Reverse(a.start_epoch_ms));
            if others.len() > remaining {
                limit_truncated = true;
                others.truncate(remaining);
            }
            selected.extend(others);
        } else if !limit_truncated {
            let has_extra_active = self.connections.iter().any(|entry| {
                let s = entry.value().snapshot();
                matches_window(&s) && !seen_ids.contains(&s.id)
            });
            let has_extra_recent = if has_extra_active {
                true
            } else {
                let ring = self.recent_diagnostics.lock();
                ring.iter()
                    .any(|s| matches_window(s) && !seen_ids.contains(&s.id))
            };
            if has_extra_recent {
                limit_truncated = true;
            }
        }

        let last_evicted = self.last_evicted_recent_epoch_ms.load(Ordering::Relaxed);
        let ring_evicted_in_window = last_evicted > 0 && last_evicted >= since_epoch_ms;

        selected.sort_by_key(|a| std::cmp::Reverse(a.start_epoch_ms));
        WindowDiagnosticsResult {
            entries: selected,
            ring_capacity,
            ring_evicted_in_window,
            limit_truncated,
            truncated: ring_evicted_in_window || limit_truncated,
        }
    }

    pub fn clear_diagnostics(&self) {
        self.recent_diagnostics.lock().clear();
        self.failed_diagnostics.lock().clear();
        self.last_evicted_recent_epoch_ms
            .store(0, Ordering::Relaxed);
    }

    pub fn totals(&self) -> (u64, u64) {
        (
            self.total_upload.load(Ordering::Acquire),
            self.total_download.load(Ordering::Acquire),
        )
    }

    pub fn record_upload(&self, conn: &ActiveConnection, bytes: usize) {
        let b = bytes as u64;
        conn.upload.fetch_add(b, Ordering::Relaxed);
        self.total_upload.fetch_add(b, Ordering::Release);
    }

    pub fn record_download(&self, conn: &ActiveConnection, bytes: usize) {
        let b = bytes as u64;
        conn.download.fetch_add(b, Ordering::Relaxed);
        self.total_download.fetch_add(b, Ordering::Release);
    }

    /// Sample instantaneous 1-second speed delta and broadcast to `/traffic` subscribers.
    pub fn sample_tick(&self) -> TrafficPoint {
        let total_up = self.total_upload.load(Ordering::Acquire);
        let total_down = self.total_download.load(Ordering::Acquire);
        let prev_up = self.last_sampled_up.swap(total_up, Ordering::AcqRel);
        let prev_down = self.last_sampled_down.swap(total_down, Ordering::AcqRel);
        self.sample_ticks.fetch_add(1, Ordering::Release);
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

    /// Returns the most recent 1-second traffic rate sample without cloning the 120-point ring buffer.
    pub fn latest_traffic_point(&self) -> Option<TrafficPoint> {
        self.history.lock().back().copied()
    }

    pub fn subscribe_traffic(&self) -> broadcast::Receiver<TrafficPoint> {
        self.traffic_tx.subscribe()
    }

    pub fn push_log(&self, level: impl Into<String>, payload: impl Into<String>) {
        self.push_log_at(Self::now_ms(), level, payload);
    }

    fn push_log_at(&self, timestamp_ms: u64, level: impl Into<String>, payload: impl Into<String>) {
        let level_str = level.into();
        if log_level_severity(&level_str) < self.min_log_severity.load(Ordering::Relaxed) {
            return;
        }
        let max_logs = if self.is_debug_mode() {
            MAX_DEBUG_LOGS
        } else {
            MAX_RECENT_LOGS
        };
        let entry = LogEntry {
            timestamp_ms,
            level: level_str,
            payload: payload.into(),
        };
        let important = is_important_log(&entry.level, &entry.payload);
        let tun_key = tun_log_coalesce_key(&entry.level, &entry.payload);
        let diag_key = diag_log_coalesce_key(&entry.level, &entry.payload);
        let mut coalesced = false;
        {
            let mut logs = self.recent_logs.lock();
            if let Some(key) = tun_key
                && let Some(existing) = logs.iter_mut().rev().take(16).find(|cand| {
                    tun_log_coalesce_key(&cand.level, &cand.payload) == Some(key)
                        && timestamp_ms.saturating_sub(cand.timestamp_ms) < 1_000
                })
            {
                let (base_payload, prev_count) = split_coalesce_suffix(&existing.payload);
                let new_count = prev_count.saturating_add(1);
                existing.timestamp_ms = timestamp_ms;
                existing.payload = format!("{base_payload} (x{new_count})");
                return;
            }
            if let Some(dkey) = diag_key
                && let Some(existing) = logs.iter_mut().rev().take(16).find(|cand| {
                    diag_log_coalesce_key(&cand.level, &cand.payload) == Some(dkey)
                        && timestamp_ms.saturating_sub(cand.timestamp_ms) < 1_000
                })
            {
                let (base_payload, prev_count) = split_coalesce_suffix(&existing.payload);
                let new_count = prev_count.saturating_add(1);
                existing.timestamp_ms = timestamp_ms;
                existing.payload = format!("{base_payload} (x{new_count})");
                coalesced = true;
            } else {
                while logs.len() >= max_logs {
                    logs.pop_front();
                }
                logs.push_back(entry.clone());
            }
        }
        if important {
            let mut imp = self.important_logs.lock();
            if let Some(dkey) = diag_key
                && let Some(existing) = imp.iter_mut().rev().take(16).find(|cand| {
                    diag_log_coalesce_key(&cand.level, &cand.payload) == Some(dkey)
                        && timestamp_ms.saturating_sub(cand.timestamp_ms) < 1_000
                })
            {
                let (base_payload, prev_count) = split_coalesce_suffix(&existing.payload);
                let new_count = prev_count.saturating_add(1);
                existing.timestamp_ms = timestamp_ms;
                existing.payload = format!("{base_payload} (x{new_count})");
                return;
            }
            while imp.len() >= MAX_IMPORTANT_LOGS {
                imp.pop_front();
            }
            imp.push_back(entry.clone());
        }
        if !coalesced {
            let _ = self.log_tx.send(entry);
        }
    }

    pub fn recent_logs(&self) -> Vec<LogEntry> {
        self.recent_logs.lock().iter().cloned().collect()
    }

    pub fn important_logs(&self) -> Vec<LogEntry> {
        self.important_logs.lock().iter().cloned().collect()
    }

    pub fn logs_since(&self, since_epoch_ms: u64, limit: usize) -> Vec<LogEntry> {
        self.logs_in_window(since_epoch_ms, u64::MAX, limit)
    }

    /// Return structured logs in `[since_epoch_ms, until_epoch_ms]` in chronological order,
    /// prioritizing `important_logs` (warnings, errors, and non-routine lifecycle events) so
    /// high-volume `[TUN]`/`[SOCKS5]`/`[HTTP]` traffic bursts never evict diagnostic events.
    pub fn logs_in_window(
        &self,
        since_epoch_ms: u64,
        until_epoch_ms: u64,
        limit: usize,
    ) -> Vec<LogEntry> {
        if since_epoch_ms > until_epoch_ms {
            return Vec::new();
        }
        let cap = limit.clamp(1, MAX_DEBUG_LOGS);
        let in_window = |e: &LogEntry| -> bool {
            e.timestamp_ms >= since_epoch_ms && e.timestamp_ms <= until_epoch_ms
        };

        let mut selected: Vec<LogEntry> = {
            let imp = self.important_logs.lock();
            let mut v: Vec<LogEntry> = imp
                .iter()
                .rev()
                .filter(|e| in_window(e))
                .take(cap)
                .cloned()
                .collect();
            v.reverse();
            v
        };

        let remaining = cap.saturating_sub(selected.len());
        if remaining > 0 {
            let logs = self.recent_logs.lock();
            let mut routine: Vec<LogEntry> = logs
                .iter()
                .rev()
                .filter(|e| in_window(e) && !is_important_log(&e.level, &e.payload))
                .take(remaining)
                .cloned()
                .collect();
            routine.reverse();
            selected.extend(routine);
        }

        selected.sort_by_key(|e| e.timestamp_ms);
        selected
    }

    pub fn clear_logs(&self) {
        self.recent_logs.lock().clear();
        self.important_logs.lock().clear();
    }

    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEntry> {
        self.log_tx.subscribe()
    }
}

/// RAII guard for a newly registered [`ActiveConnection`] before it is handed off to [`TrackedStream`].
///
/// Automatically unregisters the connection from [`TelemetryHub`] when dropped unless
/// [`ConnectionGuard::into_tracked_stream`], [`ConnectionGuard::record_failed`], or
/// [`ConnectionGuard::disarm`] is invoked first.
pub struct ConnectionGuard {
    hub: Arc<TelemetryHub>,
    conn: Arc<ActiveConnection>,
    disarmed: bool,
}

impl ConnectionGuard {
    pub fn new(hub: Arc<TelemetryHub>, conn: Arc<ActiveConnection>) -> Self {
        Self {
            hub,
            conn,
            disarmed: false,
        }
    }

    pub fn connection(&self) -> &Arc<ActiveConnection> {
        &self.conn
    }

    pub fn into_tracked_stream<S>(mut self, inner: S) -> TrackedStream<S> {
        self.disarmed = true;
        TrackedStream::new(inner, Arc::clone(&self.hub), Arc::clone(&self.conn))
    }

    pub fn record_failed(mut self, raw_reason: &str) {
        self.disarmed = true;
        self.hub.record_connection_failed(&self.conn.id, raw_reason);
    }

    pub fn disarm(mut self) -> Arc<ActiveConnection> {
        self.disarmed = true;
        Arc::clone(&self.conn)
    }
}

impl Deref for ConnectionGuard {
    type Target = ActiveConnection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            self.hub.unregister_connection(&self.conn.id);
        }
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

    pub fn connection(&self) -> &Arc<ActiveConnection> {
        &self.conn
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_guard_unregisters_on_early_drop_and_handoff_to_tracked_stream() {
        let hub = Arc::new(TelemetryHub::new());
        let target = TargetAddr::new_domain("example.com", 443).unwrap();

        {
            let _guard = hub.register_connection_guard(
                "Mixed(SOCKS5)",
                "tcp",
                None,
                &target,
                None,
                "MATCH",
                "",
                vec!["DIRECT".into()],
            );
            assert_eq!(hub.active_connection_count(), 1);
        }
        assert_eq!(
            hub.active_connection_count(),
            0,
            "dropping ConnectionGuard early must unregister phantom active connection"
        );

        let guard = hub.register_connection_guard(
            "Mixed(HTTP-CONNECT)",
            "tcp",
            None,
            &target,
            None,
            "MATCH",
            "",
            vec!["DIRECT".into()],
        );
        guard.mark_established();
        let tracked = guard.into_tracked_stream(tokio::io::empty());
        assert_eq!(hub.active_connection_count(), 1);
        drop(tracked);
        assert_eq!(hub.active_connection_count(), 0);
    }

    #[test]
    fn connection_guard_record_failed_disarms_drop() {
        let hub = Arc::new(TelemetryHub::new());
        let target = TargetAddr::new_domain("timeout.example.com", 443).unwrap();
        let guard = hub.register_connection_guard(
            "TUN(smoltcp)",
            "tcp",
            None,
            &target,
            None,
            "MATCH",
            "",
            vec!["PROXY".into()],
        );
        guard.record_failed("connect timeout");
        assert_eq!(hub.active_connection_count(), 0);
        assert_eq!(hub.failed_connections_total(), 1);
    }

    #[test]
    fn format_host_port_brackets_bare_ipv6_and_preserves_domains_and_ipv4() {
        assert_eq!(format_host_port("1.1.1.1", 443), "1.1.1.1:443");
        assert_eq!(format_host_port("chatgpt.com", 443), "chatgpt.com:443");
        assert_eq!(
            format_host_port("2606:4700:4700::1111", 443),
            "[2606:4700:4700::1111]:443"
        );
        assert_eq!(
            TelemetryHub::format_host_port("[2606:4700:4700::1111]", 443),
            "[2606:4700:4700::1111]:443"
        );

        let hub = Arc::new(TelemetryHub::new());
        let v6_target: TargetAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        let guard = hub.register_connection_guard(
            "TUN(smoltcp)",
            "tcp",
            None,
            &v6_target,
            None,
            "MATCH",
            "",
            vec!["PROXY".into()],
        );
        guard.record_failed("network unreachable");
        let logs = hub.recent_logs();
        assert_eq!(logs.len(), 1);
        assert!(
            logs[0]
                .payload
                .contains("[DIAG] [2606:4700:4700::1111]:443")
        );
    }

    #[test]
    fn important_logs_survive_tun_flood_and_window_bounds_filter_cleanly() {
        let hub = TelemetryHub::new();
        let since = TelemetryHub::now_ms();

        hub.push_log("info", "Switched routing mode to 'rule'");
        hub.push_log(
            "warn",
            "[DIAG] chatgpt.com:443 [MATCH] -> Node-A (PROXY) failed: handshake timeout",
        );

        for i in 0..2_000 {
            hub.push_log(
                "info",
                format!(
                    "[TUN] 198.18.0.1:{} -> host-{i}.example.com:443 (raw 198.18.0.10:443) [MATCH] via Node-A (PROXY)",
                    30_000 + (i % 20_000)
                ),
            );
        }

        let until = TelemetryHub::now_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        hub.push_log("warn", "Post-window warning after until_epoch_ms");

        let windowed = hub.logs_in_window(since, until, 250);
        assert_eq!(windowed.len(), 250);
        assert!(
            windowed
                .iter()
                .any(|e| e.payload == "Switched routing mode to 'rule'"),
            "non-routine lifecycle info log must survive [TUN] flood"
        );
        assert!(
            windowed
                .iter()
                .any(|e| e.payload.contains("[DIAG] chatgpt.com:443")),
            "warn diagnostic log must survive [TUN] flood"
        );
        assert!(
            !windowed
                .iter()
                .any(|e| e.payload == "Post-window warning after until_epoch_ms"),
            "logs after until_epoch_ms must be excluded"
        );
        assert!(
            windowed
                .windows(2)
                .all(|w| w[0].timestamp_ms <= w[1].timestamp_ms),
            "logs_in_window must return entries in chronological order"
        );
    }

    #[test]
    fn mark_established_uses_monotonic_clock_and_reap_idle_sessions_prunes_dead_resetters() {
        struct MockResetter(usize);
        impl SessionResetter for MockResetter {
            fn reset_sessions(&self) -> usize {
                0
            }

            fn reap_idle_sessions(&self) -> usize {
                self.0
            }
        }

        let hub = Arc::new(TelemetryHub::new());
        let r1: Arc<dyn SessionResetter> = Arc::new(MockResetter(3));
        let r2: Arc<dyn SessionResetter> = Arc::new(MockResetter(5));
        hub.register_session_resetter(Arc::downgrade(&r1));
        hub.register_session_resetter(Arc::downgrade(&r2));
        assert_eq!(hub.reap_idle_sessions(), 8);

        drop(r1);
        assert_eq!(hub.reap_idle_sessions(), 5);

        let target = TargetAddr::new_domain("mono.example.com", 443).unwrap();
        let conn = hub.register_connection(
            "TUN(smoltcp)",
            "tcp",
            None,
            &target,
            None,
            "MATCH",
            "",
            vec!["PROXY".into()],
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
        conn.mark_established();
        let snap = conn.snapshot();
        assert_eq!(snap.status, "active");
        let dur = snap.connect_duration_ms.expect("connect_duration_ms set");
        assert!(
            (4..5_000).contains(&dur),
            "unexpected handshake duration {dur}ms"
        );
        hub.unregister_connection(&conn.id);
    }

    #[test]
    fn consecutive_identical_failures_coalesce_count_within_one_second_only() {
        let hub = TelemetryHub::new();
        let make_failed = |id: &str, start_ms: u64, end_ms: u64| ConnectionSnapshot {
            id: id.to_string(),
            metadata: ConnectionMetadata {
                id: id.to_string(),
                network: "tcp".to_string(),
                inbound_type: "TUN(smoltcp)".to_string(),
                source: "198.18.0.1:50101".to_string(),
                destination_ip: None,
                destination_port: 443,
                host: "api.openai.com".to_string(),
                fake_ip: Some("198.18.0.42".to_string()),
                process: None,
                sniffed: false,
            },
            upload: 0,
            download: 0,
            start_epoch_ms: start_ms,
            chains: vec!["Node-SG".to_string(), "PROXY".to_string()],
            rule: "GEOSITE".to_string(),
            rule_payload: "openai".to_string(),
            effective_outbound: "Node-SG".to_string(),
            effective_protocol: "vless".to_string(),
            exit_type: "PROXY".to_string(),
            remote_endpoint: "example.net:443".to_string(),
            status: "failed".to_string(),
            error: Some("connection reset by peer".to_string()),
            end_epoch_ms: Some(end_ms),
            connect_duration_ms: None,
            coalesced_count: 1,
        };

        hub.archive_diagnostic(make_failed("f1", 1_000, 1_040));
        hub.archive_diagnostic(make_failed("f2", 1_300, 1_340));
        hub.archive_diagnostic(make_failed("f3", 1_850, 1_890));

        let snap1 = hub.diagnostics_snapshot(10);
        assert_eq!(snap1.len(), 1);
        assert_eq!(snap1[0].coalesced_count, 3);
        assert_eq!(snap1[0].end_epoch_ms, Some(1_890));

        // Failure >= 1000ms after the initial burst start_epoch_ms (2_000 - 1_000 == 1_000) stays separate.
        hub.archive_diagnostic(make_failed("f4", 2_000, 2_050));
        hub.archive_diagnostic(make_failed("f5", 3_100, 3_150));

        let snap2 = hub.diagnostics_snapshot(10);
        assert_eq!(snap2.len(), 3);
        assert_eq!(snap2[0].start_epoch_ms, 3_100);
        assert_eq!(snap2[0].coalesced_count, 1);
        assert_eq!(snap2[1].start_epoch_ms, 2_000);
        assert_eq!(snap2[1].coalesced_count, 1);
        assert_eq!(snap2[2].start_epoch_ms, 1_000);
        assert_eq!(snap2[2].coalesced_count, 3);
        assert_eq!(hub.failed_connections_total(), 5);
    }

    #[test]
    fn tun_routine_info_logs_coalesce_within_one_second_by_protocol_and_destination() {
        let hub = TelemetryHub::new();

        hub.push_log_at(
            5_000,
            "info",
            "[TUN] TCP 198.18.0.1:50101 -> ws.xiaoheihe.cn:443 (198.18.0.42) [DomainSuffix(xiaoheihe.cn) -> DIRECT]",
        );
        hub.push_log_at(
            5_350,
            "info",
            "[TUN] TCP 198.18.0.1:50102 -> ws.xiaoheihe.cn:443 (198.18.0.42) [DomainSuffix(xiaoheihe.cn) -> DIRECT]",
        );

        let logs_after_burst = hub.recent_logs();
        assert_eq!(logs_after_burst.len(), 1);
        assert_eq!(logs_after_burst[0].timestamp_ms, 5_350);
        assert_eq!(
            logs_after_burst[0].payload,
            "[TUN] TCP 198.18.0.1:50101 -> ws.xiaoheihe.cn:443 (198.18.0.42) [DomainSuffix(xiaoheihe.cn) -> DIRECT] (x2)"
        );

        // Different protocol (UDP vs TCP) must not coalesce.
        hub.push_log_at(
            5_500,
            "info",
            "[TUN] UDP 198.18.0.1:50103 -> ws.xiaoheihe.cn:443 (198.18.0.42) [DomainSuffix(xiaoheihe.cn) -> DIRECT]",
        );
        // Different destination must not coalesce.
        hub.push_log_at(
            5_600,
            "info",
            "[TUN] TCP 198.18.0.1:50104 -> api.xiaoheihe.cn:443 (198.18.0.43) [DomainSuffix(xiaoheihe.cn) -> DIRECT]",
        );
        // Same destination >= 1000ms apart (6_600 - 5_600 == 1_000) must not coalesce.
        hub.push_log_at(
            6_600,
            "info",
            "[TUN] TCP 198.18.0.1:50105 -> api.xiaoheihe.cn:443 (198.18.0.43) [DomainSuffix(xiaoheihe.cn) -> DIRECT]",
        );

        let logs = hub.recent_logs();
        assert_eq!(logs.len(), 4);
        assert!(logs[0].payload.ends_with(" (x2)"));
        assert!(!logs[1].payload.ends_with(" (x2)"));
        assert!(!logs[2].payload.ends_with(" (x2)"));
        assert!(!logs[3].payload.ends_with(" (x2)"));
    }

    #[test]
    fn diagnostics_in_window_retains_failed_connections_across_high_volume_closed_churn() {
        let hub = TelemetryHub::new();
        hub.set_debug_mode(true);

        let make_snap =
            |id: &str, status: &str, start_ms: u64, err: Option<&str>| ConnectionSnapshot {
                id: id.to_string(),
                metadata: ConnectionMetadata {
                    id: id.to_string(),
                    network: "tcp".to_string(),
                    inbound_type: "TUN(smoltcp)".to_string(),
                    source: "198.18.0.1:50101".to_string(),
                    destination_ip: None,
                    destination_port: 443,
                    host: format!("{id}.example.com"),
                    fake_ip: Some("198.18.0.42".to_string()),
                    process: None,
                    sniffed: false,
                },
                upload: 128,
                download: if status == "failed" { 0 } else { 512 },
                start_epoch_ms: start_ms,
                chains: vec!["DIRECT".to_string()],
                rule: "GEOSITE".to_string(),
                rule_payload: "cn".to_string(),
                effective_outbound: "DIRECT".to_string(),
                effective_protocol: "direct".to_string(),
                exit_type: "DIRECT".to_string(),
                remote_endpoint: "223.5.5.5:443".to_string(),
                status: status.to_string(),
                error: err.map(String::from),
                end_epoch_ms: Some(start_ms + 50),
                connect_duration_ms: (status != "failed").then_some(20),
                coalesced_count: 1,
            };

        // Record 2 failed connections early in the 30-minute slice, followed by > MAX_DEBUG_DIAGNOSTICS routine closed connections
        hub.archive_diagnostic(make_snap(
            "early-fail-1",
            "failed",
            1_000,
            Some("direct-nameserver DNS resolution failed"),
        ));
        hub.archive_diagnostic(make_snap(
            "early-fail-2",
            "failed",
            2_500,
            Some("direct-nameserver DNS resolution failed"),
        ));
        let overflow_count = MAX_DEBUG_DIAGNOSTICS as u64 + 300;
        for i in 0..overflow_count {
            hub.archive_diagnostic(make_snap(
                &format!("closed-{i}"),
                "closed",
                10_000 + i * 10,
                None,
            ));
        }

        let until_ms = 10_000 + overflow_count * 10 + 1_000;
        let meta = hub.diagnostics_in_window_with_meta(500, until_ms, MAX_DEBUG_DIAGNOSTICS);
        assert_eq!(meta.ring_capacity, MAX_DEBUG_DIAGNOSTICS);
        assert!(meta.ring_evicted_in_window);
        assert!(meta.truncated);
        let window = meta.entries;
        assert_eq!(window.len(), MAX_DEBUG_DIAGNOSTICS);
        let failed_in_window: Vec<&ConnectionSnapshot> =
            window.iter().filter(|s| s.status == "failed").collect();
        assert_eq!(
            failed_in_window.len(),
            2,
            "failed connections in window must never be evicted by routine closed churn"
        );
        assert_eq!(failed_in_window[0].id, "early-fail-2");
        assert_eq!(failed_in_window[1].id, "early-fail-1");

        // Verify newest-first ordering and zero duplicate IDs
        let mut seen = HashSet::new();
        for pair in window.windows(2) {
            assert!(pair[0].start_epoch_ms >= pair[1].start_epoch_ms);
        }
        for s in &window {
            assert!(seen.insert(&s.id), "duplicate snapshot id {}", s.id);
        }

        // Subsequent non-overlapping future window must NOT be marked ring-evicted
        let future_meta =
            hub.diagnostics_in_window_with_meta(until_ms + 10_000, until_ms + 20_000, 100);
        assert!(!future_meta.ring_evicted_in_window);
        assert!(!future_meta.truncated);

        hub.clear_diagnostics();
        let after_clear = hub.diagnostics_in_window_with_meta(0, u64::MAX, 100);
        assert!(after_clear.entries.is_empty());
        assert!(!after_clear.truncated);
    }

    #[test]
    fn cancelled_pre_handshake_dials_close_connection_accounting_gap() {
        let hub = Arc::new(TelemetryHub::new());
        let target = TargetAddr::new_domain("example.com", 443).unwrap();

        // 1. Pre-handshake drop (e.g. client closed SYN/RST while outbound dial was in flight)
        {
            let _cancelled = hub.register_connection_guard(
                "TUN(smoltcp)",
                "tcp",
                None,
                &target,
                None,
                "MATCH",
                "",
                vec!["DIRECT".to_string()],
            );
        }

        // 2. Established and later closed normally
        {
            let established = hub.register_connection_guard(
                "TUN(smoltcp)",
                "tcp",
                None,
                &target,
                None,
                "MATCH",
                "",
                vec!["DIRECT".to_string()],
            );
            established.mark_established();
        }

        // 3. Explicit dial failure
        {
            let failed = hub.register_connection_guard(
                "TUN(smoltcp)",
                "tcp",
                None,
                &target,
                None,
                "MATCH",
                "",
                vec!["DIRECT".to_string()],
            );
            failed.record_failed("connect timeout");
        }

        // 4. Still active (mid-handshake)
        let _active = hub.register_connection_guard(
            "TUN(smoltcp)",
            "tcp",
            None,
            &target,
            None,
            "MATCH",
            "",
            vec!["DIRECT".to_string()],
        );

        assert_eq!(hub.total_connections(), 4);
        assert_eq!(hub.active_connection_count(), 1);
        assert_eq!(hub.established_connections_total(), 1);
        assert_eq!(hub.failed_connections_total(), 1);
        assert_eq!(hub.cancelled_connections_total(), 1);
        assert_eq!(
            hub.active_connection_count() as u64
                + hub.established_connections_total()
                + hub.failed_connections_total()
                + hub.cancelled_connections_total(),
            hub.total_connections()
        );
    }

    #[test]
    fn unmapped_fake_ip_failures_coalesce_across_destination_ports() {
        let hub = TelemetryHub::new();
        let err_ob = crate::outbound::ErrorOutbound::new(
            "UNMAPPED-FAKE-IP",
            std::io::ErrorKind::HostUnreachable,
            "target 198.18.1.24:33861 is an unmapped Fake-IP",
        );
        for port in [13861u16, 23861, 33861, 43861] {
            let target = TargetAddr::new_ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 1, 24)),
                port,
            );
            hub.record_instant_failed_diagnostic(
                "TUN(smoltcp)",
                "tcp",
                None,
                &target,
                None,
                "FakeIpMiss",
                "198.18.0.0/15",
                vec!["UNMAPPED-FAKE-IP".to_string()],
                &err_ob,
                &format!("target 198.18.1.24:{port} is an unmapped Fake-IP"),
            );
        }
        let diags = hub.diagnostics_snapshot(20);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].coalesced_count, 4);
    }

    #[test]
    fn latest_traffic_point_returns_newest_sample_without_cloning_history() {
        let hub = TelemetryHub::new();
        assert!(hub.latest_traffic_point().is_none());
        hub.total_upload.fetch_add(1024, Ordering::Release);
        hub.total_download.fetch_add(4096, Ordering::Release);
        let first = hub.sample_tick();
        assert_eq!(first.up, 1024);
        assert_eq!(first.down, 4096);
        assert_eq!(
            hub.latest_traffic_point().map(|p| (p.up, p.down)),
            Some((1024, 4096))
        );

        hub.total_upload.fetch_add(512, Ordering::Release);
        hub.total_download.fetch_add(2048, Ordering::Release);
        let second = hub.sample_tick();
        assert_eq!(second.up, 512);
        assert_eq!(second.down, 2048);
        assert_eq!(
            hub.latest_traffic_point().map(|p| (p.up, p.down)),
            hub.traffic_history().last().map(|p| (p.up, p.down))
        );
    }
}
