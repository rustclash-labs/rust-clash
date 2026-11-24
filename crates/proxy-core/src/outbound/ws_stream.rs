use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

use aws_lc_rs::digest::{Context as DigestContext, SHA1_FOR_LEGACY_USE_ONLY};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD},
};
use bytes::{Bytes, BytesMut};
use futures_util::{Sink, Stream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{Request as WsServerRequest, Response as WsServerResponse},
        protocol::{Message, Role},
    },
};

use crate::outbound::BoxedStream;

fn default_ws_path() -> String {
    "/".to_string()
}

/// Clash Meta / Xray compatible WebSocket (`ws-opts`) transport configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WsTransportConfig {
    #[serde(default = "default_ws_path")]
    pub path: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_early_data: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data_header_name: Option<String>,
}

impl Default for WsTransportConfig {
    fn default() -> Self {
        Self {
            path: default_ws_path(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        }
    }
}

fn sanitize_ws_uri_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        let is_valid_uri_char = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'&'
                    | b'='
                    | b'+'
                    | b'!'
                    | b'$'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b','
                    | b';'
                    | b'@'
                    | b'['
                    | b']'
                    | b'%'
            );
        if is_valid_uri_char {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl WsTransportConfig {
    /// Normalize `?ed=<N>` inline query parameter (common in Xray/v2rayN share URIs and Clash configs)
    /// into `(request_path, effective_max_early_data, early_data_header_name)`.
    pub fn normalized_parts(&self) -> (String, usize, String) {
        let raw_path = if self.path.trim().is_empty() {
            "/"
        } else {
            self.path.trim()
        };

        let mut extracted_ed: Option<usize> = None;
        let raw_clean_path = if let Some((base, query)) = raw_path.split_once('?') {
            let mut kept_pairs = Vec::new();
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                if let Some((k, v)) = pair.split_once('=')
                    && k.eq_ignore_ascii_case("ed")
                    && let Ok(n) = v.trim().parse::<usize>()
                {
                    extracted_ed = Some(n);
                    continue;
                }
                kept_pairs.push(pair);
            }
            let norm_base = if base.starts_with('/') {
                base.to_string()
            } else {
                format!("/{base}")
            };
            if kept_pairs.is_empty() {
                norm_base
            } else {
                format!("{norm_base}?{}", kept_pairs.join("&"))
            }
        } else if raw_path.starts_with('/') {
            raw_path.to_string()
        } else {
            format!("/{raw_path}")
        };
        let clean_path = sanitize_ws_uri_path(&raw_clean_path);

        let max_ed = self.max_early_data.or(extracted_ed).unwrap_or(0).min(8192);
        let hdr_name = self
            .early_data_header_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Sec-WebSocket-Protocol")
            .to_string();

        (clean_path, max_ed, hdr_name)
    }

    pub fn host_header(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
    }
}

fn save_waker_slot(slot: &mut Option<Waker>, waker: &Waker) {
    match slot {
        Some(existing) if existing.will_wake(waker) => {}
        _ => *slot = Some(waker.clone()),
    }
}

fn wake_both_opt(w1: Option<Waker>, w2: Option<Waker>) {
    match (w1, w2) {
        (Some(a), Some(b)) => {
            if a.will_wake(&b) {
                a.wake();
            } else {
                a.wake();
                b.wake();
            }
        }
        (Some(a), None) | (None, Some(a)) => a.wake(),
        (None, None) => {}
    }
}

/// Small stack-allocated deduplicating waker collector used to gather companion split-stream
/// wakers while holding an inner or outer mutex (such as `LazyWsEarlyDataStream::state`) and wake
/// them strictly AFTER all locks are dropped.
#[derive(Default)]
struct PendingWakers {
    slots: [Option<Waker>; 4],
}

impl PendingWakers {
    fn push(&mut self, waker: Option<Waker>) {
        let Some(waker) = waker else {
            return;
        };
        if self
            .slots
            .iter()
            .flatten()
            .any(|existing| existing.will_wake(&waker))
        {
            return;
        }
        if let Some(empty) = self.slots.iter_mut().find(|slot| slot.is_none()) {
            *empty = Some(waker);
        }
    }

    fn wake_all(self) {
        for waker in self.slots.into_iter().flatten() {
            waker.wake();
        }
    }
}

/// Tri-slot waker fanout coordinating split-stream `poll_read` and `poll_write`/`poll_flush`/
/// `poll_shutdown` sharing a single underlying write/handshake waker slot:
/// - slot `0` (`read_tx`): reader waiting on TX write-readiness (or `LazyWsEarlyDataStream`
///   `Handshaking` read waiter); woken by `wake_by_ref` and writer completion.
/// - slot `1` (`write_tx`): writer waiting on TX write-readiness (or `LazyWsEarlyDataStream`
///   `Handshaking` write waiter); woken by `wake_by_ref` and reader drain/flush completion.
/// - slot `2` (`parked_read`): reader currently parked in `WsByteStream::poll_read`
///   (`Poll::Pending`); NOT woken by `wake_by_ref` (avoiding spurious wakeups during streaming
///   uploads), ONLY woken when a writer returns `Poll::Ready` leaving buffered outbound frames or
///   an uplink error, or when `LazyWsEarlyDataStream` poisons `Connected -> Failed`.
///
/// Always releases its internal mutex BEFORE invoking `Waker::wake()`.
#[derive(Default)]
struct FanoutWaker {
    wakers: parking_lot::Mutex<(Option<Waker>, Option<Waker>, Option<Waker>)>,
}

impl FanoutWaker {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn register_read(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        save_waker_slot(&mut guard.0, waker);
    }

    fn register_write(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        save_waker_slot(&mut guard.1, waker);
    }

    fn register_parked_read(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();
        save_waker_slot(&mut guard.2, waker);
    }

    fn clear_read(&self) {
        let mut guard = self.wakers.lock();
        guard.0 = None;
        guard.2 = None;
    }

    fn clear_write(&self) {
        self.wakers.lock().1 = None;
    }

    fn clear_read_tx_and_take_write(&self) -> Option<Waker> {
        let mut guard = self.wakers.lock();
        guard.0 = None;
        guard.1.take()
    }

    fn clear_write_and_take_read_tx(&self) -> Option<Waker> {
        let mut guard = self.wakers.lock();
        guard.1 = None;
        guard.0.take()
    }

    fn clear_write_and_take_read(&self) -> (Option<Waker>, Option<Waker>) {
        let mut guard = self.wakers.lock();
        guard.1 = None;
        (guard.0.take(), guard.2.take())
    }

    fn take_all(&self) -> (Option<Waker>, Option<Waker>, Option<Waker>) {
        let mut guard = self.wakers.lock();
        (guard.0.take(), guard.1.take(), guard.2.take())
    }
}

impl Wake for FanoutWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let (w_rd, w_wr) = {
            let mut guard = self.wakers.lock();
            (guard.0.take(), guard.1.take())
        };
        wake_both_opt(w_wr, w_rd);
    }
}

/// Bidirectional `AsyncRead + AsyncWrite` adapter over a binary RFC 6455 `WebSocketStream`.
pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    read_buf: BytesMut,
    eof: bool,
    any_read_bytes: bool,
    uplink_flush_failed: bool,
    tx_fanout: Arc<FanoutWaker>,
    tx_fanout_waker: Waker,
}

impl<S> WsByteStream<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self::with_initial_read(ws, BytesMut::new())
    }

    pub fn with_initial_read(ws: WebSocketStream<S>, initial_read: BytesMut) -> Self {
        let tx_fanout = FanoutWaker::new();
        let tx_fanout_waker = Waker::from(Arc::clone(&tx_fanout));
        Self {
            ws,
            read_buf: initial_read,
            eof: false,
            any_read_bytes: false,
            uplink_flush_failed: false,
            tx_fanout,
            tx_fanout_waker,
        }
    }
}

fn ws_err_to_io(err: tokio_tungstenite::tungstenite::Error) -> io::Error {
    match err {
        tokio_tungstenite::tungstenite::Error::Io(e) => e,
        tokio_tungstenite::tungstenite::Error::ConnectionClosed
        | tokio_tungstenite::tungstenite::Error::AlreadyClosed => {
            io::Error::new(io::ErrorKind::UnexpectedEof, "websocket closed")
        }
        other => io::Error::other(format!("websocket error: {other}")),
    }
}

const MAX_WS_FRAME_CHUNK: usize = 32 * 1024;

impl<S: AsyncRead + AsyncWrite + Unpin> WsByteStream<S> {
    /// Opportunistically flush queued outbound WebSocket frames (including automatic Pong/Close
    /// replies queued by `tungstenite`) from `poll_read` through `tx_fanout_waker`, so a
    /// concurrent split writer's waker registered on `tokio-tungstenite`'s `ContextWaker::Write`
    /// slot is never overwritten and lost. Companion wakers are collected into `pending_wakers`
    /// so callers (including `LazyWsEarlyDataStream`) invoke `.wake()` strictly outside all locks.
    fn poll_flush_from_read(
        &mut self,
        cx: &mut Context<'_>,
        pending_wakers: &mut PendingWakers,
    ) -> Poll<io::Result<()>> {
        self.tx_fanout.register_read(cx.waker());
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);
        let res = Pin::new(&mut self.ws)
            .poll_flush(&mut fanout_cx)
            .map_err(ws_err_to_io);
        if res.is_ready() {
            pending_wakers.push(self.tx_fanout.clear_read_tx_and_take_write());
        }
        res
    }

    fn poll_read_collecting(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        pending_wakers: &mut PendingWakers,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            self.tx_fanout.clear_read();
            return Poll::Ready(Ok(()));
        }

        let mut pending_flush_err: Option<io::Error> = None;

        loop {
            if !self.read_buf.is_empty() {
                let to_copy = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf.split_to(to_copy));
                self.any_read_bytes = true;
                self.tx_fanout.clear_read();
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                self.tx_fanout.clear_read();
                return Poll::Ready(Ok(()));
            }

            // Ensure any queued outbound frames are flushed to the underlying transport even if
            // the caller went straight from `write_all` into `read` without `flush`. Using
            // `tx_fanout_waker` preserves any concurrent split writer's waker, and falling
            // through to `poll_next` on `Pending` (or write error) ensures downlink frames are
            // never stalled or dropped behind a congested or write-broken uplink.
            // Once an uplink flush has failed after downlink bytes have been received
            // (`uplink_flush_failed`), skip futile uplink flush retries so multi-frame server
            // responses separated by async gaps drain cleanly through EOF.
            if !self.uplink_flush_failed
                && pending_flush_err.is_none()
                && let Poll::Ready(Err(e)) = self.poll_flush_from_read(cx, pending_wakers)
            {
                if self.any_read_bytes {
                    self.uplink_flush_failed = true;
                }
                pending_flush_err = Some(e);
            }

            // `tokio-tungstenite`'s `Stream::poll_next` registers `cx` strictly on
            // `ContextWaker::Read` (leaving `ContextWaker::Write` pointing at `tx_fanout_waker`),
            // so even if `tungstenite::read()` auto-flushes a queued Pong/Close frame, both read
            // and write task wakers stay armed.
            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Pending => {
                    if let Some(err) = pending_flush_err {
                        if !self.any_read_bytes {
                            self.tx_fanout.clear_read();
                            return Poll::Ready(Err(err));
                        }
                        self.uplink_flush_failed = true;
                    }
                    self.tx_fanout.register_parked_read(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    self.tx_fanout.clear_read();
                    if let Some(err) = pending_flush_err {
                        if !self.any_read_bytes {
                            return Poll::Ready(Err(err));
                        }
                        self.uplink_flush_failed = true;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        if !data.is_empty() {
                            self.any_read_bytes = true;
                            if pending_flush_err.is_some() {
                                self.uplink_flush_failed = true;
                            }
                            self.read_buf.extend_from_slice(&data);
                        }
                    }
                    Message::Text(text) => {
                        if !text.is_empty() {
                            self.any_read_bytes = true;
                            if pending_flush_err.is_some() {
                                self.uplink_flush_failed = true;
                            }
                            self.read_buf.extend_from_slice(text.as_bytes());
                        }
                    }
                    Message::Close(_) => {
                        self.eof = true;
                        if !self.uplink_flush_failed && pending_flush_err.is_none() {
                            let _ = self.poll_flush_from_read(cx, pending_wakers);
                        }
                        self.tx_fanout.clear_read();
                        if let Some(err) = pending_flush_err {
                            if !self.any_read_bytes {
                                return Poll::Ready(Err(err));
                            }
                            self.uplink_flush_failed = true;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                        continue;
                    }
                },
                Poll::Ready(Some(Err(err))) => {
                    self.tx_fanout.clear_read();
                    return Poll::Ready(Err(ws_err_to_io(err)));
                }
            }
        }
    }

    fn poll_write_collecting(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
        pending_wakers: &mut PendingWakers,
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            pending_wakers.push(self.tx_fanout.clear_write_and_take_read_tx());
            return Poll::Ready(Ok(0));
        }
        self.tx_fanout.register_write(cx.waker());
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);
        match Pin::new(&mut self.ws).poll_ready(&mut fanout_cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                let (w_tx, w_parked) = self.tx_fanout.clear_write_and_take_read();
                pending_wakers.push(w_tx);
                pending_wakers.push(w_parked);
                Poll::Ready(Err(ws_err_to_io(e)))
            }
            Poll::Ready(Ok(())) => {
                let chunk_len = buf.len().min(MAX_WS_FRAME_CHUNK);
                let msg = Message::Binary(Bytes::copy_from_slice(&buf[..chunk_len]));
                if let Err(e) = Pin::new(&mut self.ws).start_send(msg) {
                    let (w_tx, w_parked) = self.tx_fanout.clear_write_and_take_read();
                    pending_wakers.push(w_tx);
                    pending_wakers.push(w_parked);
                    return Poll::Ready(Err(ws_err_to_io(e)));
                }
                match Pin::new(&mut self.ws).poll_flush(&mut fanout_cx) {
                    Poll::Ready(Ok(())) => {
                        self.uplink_flush_failed = false;
                        pending_wakers.push(self.tx_fanout.clear_write_and_take_read_tx());
                        Poll::Ready(Ok(chunk_len))
                    }
                    Poll::Pending => {
                        // Returning `Ready(Ok(chunk_len))` while buffered frame bytes remain in
                        // `tungstenite` / inner `BufStream`: clear write slot and wake both
                        // `read_tx` and any `parked_read` so a parked split reader re-polls
                        // `poll_flush_from_read` and drains remaining bytes even without `flush()`.
                        self.uplink_flush_failed = false;
                        let (w_tx, w_parked) = self.tx_fanout.clear_write_and_take_read();
                        pending_wakers.push(w_tx);
                        pending_wakers.push(w_parked);
                        Poll::Ready(Ok(chunk_len))
                    }
                    Poll::Ready(Err(e)) => {
                        let (w_tx, w_parked) = self.tx_fanout.clear_write_and_take_read();
                        pending_wakers.push(w_tx);
                        pending_wakers.push(w_parked);
                        Poll::Ready(Err(ws_err_to_io(e)))
                    }
                }
            }
        }
    }

    fn poll_flush_collecting(
        &mut self,
        cx: &mut Context<'_>,
        pending_wakers: &mut PendingWakers,
    ) -> Poll<io::Result<()>> {
        self.tx_fanout.register_write(cx.waker());
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);
        let res = Pin::new(&mut self.ws)
            .poll_flush(&mut fanout_cx)
            .map_err(ws_err_to_io);
        match &res {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.uplink_flush_failed = false;
                pending_wakers.push(self.tx_fanout.clear_write_and_take_read_tx());
            }
            Poll::Ready(Err(_)) => {
                let (w_tx, w_parked) = self.tx_fanout.clear_write_and_take_read();
                pending_wakers.push(w_tx);
                pending_wakers.push(w_parked);
            }
        }
        res
    }

    fn poll_shutdown_collecting(
        &mut self,
        cx: &mut Context<'_>,
        pending_wakers: &mut PendingWakers,
    ) -> Poll<io::Result<()>> {
        self.tx_fanout.register_write(cx.waker());
        let mut fanout_cx = Context::from_waker(&self.tx_fanout_waker);
        let res = Pin::new(&mut self.ws)
            .poll_close(&mut fanout_cx)
            .map_err(ws_err_to_io);
        match &res {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.uplink_flush_failed = false;
                pending_wakers.push(self.tx_fanout.clear_write_and_take_read_tx());
            }
            Poll::Ready(Err(_)) => {
                let (w_tx, w_parked) = self.tx_fanout.clear_write_and_take_read();
                pending_wakers.push(w_tx);
                pending_wakers.push(w_parked);
            }
        }
        res
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsByteStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut pending_wakers = PendingWakers::default();
        let res = self
            .get_mut()
            .poll_read_collecting(cx, buf, &mut pending_wakers);
        pending_wakers.wake_all();
        res
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsByteStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut pending_wakers = PendingWakers::default();
        let res = self
            .get_mut()
            .poll_write_collecting(cx, buf, &mut pending_wakers);
        pending_wakers.wake_all();
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pending_wakers = PendingWakers::default();
        let res = self
            .get_mut()
            .poll_flush_collecting(cx, &mut pending_wakers);
        pending_wakers.wake_all();
        res
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pending_wakers = PendingWakers::default();
        let res = self
            .get_mut()
            .poll_shutdown_collecting(cx, &mut pending_wakers);
        pending_wakers.wake_all();
        res
    }
}

fn format_ws_host_authority(effective_host: &str, port: u16, is_tls: bool) -> String {
    let host_for_uri = if effective_host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{effective_host}]")
    } else {
        effective_host.to_string()
    };
    let is_default_port = (is_tls && port == 443) || (!is_tls && port == 80);
    let has_explicit_port = if host_for_uri.starts_with('[') {
        host_for_uri.contains("]:")
    } else {
        host_for_uri.contains(':')
    };
    if has_explicit_port || is_default_port {
        host_for_uri
    } else {
        format!("{host_for_uri}:{port}")
    }
}

fn build_ws_upgrade_request(
    default_host: &str,
    port: u16,
    is_tls: bool,
    cfg: &WsTransportConfig,
    early_data: Option<&[u8]>,
) -> io::Result<http::Request<()>> {
    let (clean_path, _, ed_header_name) = cfg.normalized_parts();
    let effective_host = cfg.host_header().unwrap_or(default_host);
    let host_authority = format_ws_host_authority(effective_host, port, is_tls);
    let scheme = if is_tls { "wss" } else { "ws" };
    let uri = format!("{scheme}://{host_authority}{clean_path}");

    let mut req = uri.as_str().into_client_request().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid WebSocket request URI '{uri}': {e}"),
        )
    })?;

    if let Ok(hv) = http::HeaderValue::from_str(&host_authority) {
        req.headers_mut().insert(http::header::HOST, hv);
    }

    let mut has_ua = false;
    for (k, v) in &cfg.headers {
        let k_trim = k.trim();
        if k_trim.is_empty() || k_trim.eq_ignore_ascii_case("host") {
            continue;
        }
        if k_trim.eq_ignore_ascii_case("user-agent") {
            has_ua = true;
        }
        let hname = http::header::HeaderName::from_bytes(k_trim.as_bytes()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid WebSocket header name '{k_trim}': {e}"),
            )
        })?;
        let hval = http::HeaderValue::from_str(v.trim()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid WebSocket header value for '{k_trim}': {e}"),
            )
        })?;
        req.headers_mut().insert(hname, hval);
    }

    if !has_ua
        && let Ok(ua) =
            http::HeaderValue::from_str(&format!("rust-clash/{}", env!("CARGO_PKG_VERSION")))
    {
        req.headers_mut().insert(http::header::USER_AGENT, ua);
    }

    if let Some(ed) = early_data
        && !ed.is_empty()
    {
        let encoded = URL_SAFE_NO_PAD.encode(ed);
        let hname =
            http::header::HeaderName::from_bytes(ed_header_name.as_bytes()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid early-data header name '{ed_header_name}': {e}"),
                )
            })?;
        let hval = http::HeaderValue::from_str(&encoded).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid early-data header value: {e}"),
            )
        })?;
        req.headers_mut().insert(hname, hval);
    }

    Ok(req)
}

const MAX_WS_UPGRADE_RESPONSE_BYTES: usize = 16 * 1024;
const WS_ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn compute_sec_websocket_accept(sec_ws_key: &str) -> String {
    let mut ctx = DigestContext::new(&SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(sec_ws_key.as_bytes());
    ctx.update(WS_ACCEPT_GUID);
    BASE64_STD.encode(ctx.finish().as_ref())
}

/// Perform an RFC 6455 HTTP/1.1 client WebSocket upgrade on `inner` that validates
/// `101 Switching Protocols`, `Upgrade: websocket`, `Connection: Upgrade`, and
/// `Sec-WebSocket-Accept`, while tolerating servers (Xray-core, v2ray-core, sing-box)
/// that consume `Sec-WebSocket-Protocol` as 0-RTT early data without echoing it back.
async fn client_ws_handshake_rfc6455(
    mut inner: BoxedStream,
    req: http::Request<()>,
) -> io::Result<(WebSocketStream<BoxedStream>, BytesMut)> {
    let sec_ws_key = req
        .headers()
        .get("Sec-WebSocket-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing Sec-WebSocket-Key in WebSocket upgrade request",
            )
        })?
        .to_string();
    let expected_accept = compute_sec_websocket_accept(&sec_ws_key);

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    if path_and_query.contains(['\r', '\n', ' ']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid characters in WebSocket request target",
        ));
    }

    let mut raw_req = Vec::with_capacity(512);
    raw_req.extend_from_slice(b"GET ");
    raw_req.extend_from_slice(path_and_query.as_bytes());
    raw_req.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in req.headers() {
        raw_req.extend_from_slice(name.as_str().as_bytes());
        raw_req.extend_from_slice(b": ");
        raw_req.extend_from_slice(value.as_bytes());
        raw_req.extend_from_slice(b"\r\n");
    }
    raw_req.extend_from_slice(b"\r\n");

    inner.write_all(&raw_req).await?;
    inner.flush().await?;

    let mut resp_buf = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 2048];
    let hdr_end = loop {
        if let Some(pos) = resp_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if resp_buf.len() >= MAX_WS_UPGRADE_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WebSocket upgrade response headers exceeded 16 KiB",
            ));
        }
        let max_read = (MAX_WS_UPGRADE_RESPONSE_BYTES + 4)
            .saturating_sub(resp_buf.len())
            .min(tmp.len());
        let n = inner.read(&mut tmp[..max_read]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before WebSocket upgrade response completed",
            ));
        }
        resp_buf.extend_from_slice(&tmp[..n]);
    };

    let leftover = resp_buf.split_off(hdr_end + 4);
    let head_bytes = &resp_buf[..hdr_end];
    let head_str = std::str::from_utf8(head_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "non-UTF8 WebSocket upgrade response headers",
        )
    })?;

    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut status_parts = status_line.split_whitespace();
    let http_ver = status_parts.next().unwrap_or("");
    let status_code = status_parts.next().unwrap_or("");
    if !http_ver.starts_with("HTTP/1.") || status_code != "101" {
        return Err(io::Error::other(format!(
            "WebSocket upgrade rejected with status: {status_line}"
        )));
    }

    let mut has_upgrade_ws = false;
    let mut has_conn_upgrade = false;
    let mut accept_matched = false;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let val = val.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            if val
                .split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("websocket"))
            {
                has_upgrade_ws = true;
            }
        } else if name.eq_ignore_ascii_case("connection") {
            if val
                .split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
            {
                has_conn_upgrade = true;
            }
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") && val == expected_accept {
            accept_matched = true;
        }
    }

    if !has_upgrade_ws || !has_conn_upgrade || !accept_matched {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WebSocket 101 response missing valid Upgrade, Connection, or Sec-WebSocket-Accept header",
        ));
    }

    let ws = if leftover.is_empty() {
        WebSocketStream::from_raw_socket(inner, Role::Client, None).await
    } else {
        WebSocketStream::from_partially_read(inner, leftover.to_vec(), Role::Client, None).await
    };
    Ok((ws, BytesMut::new()))
}

type HandshakeBoxFuture = Pin<
    Box<
        dyn std::future::Future<Output = io::Result<(WebSocketStream<BoxedStream>, BytesMut)>>
            + Send,
    >,
>;

enum LazyEarlyDataState {
    Init {
        inner: Option<BoxedStream>,
        default_host: String,
        port: u16,
        is_tls: bool,
        cfg: WsTransportConfig,
        max_ed: usize,
    },
    Handshaking {
        fut: HandshakeBoxFuture,
        pending_ed_bytes: Vec<u8>,
        shared_waker: Arc<FanoutWaker>,
        poll_waker: Waker,
    },
    Connected {
        ws_stream: Box<WsByteStream<BoxedStream>>,
        pending_ed_bytes: Vec<u8>,
    },
    Failed,
}

/// Lazy WebSocket wrapper that piggybacks the first application write (`<= max_early_data` bytes)
/// into the HTTP Upgrade header (`Sec-WebSocket-Protocol` by default) for 0-RTT WS setup,
/// while streaming any remaining bytes over the established `WebSocketStream` with full backpressure.
pub struct LazyWsEarlyDataStream {
    state: parking_lot::Mutex<LazyEarlyDataState>,
}

impl LazyWsEarlyDataStream {
    fn new(
        inner: BoxedStream,
        default_host: String,
        port: u16,
        is_tls: bool,
        cfg: WsTransportConfig,
        max_ed: usize,
    ) -> Self {
        Self {
            state: parking_lot::Mutex::new(LazyEarlyDataState::Init {
                inner: Some(inner),
                default_host,
                port,
                is_tls,
                cfg,
                max_ed,
            }),
        }
    }
}

fn spawn_ws_handshake_future(
    inner: BoxedStream,
    default_host: String,
    port: u16,
    is_tls: bool,
    cfg: WsTransportConfig,
    ed_bytes: Option<Vec<u8>>,
) -> HandshakeBoxFuture {
    Box::pin(async move {
        let req = build_ws_upgrade_request(&default_host, port, is_tls, &cfg, ed_bytes.as_deref())?;
        tokio::time::timeout(
            crate::outbound::OUTBOUND_HANDSHAKE_TIMEOUT,
            client_ws_handshake_rfc6455(inner, req),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "WebSocket 0-RTT upgrade handshake timed out",
            )
        })?
    })
}

fn new_handshaking_state(fut: HandshakeBoxFuture, pending_ed_bytes: Vec<u8>) -> LazyEarlyDataState {
    let shared_waker = FanoutWaker::new();
    let poll_waker = Waker::from(Arc::clone(&shared_waker));
    LazyEarlyDataState::Handshaking {
        fut,
        pending_ed_bytes,
        shared_waker,
        poll_waker,
    }
}

impl AsyncRead for LazyWsEarlyDataStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut pending_wakers = PendingWakers::default();
        let poll_res = {
            let mut guard = self.state.lock();
            if buf.remaining() == 0 {
                match &mut *guard {
                    LazyEarlyDataState::Init { .. } | LazyEarlyDataState::Failed => {
                        Poll::Ready(Ok(()))
                    }
                    LazyEarlyDataState::Handshaking { shared_waker, .. } => {
                        shared_waker.clear_read();
                        Poll::Ready(Ok(()))
                    }
                    LazyEarlyDataState::Connected { ws_stream, .. } => {
                        ws_stream.poll_read_collecting(cx, buf, &mut pending_wakers)
                    }
                }
            } else {
                loop {
                    match &mut *guard {
                        LazyEarlyDataState::Init {
                            inner,
                            default_host,
                            port,
                            is_tls,
                            cfg,
                            ..
                        } => {
                            let Some(stream) = inner.take() else {
                                *guard = LazyEarlyDataState::Failed;
                                break Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "WS stream already consumed",
                                )));
                            };
                            let fut = spawn_ws_handshake_future(
                                stream,
                                default_host.clone(),
                                *port,
                                *is_tls,
                                cfg.clone(),
                                None,
                            );
                            *guard = new_handshaking_state(fut, Vec::new());
                        }
                        LazyEarlyDataState::Handshaking {
                            fut,
                            pending_ed_bytes,
                            shared_waker,
                            poll_waker,
                        } => {
                            shared_waker.register_read(cx.waker());
                            let mut shared_cx = Context::from_waker(poll_waker);
                            match fut.as_mut().poll(&mut shared_cx) {
                                Poll::Pending => break Poll::Pending,
                                Poll::Ready(Err(e)) => {
                                    pending_wakers
                                        .push(shared_waker.clear_read_tx_and_take_write());
                                    *guard = LazyEarlyDataState::Failed;
                                    break Poll::Ready(Err(e));
                                }
                                Poll::Ready(Ok((ws, init_rd))) => {
                                    let ed_bytes = std::mem::take(pending_ed_bytes);
                                    pending_wakers
                                        .push(shared_waker.clear_read_tx_and_take_write());
                                    *guard = LazyEarlyDataState::Connected {
                                        ws_stream: Box::new(WsByteStream::with_initial_read(
                                            ws, init_rd,
                                        )),
                                        pending_ed_bytes: ed_bytes,
                                    };
                                }
                            }
                        }
                        LazyEarlyDataState::Connected { ws_stream, .. } => {
                            break ws_stream.poll_read_collecting(cx, buf, &mut pending_wakers);
                        }
                        LazyEarlyDataState::Failed => {
                            break Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "WebSocket early-data handshake previously failed",
                            )));
                        }
                    }
                }
            }
        };
        pending_wakers.wake_all();
        poll_res
    }
}

impl AsyncWrite for LazyWsEarlyDataStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut pending_wakers = PendingWakers::default();
        let poll_res = {
            let mut guard = self.state.lock();
            if buf.is_empty() {
                match &mut *guard {
                    LazyEarlyDataState::Init { .. } | LazyEarlyDataState::Failed => {
                        Poll::Ready(Ok(0))
                    }
                    LazyEarlyDataState::Handshaking { shared_waker, .. } => {
                        shared_waker.clear_write();
                        Poll::Ready(Ok(0))
                    }
                    LazyEarlyDataState::Connected { ws_stream, .. } => {
                        ws_stream.poll_write_collecting(cx, buf, &mut pending_wakers)
                    }
                }
            } else {
                loop {
                    match &mut *guard {
                        LazyEarlyDataState::Init {
                            inner,
                            default_host,
                            port,
                            is_tls,
                            cfg,
                            max_ed,
                        } => {
                            let Some(stream) = inner.take() else {
                                *guard = LazyEarlyDataState::Failed;
                                break Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "WS stream already consumed",
                                )));
                            };
                            let ed_take = buf.len().min(*max_ed);
                            let ed_slice = buf[..ed_take].to_vec();
                            let fut = spawn_ws_handshake_future(
                                stream,
                                default_host.clone(),
                                *port,
                                *is_tls,
                                cfg.clone(),
                                Some(ed_slice.clone()),
                            );
                            *guard = new_handshaking_state(fut, ed_slice);
                        }
                        LazyEarlyDataState::Handshaking {
                            fut,
                            pending_ed_bytes,
                            shared_waker,
                            poll_waker,
                        } => {
                            shared_waker.register_write(cx.waker());
                            let mut shared_cx = Context::from_waker(poll_waker);
                            match fut.as_mut().poll(&mut shared_cx) {
                                Poll::Pending => break Poll::Pending,
                                Poll::Ready(Err(e)) => {
                                    pending_wakers
                                        .push(shared_waker.clear_write_and_take_read_tx());
                                    *guard = LazyEarlyDataState::Failed;
                                    break Poll::Ready(Err(e));
                                }
                                Poll::Ready(Ok((ws, init_rd))) => {
                                    let ed_bytes = std::mem::take(pending_ed_bytes);
                                    pending_wakers
                                        .push(shared_waker.clear_write_and_take_read_tx());
                                    *guard = LazyEarlyDataState::Connected {
                                        ws_stream: Box::new(WsByteStream::with_initial_read(
                                            ws, init_rd,
                                        )),
                                        pending_ed_bytes: ed_bytes,
                                    };
                                }
                            }
                        }
                        LazyEarlyDataState::Connected {
                            ws_stream,
                            pending_ed_bytes,
                        } => {
                            if !pending_ed_bytes.is_empty() {
                                let ed_len = pending_ed_bytes.len();
                                if buf.len() >= ed_len && buf[..ed_len] == pending_ed_bytes[..] {
                                    pending_ed_bytes.clear();
                                    pending_wakers
                                        .push(ws_stream.tx_fanout.clear_write_and_take_read_tx());
                                    break Poll::Ready(Ok(ed_len));
                                }
                                // Caller cancelled the initial 0-RTT write mid-handshake and retried
                                // with a shorter or mismatched buffer after those bytes were already
                                // transmitted in the HTTP Upgrade header. Poison the stream rather
                                // than returning `Ok(ed_len > buf.len())` (slice panic) or desyncing,
                                // and collect ALL parked companion wakers (including `parked_read`
                                // when the split reader is parked inside `poll_next` after
                                // `tx_fanout` cleared its `read_tx` slot) so dropping `ws_stream`
                                // never orphans a parked split reader.
                                let (w_rd, w_wr, w_parked) = ws_stream.tx_fanout.take_all();
                                pending_wakers.push(w_rd);
                                pending_wakers.push(w_wr);
                                pending_wakers.push(w_parked);
                                *guard = LazyEarlyDataState::Failed;
                                break Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "WebSocket 0-RTT write cancelled mid-handshake with mismatched retry buffer",
                                )));
                            }
                            break ws_stream.poll_write_collecting(cx, buf, &mut pending_wakers);
                        }
                        LazyEarlyDataState::Failed => {
                            break Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "WebSocket early-data handshake previously failed",
                            )));
                        }
                    }
                }
            }
        };
        pending_wakers.wake_all();
        poll_res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pending_wakers = PendingWakers::default();
        let poll_res = {
            let mut guard = self.state.lock();
            loop {
                match &mut *guard {
                    LazyEarlyDataState::Init {
                        inner,
                        default_host,
                        port,
                        is_tls,
                        cfg,
                        ..
                    } => {
                        let Some(stream) = inner.take() else {
                            *guard = LazyEarlyDataState::Failed;
                            break Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "WS stream already consumed",
                            )));
                        };
                        let fut = spawn_ws_handshake_future(
                            stream,
                            default_host.clone(),
                            *port,
                            *is_tls,
                            cfg.clone(),
                            None,
                        );
                        *guard = new_handshaking_state(fut, Vec::new());
                    }
                    LazyEarlyDataState::Handshaking {
                        fut,
                        pending_ed_bytes,
                        shared_waker,
                        poll_waker,
                    } => {
                        shared_waker.register_write(cx.waker());
                        let mut shared_cx = Context::from_waker(poll_waker);
                        match fut.as_mut().poll(&mut shared_cx) {
                            Poll::Pending => break Poll::Pending,
                            Poll::Ready(Err(e)) => {
                                pending_wakers.push(shared_waker.clear_write_and_take_read_tx());
                                *guard = LazyEarlyDataState::Failed;
                                break Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok((ws, init_rd))) => {
                                let ed_bytes = std::mem::take(pending_ed_bytes);
                                pending_wakers.push(shared_waker.clear_write_and_take_read_tx());
                                *guard = LazyEarlyDataState::Connected {
                                    ws_stream: Box::new(WsByteStream::with_initial_read(
                                        ws, init_rd,
                                    )),
                                    pending_ed_bytes: ed_bytes,
                                };
                            }
                        }
                    }
                    LazyEarlyDataState::Connected { ws_stream, .. } => {
                        break ws_stream.poll_flush_collecting(cx, &mut pending_wakers);
                    }
                    LazyEarlyDataState::Failed => {
                        break Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "WebSocket early-data handshake previously failed",
                        )));
                    }
                }
            }
        };
        pending_wakers.wake_all();
        poll_res
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pending_wakers = PendingWakers::default();
        let poll_res = {
            let mut guard = self.state.lock();
            loop {
                match &mut *guard {
                    LazyEarlyDataState::Init { .. } => {
                        *guard = LazyEarlyDataState::Failed;
                        break Poll::Ready(Ok(()));
                    }
                    LazyEarlyDataState::Handshaking {
                        fut,
                        pending_ed_bytes,
                        shared_waker,
                        poll_waker,
                    } => {
                        shared_waker.register_write(cx.waker());
                        let mut shared_cx = Context::from_waker(poll_waker);
                        match fut.as_mut().poll(&mut shared_cx) {
                            Poll::Pending => break Poll::Pending,
                            Poll::Ready(Err(e)) => {
                                pending_wakers.push(shared_waker.clear_write_and_take_read_tx());
                                *guard = LazyEarlyDataState::Failed;
                                break Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok((ws, init_rd))) => {
                                let ed_bytes = std::mem::take(pending_ed_bytes);
                                pending_wakers.push(shared_waker.clear_write_and_take_read_tx());
                                *guard = LazyEarlyDataState::Connected {
                                    ws_stream: Box::new(WsByteStream::with_initial_read(
                                        ws, init_rd,
                                    )),
                                    pending_ed_bytes: ed_bytes,
                                };
                            }
                        }
                    }
                    LazyEarlyDataState::Connected { ws_stream, .. } => {
                        break ws_stream.poll_shutdown_collecting(cx, &mut pending_wakers);
                    }
                    LazyEarlyDataState::Failed => {
                        break Poll::Ready(Ok(()));
                    }
                }
            }
        };
        pending_wakers.wake_all();
        poll_res
    }
}

/// Establish a client WebSocket byte stream over `inner` (either immediate 1-RTT HTTP Upgrade
/// or lazy 0-RTT Early-Data header injection when `max-early-data` / `?ed=` is configured).
pub async fn connect_ws_stream(
    inner: BoxedStream,
    default_host: &str,
    port: u16,
    is_tls: bool,
    cfg: &WsTransportConfig,
) -> io::Result<BoxedStream> {
    let (_clean_path, max_ed, _hdr_name) = cfg.normalized_parts();
    if max_ed > 0 {
        return Ok(Box::new(LazyWsEarlyDataStream::new(
            inner,
            default_host.to_string(),
            port,
            is_tls,
            cfg.clone(),
            max_ed,
        )));
    }

    let req = build_ws_upgrade_request(default_host, port, is_tls, cfg, None)?;
    let (ws, init_rd) = tokio::time::timeout(
        crate::outbound::OUTBOUND_HANDSHAKE_TIMEOUT,
        client_ws_handshake_rfc6455(inner, req),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "WebSocket upgrade handshake timed out",
        )
    })??;
    Ok(Box::new(WsByteStream::with_initial_read(ws, init_rd)))
}

/// Accept an inbound WebSocket stream (supporting optional `Sec-WebSocket-Protocol` early data)
/// for loopback E2E protocol servers (`VLESS+WS` and `Trojan+WS`).
/// Note: Matches Xray-core / v2ray-core / sing-box server behavior by consuming
/// `Sec-WebSocket-Protocol` early data WITHOUT echoing it in the `101 Switching Protocols` response.
#[allow(clippy::result_large_err)]
pub async fn accept_ws_stream(
    inner: BoxedStream,
    expected_path: Option<&str>,
) -> io::Result<BoxedStream> {
    let mut early_data = BytesMut::new();
    let expected = expected_path.map(|p| {
        let base = p.split('?').next().unwrap_or(p).trim();
        if base.is_empty() {
            "/".to_string()
        } else if base.starts_with('/') {
            base.to_string()
        } else {
            format!("/{base}")
        }
    });

    let ws = tokio_tungstenite::accept_hdr_async(
        inner,
        |req: &WsServerRequest, resp: WsServerResponse| {
            if let Some(exp) = &expected
                && req.uri().path() != exp
            {
                let err_resp = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Some("WebSocket path mismatch".to_string()))
                    .unwrap();
                return Err(err_resp);
            }
            if let Some(proto_val) = req.headers().get("Sec-WebSocket-Protocol")
                && let Ok(proto_str) = proto_val.to_str()
            {
                let trimmed = proto_str.trim();
                if let Ok(decoded) = URL_SAFE_NO_PAD.decode(trimmed.trim_end_matches('=')) {
                    early_data.extend_from_slice(&decoded);
                }
            }
            Ok(resp)
        },
    )
    .await
    .map_err(ws_err_to_io)?;

    Ok(Box::new(WsByteStream::with_initial_read(ws, early_data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_upgrade_request_encodes_spaces_and_utf8_while_preserving_plus_and_percent() {
        let cfg = WsTransportConfig {
            path: "/ws path/节点%20ok?token=a+b&ed=2048".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };
        let (clean_path, max_ed, _) = cfg.normalized_parts();
        assert_eq!(max_ed, 2048);
        assert_eq!(clean_path, "/ws%20path/%E8%8A%82%E7%82%B9%20ok?token=a+b");

        let req = build_ws_upgrade_request("edge.example.com", 443, true, &cfg, Some(b"hi"))
            .expect("upgrade request with spaces/UTF-8 path must build cleanly");
        assert_eq!(
            req.uri().path_and_query().unwrap().as_str(),
            "/ws%20path/%E8%8A%82%E7%82%B9%20ok?token=a+b"
        );
    }

    #[tokio::test]
    async fn lazy_ws_early_data_cancelled_pending_write_with_smaller_retry_never_panics() {
        let (c_io, s_io) = tokio::io::duplex(64 * 1024);
        let (allow_accept_tx, allow_accept_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let _ = allow_accept_rx.await;
            let _ws = accept_ws_stream(Box::new(s_io), Some("/ws")).await.unwrap();
        });

        let cfg = WsTransportConfig {
            path: "/ws?ed=2048".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };
        let mut cli_ws = connect_ws_stream(Box::new(c_io), "127.0.0.1", 8080, false, &cfg)
            .await
            .unwrap();

        // Drive `poll_write` with a 4096-byte buffer until `Poll::Pending` (handshake in flight
        // with 2048 bytes of early data embedded in the HTTP Upgrade header), then drop the future.
        let large_buf = vec![0xABu8; 4096];
        let mut polled_once = false;
        let first_poll = std::future::poll_fn(|cx| {
            if polled_once {
                return Poll::Ready(None);
            }
            polled_once = true;
            match Pin::new(&mut cli_ws).poll_write(cx, &large_buf) {
                Poll::Ready(res) => Poll::Ready(Some(res)),
                Poll::Pending => Poll::Ready(None),
            }
        })
        .await;
        assert!(
            first_poll.is_none(),
            "expected initial 0-RTT poll_write(4096) to return Poll::Pending while awaiting HTTP 101"
        );

        // Allow the server to send HTTP 101 Switching Protocols, then retry with a 4-byte slice.
        let _ = allow_accept_tx.send(());
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            cli_ws.write_all(&[1, 2, 3, 4]),
        )
        .await
        .expect("retry write_all timed out")
        .expect_err(
            "mismatched smaller retry after cancelled 0-RTT write must return Err, not slice-panic",
        );
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), srv_task).await;
    }

    #[tokio::test]
    async fn lazy_ws_early_data_split_dropped_reader_does_not_hang_writer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_101_tx, release_101_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // Wait until the test confirms Task W started handshaking and Task R polled once and dropped,
            // plus a brief delay to ensure Task W is parked awaiting HTTP 101.
            let _ = release_101_rx.await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let mut ws_srv = accept_ws_stream(Box::new(tcp), Some("/ws")).await.unwrap();
            let mut got = [0u8; 14];
            ws_srv.read_exact(&mut got).await.unwrap();
            got
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let cfg = WsTransportConfig {
            path: "/ws?ed=2048".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };
        let cli_ws = connect_ws_stream(Box::new(tcp), "127.0.0.1", addr.port(), false, &cfg)
            .await
            .unwrap();
        let (mut rd_half, mut wr_half) = tokio::io::split(cli_ws);

        // Task W initiates the 0-RTT handshake and parks awaiting HTTP 101.
        let wr_task = tokio::spawn(async move {
            wr_half.write_all(b"WAKE-WRITER-OK").await.unwrap();
            wr_half.flush().await.unwrap();
        });

        // Yield briefly so Task W enters `LazyEarlyDataState::Handshaking` and registers its waker.
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;

        // Task R polls `poll_read` ONCE against the same `Handshaking` future and is then DROPPED.
        // Without `SharedHandshakeWaker`, polling `fut` from Task R overwrites the socket waker
        // with Task R's dead waker and permanently hangs Task W.
        let rd_task = tokio::spawn(async move {
            let mut tmp = [0u8; 16];
            let mut polled_once = false;
            std::future::poll_fn(|cx| {
                if polled_once {
                    return Poll::Ready(());
                }
                polled_once = true;
                let mut rb = ReadBuf::new(&mut tmp);
                let poll = Pin::new(&mut rd_half).poll_read(cx, &mut rb);
                assert!(
                    matches!(poll, Poll::Pending),
                    "expected Handshaking poll_read to return Pending before HTTP 101"
                );
                Poll::Ready(())
            })
            .await;
            drop(rd_half);
        });
        rd_task.await.unwrap();

        // Now allow the server to send HTTP 101 — Task W MUST wake up and complete cleanly!
        let _ = release_101_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), wr_task)
            .await
            .expect("Task W hung after Task R polled Handshaking once and dropped!")
            .unwrap();

        let srv_got = tokio::time::timeout(std::time::Duration::from_secs(2), srv_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&srv_got, b"WAKE-WRITER-OK");
    }

    async fn run_direct_ws_split_saturated_upload_case(payload: Vec<u8>) {
        let expected_len = payload.len();
        let (c_io, s_io) = tokio::io::duplex(256);
        let cfg = WsTransportConfig {
            path: "/ws".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };

        let (cli_ws, mut srv_ws) = tokio::try_join!(
            connect_ws_stream(Box::new(c_io), "127.0.0.1", 8080, false, &cfg),
            accept_ws_stream(Box::new(s_io), Some("/ws")),
        )
        .expect("direct WS handshake over duplex(256) failed");

        let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);
        let (start_drain_tx, start_drain_rx) = tokio::sync::oneshot::channel::<()>();

        let expected_srv = payload.clone();
        let srv_task = tokio::spawn(async move {
            let _ = start_drain_rx.await;
            let mut got = vec![0u8; expected_len];
            srv_ws.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_srv);
            srv_ws.write_all(b"ws-done").await.unwrap();
            srv_ws.flush().await.unwrap();
        });

        // Writer saturates `duplex(256)` and parks `Pending` inside `poll_ready` / `poll_flush`.
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&payload).await.unwrap();
            c_wr.flush().await.unwrap();
        });

        // Give writer time to fill the 256-byte duplex and park its write waker.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        // Concurrent reader polls `WsByteStream::poll_read`, which opportunistically flushes.
        // Without `FanoutWaker`, this overwrites the writer's waker and permanently deadlocks.
        let rd_task = tokio::spawn(async move {
            let mut resp = [0u8; 7];
            c_rd.read_exact(&mut resp).await.unwrap();
            resp
        });

        // Give reader time to execute `poll_read` -> `poll_flush` while writer is parked.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        // Release server to drain the entire upload before replying `b"ws-done"`.
        let _ = start_drain_tx.send(());

        let (wr_res, rd_res, srv_res) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(wr_task, rd_task, srv_task)
            })
            .await
            .expect("direct WsByteStream split saturated upload deadlocked (waker clobbered)");

        wr_res.unwrap();
        assert_eq!(&rd_res.unwrap(), b"ws-done");
        srv_res.unwrap();
    }

    #[tokio::test]
    async fn ws_byte_stream_split_saturated_upload_does_not_clobber_writer_waker() {
        // Case A: 64 KiB upload + flush (exact Challenger 1 exploit; writer parks in `poll_flush`).
        run_direct_ws_split_saturated_upload_case(vec![0xABu8; 64 * 1024]).await;

        // Case B: 256 KiB upload (exceeds tungstenite's 128 KiB `write_buffer_size`, so writer
        // parks mid-`write_all` inside `Sink::poll_ready` even before reaching `flush`).
        let payload_256k: Vec<u8> = (0..(256 * 1024))
            .map(|i| ((i * 31 + 7) & 0xFF) as u8)
            .collect();
        run_direct_ws_split_saturated_upload_case(payload_256k).await;
    }

    #[tokio::test]
    async fn lazy_ws_early_data_connected_split_saturated_upload_does_not_clobber_writer_waker() {
        let (c_io, s_io) = tokio::io::duplex(256);
        let cfg = WsTransportConfig {
            path: "/ws?ed=2048".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };

        let cli_ws = connect_ws_stream(Box::new(c_io), "127.0.0.1", 8080, false, &cfg)
            .await
            .unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);

        let payload: Vec<u8> = (0..(256 * 1024))
            .map(|i| ((i * 53 + 11) & 0xFF) as u8)
            .collect();
        let expected_srv = payload.clone();
        let (start_drain_tx, start_drain_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let mut srv_ws = accept_ws_stream(Box::new(s_io), Some("/ws")).await.unwrap();
            // Phase 1: Complete 0-RTT handshake so client transitions to `Connected`.
            let mut hello = [0u8; 10];
            srv_ws.read_exact(&mut hello).await.unwrap();
            assert_eq!(&hello, b"HELLO-0RTT");
            srv_ws.write_all(b"READY").await.unwrap();
            srv_ws.flush().await.unwrap();

            // Phase 2: Wait until client writer is parked and client reader has polled `poll_read`.
            let _ = start_drain_rx.await;
            let mut got = vec![0u8; expected_srv.len()];
            srv_ws.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_srv);
            srv_ws.write_all(b"ed-done").await.unwrap();
            srv_ws.flush().await.unwrap();
        });

        // Drive initial 0-RTT handshake to completion so `LazyWsEarlyDataStream` is in `Connected`.
        let ((), ready_ack) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let wr = async {
                c_wr.write_all(b"HELLO-0RTT").await.unwrap();
                c_wr.flush().await.unwrap();
            };
            let rd = async {
                let mut ack = [0u8; 5];
                c_rd.read_exact(&mut ack).await.unwrap();
                ack
            };
            tokio::join!(wr, rd)
        })
        .await
        .expect("0-RTT handshake phase timed out");
        assert_eq!(&ready_ack, b"READY");

        // Now exercise saturated split-stream upload in `LazyEarlyDataState::Connected`.
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&payload).await.unwrap();
            c_wr.flush().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let rd_task = tokio::spawn(async move {
            let mut resp = [0u8; 7];
            c_rd.read_exact(&mut resp).await.unwrap();
            resp
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let _ = start_drain_tx.send(());

        let (wr_res, rd_res, srv_res) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(wr_task, rd_task, srv_task)
            })
            .await
            .expect("LazyWsEarlyDataStream Connected split saturated upload deadlocked");

        wr_res.unwrap();
        assert_eq!(&rd_res.unwrap(), b"ed-done");
        srv_res.unwrap();
    }

    #[tokio::test]
    async fn ws_byte_stream_split_saturated_upload_with_interleaved_ping_delivers_pong_and_completes()
     {
        use futures_util::{SinkExt, StreamExt};

        let (c_io, s_io) = tokio::io::duplex(256);
        let cfg = WsTransportConfig {
            path: "/ws".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };

        let (cli_ws, mut raw_srv_ws) = tokio::try_join!(
            connect_ws_stream(Box::new(c_io), "127.0.0.1", 8080, false, &cfg),
            async move {
                tokio_tungstenite::accept_async(s_io)
                    .await
                    .map_err(ws_err_to_io)
            },
        )
        .expect("raw WS handshake over duplex(256) failed");

        let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);
        let payload: Vec<u8> = (0..(256 * 1024))
            .map(|i| ((i * 17 + 3) & 0xFF) as u8)
            .collect();
        let expected_srv = payload.clone();

        let (send_ping_tx, send_ping_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let _ = send_ping_rx.await;

            // Send Ping #1 while the client's upload path is completely saturated so `poll_next`
            // auto-queues a `Pong` reply right into the congested outbound write path.
            raw_srv_ws
                .send(Message::Ping(Bytes::from_static(b"ping-sat-1")))
                .await
                .unwrap();

            // Give client reader time to receive Ping #1 and attempt Pong flush under saturation.
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;

            let mut received = Vec::with_capacity(expected_srv.len());
            let mut pongs: Vec<Bytes> = Vec::new();
            let mut sent_second_ping = false;

            while received.len() < expected_srv.len() || pongs.len() < 2 {
                let msg = raw_srv_ws
                    .next()
                    .await
                    .expect("server WS ended prematurely")
                    .expect("server WS read error");
                match msg {
                    Message::Binary(data) => received.extend_from_slice(&data),
                    Message::Pong(p) => {
                        pongs.push(p.clone());
                        if !sent_second_ping && p.as_ref() == b"ping-sat-1" {
                            sent_second_ping = true;
                            raw_srv_ws
                                .send(Message::Ping(Bytes::from_static(b"ping-mid-2")))
                                .await
                                .unwrap();
                        }
                    }
                    other => panic!("unexpected WS message from client: {other:?}"),
                }
            }

            assert_eq!(received, expected_srv);
            assert_eq!(
                pongs,
                vec![
                    Bytes::from_static(b"ping-sat-1"),
                    Bytes::from_static(b"ping-mid-2"),
                ]
            );

            raw_srv_ws
                .send(Message::Binary(Bytes::from_static(b"ping-done")))
                .await
                .unwrap();
        });

        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&payload).await.unwrap();
            c_wr.flush().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let rd_task = tokio::spawn(async move {
            let mut resp = [0u8; 9];
            c_rd.read_exact(&mut resp).await.unwrap();
            resp
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let _ = send_ping_tx.send(());

        let (wr_res, rd_res, srv_res) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(wr_task, rd_task, srv_task)
            })
            .await
            .expect("WsByteStream split upload with interleaved Ping deadlocked");

        wr_res.unwrap();
        assert_eq!(&rd_res.unwrap(), b"ping-done");
        srv_res.unwrap();
    }

    #[tokio::test]
    async fn ws_byte_stream_poll_read_delivers_buffered_downlink_on_write_error_and_half_close() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct ControlledWriteFailStream {
            rx: BytesMut,
            block_writes: Arc<AtomicBool>,
            fail_writes: Arc<AtomicBool>,
        }

        impl AsyncRead for ControlledWriteFailStream {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.rx.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let n = self.rx.len().min(buf.remaining());
                buf.put_slice(&self.rx.split_to(n));
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for ControlledWriteFailStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.fail_writes.load(Ordering::Acquire) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "simulated uplink failure",
                    )));
                }
                if self.block_writes.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.fail_writes.load(Ordering::Acquire) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "simulated uplink flush failure",
                    )));
                }
                if self.block_writes.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Part A: Queued outbound frame hits `BrokenPipe` on `poll_flush` inside `poll_read`,
        // yet `poll_read` still drains the server's buffered Binary + Close frames cleanly.
        let mut rx_frames = BytesMut::new();
        // Unmasked server Binary frame: FIN=1, opcode=0x2, len=12, payload="HTTP-413-ERR"
        rx_frames.extend_from_slice(&[0x82, 12]);
        rx_frames.extend_from_slice(b"HTTP-413-ERR");
        // Unmasked server Close frame: FIN=1, opcode=0x8, len=0
        rx_frames.extend_from_slice(&[0x88, 0x00]);

        let block_writes = Arc::new(AtomicBool::new(true));
        let fail_writes = Arc::new(AtomicBool::new(false));
        let mock = ControlledWriteFailStream {
            rx: rx_frames,
            block_writes: Arc::clone(&block_writes),
            fail_writes: Arc::clone(&fail_writes),
        };
        let ws = WebSocketStream::from_raw_socket(mock, Role::Client, None).await;
        let mut byte_ws = WsByteStream::new(ws);

        // Queue an outbound frame while inner write returns Pending so it stays in `out_buffer`.
        byte_ws.write_all(b"queued-upload").await.unwrap();
        // Now flip inner write to return BrokenPipe; `poll_read` must still deliver buffered server data!
        fail_writes.store(true, Ordering::Release);
        block_writes.store(false, Ordering::Release);

        let mut drained = Vec::new();
        byte_ws.read_to_end(&mut drained).await.unwrap();
        assert_eq!(&drained, b"HTTP-413-ERR");

        // Part B: Split-stream saturated upload + `shutdown()` (writer parks in `poll_shutdown`)
        // with concurrent `read_to_end`, while server drains exact payload and sends response data
        // before observing the client's Close frame (RFC 6455 `ClosedByUs::can_read()`).
        let (c_io, s_io) = tokio::io::duplex(256);
        let cfg = WsTransportConfig {
            path: "/ws".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };
        let (cli_ws, mut srv_ws) = tokio::try_join!(
            connect_ws_stream(Box::new(c_io), "127.0.0.1", 8080, false, &cfg),
            accept_ws_stream(Box::new(s_io), Some("/ws")),
        )
        .unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);
        let payload = vec![0x5Au8; 64 * 1024];
        let expected_srv = payload.clone();
        let (release_srv_tx, release_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let _ = release_srv_rx.await;
            let mut req = vec![0u8; expected_srv.len()];
            srv_ws.read_exact(&mut req).await.unwrap();
            assert_eq!(req, expected_srv);
            srv_ws.write_all(b"after-client-close").await.unwrap();
            srv_ws.flush().await.unwrap();
            srv_ws.shutdown().await.unwrap();
            let mut tail = Vec::new();
            srv_ws.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());
        });

        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&payload).await.unwrap();
            c_wr.shutdown().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let rd_task = tokio::spawn(async move {
            let mut resp = Vec::new();
            c_rd.read_to_end(&mut resp).await.unwrap();
            resp
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let _ = release_srv_tx.send(());

        let (wr_res, rd_res, srv_res) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(wr_task, rd_task, srv_task)
            })
            .await
            .expect("half-close saturated split WS test timed out");
        wr_res.unwrap();
        assert_eq!(&rd_res.unwrap(), b"after-client-close");
        srv_res.unwrap();
    }

    async fn run_lazy_ws_connected_to_failed_wakes_split_reader(
        client_io: BoxedStream,
        server_io: BoxedStream,
        port: u16,
    ) {
        let (release_101_tx, release_101_rx) = tokio::sync::oneshot::channel::<()>();
        let (srv_accepted_tx, srv_accepted_rx) = tokio::sync::oneshot::channel::<()>();
        let (close_srv_tx, close_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let _ = release_101_rx.await;
            let mut srv_ws = accept_ws_stream(server_io, Some("/ws")).await.unwrap();
            let mut early = [0u8; 15];
            srv_ws.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"EARLY-0RTT-DATA");
            let _ = srv_accepted_tx.send(());
            // Keep the server connection open and completely silent until the test finishes
            // asserting the client's split reader woke up strictly from `Connected -> Failed`.
            let _ = close_srv_rx.await;
            drop(srv_ws);
        });

        let cfg = WsTransportConfig {
            path: "/ws?ed=2048".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };
        let cli_ws = connect_ws_stream(client_io, "127.0.0.1", port, false, &cfg)
            .await
            .unwrap();
        let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);

        // Step 1: Writer initiates 0-RTT write (`Init -> Handshaking`) and cancels mid-handshake.
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            c_wr.write(b"EARLY-0RTT-DATA"),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "expected initial 0-RTT write to remain Pending while server holds HTTP 101"
        );

        // Step 2: Release HTTP 101; split reader drives `Handshaking -> Connected` and then parks
        // inside `WsByteStream::poll_read` (`poll_flush_from_read` clears `tx_fanout` slot 0, and
        // `poll_next` parks in `AllowStd` + `WsByteStream::rx_waker`).
        let _ = release_101_tx.send(());
        let rd_task = tokio::spawn(async move {
            let mut buf = [0u8; 32];
            c_rd.read(&mut buf).await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), srv_accepted_rx)
            .await
            .expect("server did not complete 0-RTT WS accept")
            .unwrap();
        // Give the reader task time to process HTTP 101 and park in `Connected::poll_next`.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Step 3: Writer retries with a shorter/mismatched buffer, poisoning `Connected -> Failed`.
        let wr_err = tokio::time::timeout(std::time::Duration::from_secs(1), c_wr.write(b"SHORT"))
            .await
            .expect("mismatched writer retry timed out")
            .expect_err("mismatched 0-RTT retry must fail with BrokenPipe");
        assert_eq!(wr_err.kind(), io::ErrorKind::BrokenPipe);

        // Step 4: Parked split reader MUST wake promptly (while server is still open and silent)
        // and observe `LazyEarlyDataState::Failed` (`BrokenPipe`) instead of hanging forever.
        let rd_err = tokio::time::timeout(std::time::Duration::from_secs(1), rd_task)
            .await
            .expect("parked split reader hung forever after Connected -> Failed poison!")
            .unwrap()
            .expect_err("parked split reader must observe BrokenPipe after poison");
        assert_eq!(rd_err.kind(), io::ErrorKind::BrokenPipe);

        let _ = close_srv_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), srv_task).await;
    }

    #[tokio::test]
    async fn lazy_ws_early_data_connected_to_failed_wakes_parked_split_reader_duplex_and_tcp() {
        // Case A: In-memory `tokio::io::duplex`.
        let (c_duplex, s_duplex) = tokio::io::duplex(4096);
        run_lazy_ws_connected_to_failed_wakes_split_reader(
            Box::new(c_duplex),
            Box::new(s_duplex),
            8080,
        )
        .await;

        // Case B: Real loopback `tokio::net::TcpStream` (dropping fd does not wake local epoll
        // reader without explicit `rx_waker` notification).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cli_tcp, (srv_tcp, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).unwrap();
        run_lazy_ws_connected_to_failed_wakes_split_reader(
            Box::new(cli_tcp),
            Box::new(srv_tcp),
            addr.port(),
        )
        .await;
    }

    #[tokio::test]
    async fn ws_byte_stream_poll_read_drains_async_multi_frame_after_uplink_broken_pipe_and_fails_promptly_on_silent_broken_uplink()
     {
        struct AsymmetricDuplex {
            rd: tokio::io::DuplexStream,
            wr: tokio::io::DuplexStream,
        }

        impl AsyncRead for AsymmetricDuplex {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.rd).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for AsymmetricDuplex {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.wr).poll_write(cx, buf)
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.wr).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.wr).poll_shutdown(cx)
            }
        }

        async fn server_raw_ws_upgrade(
            s_up_rd: &mut tokio::io::DuplexStream,
            s_dn_wr: &mut tokio::io::DuplexStream,
        ) {
            let mut req_buf = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = s_up_rd.read(&mut tmp).await.unwrap();
                assert!(n > 0, "EOF before client WS upgrade request completed");
                req_buf.extend_from_slice(&tmp[..n]);
                if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let req_str = std::str::from_utf8(&req_buf).unwrap();
            let ws_key = req_str
                .lines()
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| v.trim().to_string())
                })
                .expect("missing Sec-WebSocket-Key in client upgrade request");
            let accept = compute_sec_websocket_accept(&ws_key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            s_dn_wr.write_all(resp.as_bytes()).await.unwrap();
            s_dn_wr.flush().await.unwrap();
        }

        // Case A: Pure `tokio::io::duplex` (256B uplink, 4096B downlink). Client saturates
        // `out_buffer` with a 32 KiB write; server reads 16B and drops its uplink reader (genuine
        // `BrokenPipe` on client uplink), then streams `Binary("HTTP-413-PART1")`, sleeps 25ms,
        // and sends `Binary("-PART2")` + `Close`. Client `read_to_end` must drain BOTH frames and
        // clean EOF without truncating on the inter-frame async gap, while write-side calls still
        // surface `BrokenPipe`.
        {
            let (c_up_wr, mut s_up_rd) = tokio::io::duplex(256);
            let (mut s_dn_wr, c_dn_rd) = tokio::io::duplex(4096);
            let client_io = AsymmetricDuplex {
                rd: c_dn_rd,
                wr: c_up_wr,
            };
            let cfg = WsTransportConfig {
                path: "/ws".to_string(),
                headers: HashMap::new(),
                max_early_data: None,
                early_data_header_name: None,
            };

            let (uplink_ready_tx, uplink_ready_rx) = tokio::sync::oneshot::channel::<()>();
            let (uplink_dropped_tx, uplink_dropped_rx) = tokio::sync::oneshot::channel::<()>();

            let srv_task = tokio::spawn(async move {
                server_raw_ws_upgrade(&mut s_up_rd, &mut s_dn_wr).await;
                let _ = uplink_ready_rx.await;

                // Read 16 bytes from the saturated uplink and drop the uplink reader to produce
                // a genuine `BrokenPipe` on any further client uplink flush/write.
                let mut hdr = [0u8; 16];
                s_up_rd.read_exact(&mut hdr).await.unwrap();
                drop(s_up_rd);

                // Send Part 1 as an unmasked server Binary frame before letting client start reading.
                let mut part1 = Vec::with_capacity(2 + 14);
                part1.extend_from_slice(&[0x82, 14]);
                part1.extend_from_slice(b"HTTP-413-PART1");
                s_dn_wr.write_all(&part1).await.unwrap();
                s_dn_wr.flush().await.unwrap();
                let _ = uplink_dropped_tx.send(());

                // Async inter-frame gap: previously caused poll #2 to retry `poll_flush_from_read`,
                // hit `BrokenPipe` while `poll_next` was `Pending`, and truncate `-PART2`.
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;

                let mut part2_and_close = Vec::with_capacity(2 + 6 + 2);
                part2_and_close.extend_from_slice(&[0x82, 6]);
                part2_and_close.extend_from_slice(b"-PART2");
                part2_and_close.extend_from_slice(&[0x88, 0x00]); // Unmasked Close frame
                s_dn_wr.write_all(&part2_and_close).await.unwrap();
                s_dn_wr.flush().await.unwrap();
            });

            let cli_ws = connect_ws_stream(Box::new(client_io), "127.0.0.1", 8080, false, &cfg)
                .await
                .unwrap();
            let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);

            // Saturate 256B uplink so ~32 KiB stays buffered in `tungstenite`'s `out_buffer`.
            let written = c_wr.write(&vec![0xAAu8; 32 * 1024]).await.unwrap();
            assert_eq!(written, 32 * 1024);
            let _ = uplink_ready_tx.send(());
            uplink_dropped_rx.await.unwrap();

            let mut got = Vec::new();
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                c_rd.read_to_end(&mut got),
            )
            .await
            .expect("multi-frame read_to_end timed out")
            .expect("multi-frame downlink after uplink BrokenPipe must return clean EOF");
            assert_eq!(n, b"HTTP-413-PART1-PART2".len());
            assert_eq!(&got, b"HTTP-413-PART1-PART2");

            // Write-side operations must still report the underlying uplink BrokenPipe error.
            let flush_err = c_wr
                .flush()
                .await
                .expect_err("write-side flush must still surface BrokenPipe");
            assert_eq!(flush_err.kind(), io::ErrorKind::BrokenPipe);

            tokio::time::timeout(std::time::Duration::from_secs(2), srv_task)
                .await
                .unwrap()
                .unwrap();
        }

        // Case B: Broken uplink with ZERO server response (downlink kept open and silent) must
        // still surface `Err(BrokenPipe)` promptly from `poll_read` without hanging.
        {
            let (c_up_wr, mut s_up_rd) = tokio::io::duplex(256);
            let (mut s_dn_wr, c_dn_rd) = tokio::io::duplex(4096);
            let client_io = AsymmetricDuplex {
                rd: c_dn_rd,
                wr: c_up_wr,
            };
            let cfg = WsTransportConfig {
                path: "/ws".to_string(),
                headers: HashMap::new(),
                max_early_data: None,
                early_data_header_name: None,
            };

            let (uplink_ready_tx, uplink_ready_rx) = tokio::sync::oneshot::channel::<()>();
            let (uplink_dropped_tx, uplink_dropped_rx) = tokio::sync::oneshot::channel::<()>();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

            let srv_task = tokio::spawn(async move {
                server_raw_ws_upgrade(&mut s_up_rd, &mut s_dn_wr).await;
                let _ = uplink_ready_rx.await;
                let mut hdr = [0u8; 16];
                s_up_rd.read_exact(&mut hdr).await.unwrap();
                drop(s_up_rd);
                let _ = uplink_dropped_tx.send(());
                // Hold downlink writer open with zero bytes sent until client read returns error.
                let _ = done_rx.await;
                drop(s_dn_wr);
            });

            let cli_ws = connect_ws_stream(Box::new(client_io), "127.0.0.1", 8080, false, &cfg)
                .await
                .unwrap();
            let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);

            let written = c_wr.write(&vec![0xBBu8; 32 * 1024]).await.unwrap();
            assert_eq!(written, 32 * 1024);
            let _ = uplink_ready_tx.send(());
            uplink_dropped_rx.await.unwrap();

            let mut buf = [0u8; 32];
            let err = tokio::time::timeout(std::time::Duration::from_secs(1), c_rd.read(&mut buf))
                .await
                .expect("poll_read hung on silent broken uplink instead of returning BrokenPipe!")
                .expect_err("silent broken uplink with zero server response must fail");
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

            let _ = done_tx.send(());
            tokio::time::timeout(std::time::Duration::from_secs(2), srv_task)
                .await
                .unwrap()
                .unwrap();
        }

        // Case C: Broken uplink with ZERO downlink payload followed immediately by `Close` must
        // surface `Err(BrokenPipe)` rather than silently returning `Ok(0)` EOF.
        {
            let (c_up_wr, mut s_up_rd) = tokio::io::duplex(256);
            let (mut s_dn_wr, c_dn_rd) = tokio::io::duplex(4096);
            let client_io = AsymmetricDuplex {
                rd: c_dn_rd,
                wr: c_up_wr,
            };
            let cfg = WsTransportConfig {
                path: "/ws".to_string(),
                headers: HashMap::new(),
                max_early_data: None,
                early_data_header_name: None,
            };

            let (uplink_ready_tx, uplink_ready_rx) = tokio::sync::oneshot::channel::<()>();
            let (uplink_dropped_tx, uplink_dropped_rx) = tokio::sync::oneshot::channel::<()>();

            let srv_task = tokio::spawn(async move {
                server_raw_ws_upgrade(&mut s_up_rd, &mut s_dn_wr).await;
                let _ = uplink_ready_rx.await;
                let mut hdr = [0u8; 16];
                s_up_rd.read_exact(&mut hdr).await.unwrap();
                drop(s_up_rd);
                // Immediately send Close with zero preceding payload frames.
                s_dn_wr.write_all(&[0x88, 0x00]).await.unwrap();
                s_dn_wr.flush().await.unwrap();
                let _ = uplink_dropped_tx.send(());
            });

            let cli_ws = connect_ws_stream(Box::new(client_io), "127.0.0.1", 8080, false, &cfg)
                .await
                .unwrap();
            let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);

            let written = c_wr.write(&vec![0xCCu8; 32 * 1024]).await.unwrap();
            assert_eq!(written, 32 * 1024);
            let _ = uplink_ready_tx.send(());
            uplink_dropped_rx.await.unwrap();

            let mut buf = [0u8; 32];
            let err = tokio::time::timeout(std::time::Duration::from_secs(1), c_rd.read(&mut buf))
                .await
                .expect("read after broken uplink + immediate Close timed out")
                .expect_err("broken uplink with zero payload bytes + Close must return BrokenPipe");
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

            tokio::time::timeout(std::time::Duration::from_secs(2), srv_task)
                .await
                .unwrap()
                .unwrap();
        }

        // Case D: Downlink bytes were ALREADY received earlier (`any_read_bytes == true`), THEN
        // uplink breaks while the next server frame is still 25ms away. `poll_read` must park
        // (`Poll::Pending`), receive the delayed frame, and return clean EOF on `Close`.
        {
            let (c_up_wr, mut s_up_rd) = tokio::io::duplex(256);
            let (mut s_dn_wr, c_dn_rd) = tokio::io::duplex(4096);
            let client_io = AsymmetricDuplex {
                rd: c_dn_rd,
                wr: c_up_wr,
            };
            let cfg = WsTransportConfig {
                path: "/ws".to_string(),
                headers: HashMap::new(),
                max_early_data: None,
                early_data_header_name: None,
            };

            let (uplink_ready_tx, uplink_ready_rx) = tokio::sync::oneshot::channel::<()>();
            let (uplink_dropped_tx, uplink_dropped_rx) = tokio::sync::oneshot::channel::<()>();

            let srv_task = tokio::spawn(async move {
                server_raw_ws_upgrade(&mut s_up_rd, &mut s_dn_wr).await;
                // Deliver initial downlink frame while uplink is still healthy.
                let mut pre = Vec::with_capacity(2 + 7);
                pre.extend_from_slice(&[0x82, 7]);
                pre.extend_from_slice(b"PRE-ERR");
                s_dn_wr.write_all(&pre).await.unwrap();
                s_dn_wr.flush().await.unwrap();

                let _ = uplink_ready_rx.await;
                let mut hdr = [0u8; 16];
                s_up_rd.read_exact(&mut hdr).await.unwrap();
                drop(s_up_rd);
                let _ = uplink_dropped_tx.send(());

                // Delay before sending post-error frame so first post-error `poll_read` hits
                // `BrokenPipe` on `poll_flush_from_read` AND `Poll::Pending` on `poll_next`.
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                let mut post_and_close = Vec::with_capacity(2 + 9 + 2);
                post_and_close.extend_from_slice(&[0x82, 9]);
                post_and_close.extend_from_slice(b"-POST-ERR");
                post_and_close.extend_from_slice(&[0x88, 0x00]);
                s_dn_wr.write_all(&post_and_close).await.unwrap();
                s_dn_wr.flush().await.unwrap();
            });

            let cli_ws = connect_ws_stream(Box::new(client_io), "127.0.0.1", 8080, false, &cfg)
                .await
                .unwrap();
            let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);

            let mut pre_buf = [0u8; 7];
            c_rd.read_exact(&mut pre_buf).await.unwrap();
            assert_eq!(&pre_buf, b"PRE-ERR");

            let written = c_wr.write(&vec![0xDDu8; 32 * 1024]).await.unwrap();
            assert_eq!(written, 32 * 1024);
            let _ = uplink_ready_tx.send(());
            uplink_dropped_rx.await.unwrap();

            let mut rest = Vec::new();
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                c_rd.read_to_end(&mut rest),
            )
            .await
            .expect("post-error delayed frame read_to_end timed out")
            .expect("delayed frame after prior any_read_bytes + broken uplink must succeed");
            assert_eq!(n, b"-POST-ERR".len());
            assert_eq!(&rest, b"-POST-ERR");

            tokio::time::timeout(std::time::Duration::from_secs(2), srv_task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_byte_stream_split_parked_reader_then_write_without_flush_drains_and_replies() {
        let (c_io, s_io) = tokio::io::duplex(256);
        let cli_ws =
            WsByteStream::new(WebSocketStream::from_raw_socket(c_io, Role::Client, None).await);
        let mut srv_ws =
            WsByteStream::new(WebSocketStream::from_raw_socket(s_io, Role::Server, None).await);

        let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);
        let payload: Vec<u8> = (0..4096).map(|i| ((i * 29 + 5) & 0xFF) as u8).collect();
        let expected_srv = payload.clone();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let _ = start_srv_rx.await;
            let mut got = vec![0u8; expected_srv.len()];
            srv_ws.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_srv);
            srv_ws.write_all(b"REPLY-OK").await.unwrap();
            srv_ws.flush().await.unwrap();
        });

        // Pre-park split Task R in `read_exact` while nothing is queued for TX.
        let rd_task = tokio::spawn(async move {
            let mut resp = [0u8; 8];
            c_rd.read_exact(&mut resp).await.unwrap();
            resp
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        // Task W writes 4096 B over duplex(256) WITHOUT calling `flush()`.
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&payload).await.unwrap();
            c_wr
        });
        let _c_wr = tokio::time::timeout(std::time::Duration::from_secs(2), wr_task)
            .await
            .expect("Task W write_all(4096) without flush timed out")
            .unwrap();

        // Release server to read all 4096 B and send reply.
        let _ = start_srv_tx.send(());

        let (rd_res, srv_res) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(rd_task, srv_task)
        })
        .await
        .expect("parked split Task R deadlocked after Task W write_all without flush");
        assert_eq!(&rd_res.unwrap(), b"REPLY-OK");
        srv_res.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_byte_stream_bufstream_split_cancelled_flush_then_reader_drains_and_replies() {
        let (c_io, s_io) = tokio::io::duplex(256);
        let c_buf = tokio::io::BufStream::new(c_io);
        let cli_ws =
            WsByteStream::new(WebSocketStream::from_raw_socket(c_buf, Role::Client, None).await);
        let mut srv_ws =
            WsByteStream::new(WebSocketStream::from_raw_socket(s_io, Role::Server, None).await);

        let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);
        let payload: Vec<u8> = (0..4096).map(|i| ((i * 41 + 13) & 0xFF) as u8).collect();
        let expected_srv = payload.clone();
        let (start_srv_tx, start_srv_rx) = tokio::sync::oneshot::channel::<()>();

        let srv_task = tokio::spawn(async move {
            let _ = start_srv_rx.await;
            let mut got = vec![0u8; expected_srv.len()];
            srv_ws.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_srv);
            srv_ws.write_all(b"BUF-OK").await.unwrap();
            srv_ws.flush().await.unwrap();
        });

        // Task W writes 4096 B into BufStream<duplex(256)> and timeout-cancels `flush()`.
        let wr_task = tokio::spawn(async move {
            c_wr.write_all(&payload).await.unwrap();
            let cancelled =
                tokio::time::timeout(std::time::Duration::from_millis(25), c_wr.flush()).await;
            assert!(
                cancelled.is_err(),
                "expected flush() over saturated BufStream<duplex(256)> to time out"
            );
            c_wr
        });
        let _c_wr = tokio::time::timeout(std::time::Duration::from_secs(2), wr_task)
            .await
            .expect("Task W cancelled-flush setup timed out")
            .unwrap();

        // Release server and spawn split Task R to drain the remaining buffered bytes and read reply.
        let _ = start_srv_tx.send(());
        let rd_task = tokio::spawn(async move {
            let mut resp = [0u8; 6];
            c_rd.read_exact(&mut resp).await.unwrap();
            resp
        });

        let (rd_res, srv_res) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(rd_task, srv_task)
        })
        .await
        .expect("split Task R deadlocked after Task W timeout-cancelled flush() on BufStream");
        assert_eq!(&rd_res.unwrap(), b"BUF-OK");
        srv_res.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_byte_stream_poll_write_wakes_parked_reader_on_pending_flush_and_broken_uplink() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingWake(AtomicUsize);
        impl Wake for CountingWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }

        // Part A: `poll_write` returning `Ready(Ok(chunk))`:
        // - on a fully flushed small frame: MUST NOT spuriously wake `parked_read`.
        // - on a `Pending` flush (4096 B over duplex(256)): MUST collect & wake `parked_read`
        //   strictly outside any outer mutex (`PendingWakers::wake_all`), without relying on
        //   `tokio-tungstenite`'s internal `write_waker_proxy.read_waker`.
        {
            let (c_io, _s_io) = tokio::io::duplex(256);
            let mut cli_ws =
                WsByteStream::new(WebSocketStream::from_raw_socket(c_io, Role::Client, None).await);

            let rd_counter = Arc::new(CountingWake(AtomicUsize::new(0)));
            let rd_waker = Waker::from(Arc::clone(&rd_counter));
            let mut rd_cx = Context::from_waker(&rd_waker);
            let mut tmp = [0u8; 16];
            let mut rb = ReadBuf::new(&mut tmp);
            assert!(
                matches!(
                    Pin::new(&mut cli_ws).poll_read(&mut rd_cx, &mut rb),
                    Poll::Pending
                ),
                "expected initial poll_read to park Pending"
            );
            assert_eq!(rd_counter.0.load(Ordering::Acquire), 0);

            let wr_counter = Arc::new(CountingWake(AtomicUsize::new(0)));
            let wr_waker = Waker::from(Arc::clone(&wr_counter));
            let mut wr_cx = Context::from_waker(&wr_waker);

            // Small frame flushes completely into duplex(256) -> no spurious parked-reader wakeup.
            let small_poll = Pin::new(&mut cli_ws).poll_write(&mut wr_cx, b"small-frame-16!!");
            assert!(matches!(small_poll, Poll::Ready(Ok(16))));
            assert_eq!(
                rd_counter.0.load(Ordering::Acquire),
                0,
                "fully flushed poll_write must not spuriously wake parked_read"
            );

            // Large frame saturates duplex(256) and leaves buffered bytes in tungstenite:
            // `poll_write_collecting` must defer waking until `PendingWakers::wake_all()` (so
            // `LazyWsEarlyDataStream` never calls `wake()` while holding `self.state.lock()`).
            let payload = vec![0xABu8; 4096];
            let mut collected = PendingWakers::default();
            let wr_poll = cli_ws.poll_write_collecting(&mut wr_cx, &payload, &mut collected);
            assert!(
                matches!(wr_poll, Poll::Ready(Ok(4096))),
                "expected poll_write(4096) to return Ready(Ok(4096)), got {wr_poll:?}"
            );
            assert_eq!(
                rd_counter.0.load(Ordering::Acquire),
                0,
                "poll_write_collecting must not invoke wake() before outer lock release"
            );
            collected.wake_all();
            assert_eq!(
                rd_counter.0.load(Ordering::Acquire),
                1,
                "poll_write returning Ready(Ok(chunk)) on Pending flush MUST wake parked reader"
            );
        }

        // Part B: Pre-parked split Task R on a silent broken uplink MUST wake promptly and observe
        // `BrokenPipe` when split Task W's `write()` hits `BrokenPipe` (without waking `write_waker_proxy`).
        {
            struct AsymmetricDuplex {
                rd: tokio::io::DuplexStream,
                wr: tokio::io::DuplexStream,
            }
            impl AsyncRead for AsymmetricDuplex {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &mut ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    Pin::new(&mut self.rd).poll_read(cx, buf)
                }
            }
            impl AsyncWrite for AsymmetricDuplex {
                fn poll_write(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<io::Result<usize>> {
                    Pin::new(&mut self.wr).poll_write(cx, buf)
                }
                fn poll_flush(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Pin::new(&mut self.wr).poll_flush(cx)
                }
                fn poll_shutdown(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Pin::new(&mut self.wr).poll_shutdown(cx)
                }
            }

            let (c_up_wr, s_up_rd) = tokio::io::duplex(256);
            let (_s_dn_wr, c_dn_rd) = tokio::io::duplex(4096);
            let client_io = AsymmetricDuplex {
                rd: c_dn_rd,
                wr: c_up_wr,
            };
            let cli_ws = WsByteStream::new(
                WebSocketStream::from_raw_socket(client_io, Role::Client, None).await,
            );
            let (mut c_rd, mut c_wr) = tokio::io::split(cli_ws);

            // Pre-park split Task R in `read` while uplink is healthy and nothing is queued.
            let rd_task = tokio::spawn(async move {
                let mut buf = [0u8; 32];
                c_rd.read(&mut buf).await
            });
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;

            // Break uplink while keeping downlink open and silent.
            drop(s_up_rd);

            // Task W writes and synchronously hits BrokenPipe on flush.
            let wr_err = c_wr
                .write(&vec![0xAAu8; 32 * 1024])
                .await
                .expect_err("expected Task W write on broken uplink to fail with BrokenPipe");
            assert_eq!(wr_err.kind(), io::ErrorKind::BrokenPipe);

            // Parked Task R MUST wake promptly and surface BrokenPipe instead of hanging forever.
            let rd_err = tokio::time::timeout(std::time::Duration::from_secs(1), rd_task)
                .await
                .expect("pre-parked split Task R hung after Task W hit BrokenPipe on silent broken uplink!")
                .unwrap()
                .expect_err("expected pre-parked split Task R to observe BrokenPipe");
            assert_eq!(rd_err.kind(), io::ErrorKind::BrokenPipe);
        }
    }

    #[tokio::test]
    async fn lazy_ws_early_data_zero_len_read_preserves_0rtt_header() {
        let (c_io, mut s_io) = tokio::io::duplex(4096);
        let cfg = WsTransportConfig {
            path: "/ws?ed=2048".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };
        let mut cli_ws = connect_ws_stream(Box::new(c_io), "127.0.0.1", 8080, false, &cfg)
            .await
            .unwrap();

        // A 0-byte read in `Init` must be a no-op and NOT trigger a non-0-RTT upgrade request.
        let mut empty = [];
        let n = cli_ws.read(&mut empty).await.unwrap();
        assert_eq!(n, 0);

        let srv_task = tokio::spawn(async move {
            let mut req_buf = Vec::new();
            let mut tmp = [0u8; 512];
            while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let k = s_io.read(&mut tmp).await.unwrap();
                assert!(k > 0);
                req_buf.extend_from_slice(&tmp[..k]);
            }
            let req_str = String::from_utf8(req_buf).unwrap();
            let ws_key = req_str
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| v.trim().to_string())
                })
                .unwrap();
            let has_ed_hdr = req_str.lines().any(|l| {
                l.split_once(':').is_some_and(|(k, v)| {
                    k.trim().eq_ignore_ascii_case("sec-websocket-protocol")
                        && URL_SAFE_NO_PAD
                            .decode(v.trim())
                            .is_ok_and(|d| d == b"0RTT-HELLO")
                })
            });
            let accept = compute_sec_websocket_accept(&ws_key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            s_io.write_all(resp.as_bytes()).await.unwrap();
            s_io.flush().await.unwrap();
            has_ed_hdr
        });

        cli_ws.write_all(b"0RTT-HELLO").await.unwrap();
        let saw_0rtt = tokio::time::timeout(std::time::Duration::from_secs(2), srv_task)
            .await
            .expect("0-RTT handshake server task timed out")
            .unwrap();
        assert!(
            saw_0rtt,
            "zero-length read before first write broke 0-RTT Sec-WebSocket-Protocol header!"
        );
    }
}
