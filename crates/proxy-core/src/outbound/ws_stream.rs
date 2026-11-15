use std::{
    collections::HashMap,
    io,
    pin::Pin,
    task::{Context, Poll},
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

/// Bidirectional `AsyncRead + AsyncWrite` adapter over a binary RFC 6455 `WebSocketStream`.
pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    read_buf: BytesMut,
    eof: bool,
}

impl<S> WsByteStream<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self::with_initial_read(ws, BytesMut::new())
    }

    pub fn with_initial_read(ws: WebSocketStream<S>, initial_read: BytesMut) -> Self {
        Self {
            ws,
            read_buf: initial_read,
            eof: false,
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsByteStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !self.read_buf.is_empty() {
                let to_copy = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf.split_to(to_copy));
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }

            // Ensure any queued outbound frames are flushed to the underlying transport
            // even if the caller went straight from `write_all` into `read` without `flush`.
            if let Poll::Ready(Err(e)) = Pin::new(&mut self.ws).poll_flush(cx) {
                return Poll::Ready(Err(ws_err_to_io(e)));
            }

            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        if !data.is_empty() {
                            self.read_buf.extend_from_slice(&data);
                        }
                    }
                    Message::Text(text) => {
                        if !text.is_empty() {
                            self.read_buf.extend_from_slice(text.as_bytes());
                        }
                    }
                    Message::Close(_) => {
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                        continue;
                    }
                },
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(ws_err_to_io(err)));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsByteStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match Pin::new(&mut self.ws).poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(ws_err_to_io(e))),
            Poll::Ready(Ok(())) => {
                let chunk_len = buf.len().min(MAX_WS_FRAME_CHUNK);
                let msg = Message::Binary(Bytes::copy_from_slice(&buf[..chunk_len]));
                Pin::new(&mut self.ws)
                    .start_send(msg)
                    .map_err(ws_err_to_io)?;
                if let Poll::Ready(Err(e)) = Pin::new(&mut self.ws).poll_flush(cx) {
                    return Poll::Ready(Err(ws_err_to_io(e)));
                }
                Poll::Ready(Ok(chunk_len))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws).poll_flush(cx).map_err(ws_err_to_io)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws).poll_close(cx).map_err(ws_err_to_io)
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
        pending_ed_len: usize,
        read_waker: Option<std::task::Waker>,
        write_waker: Option<std::task::Waker>,
    },
    Connected {
        ws_stream: WsByteStream<BoxedStream>,
        pending_ed_ack: usize,
    },
    Failed,
}

fn save_waker_slot(slot: &mut Option<std::task::Waker>, waker: &std::task::Waker) {
    match slot {
        Some(existing) if existing.will_wake(waker) => {}
        _ => *slot = Some(waker.clone()),
    }
}

fn wake_both_opt(w1: Option<std::task::Waker>, w2: Option<std::task::Waker>) {
    if let Some(w) = w1 {
        w.wake();
    }
    if let Some(w) = w2 {
        w.wake();
    }
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

impl AsyncRead for LazyWsEarlyDataStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
                        return Poll::Ready(Err(io::Error::new(
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
                    *guard = LazyEarlyDataState::Handshaking {
                        fut,
                        pending_ed_len: 0,
                        read_waker: None,
                        write_waker: None,
                    };
                }
                LazyEarlyDataState::Handshaking {
                    fut,
                    pending_ed_len,
                    read_waker,
                    write_waker,
                } => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        save_waker_slot(read_waker, cx.waker());
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        let w_rd = read_waker.take();
                        let w_wr = write_waker.take();
                        *guard = LazyEarlyDataState::Failed;
                        drop(guard);
                        wake_both_opt(w_rd, w_wr);
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok((ws, init_rd))) => {
                        let ed_ack = *pending_ed_len;
                        let w_wr = write_waker.take();
                        *guard = LazyEarlyDataState::Connected {
                            ws_stream: WsByteStream::with_initial_read(ws, init_rd),
                            pending_ed_ack: ed_ack,
                        };
                        if let Some(w) = w_wr {
                            w.wake();
                        }
                    }
                },
                LazyEarlyDataState::Connected { ws_stream, .. } => {
                    return Pin::new(ws_stream).poll_read(cx, buf);
                }
                LazyEarlyDataState::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "WebSocket early-data handshake previously failed",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for LazyWsEarlyDataStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut guard = self.state.lock();
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
                        return Poll::Ready(Err(io::Error::new(
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
                        Some(ed_slice),
                    );
                    *guard = LazyEarlyDataState::Handshaking {
                        fut,
                        pending_ed_len: ed_take,
                        read_waker: None,
                        write_waker: None,
                    };
                }
                LazyEarlyDataState::Handshaking {
                    fut,
                    pending_ed_len,
                    read_waker,
                    write_waker,
                } => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        save_waker_slot(write_waker, cx.waker());
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        let w_rd = read_waker.take();
                        let w_wr = write_waker.take();
                        *guard = LazyEarlyDataState::Failed;
                        drop(guard);
                        wake_both_opt(w_rd, w_wr);
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok((ws, init_rd))) => {
                        let ed_ack = *pending_ed_len;
                        let w_rd = read_waker.take();
                        *guard = LazyEarlyDataState::Connected {
                            ws_stream: WsByteStream::with_initial_read(ws, init_rd),
                            pending_ed_ack: 0,
                        };
                        if let Some(w) = w_rd {
                            w.wake();
                        }
                        if ed_ack > 0 {
                            return Poll::Ready(Ok(ed_ack));
                        }
                    }
                },
                LazyEarlyDataState::Connected {
                    ws_stream,
                    pending_ed_ack,
                } => {
                    if *pending_ed_ack > 0 {
                        let ack = *pending_ed_ack;
                        *pending_ed_ack = 0;
                        return Poll::Ready(Ok(ack));
                    }
                    return Pin::new(ws_stream).poll_write(cx, buf);
                }
                LazyEarlyDataState::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "WebSocket early-data handshake previously failed",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
                        return Poll::Ready(Err(io::Error::new(
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
                    *guard = LazyEarlyDataState::Handshaking {
                        fut,
                        pending_ed_len: 0,
                        read_waker: None,
                        write_waker: None,
                    };
                }
                LazyEarlyDataState::Handshaking {
                    fut,
                    pending_ed_len,
                    read_waker,
                    write_waker,
                } => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        save_waker_slot(write_waker, cx.waker());
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        let w_rd = read_waker.take();
                        let w_wr = write_waker.take();
                        *guard = LazyEarlyDataState::Failed;
                        drop(guard);
                        wake_both_opt(w_rd, w_wr);
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok((ws, init_rd))) => {
                        let ed_ack = *pending_ed_len;
                        let w_rd = read_waker.take();
                        *guard = LazyEarlyDataState::Connected {
                            ws_stream: WsByteStream::with_initial_read(ws, init_rd),
                            pending_ed_ack: ed_ack,
                        };
                        if let Some(w) = w_rd {
                            w.wake();
                        }
                    }
                },
                LazyEarlyDataState::Connected { ws_stream, .. } => {
                    return Pin::new(ws_stream).poll_flush(cx);
                }
                LazyEarlyDataState::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "WebSocket early-data handshake previously failed",
                    )));
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.state.lock();
        loop {
            match &mut *guard {
                LazyEarlyDataState::Init { .. } => {
                    *guard = LazyEarlyDataState::Failed;
                    return Poll::Ready(Ok(()));
                }
                LazyEarlyDataState::Handshaking {
                    fut,
                    pending_ed_len,
                    read_waker,
                    write_waker,
                } => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        save_waker_slot(write_waker, cx.waker());
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        let w_rd = read_waker.take();
                        let w_wr = write_waker.take();
                        *guard = LazyEarlyDataState::Failed;
                        drop(guard);
                        wake_both_opt(w_rd, w_wr);
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok((ws, init_rd))) => {
                        let ed_ack = *pending_ed_len;
                        let w_rd = read_waker.take();
                        *guard = LazyEarlyDataState::Connected {
                            ws_stream: WsByteStream::with_initial_read(ws, init_rd),
                            pending_ed_ack: ed_ack,
                        };
                        if let Some(w) = w_rd {
                            w.wake();
                        }
                    }
                },
                LazyEarlyDataState::Connected { ws_stream, .. } => {
                    return Pin::new(ws_stream).poll_shutdown(cx);
                }
                LazyEarlyDataState::Failed => {
                    return Poll::Ready(Ok(()));
                }
            }
        }
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
}
