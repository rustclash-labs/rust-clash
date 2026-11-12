use std::{
    collections::HashMap,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Bytes, BytesMut};
use futures_util::{Sink, Stream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{Request as WsServerRequest, Response as WsServerResponse},
        protocol::Message,
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
        let clean_path = if let Some((base, query)) = raw_path.split_once('?') {
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

fn build_ws_upgrade_request(
    default_host: &str,
    port: u16,
    is_tls: bool,
    cfg: &WsTransportConfig,
    early_data: Option<&[u8]>,
) -> io::Result<http::Request<()>> {
    let (clean_path, _, ed_header_name) = cfg.normalized_parts();
    let effective_host = cfg.host_header().unwrap_or(default_host);
    let host_authority =
        if effective_host.contains(':') || (is_tls && port == 443) || (!is_tls && port == 80) {
            effective_host.to_string()
        } else {
            format!("{effective_host}:{port}")
        };
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
        read_waker: Option<std::task::Waker>,
        write_waker: Option<std::task::Waker>,
    },
    Connected(WsByteStream<BoxedStream>),
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
        let (ws, _resp) = tokio_tungstenite::client_async(req, inner)
            .await
            .map_err(ws_err_to_io)?;
        Ok((ws, BytesMut::new()))
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
                        read_waker: None,
                        write_waker: None,
                    };
                }
                LazyEarlyDataState::Handshaking {
                    fut,
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
                        let w_wr = write_waker.take();
                        *guard = LazyEarlyDataState::Connected(WsByteStream::with_initial_read(
                            ws, init_rd,
                        ));
                        if let Some(w) = w_wr {
                            w.wake();
                        }
                    }
                },
                LazyEarlyDataState::Connected(ws_stream) => {
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
                        read_waker: None,
                        write_waker: None,
                    };
                    if let LazyEarlyDataState::Handshaking {
                        fut, write_waker, ..
                    } = &mut *guard
                    {
                        match fut.as_mut().poll(cx) {
                            Poll::Pending => {
                                save_waker_slot(write_waker, cx.waker());
                                return Poll::Ready(Ok(ed_take));
                            }
                            Poll::Ready(Err(e)) => {
                                *guard = LazyEarlyDataState::Failed;
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok((ws, init_rd))) => {
                                *guard = LazyEarlyDataState::Connected(
                                    WsByteStream::with_initial_read(ws, init_rd),
                                );
                                return Poll::Ready(Ok(ed_take));
                            }
                        }
                    }
                }
                LazyEarlyDataState::Handshaking {
                    fut,
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
                        let w_rd = read_waker.take();
                        *guard = LazyEarlyDataState::Connected(WsByteStream::with_initial_read(
                            ws, init_rd,
                        ));
                        if let Some(w) = w_rd {
                            w.wake();
                        }
                    }
                },
                LazyEarlyDataState::Connected(ws_stream) => {
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
                LazyEarlyDataState::Init { .. } => return Poll::Ready(Ok(())),
                LazyEarlyDataState::Handshaking {
                    fut,
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
                        let w_rd = read_waker.take();
                        *guard = LazyEarlyDataState::Connected(WsByteStream::with_initial_read(
                            ws, init_rd,
                        ));
                        if let Some(w) = w_rd {
                            w.wake();
                        }
                    }
                },
                LazyEarlyDataState::Connected(ws_stream) => {
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
                        let w_rd = read_waker.take();
                        *guard = LazyEarlyDataState::Connected(WsByteStream::with_initial_read(
                            ws, init_rd,
                        ));
                        if let Some(w) = w_rd {
                            w.wake();
                        }
                    }
                },
                LazyEarlyDataState::Connected(ws_stream) => {
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
    let (ws, _resp) = tokio_tungstenite::client_async(req, inner)
        .await
        .map_err(ws_err_to_io)?;
    Ok(Box::new(WsByteStream::new(ws)))
}

/// Accept an inbound WebSocket stream (supporting optional `Sec-WebSocket-Protocol` early data)
/// for loopback E2E protocol servers (`VLESS+WS` and `Trojan+WS`).
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
        |req: &WsServerRequest, mut resp: WsServerResponse| {
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
                    resp.headers_mut()
                        .insert("Sec-WebSocket-Protocol", proto_val.clone());
                }
            }
            Ok(resp)
        },
    )
    .await
    .map_err(ws_err_to_io)?;

    Ok(Box::new(WsByteStream::with_initial_read(ws, early_data)))
}
