use std::{
    collections::{HashMap, VecDeque},
    ffi::{CStr, CString, c_char},
    ptr,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::{Condvar, Mutex};
use proxy_core::{
    api::read_process_rss_bytes, config::ClashConfig, engine::ProxyEngine,
    inbound::tun::VirtualTunHandle,
};

const MAX_EGRESS_QUEUE_PACKETS: usize = 1024;

/// Uninhabited opaque C handle matching `typedef struct RcNeEngineHandle RcNeEngineHandle;`
/// in `platforms/macos-ne/RustClashNEBridge.h`.
///
/// Concurrency & UAF safety invariant:
/// `*mut RcNeEngineHandle` is an opaque integer token (`without_provenance_mut(id)`), NEVER
/// dereferenced as a raw pointer. Every FFI call resolves the token via `NE_ENGINES` into an
/// `Arc<NeEngineContext>`, completely eliminating Use-After-Free (UAF) and double-free races
/// when `stopTunnel` executes concurrently with `NEPacketTunnelFlow` RX/TX or IPC callbacks.
#[repr(C)]
pub struct RcNeEngineHandle {
    _private: [u8; 0],
}

struct EgressQueueInner {
    packets: VecDeque<Vec<u8>>,
    closed: bool,
}

struct EgressSyncQueue {
    inner: Mutex<EgressQueueInner>,
    ready_cv: Condvar,
    space_notify: tokio::sync::Notify,
}

impl EgressSyncQueue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(EgressQueueInner {
                packets: VecDeque::with_capacity(64),
                closed: false,
            }),
            ready_cv: Condvar::new(),
            space_notify: tokio::sync::Notify::new(),
        })
    }

    fn close(&self) {
        {
            let mut st = self.inner.lock();
            st.closed = true;
            st.packets.clear();
        }
        self.ready_cv.notify_all();
        self.space_notify.notify_waiters();
    }

    /// Pop the next outbound packet:
    /// - `Ok(Some(pkt))`: packet popped
    /// - `Ok(None)`: empty (non-blocking) or timed out while still open
    /// - `Err(())`: queue closed / engine stopped
    fn pop_packet(&self, timeout: Option<Duration>, blocking: bool) -> Result<Option<Vec<u8>>, ()> {
        let mut st = self.inner.lock();
        loop {
            if let Some(pkt) = st.packets.pop_front() {
                drop(st);
                self.space_notify.notify_one();
                return Ok(Some(pkt));
            }
            if st.closed {
                return Err(());
            }
            if !blocking {
                return Ok(None);
            }
            match timeout {
                None => {
                    // Event-driven block (`0 Hz` CPU wakeups while tunnel is idle!)
                    self.ready_cv.wait(&mut st);
                }
                Some(dur) => {
                    let wait_res = self.ready_cv.wait_for(&mut st, dur);
                    if wait_res.timed_out() && st.packets.is_empty() {
                        return if st.closed { Err(()) } else { Ok(None) };
                    }
                }
            }
        }
    }
}

struct NeEngineContext {
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    engine: Arc<ProxyEngine>,
    ingress_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    egress_queue: Arc<EgressSyncQueue>,
    pump_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl NeEngineContext {
    fn initiate_stop(&self) {
        self.egress_queue.close();
        if let Some(task) = self.pump_task.lock().take() {
            task.abort();
        }
        self.engine.shutdown();
    }
}

impl Drop for NeEngineContext {
    fn drop(&mut self) {
        self.egress_queue.close();
        if let Some(task) = self.pump_task.get_mut().take() {
            task.abort();
        }
        self.engine.shutdown();
        if let Some(rt) = self.runtime.get_mut().take() {
            rt.shutdown_timeout(Duration::from_millis(250));
        }
    }
}

static NEXT_HANDLE_ID: AtomicUsize = AtomicUsize::new(1);
static NE_ENGINES: LazyLock<Mutex<HashMap<usize, Arc<NeEngineContext>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn allocate_handle_id() -> usize {
    loop {
        let id = NEXT_HANDLE_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

#[inline]
fn handle_to_id(handle: *mut RcNeEngineHandle) -> Option<usize> {
    let id = handle.addr();
    (id != 0).then_some(id)
}

#[inline]
fn lookup_context(handle: *mut RcNeEngineHandle) -> Option<Arc<NeEngineContext>> {
    let id = handle_to_id(handle)?;
    NE_ENGINES.lock().get(&id).cloned()
}

fn write_c_error(out_error: *mut *mut c_char, msg: impl Into<String>) {
    if out_error.is_null() {
        return;
    }
    let clean = msg.into().replace('\0', " ");
    if let Ok(cstr) = CString::new(clean) {
        // SAFETY: Caller passed a valid writable `*mut *mut c_char` pointer.
        unsafe {
            *out_error = cstr.into_raw();
        }
    }
}

/// Start an embedded `ProxyEngine` in virtual `smoltcp` L3 packet mode for Apple `NEPacketTunnelProvider`.
///
/// # Safety
/// `yaml_config` must be a valid NUL-terminated UTF-8 C string. `out_error` may be null or a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_ne_start_engine(
    yaml_config: *const c_char,
    mtu: u16,
    out_error: *mut *mut c_char,
) -> *mut RcNeEngineHandle {
    if yaml_config.is_null() {
        write_c_error(out_error, "yaml_config pointer is NULL");
        return ptr::null_mut();
    }
    // SAFETY: Caller guarantees `yaml_config` is a NUL-terminated string.
    let yaml_str = match unsafe { CStr::from_ptr(yaml_config) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            write_c_error(out_error, format!("yaml_config is not valid UTF-8: {e}"));
            return ptr::null_mut();
        }
    };

    let mut cfg = match ClashConfig::from_yaml_str(yaml_str) {
        Ok(c) => c,
        Err(e) => {
            write_c_error(out_error, format!("invalid Clash YAML config: {e}"));
            return ptr::null_mut();
        }
    };

    // Inside `NEPacketTunnelProvider`, Apple owns the system interface (`NEPacketTunnelFlow`)
    // and passes raw L3 packets over FFI, so `smoltcp` runs in virtual channel mode (`auto_route = false`),
    // and internal listeners must use ephemeral ports (`0`) so the System Extension never collides
    // with the host desktop app's `mixed-port` (`7890`) or rapid tunnel restarts.
    cfg.mixed_port = 0;
    cfg.dns.listen = "127.0.0.1:0".to_string();
    cfg.tun.enable = true;
    cfg.tun.auto_route = false;
    cfg.tun.mtu = usize::from(mtu.max(1280));

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("rc-ne-worker")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            write_c_error(out_error, format!("failed building Tokio runtime: {e}"));
            return ptr::null_mut();
        }
    };

    let engine = match rt.block_on(ProxyEngine::start(cfg)) {
        Ok(eng) => eng,
        Err(e) => {
            rt.shutdown_timeout(Duration::from_millis(250));
            write_c_error(out_error, format!("failed starting ProxyEngine: {e}"));
            return ptr::null_mut();
        }
    };

    let Some(VirtualTunHandle {
        ingress_tx,
        mut egress_rx,
    }) = engine.take_virtual_tun_handle()
    else {
        engine.shutdown();
        rt.shutdown_timeout(Duration::from_millis(250));
        write_c_error(out_error, "virtual smoltcp handle unavailable");
        return ptr::null_mut();
    };

    // Spawn event-driven egress bridge (`0 Hz` wakeups when idle; bounded 1024-packet backpressure).
    // IMPORTANT: The task holds ONLY `Arc<EgressSyncQueue>`, never `Arc<NeEngineContext>`, so
    // `NeEngineContext::drop` never executes inside `rt` worker threads.
    let egress_queue = EgressSyncQueue::new();
    let queue_for_pump = Arc::clone(&egress_queue);
    let pump_task = rt.spawn(async move {
        while let Some(pkt) = egress_rx.recv().await {
            loop {
                let notified = queue_for_pump.space_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let mut st = queue_for_pump.inner.lock();
                    if st.closed {
                        return;
                    }
                    if st.packets.len() < MAX_EGRESS_QUEUE_PACKETS {
                        st.packets.push_back(pkt);
                        queue_for_pump.ready_cv.notify_one();
                        break;
                    }
                }
                notified.await;
            }
        }
        queue_for_pump.close();
    });

    let ctx = Arc::new(NeEngineContext {
        runtime: Mutex::new(Some(rt)),
        engine,
        ingress_tx,
        egress_queue,
        pump_task: Mutex::new(Some(pump_task)),
    });

    let id = allocate_handle_id();
    NE_ENGINES.lock().insert(id, ctx);
    ptr::without_provenance_mut(id)
}

/// Push a raw L3 IPv4/IPv6 packet from `NEPacketTunnelFlow` into `smoltcp`.
///
/// Safe against concurrent `rc_ne_stop_engine`: returns `false` if `handle` is NULL or already stopped.
///
/// # Safety
/// `packet_ptr` must reference at least `packet_len` readable bytes when non-null and `0 < packet_len <= 65535`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_ne_push_inbound_packet(
    handle: *mut RcNeEngineHandle,
    packet_ptr: *const u8,
    packet_len: usize,
) -> bool {
    if packet_ptr.is_null() || packet_len == 0 || packet_len > 65535 {
        return false;
    }
    let Some(ctx) = lookup_context(handle) else {
        return false;
    };
    if ctx.egress_queue.inner.lock().closed {
        return false;
    }
    // SAFETY: Caller guarantees `packet_ptr[..packet_len]` is valid for the duration of this call.
    let pkt = unsafe { std::slice::from_raw_parts(packet_ptr, packet_len) }.to_vec();
    ctx.ingress_tx.try_send(pkt).is_ok()
}

/// Event-driven blocking/timed outbound packet wait for `NEPacketTunnelProvider` (`0 Hz` idle wakeups!).
///
/// Parameters:
/// - `timeout_ms < 0`: wait indefinitely on `Condvar` until a packet arrives or `rc_ne_stop_engine` is called.
/// - `timeout_ms == 0`: non-blocking poll.
/// - `timeout_ms > 0`: wait up to `timeout_ms` milliseconds.
///
/// Return values:
/// - `> 0`: byte length copied into `out_buf`
/// - `0`: timeout elapsed (or queue empty when `timeout_ms == 0`, or buffer smaller than packet)
/// - `-1`: invalid/stopped `handle` or invalid buffer arguments
///
/// # Safety
/// `out_buf` must point to at least `buf_cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_ne_wait_outbound_packet(
    handle: *mut RcNeEngineHandle,
    out_buf: *mut u8,
    buf_cap: usize,
    timeout_ms: i32,
) -> isize {
    if out_buf.is_null() || buf_cap == 0 {
        return -1;
    }
    let Some(ctx) = lookup_context(handle) else {
        return -1;
    };
    let pop_res = if timeout_ms < 0 {
        ctx.egress_queue.pop_packet(None, true)
    } else if timeout_ms == 0 {
        ctx.egress_queue.pop_packet(None, false)
    } else {
        ctx.egress_queue
            .pop_packet(Some(Duration::from_millis(timeout_ms as u64)), true)
    };

    match pop_res {
        Ok(Some(pkt)) => {
            if pkt.len() > buf_cap || pkt.len() > isize::MAX as usize {
                return 0;
            }
            // SAFETY: `pkt.len() <= buf_cap` and `out_buf` has `buf_cap` writable bytes.
            unsafe {
                ptr::copy_nonoverlapping(pkt.as_ptr(), out_buf, pkt.len());
            }
            pkt.len() as isize
        }
        Ok(None) => 0,
        Err(()) => -1,
    }
}

/// Non-blockingly pop the next outbound L3 packet from `smoltcp` into `out_buf` (used for batch draining).
///
/// # Safety
/// `out_buf` must have at least `buf_cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_ne_pop_outbound_packet(
    handle: *mut RcNeEngineHandle,
    out_buf: *mut u8,
    buf_cap: usize,
) -> usize {
    // SAFETY: Same buffer contract as `rc_ne_wait_outbound_packet`.
    let n = unsafe { rc_ne_wait_outbound_packet(handle, out_buf, buf_cap, 0) };
    if n > 0 { n as usize } else { 0 }
}

/// Flush DNS positive/negative caches on wake or minor path update.
#[unsafe(no_mangle)]
pub extern "C" fn rc_ne_flush_dns(handle: *mut RcNeEngineHandle) {
    if let Some(ctx) = lookup_context(handle) {
        ctx.engine.router().dns().flush_cache();
    }
}

/// Perform full session recovery (UDP NAT reset + AnyTLS session pool eviction + active TCP abort + DNS flush)
/// on macOS sleep/wake (`NEPacketTunnelProvider.wake()`) or physical interface handoffs.
#[unsafe(no_mangle)]
pub extern "C" fn rc_ne_notify_network_change(handle: *mut RcNeEngineHandle) -> bool {
    let Some(ctx) = lookup_context(handle) else {
        return false;
    };
    let _ = ctx.engine.notify_network_change();
    true
}

/// Return a newly allocated JSON status string (free with `rc_ne_free_string`), or NULL if stopped.
#[unsafe(no_mangle)]
pub extern "C" fn rc_ne_get_status_json(handle: *mut RcNeEngineHandle) -> *mut c_char {
    let Some(ctx) = lookup_context(handle) else {
        return ptr::null_mut();
    };
    let (up, down) = ctx
        .engine
        .hub()
        .traffic_history()
        .last()
        .map(|p| (p.up, p.down))
        .unwrap_or((0, 0));
    let (up_tot, down_tot) = ctx.engine.hub().totals();
    let payload = serde_json::json!({
        "mode": ctx.engine.router().mode().as_str(),
        "tunMode": ctx.engine.tun_mode().as_str(),
        "upRate": up,
        "downRate": down,
        "upTotal": up_tot,
        "downTotal": down_tot,
        "rssBytes": read_process_rss_bytes(),
        "activeConnections": ctx.engine.hub().list_connections().len(),
        "fakeIpEntries": ctx.engine.router().dns().entry_count(),
    });
    match CString::new(payload.to_string()) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Gracefully stop and unregister an `RcNeEngineHandle`.
///
/// Thread-safe & idempotent:
/// - Atomically removes `handle` from `NE_ENGINES` so duplicate `rc_ne_stop_engine` calls or
///   concurrent post-stop FFI calls safely no-op without UAF or double-free.
/// - Immediately wakes any thread blocked in `rc_ne_wait_outbound_packet(..., -1)`.
/// - Underlying `NeEngineContext` & Tokio runtime are dropped only after all in-flight `Arc` borrows return.
#[unsafe(no_mangle)]
pub extern "C" fn rc_ne_stop_engine(handle: *mut RcNeEngineHandle) {
    let Some(id) = handle_to_id(handle) else {
        return;
    };
    let removed = NE_ENGINES.lock().remove(&id);
    if let Some(ctx) = removed {
        ctx.initiate_stop();
    }
}

/// Free a C string returned by `rc_ne_*`.
///
/// # Safety
/// `ptr` must be NULL or a pointer previously allocated via `CString::into_raw` by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_ne_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: Reclaiming `CString` allocated by `CString::into_raw`.
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
