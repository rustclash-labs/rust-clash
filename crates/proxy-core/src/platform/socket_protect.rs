use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
};

use parking_lot::RwLock;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Default Linux policy-routing bypass mark (`fwmark`) applied to outbound proxy & DNS sockets
/// so traffic emitted by `rust-clash` itself never re-enters the TUN default route.
pub const DEFAULT_LINUX_FWMARK: u32 = 0x0000_01a5;

/// Platform-independent socket bypass / anti-loop protection hook.
///
/// Invoked on **every** outbound TCP, UDP, and bootstrap DNS socket **before** `connect()`/`bind()`:
/// - **Linux**: `SO_MARK` (`fwmark`) exempted by `ip rule not fwmark 0x1a5 table <tun_table>`
/// - **macOS**: `IP_BOUND_IF` / `IPV6_BOUND_IF` pinned to the active physical `enX` interface
/// - **Windows**: `IP_UNICAST_IF` / `IPV6_UNICAST_IF` pinned to the active physical `InterfaceIndex`
/// - **Android**: `VpnService.protect(raw_fd)` via JNI callback
pub trait SocketProtector: Send + Sync {
    fn protect_tcp(&self, sock: &Socket, remote: SocketAddr) -> io::Result<()>;
    fn protect_udp(&self, sock: &Socket, remote_hint: Option<SocketAddr>) -> io::Result<()>;
    fn description(&self) -> String;
}

/// Default no-op protector active when system-wide TUN/VPN capture is disabled.
pub struct NoopSocketProtector;

impl SocketProtector for NoopSocketProtector {
    fn protect_tcp(&self, _sock: &Socket, _remote: SocketAddr) -> io::Result<()> {
        Ok(())
    }

    fn protect_udp(&self, _sock: &Socket, _remote_hint: Option<SocketAddr>) -> io::Result<()> {
        Ok(())
    }

    fn description(&self) -> String {
        "noop".to_string()
    }
}

/// Cross-platform callback / fd protector (used by Android `VpnService.protect(fd)` and E2E tests).
pub struct CallbackSocketProtector {
    label: String,
    protect_loopback: bool,
    protected_tcp_count: AtomicU64,
    protected_udp_count: AtomicU64,
    protect_fail_count: AtomicU64,
    #[cfg(unix)]
    fd_hook: Arc<dyn Fn(i32) -> io::Result<()> + Send + Sync>,
    #[cfg(not(unix))]
    fd_hook: Arc<dyn Fn(u64) -> io::Result<()> + Send + Sync>,
}

impl CallbackSocketProtector {
    #[cfg(unix)]
    pub fn new_unix<F>(label: impl Into<String>, protect_loopback: bool, hook: F) -> Self
    where
        F: Fn(i32) -> io::Result<()> + Send + Sync + 'static,
    {
        Self {
            label: label.into(),
            protect_loopback,
            protected_tcp_count: AtomicU64::new(0),
            protected_udp_count: AtomicU64::new(0),
            protect_fail_count: AtomicU64::new(0),
            fd_hook: Arc::new(hook),
        }
    }

    /// Create a counting/auditing protector for cross-platform verification tests.
    pub fn counting(label: impl Into<String>, protect_loopback: bool) -> Self {
        Self {
            label: label.into(),
            protect_loopback,
            protected_tcp_count: AtomicU64::new(0),
            protected_udp_count: AtomicU64::new(0),
            protect_fail_count: AtomicU64::new(0),
            fd_hook: Arc::new(|_| Ok(())),
        }
    }

    pub fn tcp_count(&self) -> u64 {
        self.protected_tcp_count.load(Ordering::Relaxed)
    }

    pub fn udp_count(&self) -> u64 {
        self.protected_udp_count.load(Ordering::Relaxed)
    }

    pub fn fail_count(&self) -> u64 {
        self.protect_fail_count.load(Ordering::Relaxed)
    }

    fn invoke(&self, sock: &Socket) -> io::Result<()> {
        let res = {
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                (self.fd_hook)(sock.as_raw_fd())
            }
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawSocket;
                (self.fd_hook)(sock.as_raw_socket())
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = sock;
                (self.fd_hook)(0)
            }
        };
        if res.is_err() {
            self.protect_fail_count.fetch_add(1, Ordering::Relaxed);
        }
        res
    }
}

impl SocketProtector for CallbackSocketProtector {
    fn protect_tcp(&self, sock: &Socket, remote: SocketAddr) -> io::Result<()> {
        if !self.protect_loopback && is_loopback_ip(remote.ip()) {
            return Ok(());
        }
        self.invoke(sock)?;
        self.protected_tcp_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn protect_udp(&self, sock: &Socket, remote_hint: Option<SocketAddr>) -> io::Result<()> {
        if !self.protect_loopback && remote_hint.is_some_and(|r| is_loopback_ip(r.ip())) {
            return Ok(());
        }
        self.invoke(sock)?;
        self.protected_udp_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn description(&self) -> String {
        format!(
            "{}(tcp={},udp={},fail={})",
            self.label,
            self.tcp_count(),
            self.udp_count(),
            self.fail_count()
        )
    }
}

/// Linux `SO_MARK` (`fwmark`) socket protector paired with `ip rule not fwmark <mark> lookup <table>`.
pub struct LinuxFwmarkProtector {
    fwmark: AtomicU32,
    strict: bool,
}

impl LinuxFwmarkProtector {
    pub fn new(fwmark: u32, strict: bool) -> Self {
        Self {
            fwmark: AtomicU32::new(fwmark),
            strict,
        }
    }

    pub fn fwmark(&self) -> u32 {
        self.fwmark.load(Ordering::Relaxed)
    }

    fn apply_mark(&self, sock: &Socket) -> io::Result<()> {
        let mark = self.fwmark.load(Ordering::Relaxed);
        if mark == 0 {
            return Ok(());
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Err(e) = sock.set_mark(mark)
                && self.strict
            {
                return Err(e);
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = (sock, self.strict);
            Ok(())
        }
    }
}

impl SocketProtector for LinuxFwmarkProtector {
    fn protect_tcp(&self, sock: &Socket, remote: SocketAddr) -> io::Result<()> {
        if is_loopback_ip(remote.ip()) {
            return Ok(());
        }
        self.apply_mark(sock)
    }

    fn protect_udp(&self, sock: &Socket, remote_hint: Option<SocketAddr>) -> io::Result<()> {
        if remote_hint.is_some_and(|r| is_loopback_ip(r.ip())) {
            return Ok(());
        }
        self.apply_mark(sock)
    }

    fn description(&self) -> String {
        format!("linux-fwmark(0x{:x})", self.fwmark())
    }
}

/// macOS `IP_BOUND_IF` / `IPV6_BOUND_IF` protector binding outbound sockets to the physical `enX` NIC.
/// The interface index can be atomically updated on Wi-Fi / Ethernet handoff without restarting `ProxyEngine`.
pub struct MacOsBoundIfProtector {
    if_index: AtomicU32,
}

impl MacOsBoundIfProtector {
    pub fn new(if_index: u32) -> Self {
        Self {
            if_index: AtomicU32::new(if_index),
        }
    }

    pub fn set_if_index(&self, if_index: u32) {
        self.if_index.store(if_index, Ordering::Release);
    }

    pub fn if_index(&self) -> u32 {
        self.if_index.load(Ordering::Acquire)
    }

    fn bind_if(&self, sock: &Socket, is_ipv6: bool) -> io::Result<()> {
        let idx = self.if_index();
        if idx == 0 {
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            use std::num::NonZeroU32;
            let nz = NonZeroU32::new(idx);
            if is_ipv6 {
                sock.bind_device_by_index_v6(nz)?;
            } else {
                sock.bind_device_by_index_v4(nz)?;
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (sock, is_ipv6);
            Ok(())
        }
    }
}

impl SocketProtector for MacOsBoundIfProtector {
    fn protect_tcp(&self, sock: &Socket, remote: SocketAddr) -> io::Result<()> {
        if is_loopback_ip(remote.ip()) {
            return Ok(());
        }
        self.bind_if(sock, remote.is_ipv6())
    }

    fn protect_udp(&self, sock: &Socket, remote_hint: Option<SocketAddr>) -> io::Result<()> {
        if remote_hint.is_some_and(|r| is_loopback_ip(r.ip())) {
            return Ok(());
        }
        let is_v6 = match remote_hint {
            Some(sa) => sa.is_ipv6(),
            None => socket_is_ipv6(sock),
        };
        self.bind_if(sock, is_v6)
    }

    fn description(&self) -> String {
        format!("macos-bound-if(idx={})", self.if_index())
    }
}

/// Windows `IP_UNICAST_IF` / `IPV6_UNICAST_IF` protector pinning outbound sockets to the active
/// physical `InterfaceIndex` discovered via `GetBestRoute2`.
/// Note per MSDN: `IP_UNICAST_IF` expects network byte order (`to_be()`), whereas
/// `IPV6_UNICAST_IF` expects host byte order (`u32`)!
pub struct WindowsUnicastIfProtector {
    if_index_v4: AtomicU32,
    if_index_v6: AtomicU32,
}

impl WindowsUnicastIfProtector {
    pub fn new(if_index_v4: u32, if_index_v6: u32) -> Self {
        Self {
            if_index_v4: AtomicU32::new(if_index_v4),
            if_index_v6: AtomicU32::new(if_index_v6),
        }
    }

    pub fn update_indices(&self, if_index_v4: u32, if_index_v6: u32) {
        self.if_index_v4.store(if_index_v4, Ordering::Release);
        self.if_index_v6.store(if_index_v6, Ordering::Release);
    }

    fn apply_unicast_if(&self, sock: &Socket, is_ipv6: bool) -> io::Result<()> {
        let idx = if is_ipv6 {
            self.if_index_v6.load(Ordering::Acquire)
        } else {
            self.if_index_v4.load(Ordering::Acquire)
        };
        if idx == 0 {
            return Ok(());
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR,
                WSAGetLastError, setsockopt,
            };

            let raw = sock.as_raw_socket() as SOCKET;
            let (level, optname, optval_u32) = if is_ipv6 {
                (IPPROTO_IPV6, IPV6_UNICAST_IF, idx)
            } else {
                (IPPROTO_IP, IP_UNICAST_IF, idx.to_be())
            };
            // SAFETY: `raw` is a valid Winsock `SOCKET` owned by `sock`, and `optval_u32` is a
            // stack-allocated 4-byte `DWORD` matching MSDN's `IP_UNICAST_IF`/`IPV6_UNICAST_IF` contract.
            let rc = unsafe {
                setsockopt(
                    raw,
                    level,
                    optname,
                    (&raw const optval_u32).cast::<u8>(),
                    std::mem::size_of::<u32>() as i32,
                )
            };
            if rc == SOCKET_ERROR {
                // SAFETY: `WSAGetLastError` reads thread-local Winsock error state with no preconditions.
                let code = unsafe { WSAGetLastError() };
                return Err(io::Error::from_raw_os_error(code));
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = sock;
            Ok(())
        }
    }
}

impl SocketProtector for WindowsUnicastIfProtector {
    fn protect_tcp(&self, sock: &Socket, remote: SocketAddr) -> io::Result<()> {
        if is_loopback_ip(remote.ip()) {
            return Ok(());
        }
        self.apply_unicast_if(sock, remote.is_ipv6())
    }

    fn protect_udp(&self, sock: &Socket, remote_hint: Option<SocketAddr>) -> io::Result<()> {
        if remote_hint.is_some_and(|r| is_loopback_ip(r.ip())) {
            return Ok(());
        }
        let is_v6 = match remote_hint {
            Some(sa) => sa.is_ipv6(),
            None => socket_is_ipv6(sock),
        };
        self.apply_unicast_if(sock, is_v6)
    }

    fn description(&self) -> String {
        format!(
            "windows-unicast-if(v4={},v6={})",
            self.if_index_v4.load(Ordering::Relaxed),
            self.if_index_v6.load(Ordering::Relaxed)
        )
    }
}

fn socket_is_ipv6(sock: &Socket) -> bool {
    sock.local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .is_some_and(|sa| sa.is_ipv6())
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

static CUSTOM_PROTECTOR_ACTIVE: AtomicBool = AtomicBool::new(false);
static PROTECTOR_EPOCH: AtomicU64 = AtomicU64::new(1);
/// `0 = Unknown`, `1 = Unavailable`, `2 = Available`.
static OS_UNDERLYING_IPV6_AVAILABLE: AtomicU8 = AtomicU8::new(0);
static DIRECT_IPV6_UNREACHABLE_UNTIL_MS: AtomicU64 = AtomicU64::new(0);
const DIRECT_IPV6_CIRCUIT_BREAKER_MS: u64 = 45_000;

/// Return `true` when `v6` is an RFC 4291 global unicast IPv6 address (`2000::/3`),
/// excluding the RFC 3849 documentation prefix (`2001:db8::/32`).
pub fn is_global_unicast_ipv6(v6: Ipv6Addr) -> bool {
    let seg = v6.segments();
    (seg[0] & 0xe000) == 0x2000 && !(seg[0] == 0x2001 && seg[1] == 0x0db8)
}

/// Update the OS-reported physical underlying network IPv6 availability (`None` = unknown,
/// `Some(false)` = IPv4-only physical link, `Some(true)` = physical global IPv6 route present).
pub fn set_os_underlying_ipv6_available(available: Option<bool>) {
    let state = match available {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    OS_UNDERLYING_IPV6_AVAILABLE.store(state, Ordering::Release);
    if available != Some(false) {
        DIRECT_IPV6_UNREACHABLE_UNTIL_MS.store(0, Ordering::Release);
    }
}

/// Read the OS-reported physical underlying network IPv6 availability, if known.
pub fn os_underlying_ipv6_available() -> Option<bool> {
    match OS_UNDERLYING_IPV6_AVAILABLE.load(Ordering::Acquire) {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

/// Clear any active `ENETUNREACH` / `EADDRNOTAVAIL` direct IPv6 circuit-breaker cooldown.
pub fn reset_direct_ipv6_reachability() {
    DIRECT_IPV6_UNREACHABLE_UNTIL_MS.store(0, Ordering::Release);
}

/// Return `true` when `err` indicates immediate local kernel IPv6 unreachability
/// (`ENETUNREACH` / `NetworkUnreachable` or `EADDRNOTAVAIL` / `AddrNotAvailable`).
pub fn is_local_ipv6_unreachable_error(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable
    ) {
        return true;
    }
    let Some(code) = err.raw_os_error() else {
        return false;
    };
    #[cfg(unix)]
    {
        code == libc::ENETUNREACH || code == libc::EADDRNOTAVAIL
    }
    #[cfg(windows)]
    {
        code == 10051 || code == 10049
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

/// Record the outcome of a direct protected TCP/UDP dial or send to `remote` so immediate
/// local IPv6 `ENETUNREACH` / `EADDRNOTAVAIL` failures open the 45-second IPv6 circuit-breaker
/// and a subsequent global-unicast IPv6 success immediately closes it.
pub fn note_direct_addr_connect_result(remote: SocketAddr, res: Result<(), &io::Error>) {
    let SocketAddr::V6(v6) = remote else {
        return;
    };
    if !is_global_unicast_ipv6(*v6.ip()) {
        return;
    }
    match res {
        Ok(()) => {
            DIRECT_IPV6_UNREACHABLE_UNTIL_MS.store(0, Ordering::Release);
        }
        Err(err) if is_local_ipv6_unreachable_error(err) => {
            let now_ms = crate::tracker::TelemetryHub::now_ms();
            DIRECT_IPV6_UNREACHABLE_UNTIL_MS.store(
                now_ms.saturating_add(DIRECT_IPV6_CIRCUIT_BREAKER_MS),
                Ordering::Release,
            );
        }
        Err(_) => {}
    }
}

/// Return `true` when direct global-unicast IPv6 egress is currently considered reachable
/// (neither disabled by OS physical link state nor tripped by the `ENETUNREACH` circuit-breaker).
pub fn is_direct_ipv6_reachable() -> bool {
    if OS_UNDERLYING_IPV6_AVAILABLE.load(Ordering::Acquire) == 1 {
        return false;
    }
    let until = DIRECT_IPV6_UNREACHABLE_UNTIL_MS.load(Ordering::Acquire);
    until == 0 || crate::tracker::TelemetryHub::now_ms() >= until
}

fn protector_slot() -> &'static RwLock<Arc<dyn SocketProtector>> {
    static SLOT: OnceLock<RwLock<Arc<dyn SocketProtector>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Arc::new(NoopSocketProtector)))
}

/// Return the monotonic generation counter of the global `SocketProtector`.
/// Connection pools key on this epoch so sockets opened before TUN/VPN activation
/// are never reused after `VpnService.protect` / `SO_MARK` / `IP_BOUND_IF` is installed.
pub fn current_protector_epoch() -> u64 {
    PROTECTOR_EPOCH.load(Ordering::Acquire)
}

/// Install an active process-wide `SocketProtector` (e.g. when OS TUN or Android `VpnService` starts).
pub fn set_global_socket_protector(protector: Arc<dyn SocketProtector>) {
    let is_custom = protector.description() != "noop";
    *protector_slot().write() = protector;
    CUSTOM_PROTECTOR_ACTIVE.store(is_custom, Ordering::Release);
    PROTECTOR_EPOCH.fetch_add(1, Ordering::AcqRel);
    reset_direct_ipv6_reachability();
    crate::dns::upstream::clear_dns_upstream_pools();
}

/// Reset the global `SocketProtector` back to `NoopSocketProtector` when TUN/VPN stops.
pub fn clear_global_socket_protector() {
    *protector_slot().write() = Arc::new(NoopSocketProtector);
    CUSTOM_PROTECTOR_ACTIVE.store(false, Ordering::Release);
    PROTECTOR_EPOCH.fetch_add(1, Ordering::AcqRel);
    set_os_underlying_ipv6_available(None);
    reset_direct_ipv6_reachability();
    crate::dns::upstream::clear_dns_upstream_pools();
}

/// Return `true` when a non-noop `SocketProtector` (such as Android `VpnService.protect`,
/// Linux `SO_MARK`, macOS `IP_BOUND_IF`, or Windows `IP_UNICAST_IF`) is currently installed.
pub fn has_custom_socket_protector() -> bool {
    CUSTOM_PROTECTOR_ACTIVE.load(Ordering::Acquire)
}

/// Retrieve the active `SocketProtector`.
pub fn global_socket_protector() -> Arc<dyn SocketProtector> {
    Arc::clone(&protector_slot().read())
}

const TCP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
const HAPPY_EYEBALLS_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
const MAX_HAPPY_EYEBALLS_CANDIDATES: usize = 6;
const HAPPY_EYEBALLS_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

/// Open a protected non-blocking TCP connection to a resolved `SocketAddr` with connect timeout and TCP keepalive.
pub async fn protected_tcp_connect_addr(remote: SocketAddr) -> io::Result<TcpStream> {
    let sock = Socket::new(
        Domain::for_address(remote),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    global_socket_protector().protect_tcp(&sock, remote)?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_nodelay(true);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(45))
        .with_interval(std::time::Duration::from_secs(15));
    let _ = sock.set_tcp_keepalive(&keepalive);
    let std_stream: std::net::TcpStream = sock.into();
    let tcp_sock = TcpSocket::from_std_stream(std_stream);
    let stream = tokio::time::timeout(TCP_CONNECT_TIMEOUT, async {
        let res = tcp_sock.connect(remote).await;
        note_direct_addr_connect_result(remote, res.as_ref().map(|_| ()));
        res
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out"))??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

fn interleave_happy_eyeballs_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    for &addr in addrs {
        if addr.is_ipv6() {
            v6.push(addr);
        } else {
            v4.push(addr);
        }
    }
    if v6.is_empty() || v4.is_empty() {
        return addrs.to_vec();
    }
    if !is_direct_ipv6_reachable()
        && v6
            .iter()
            .any(|a| matches!(a, SocketAddr::V6(s6) if is_global_unicast_ipv6(*s6.ip())))
    {
        return v4.into_iter().chain(v6).collect();
    }
    let mut out = Vec::with_capacity(addrs.len());
    let mut i6 = v6.into_iter();
    let mut i4 = v4.into_iter();
    loop {
        match (i6.next(), i4.next()) {
            (Some(a6), Some(a4)) => {
                out.push(a6);
                out.push(a4);
            }
            (Some(a6), None) => {
                out.push(a6);
                out.extend(i6);
                break;
            }
            (None, Some(a4)) => {
                out.push(a4);
                out.extend(i4);
                break;
            }
            (None, None) => break,
        }
    }
    out
}

/// Connect across candidate `SocketAddr`s using RFC 8305 Happy Eyeballs (250ms staggered IPv6/IPv4 race).
pub async fn connect_protected_addrs_happy_eyeballs(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    match addrs {
        [] => {
            return Err(io::Error::new(
                io::ErrorKind::HostUnreachable,
                "no resolved target addresses",
            ));
        }
        [single] => return protected_tcp_connect_addr(*single).await,
        _ => {}
    }

    let mut ordered = interleave_happy_eyeballs_addrs(addrs);
    ordered.truncate(MAX_HAPPY_EYEBALLS_CANDIDATES);

    tokio::time::timeout(HAPPY_EYEBALLS_TOTAL_TIMEOUT, async move {
        let mut join_set = tokio::task::JoinSet::new();
        join_set.spawn(protected_tcp_connect_addr(ordered[0]));
        let mut next_idx = 1usize;
        let mut last_err: Option<io::Error> = None;

        while !join_set.is_empty() || next_idx < ordered.len() {
            if join_set.is_empty() {
                join_set.spawn(protected_tcp_connect_addr(ordered[next_idx]));
                next_idx += 1;
            }
            if next_idx < ordered.len() {
                tokio::select! {
                    biased;
                    joined = join_set.join_next() => {
                        match joined {
                            Some(Ok(Ok(stream))) => {
                                join_set.abort_all();
                                return Ok(stream);
                            }
                            Some(Ok(Err(e))) => {
                                last_err = Some(e);
                                join_set.spawn(protected_tcp_connect_addr(ordered[next_idx]));
                                next_idx += 1;
                            }
                            Some(Err(_)) | None => {}
                        }
                    }
                    _ = tokio::time::sleep(HAPPY_EYEBALLS_DELAY) => {
                        join_set.spawn(protected_tcp_connect_addr(ordered[next_idx]));
                        next_idx += 1;
                    }
                }
            } else {
                match join_set.join_next().await {
                    Some(Ok(Ok(stream))) => {
                        join_set.abort_all();
                        return Ok(stream);
                    }
                    Some(Ok(Err(e))) => {
                        last_err = Some(e);
                    }
                    Some(Err(_)) => {}
                    None => break,
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::HostUnreachable, "unable to connect")))
    })
    .await
    .unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TCP connect timed out",
        ))
    })
}

/// Resolve `host:port` for outbound proxy server dials while strictly rejecting `198.18.0.0/15` Fake-IPs
/// so Android `VpnService` never self-loops on domain-based proxy servers.
pub async fn resolve_protected_host_addrs(
    host: &str,
    port: u16,
    dns: Option<&crate::dns::FakeIpDnsEngine>,
) -> io::Result<Vec<SocketAddr>> {
    let clean = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean.parse::<IpAddr>() {
        if dns.is_some_and(|d| d.is_fake_ip(ip)) {
            return Err(io::Error::new(
                io::ErrorKind::HostUnreachable,
                format!("refusing Fake-IP {ip} as outbound proxy server endpoint"),
            ));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if let Some(d) = dns {
        let ips = d
            .resolve_proxy_server_ips(clean)
            .await
            .map_err(|e| e.into_io())?;
        let addrs: Vec<SocketAddr> = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        if !addrs.is_empty() {
            return Ok(addrs);
        }
    }
    crate::router::geodata::resolve_host_bypassing_fake_ip(clean, port)
        .await
        .map_err(|e| e.into_io())
}

/// Resolve `host:port` using `FakeIpDnsEngine` (when provided) and connect via RFC 8305 Happy Eyeballs.
pub async fn protected_tcp_connect_host_with_dns(
    host: &str,
    port: u16,
    dns: Option<&crate::dns::FakeIpDnsEngine>,
) -> io::Result<TcpStream> {
    let addrs = resolve_protected_host_addrs(host, port, dns).await?;
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::HostUnreachable,
            "DNS lookup returned no addresses for target host",
        ));
    }
    connect_protected_addrs_happy_eyeballs(&addrs).await
}

/// Resolve `host:port` and connect via `protected_tcp_connect_addr` across candidate addresses.
pub async fn protected_tcp_connect_host(host: &str, port: u16) -> io::Result<TcpStream> {
    protected_tcp_connect_host_with_dns(host, port, None).await
}

/// Bind a protected non-blocking UDP socket before any traffic leaves the host.
pub fn protected_udp_bind(
    bind_addr: SocketAddr,
    remote_hint: Option<SocketAddr>,
) -> io::Result<UdpSocket> {
    let sock = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    global_socket_protector().protect_udp(&sock, remote_hint)?;
    sock.set_nonblocking(true)?;
    sock.bind(&bind_addr.into())?;
    let std_udp: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_udp)
}

#[cfg(test)]
pub(crate) struct Ipv6ReachabilityTestGuard {
    _guard: parking_lot::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for Ipv6ReachabilityTestGuard {
    fn drop(&mut self) {
        set_os_underlying_ipv6_available(None);
        reset_direct_ipv6_reachability();
    }
}

#[cfg(test)]
pub(crate) fn lock_ipv6_reachability_for_test() -> Ipv6ReachabilityTestGuard {
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    let guard = TEST_LOCK.lock();
    set_os_underlying_ipv6_available(None);
    reset_direct_ipv6_reachability();
    Ipv6ReachabilityTestGuard { _guard: guard }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_unicast_ipv6_classifier_distinguishes_rfc4291_from_special_ranges() {
        assert!(is_global_unicast_ipv6(
            "2409:8c1e:75b0:1123::101".parse().unwrap()
        ));
        assert!(is_global_unicast_ipv6(
            "2606:4700:4700::1111".parse().unwrap()
        ));
        assert!(is_global_unicast_ipv6(
            "2001:4860:4860::8888".parse().unwrap()
        ));
        assert!(is_global_unicast_ipv6("2000::1".parse().unwrap()));
        assert!(is_global_unicast_ipv6("3fff:ffff::1".parse().unwrap()));

        // RFC 3849 documentation prefix (`2001:db8::/32`) must be excluded for synthetic E2E tests.
        assert!(!is_global_unicast_ipv6("2001:db8::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6(
            "2001:0db8:abcd::42".parse().unwrap()
        ));

        // Loopback, unspecified, link-local, ULA, multicast, and IPv4-mapped IPv6 are not global unicast.
        assert!(!is_global_unicast_ipv6(Ipv6Addr::LOCALHOST));
        assert!(!is_global_unicast_ipv6(Ipv6Addr::UNSPECIFIED));
        assert!(!is_global_unicast_ipv6("fe80::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("fd00::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("ff02::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("::ffff:192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn os_flag_and_enetunreach_circuit_breaker_state_transitions() {
        let _guard = lock_ipv6_reachability_for_test();
        assert_eq!(os_underlying_ipv6_available(), None);
        assert!(is_direct_ipv6_reachable());

        set_os_underlying_ipv6_available(Some(false));
        assert_eq!(os_underlying_ipv6_available(), Some(false));
        assert!(!is_direct_ipv6_reachable());

        set_os_underlying_ipv6_available(Some(true));
        assert_eq!(os_underlying_ipv6_available(), Some(true));
        assert!(is_direct_ipv6_reachable());

        let global_v6: SocketAddr = "[2409:8c1e:75b0:1123::101]:443".parse().unwrap();
        let doc_v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let loopback_v6: SocketAddr = "[::1]:443".parse().unwrap();
        let net_unreach = io::Error::new(io::ErrorKind::NetworkUnreachable, "ENETUNREACH");
        let addr_unavail = io::Error::new(io::ErrorKind::AddrNotAvailable, "EADDRNOTAVAIL");
        let timed_out = io::Error::new(io::ErrorKind::TimedOut, "timed out");

        assert!(is_local_ipv6_unreachable_error(&net_unreach));
        assert!(is_local_ipv6_unreachable_error(&addr_unavail));
        assert!(!is_local_ipv6_unreachable_error(&timed_out));
        #[cfg(unix)]
        {
            assert!(is_local_ipv6_unreachable_error(
                &io::Error::from_raw_os_error(libc::ENETUNREACH)
            ));
            assert!(is_local_ipv6_unreachable_error(
                &io::Error::from_raw_os_error(libc::EADDRNOTAVAIL)
            ));
        }

        // Non-global / documentation IPv6 or generic timeouts do not trip the circuit-breaker.
        note_direct_addr_connect_result(doc_v6, Err(&net_unreach));
        note_direct_addr_connect_result(loopback_v6, Err(&net_unreach));
        note_direct_addr_connect_result(global_v6, Err(&timed_out));
        assert!(is_direct_ipv6_reachable());

        // Global unicast ENETUNREACH trips the 45s circuit-breaker, and a later Ok(()) clears it.
        note_direct_addr_connect_result(global_v6, Err(&net_unreach));
        assert!(!is_direct_ipv6_reachable());

        note_direct_addr_connect_result(global_v6, Ok(()));
        assert!(is_direct_ipv6_reachable());

        // EADDRNOTAVAIL also trips the circuit-breaker, and reset_direct_ipv6_reachability clears it.
        note_direct_addr_connect_result(global_v6, Err(&addr_unavail));
        assert!(!is_direct_ipv6_reachable());
        reset_direct_ipv6_reachability();
        assert!(is_direct_ipv6_reachable());

        // set_os_underlying_ipv6_available(Some(true)) or None also clears circuit-breaker cooldown.
        note_direct_addr_connect_result(global_v6, Err(&net_unreach));
        assert!(!is_direct_ipv6_reachable());
        set_os_underlying_ipv6_available(None);
        assert_eq!(os_underlying_ipv6_available(), None);
        assert!(is_direct_ipv6_reachable());
    }

    #[test]
    fn interleave_happy_eyeballs_orders_ipv4_first_when_direct_ipv6_unreachable() {
        let _guard = lock_ipv6_reachability_for_test();
        let v6_a: SocketAddr = "[2409:8c1e::1]:443".parse().unwrap();
        let v6_b: SocketAddr = "[2409:8c1e::2]:443".parse().unwrap();
        let v4_a: SocketAddr = "223.5.5.5:443".parse().unwrap();
        let v4_b: SocketAddr = "119.29.29.29:443".parse().unwrap();

        assert_eq!(
            interleave_happy_eyeballs_addrs(&[v6_a, v6_b, v4_a, v4_b]),
            vec![v6_a, v4_a, v6_b, v4_b]
        );

        set_os_underlying_ipv6_available(Some(false));
        assert_eq!(
            interleave_happy_eyeballs_addrs(&[v6_a, v6_b, v4_a, v4_b]),
            vec![v4_a, v4_b, v6_a, v6_b]
        );

        // RFC 3849 documentation IPv6 remains interleaved so synthetic dual-stack tests are unaffected.
        let doc_v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let loop_v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert_eq!(
            interleave_happy_eyeballs_addrs(&[doc_v6, loop_v4]),
            vec![doc_v6, loop_v4]
        );
    }
}
