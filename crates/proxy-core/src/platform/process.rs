#[cfg(any(unix, target_os = "windows"))]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::LazyLock,
    time::{Duration, Instant},
};

use lru::LruCache;
use parking_lot::{Mutex, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalProcessInfo {
    /// Executable base name (e.g. `curl`, `firefox`, `chrome.exe`).
    pub name: String,
    /// Full executable path when available from OS kernel APIs.
    pub path: Option<String>,
    pub pid: u32,
}

impl LocalProcessInfo {
    /// Case-insensitive `PROCESS-NAME` comparison compatible with Clash / Mihomo configs
    /// (matches either exact basename or basename without `.exe` suffix across platforms).
    pub fn matches_name(&self, expected: &str) -> bool {
        let exp = expected.trim();
        if exp.is_empty() {
            return false;
        }
        if self.name.eq_ignore_ascii_case(exp) {
            return true;
        }
        let self_stem = self
            .name
            .strip_suffix(".exe")
            .or_else(|| self.name.strip_suffix(".EXE"))
            .unwrap_or(&self.name);
        let exp_stem = exp
            .strip_suffix(".exe")
            .or_else(|| exp.strip_suffix(".EXE"))
            .unwrap_or(exp);
        self_stem.eq_ignore_ascii_case(exp_stem)
    }

    /// Path matching for `PROCESS-PATH` rules (case-insensitive on Windows/macOS, exact or normalized).
    pub fn matches_path(&self, expected: &str) -> bool {
        let Some(ref p) = self.path else {
            return false;
        };
        if cfg!(any(target_os = "windows", target_os = "macos")) {
            p.replace('\\', "/")
                .eq_ignore_ascii_case(&expected.trim().replace('\\', "/"))
        } else {
            p == expected.trim()
        }
    }
}

const PROCESS_CACHE_TTL: Duration = Duration::from_secs(2);

type ProcessCacheKey = (SocketTransport, SocketAddr);
type ProcessCacheEntry = (Instant, Option<LocalProcessInfo>);

static PROCESS_CACHE: LazyLock<Mutex<LruCache<ProcessCacheKey, ProcessCacheEntry>>> =
    LazyLock::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(1024).expect("non-zero"))));

const LOCAL_IFACE_IPS_TTL: Duration = Duration::from_secs(3);

struct LocalInterfaceIpCache {
    refreshed_at: Option<Instant>,
    ips: HashSet<IpAddr>,
}

static LOCAL_IFACE_IPS: LazyLock<RwLock<LocalInterfaceIpCache>> = LazyLock::new(|| {
    RwLock::new(LocalInterfaceIpCache {
        refreshed_at: None,
        ips: HashSet::new(),
    })
});

/// Look up the owning local process for a client socket `local_addr`.
/// Only queries OS socket tables when `local_addr.ip()` is a potentially local subnet
/// (loopback, RFC 1918, CGNAT, link-local, RFC 2544 Fake-IP, ULA) or currently assigned to
/// one of this host's own network interfaces (enabling global unicast IPv6 / public host IPs /
/// custom TUN CIDRs while still rejecting remote WAN clients).
pub fn find_local_process(
    transport: SocketTransport,
    local_addr: SocketAddr,
) -> Option<LocalProcessInfo> {
    if local_addr.port() == 0 {
        return None;
    }
    if !is_local_lookup_candidate_ip(local_addr.ip()) {
        return None;
    }

    if let Some((ts, cached)) = PROCESS_CACHE.lock().get(&(transport, local_addr)).cloned()
        && ts.elapsed() < PROCESS_CACHE_TTL
    {
        return cached;
    }

    let resolved = platform_find_process(transport, local_addr);
    PROCESS_CACHE
        .lock()
        .put((transport, local_addr), (Instant::now(), resolved.clone()));
    resolved
}

/// Non-spawning variant of [`find_local_process`] safe to call from hot synchronous telemetry
/// hooks on Tokio worker threads: on Linux and Windows it queries in-memory kernel tables
/// (`/proc` / `GetExtended*Table`), while on macOS it checks the cache and then inspects our own
/// process's open socket descriptors via `proc_pidinfo(PROC_PIDLISTFDS)` + `getsockname()` without
/// spawning `/usr/sbin/lsof` (preserving App Sandbox / NetworkExtension compatibility while still
/// powering `drop_self_pid` loop prevention on macOS `utun`).
pub fn find_local_process_nonblocking(
    transport: SocketTransport,
    local_addr: SocketAddr,
) -> Option<LocalProcessInfo> {
    #[cfg(target_os = "macos")]
    {
        if local_addr.port() == 0 || !is_local_lookup_candidate_ip(local_addr.ip()) {
            return None;
        }
        if let Some((ts, cached)) = PROCESS_CACHE.lock().get(&(transport, local_addr)).cloned()
            && ts.elapsed() < PROCESS_CACHE_TTL
        {
            return cached;
        }
        if let Some(self_info) = find_macos_own_process_socket(transport, local_addr) {
            PROCESS_CACHE.lock().put(
                (transport, local_addr),
                (Instant::now(), Some(self_info.clone())),
            );
            return Some(self_info);
        }
        None
    }
    #[cfg(not(target_os = "macos"))]
    {
        find_local_process(transport, local_addr)
    }
}

fn is_local_lookup_candidate_ip(ip: IpAddr) -> bool {
    is_potentially_local_ip(ip) || is_assigned_local_interface_ip(ip)
}

fn normalize_local_lookup_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn is_assigned_local_interface_ip(ip: IpAddr) -> bool {
    let normalized = normalize_local_lookup_ip(ip);
    {
        let guard = LOCAL_IFACE_IPS.read();
        if let Some(ts) = guard.refreshed_at
            && ts.elapsed() < LOCAL_IFACE_IPS_TTL
        {
            return guard.ips.contains(&normalized);
        }
    }
    let fresh = enumerate_local_interface_ips();
    let found = fresh.contains(&normalized);
    let mut guard = LOCAL_IFACE_IPS.write();
    guard.ips = fresh;
    guard.refreshed_at = Some(Instant::now());
    found
}

#[cfg(unix)]
fn enumerate_local_interface_ips() -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` allocates a linked list of interface addresses released by `freeifaddrs`.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 || head.is_null() {
        return ips;
    }

    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` points to a valid `ifaddrs` node in the list returned by `getifaddrs`.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` is non-null; `read_unaligned` safely extracts `sa_family`.
            let family = i32::from(unsafe { std::ptr::read_unaligned(ifa.ifa_addr).sa_family });
            match family {
                libc::AF_INET => {
                    // SAFETY: `sa_family == AF_INET` guarantees `ifa_addr` points to a `sockaddr_in`.
                    let sin = unsafe {
                        std::ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in>())
                    };
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    ips.insert(IpAddr::V4(ip));
                }
                libc::AF_INET6 => {
                    // SAFETY: `sa_family == AF_INET6` guarantees `ifa_addr` points to a `sockaddr_in6`.
                    let sin6 = unsafe {
                        std::ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in6>())
                    };
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    ips.insert(normalize_local_lookup_ip(IpAddr::V6(ip)));
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }

    // SAFETY: `head` was allocated by a successful `getifaddrs` call above.
    unsafe { libc::freeifaddrs(head) };
    ips
}

#[cfg(target_os = "windows")]
fn enumerate_local_interface_ips() -> HashSet<IpAddr> {
    use windows_sys::Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{
            FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW,
            MIB_UNICASTIPADDRESS_TABLE,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
    };

    let mut ips = HashSet::new();
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: `GetUnicastIpAddressTable` allocates `table` which is freed via `FreeMibTable` below.
    unsafe {
        let status = GetUnicastIpAddressTable(AF_UNSPEC, &raw mut table);
        if status != NO_ERROR || table.is_null() {
            return ips;
        }
        let num_entries = (*table).NumEntries as usize;
        if num_entries > 0 {
            let rows_ptr = table
                .cast_const()
                .cast::<u8>()
                .add(std::mem::offset_of!(MIB_UNICASTIPADDRESS_TABLE, Table))
                .cast::<MIB_UNICASTIPADDRESS_ROW>();
            let rows = std::slice::from_raw_parts(rows_ptr, num_entries);
            for row in rows {
                let sa = &row.Address;
                if sa.si_family == AF_INET {
                    let bytes = sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                    ips.insert(IpAddr::V4(Ipv4Addr::from(bytes)));
                } else if sa.si_family == AF_INET6 {
                    let ip = Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte);
                    ips.insert(normalize_local_lookup_ip(IpAddr::V6(ip)));
                }
            }
        }
        FreeMibTable(table.cast_const().cast::<std::ffi::c_void>());
    }
    ips
}

#[cfg(not(any(unix, target_os = "windows")))]
fn enumerate_local_interface_ips() -> HashSet<IpAddr> {
    HashSet::new()
}

fn is_potentially_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_potentially_local_ip(IpAddr::V4(v4)))
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Compute the safe number of MIB table rows that actually fit inside `byte_len` bytes,
/// clamping the kernel-reported `claimed_entries` against buffer capacity.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn bounded_mib_row_count(
    byte_len: usize,
    row_offset: usize,
    row_size: usize,
    claimed_entries: u32,
) -> usize {
    if byte_len < row_offset || row_size == 0 {
        return 0;
    }
    let max_rows = (byte_len - row_offset) / row_size;
    (claimed_entries as usize).min(max_rows)
}

/// Fetch a variable-sized Windows IP Helper MIB table into 8-byte aligned `Vec<u64>` storage,
/// retrying up to 5 times on `ERROR_INSUFFICIENT_BUFFER` with monotonic growth.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn query_aligned_mib_table<F>(
    no_error: u32,
    err_insufficient_buffer: u32,
    mut fetch: F,
) -> Option<(Vec<u64>, usize)>
where
    F: FnMut(*mut std::ffi::c_void, *mut u32) -> u32,
{
    const MAX_ATTEMPTS: usize = 5;
    let mut size: u32 = 0;
    let first_rc = fetch(std::ptr::null_mut(), &raw mut size);
    if (first_rc != err_insufficient_buffer && first_rc != no_error) || size == 0 {
        return None;
    }

    let mut prev_bytes: usize = 0;
    for _ in 0..MAX_ATTEMPTS {
        let base = (size as usize).max(prev_bytes);
        let target_bytes = base.saturating_add(4096).saturating_add(base / 4);
        let alloc_u64s = target_bytes.div_ceil(std::mem::size_of::<u64>()).max(1);
        let alloc_bytes = alloc_u64s.saturating_mul(std::mem::size_of::<u64>());
        if alloc_bytes > u32::MAX as usize {
            return None;
        }
        let mut buf = vec![0u64; alloc_u64s];
        let mut out_size = alloc_bytes as u32;
        let rc = fetch(
            buf.as_mut_ptr().cast::<std::ffi::c_void>(),
            &raw mut out_size,
        );
        if rc == no_error {
            let valid_bytes = (out_size as usize).min(alloc_bytes);
            return Some((buf, valid_bytes));
        }
        if rc != err_insufficient_buffer {
            return None;
        }
        prev_bytes = alloc_bytes;
        size = out_size;
    }
    None
}

/// Extract a bounds-checked, properly aligned slice of MIB table rows from 8-byte aligned
/// `Vec<u64>` storage filled by `GetExtendedTcpTable` / `GetExtendedUdpTable`.
///
/// # Safety
/// `buf[..byte_len]` must contain valid initialized bytes representing a `Table` header
/// (`dwNumEntries: u32` at `num_entries_offset`) followed by `Row` elements starting at
/// `rows_offset` (which must be a multiple of `align_of::<Row>()`).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
unsafe fn mib_table_rows<Table, Row>(
    buf: &[u64],
    byte_len: usize,
    num_entries_offset: usize,
    rows_offset: usize,
) -> &[Row] {
    const {
        assert!(std::mem::align_of::<Table>() <= std::mem::align_of::<u64>());
        assert!(std::mem::align_of::<Row>() <= std::mem::align_of::<u64>());
    }
    let avail_bytes = byte_len.min(buf.len().saturating_mul(std::mem::size_of::<u64>()));
    if avail_bytes < num_entries_offset.saturating_add(std::mem::size_of::<u32>()) {
        return &[];
    }
    if !rows_offset.is_multiple_of(std::mem::align_of::<Row>()) {
        return &[];
    }
    let base = buf.as_ptr().cast::<u8>();
    // SAFETY: `avail_bytes >= num_entries_offset + 4`, so reading `u32` at `num_entries_offset` is in bounds.
    let claimed_entries =
        unsafe { std::ptr::read_unaligned(base.add(num_entries_offset).cast::<u32>()) };
    let count = bounded_mib_row_count(
        avail_bytes,
        rows_offset,
        std::mem::size_of::<Row>(),
        claimed_entries,
    );
    if count == 0 {
        return &[];
    }
    // SAFETY: `buf` is 8-byte aligned (`>= align_of::<Row>()`), `rows_offset` is a multiple of
    // `align_of::<Row>()`, and `bounded_mib_row_count` guarantees
    // `rows_offset + count * size_of::<Row>() <= avail_bytes <= buf.len() * 8`.
    unsafe { std::slice::from_raw_parts(base.add(rows_offset).cast::<Row>(), count) }
}

/// Select the owning PID from UDP table entries `(local_addr, local_port_be, owning_pid)`,
/// preferring an exact local IP match over a wildcard (`0.0.0.0` / `::`) binding on the same port.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn select_udp_pid_preferring_exact<Addr: Copy + PartialEq>(
    entries: impl IntoIterator<Item = (Addr, u16, u32)>,
    want_addr: Addr,
    wildcard_addr: Addr,
    want_port_be: u16,
) -> Option<u32> {
    let mut wildcard_pid: Option<u32> = None;
    for (addr, port_be, pid) in entries {
        if port_be != want_port_be || pid == 0 {
            continue;
        }
        if addr == want_addr {
            return Some(pid);
        }
        if addr == wildcard_addr && wildcard_pid.is_none() {
            wildcard_pid = Some(pid);
        }
    }
    wildcard_pid
}

/// Resolve a UDP IPv4 socket against the IPv4 table first, falling back to the IPv6 table with
/// the IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) for dual-stack `IPV6_V6ONLY = 0` sockets.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn resolve_udp4_with_dual_stack_fallback<F4, F6>(
    v4: std::net::SocketAddrV4,
    mut find_v4: F4,
    mut find_v6: F6,
) -> Option<u32>
where
    F4: FnMut(std::net::SocketAddrV4) -> Option<u32>,
    F6: FnMut(std::net::SocketAddrV6) -> Option<u32>,
{
    find_v4(v4).or_else(|| {
        find_v6(std::net::SocketAddrV6::new(
            v4.ip().to_ipv6_mapped(),
            v4.port(),
            0,
            0,
        ))
    })
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub(crate) fn basename_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .or_else(|| path.rsplit(['/', '\\']).next())
        .unwrap_or(path)
        .to_string()
}

// ============================================================================
// Linux: `/proc/net/{tcp,tcp6,udp,udp6}` + `/proc/<pid>/fd` + `/proc/<pid>/{exe,comm}`
// ============================================================================
#[cfg(target_os = "linux")]
fn platform_find_process(
    transport: SocketTransport,
    local_addr: SocketAddr,
) -> Option<LocalProcessInfo> {
    let inode = find_linux_socket_inode(transport, local_addr)?;
    if inode == 0 {
        return None;
    }
    let target_link = format!("socket:[{inode}]");

    // Fast path: check our own process (`/proc/self/fd`) first (< 50 us for in-process callers/tests)
    if let Some(info) = check_pid_fds_for_socket(std::process::id(), "/proc/self", &target_link) {
        return Some(info);
    }

    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return None;
    };
    for entry in proc_entries.flatten() {
        let fname = entry.file_name();
        let Some(fname_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = fname_str.parse::<u32>() else {
            continue;
        };
        let proc_dir = format!("/proc/{pid}");
        if let Some(info) = check_pid_fds_for_socket(pid, &proc_dir, &target_link) {
            return Some(info);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn check_pid_fds_for_socket(
    pid: u32,
    proc_dir: &str,
    target_link: &str,
) -> Option<LocalProcessInfo> {
    let fd_dir = format!("{proc_dir}/fd");
    let entries = std::fs::read_dir(fd_dir).ok()?;
    for fd_entry in entries.flatten() {
        let Ok(link) = std::fs::read_link(fd_entry.path()) else {
            continue;
        };
        if link.to_str() == Some(target_link) {
            let exe_path = std::fs::read_link(format!("{proc_dir}/exe"))
                .ok()
                .and_then(|p| p.into_os_string().into_string().ok())
                .map(|s| s.strip_suffix(" (deleted)").unwrap_or(&s).to_string());
            let comm = std::fs::read_to_string(format!("{proc_dir}/comm"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let name = exe_path
                .as_deref()
                .map(basename_from_path)
                .or(comm)
                .unwrap_or_else(|| format!("pid-{pid}"));
            return Some(LocalProcessInfo {
                name,
                path: exe_path,
                pid,
            });
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn find_linux_socket_inode(transport: SocketTransport, local_addr: SocketAddr) -> Option<u64> {
    let tables: &[&str] = match (transport, local_addr) {
        (SocketTransport::Tcp, SocketAddr::V4(_)) => &["/proc/net/tcp", "/proc/net/tcp6"],
        (SocketTransport::Tcp, SocketAddr::V6(_)) => &["/proc/net/tcp6"],
        (SocketTransport::Udp, SocketAddr::V4(_)) => &["/proc/net/udp", "/proc/net/udp6"],
        (SocketTransport::Udp, SocketAddr::V6(_)) => &["/proc/net/udp6"],
    };

    for table_path in tables {
        let Ok(content) = std::fs::read_to_string(table_path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let mut cols = line.split_whitespace();
            let _sl = cols.next();
            let Some(local_hex) = cols.next() else {
                continue;
            };
            let Some(parsed_local) = parse_proc_net_addr(local_hex) else {
                continue;
            };
            if !socket_addr_matches_proc(parsed_local, local_addr, transport) {
                continue;
            }
            // Skip rem_address(2), st(3), tx_queue:rx_queue(4), tr:tm->when(5), retrnsmt(6), uid(7), timeout(8) -> inode(9)
            let inode_str = cols.nth(7);
            if let Some(inode) = inode_str.and_then(|s| s.parse::<u64>().ok())
                && inode > 0
            {
                return Some(inode);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn socket_addr_matches_proc(
    proc_addr: SocketAddr,
    query: SocketAddr,
    transport: SocketTransport,
) -> bool {
    if proc_addr.port() != query.port() {
        return false;
    }
    if proc_addr.ip() == query.ip() {
        return true;
    }
    // Dual-stack IPv4-mapped IPv6 (`::ffff:127.0.0.1`) or UDP wildcard `0.0.0.0:<port>` / `[::]:<port>`
    match (proc_addr.ip(), query.ip()) {
        (IpAddr::V6(v6), IpAddr::V4(v4)) if v6.to_ipv4_mapped() == Some(v4) => true,
        (IpAddr::V4(v4), IpAddr::V6(v6)) if v6.to_ipv4_mapped() == Some(v4) => true,
        (IpAddr::V4(v4), _) if transport == SocketTransport::Udp && v4.is_unspecified() => true,
        (IpAddr::V6(v6), _) if transport == SocketTransport::Udp && v6.is_unspecified() => true,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_net_addr(hex_col: &str) -> Option<SocketAddr> {
    let (ip_hex, port_hex) = hex_col.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if ip_hex.len() == 8 {
        let raw = u32::from_str_radix(ip_hex, 16).ok()?;
        // `/proc/net/tcp` stores IPv4 words in host byte order
        let octets = raw.to_ne_bytes();
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
    } else if ip_hex.len() == 32 {
        let mut octets = [0u8; 16];
        for i in 0..4 {
            let word = u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16).ok()?;
            octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
        }
        Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
    } else {
        None
    }
}

// ============================================================================
// Windows: `GetExtendedTcpTable` / `GetExtendedUdpTable` + `QueryFullProcessImageNameW`
// ============================================================================
#[cfg(target_os = "windows")]
fn platform_find_process(
    transport: SocketTransport,
    local_addr: SocketAddr,
) -> Option<LocalProcessInfo> {
    let pid = match (transport, local_addr) {
        (SocketTransport::Tcp, SocketAddr::V4(v4)) => find_win_tcp4_pid(v4).or_else(|| {
            find_win_tcp6_pid(std::net::SocketAddrV6::new(
                v4.ip().to_ipv6_mapped(),
                v4.port(),
                0,
                0,
            ))
        }),
        (SocketTransport::Tcp, SocketAddr::V6(v6)) => find_win_tcp6_pid(v6),
        (SocketTransport::Udp, SocketAddr::V4(v4)) => {
            resolve_udp4_with_dual_stack_fallback(v4, find_win_udp4_pid, find_win_udp6_pid)
        }
        (SocketTransport::Udp, SocketAddr::V6(v6)) => find_win_udp6_pid(v6),
    }?;
    if pid == 0 {
        return None;
    }
    query_win_process_info(pid)
}

#[cfg(target_os = "windows")]
static WIN_PID_INFO_CACHE: LazyLock<Mutex<LruCache<u32, (Instant, Option<LocalProcessInfo>)>>> =
    LazyLock::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(512).expect("non-zero"))));

#[cfg(target_os = "windows")]
fn query_win_process_info(pid: u32) -> Option<LocalProcessInfo> {
    if let Some((ts, cached)) = WIN_PID_INFO_CACHE.lock().get(&pid).cloned()
        && ts.elapsed() < PROCESS_CACHE_TTL
    {
        return cached;
    }

    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    };

    let info = unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            None
        } else {
            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;
            let ok =
                QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut size);
            let _ = CloseHandle(handle);
            if ok == 0 || size == 0 {
                None
            } else {
                let full_path = String::from_utf16_lossy(&buf[..size as usize]);
                let name = basename_from_path(&full_path);
                Some(LocalProcessInfo {
                    name,
                    path: Some(full_path),
                    pid,
                })
            }
        }
    };
    WIN_PID_INFO_CACHE
        .lock()
        .put(pid, (Instant::now(), info.clone()));
    info
}

#[cfg(target_os = "windows")]
fn find_win_tcp4_pid(target: std::net::SocketAddrV4) -> Option<u32> {
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL,
        },
        Networking::WinSock::AF_INET,
    };
    let (buf, byte_len) =
        query_aligned_mib_table(NO_ERROR, ERROR_INSUFFICIENT_BUFFER, |ptr, size_ptr| {
            // SAFETY: `ptr` is either null (sizing probe) or points to `*size_ptr` writable bytes.
            unsafe {
                GetExtendedTcpTable(
                    ptr,
                    size_ptr,
                    0,
                    u32::from(AF_INET),
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            }
        })?;
    // SAFETY: `buf[..byte_len]` was filled by `GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_ALL)`.
    let rows = unsafe {
        mib_table_rows::<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(
            &buf,
            byte_len,
            std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, dwNumEntries),
            std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
        )
    };
    let want_port_be = target.port().to_be();
    let want_ip = u32::from_ne_bytes(target.ip().octets());
    for row in rows {
        if row.dwOwningPid != 0
            && (row.dwLocalPort as u16) == want_port_be
            && row.dwLocalAddr == want_ip
        {
            return Some(row.dwOwningPid);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn find_win_tcp6_pid(target: std::net::SocketAddrV6) -> Option<u32> {
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL,
        },
        Networking::WinSock::AF_INET6,
    };
    let (buf, byte_len) =
        query_aligned_mib_table(NO_ERROR, ERROR_INSUFFICIENT_BUFFER, |ptr, size_ptr| {
            // SAFETY: `ptr` is either null (sizing probe) or points to `*size_ptr` writable bytes.
            unsafe {
                GetExtendedTcpTable(
                    ptr,
                    size_ptr,
                    0,
                    u32::from(AF_INET6),
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            }
        })?;
    // SAFETY: `buf[..byte_len]` was filled by `GetExtendedTcpTable(AF_INET6, TCP_TABLE_OWNER_PID_ALL)`.
    let rows = unsafe {
        mib_table_rows::<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(
            &buf,
            byte_len,
            std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, dwNumEntries),
            std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
        )
    };
    let want_port_be = target.port().to_be();
    let want_octets = target.ip().octets();
    for row in rows {
        if row.dwOwningPid != 0
            && (row.dwLocalPort as u16) == want_port_be
            && row.ucLocalAddr == want_octets
        {
            return Some(row.dwOwningPid);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn find_win_udp4_pid(target: std::net::SocketAddrV4) -> Option<u32> {
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::AF_INET,
    };
    let (buf, byte_len) =
        query_aligned_mib_table(NO_ERROR, ERROR_INSUFFICIENT_BUFFER, |ptr, size_ptr| {
            // SAFETY: `ptr` is either null (sizing probe) or points to `*size_ptr` writable bytes.
            unsafe {
                GetExtendedUdpTable(ptr, size_ptr, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0)
            }
        })?;
    // SAFETY: `buf[..byte_len]` was filled by `GetExtendedUdpTable(AF_INET, UDP_TABLE_OWNER_PID)`.
    let rows = unsafe {
        mib_table_rows::<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(
            &buf,
            byte_len,
            std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, dwNumEntries),
            std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
        )
    };
    let want_port_be = target.port().to_be();
    let want_ip = u32::from_ne_bytes(target.ip().octets());
    select_udp_pid_preferring_exact(
        rows.iter()
            .map(|row| (row.dwLocalAddr, row.dwLocalPort as u16, row.dwOwningPid)),
        want_ip,
        0u32,
        want_port_be,
    )
}

#[cfg(target_os = "windows")]
fn find_win_udp6_pid(target: std::net::SocketAddrV6) -> Option<u32> {
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
            UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::AF_INET6,
    };
    let (buf, byte_len) =
        query_aligned_mib_table(NO_ERROR, ERROR_INSUFFICIENT_BUFFER, |ptr, size_ptr| {
            // SAFETY: `ptr` is either null (sizing probe) or points to `*size_ptr` writable bytes.
            unsafe {
                GetExtendedUdpTable(
                    ptr,
                    size_ptr,
                    0,
                    u32::from(AF_INET6),
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            }
        })?;
    // SAFETY: `buf[..byte_len]` was filled by `GetExtendedUdpTable(AF_INET6, UDP_TABLE_OWNER_PID)`.
    let rows = unsafe {
        mib_table_rows::<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(
            &buf,
            byte_len,
            std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, dwNumEntries),
            std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
        )
    };
    let want_port_be = target.port().to_be();
    let want_octets = target.ip().octets();
    select_udp_pid_preferring_exact(
        rows.iter()
            .map(|row| (row.ucLocalAddr, row.dwLocalPort as u16, row.dwOwningPid)),
        want_octets,
        [0u8; 16],
        want_port_be,
    )
}

// ============================================================================
// macOS: Darwin `libproc` (`proc_pidinfo(PROC_PIDLISTFDS)` self fast-path + `proc_pidpath` + `lsof` fallback)
// ============================================================================
#[cfg(target_os = "macos")]
static MACOS_PID_INFO_CACHE: LazyLock<Mutex<LruCache<u32, ProcessCacheEntry>>> =
    LazyLock::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(512).expect("non-zero"))));

#[cfg(target_os = "macos")]
fn query_darwin_process_info(pid: u32, fallback_cmd: Option<&str>) -> Option<LocalProcessInfo> {
    if let Some((ts, cached)) = MACOS_PID_INFO_CACHE.lock().get(&pid).cloned()
        && ts.elapsed() < PROCESS_CACHE_TTL
    {
        return cached;
    }
    let path = darwin_pid_path(pid);
    let name = path
        .as_deref()
        .map(basename_from_path)
        .or_else(|| fallback_cmd.map(ToString::to_string));
    let info = name.map(|name| LocalProcessInfo { name, path, pid });
    MACOS_PID_INFO_CACHE
        .lock()
        .put(pid, (Instant::now(), info.clone()));
    info
}

#[cfg(target_os = "macos")]
fn macos_socket_addr_matches(
    sock_addr: SocketAddr,
    query: SocketAddr,
    transport: SocketTransport,
) -> bool {
    if sock_addr.port() != query.port() {
        return false;
    }
    if sock_addr.ip() == query.ip() {
        return true;
    }
    match (sock_addr.ip(), query.ip()) {
        (IpAddr::V6(v6), IpAddr::V4(v4)) if v6.to_ipv4_mapped() == Some(v4) => true,
        (IpAddr::V4(v4), IpAddr::V6(v6)) if v6.to_ipv4_mapped() == Some(v4) => true,
        (IpAddr::V4(v4), _) if transport == SocketTransport::Udp && v4.is_unspecified() => true,
        (IpAddr::V6(v6), _) if transport == SocketTransport::Udp && v6.is_unspecified() => true,
        _ => false,
    }
}

/// Inspect our own process's open socket descriptors in-memory via Darwin `proc_pidinfo(PROC_PIDLISTFDS)`
/// + POSIX `getsockopt(SO_TYPE)` + `getsockname()` without spawning `/usr/sbin/lsof`.
#[cfg(target_os = "macos")]
fn find_macos_own_process_socket(
    transport: SocketTransport,
    local_addr: SocketAddr,
) -> Option<LocalProcessInfo> {
    const PROC_PIDLISTFDS: libc::c_int = 1;
    const PROX_FDTYPE_SOCKET: u32 = 2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcFdInfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    let my_pid = std::process::id();
    // SAFETY: Querying buffer size with NULL buffer for our own PID is standard Darwin libproc usage.
    let bytes_needed = unsafe {
        proc_pidinfo(
            my_pid as libc::c_int,
            PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    if bytes_needed <= 0 {
        return None;
    }

    let entry_size = std::mem::size_of::<ProcFdInfo>();
    let cap = (bytes_needed as usize / entry_size).saturating_add(32);
    let mut fds = vec![
        ProcFdInfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        cap
    ];
    let buf_bytes = fds
        .len()
        .saturating_mul(entry_size)
        .min(libc::c_int::MAX as usize) as libc::c_int;
    // SAFETY: `fds` has capacity `buf_bytes` bytes and proper alignment for `ProcFdInfo`.
    let filled = unsafe {
        proc_pidinfo(
            my_pid as libc::c_int,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast::<libc::c_void>(),
            buf_bytes,
        )
    };
    if filled <= 0 {
        return None;
    }

    let count = (filled as usize / entry_size).min(fds.len());
    let want_sock_type = match transport {
        SocketTransport::Tcp => libc::SOCK_STREAM,
        SocketTransport::Udp => libc::SOCK_DGRAM,
    };

    for fd_info in &fds[..count] {
        if fd_info.proc_fdtype != PROX_FDTYPE_SOCKET {
            continue;
        }
        let fd = fd_info.proc_fd;
        let mut sock_type: libc::c_int = 0;
        let mut sock_type_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `getsockopt(SOL_SOCKET, SO_TYPE)` reads into `sock_type` of size `sock_type_len`.
        let trc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut sock_type).cast::<libc::c_void>(),
                &raw mut sock_type_len,
            )
        };
        if trc != 0 || sock_type != want_sock_type {
            continue;
        }

        // SAFETY: `sockaddr_storage` is a plain C struct safe to zero-initialize.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut storage_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: `getsockname` writes at most `storage_len` bytes into `storage`.
        let grc = unsafe {
            libc::getsockname(
                fd,
                (&raw mut storage).cast::<libc::sockaddr>(),
                &raw mut storage_len,
            )
        };
        if grc != 0 {
            continue;
        }

        let bound_addr = match i32::from(storage.ss_family) {
            libc::AF_INET => {
                // SAFETY: `ss_family == AF_INET` guarantees `storage` holds a `sockaddr_in`.
                let sin = unsafe {
                    std::ptr::read_unaligned((&raw const storage).cast::<libc::sockaddr_in>())
                };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            libc::AF_INET6 => {
                // SAFETY: `ss_family == AF_INET6` guarantees `storage` holds a `sockaddr_in6`.
                let sin6 = unsafe {
                    std::ptr::read_unaligned((&raw const storage).cast::<libc::sockaddr_in6>())
                };
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                SocketAddr::new(IpAddr::V6(ip), port)
            }
            _ => continue,
        };

        if macos_socket_addr_matches(bound_addr, local_addr, transport) {
            return query_darwin_process_info(my_pid, None);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn platform_find_process(
    transport: SocketTransport,
    local_addr: SocketAddr,
) -> Option<LocalProcessInfo> {
    // Fast in-memory path: check our own process's open socket descriptors first without spawning `lsof`.
    if let Some(self_info) = find_macos_own_process_socket(transport, local_addr) {
        return Some(self_info);
    }

    use std::process::Command;
    // Query macOS socket owner narrowly by exact protocol and local port (`-iTCP:<port>` / `-iUDP:<port>`)
    // with machine-readable `-Fpcn` output (< 5ms when scoped to a single port, cached for 2s).
    let proto_arg = match transport {
        SocketTransport::Tcp => format!("-iTCP:{}", local_addr.port()),
        SocketTransport::Udp => format!("-iUDP:{}", local_addr.port()),
    };
    let out = Command::new("/usr/sbin/lsof")
        .args(["-n", "-P", "-Fpcn", &proto_arg])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut cur_pid: Option<u32> = None;
    let mut cur_cmd: Option<String> = None;
    let port_suffix = format!(":{}", local_addr.port());

    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            cur_pid = p.parse::<u32>().ok();
        } else if let Some(c) = line.strip_prefix('c') {
            cur_cmd = Some(c.to_string());
        } else if let Some(net_name) = line.strip_prefix('n') {
            let local_part = net_name.split("->").next().unwrap_or(net_name);
            if local_part.ends_with(&port_suffix)
                && let Some(pid) = cur_pid
            {
                return query_darwin_process_info(pid, cur_cmd.as_deref());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn darwin_pid_path(pid: u32) -> Option<String> {
    unsafe extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_void,
            buffersize: u32,
        ) -> libc::c_int;
    }
    let mut buf = [0u8; 4096];
    let len = unsafe { proc_pidpath(pid as libc::c_int, buf.as_mut_ptr() as *mut _, 4096) };
    if len <= 0 {
        return None;
    }
    std::str::from_utf8(&buf[..len as usize])
        .ok()
        .map(ToString::to_string)
}

// ============================================================================
// Android / Other Unix: graceful None (Android uses per-app VpnService UID allow/disallow)
// ============================================================================
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn platform_find_process(
    _transport: SocketTransport,
    _local_addr: SocketAddr,
) -> Option<LocalProcessInfo> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_current_process_for_live_tcp_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(srv_addr).await.unwrap();
        let (_accepted, peer_addr) = listener.accept().await.unwrap();
        let _keep_alive = client;

        if cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        )) {
            let info = find_local_process(SocketTransport::Tcp, peer_addr)
                .expect("expected owning process for live local TCP socket");
            assert_eq!(info.pid, std::process::id());
            assert!(!info.name.is_empty());
            assert!(info.matches_name(&info.name));
        }
    }

    #[tokio::test]
    async fn nonblocking_lookup_resolves_current_process_tcp_and_udp_sockets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(srv_addr).await.unwrap();
        let (_accepted, tcp_peer_addr) = listener.accept().await.unwrap();
        let _keep_tcp = client;

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_local_addr = udp.local_addr().unwrap();

        if cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        )) {
            let tcp_info = find_local_process_nonblocking(SocketTransport::Tcp, tcp_peer_addr)
                .expect("expected nonblocking lookup to resolve own TCP socket");
            assert_eq!(tcp_info.pid, std::process::id());

            let udp_info = find_local_process_nonblocking(SocketTransport::Udp, udp_local_addr)
                .expect("expected nonblocking lookup to resolve own UDP socket");
            assert_eq!(udp_info.pid, std::process::id());
        }
    }

    #[test]
    fn potentially_local_ip_restricts_198_to_rfc2544_subnet() {
        for local_ip in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.20",
            "198.18.0.1",
            "198.19.255.254",
            "::ffff:198.18.1.2",
            "::1",
            "fe80::1",
        ] {
            assert!(
                is_potentially_local_ip(local_ip.parse().unwrap()),
                "expected {local_ip} to be recognized as potentially local"
            );
        }

        for public_ip in [
            "198.0.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "198.51.100.10",
            "::ffff:198.51.100.10",
            "8.8.8.8",
            "2606:4700:4700::1111",
        ] {
            assert!(
                !is_potentially_local_ip(public_ip.parse().unwrap()),
                "expected public IP {public_ip} NOT to be treated as local"
            );
        }
    }

    #[test]
    fn potentially_local_ip_accepts_cgnat_range_and_rejects_neighbors() {
        for cgnat_ip in [
            "100.64.0.0",
            "100.64.0.1",
            "100.100.100.100",
            "100.127.255.254",
            "100.127.255.255",
            "::ffff:100.64.0.1",
            "::ffff:100.127.255.254",
        ] {
            assert!(
                is_potentially_local_ip(cgnat_ip.parse().unwrap()),
                "expected CGNAT IP {cgnat_ip} to be recognized as potentially local"
            );
        }

        for outside_ip in [
            "100.63.255.255",
            "100.128.0.0",
            "100.128.0.1",
            "::ffff:100.63.255.255",
            "::ffff:100.128.0.1",
        ] {
            assert!(
                !is_potentially_local_ip(outside_ip.parse().unwrap()),
                "expected non-CGNAT IP {outside_ip} NOT to be treated as local"
            );
        }
    }

    #[test]
    fn bounded_mib_row_count_and_aligned_slice_clamp_excessive_and_truncated_buffers() {
        assert_eq!(bounded_mib_row_count(0, 4, 24, 10), 0);
        assert_eq!(bounded_mib_row_count(3, 4, 24, 10), 0);
        assert_eq!(bounded_mib_row_count(4, 4, 24, 10), 0);
        assert_eq!(bounded_mib_row_count(4 + 24 * 3, 4, 24, 10_000), 3);
        assert_eq!(bounded_mib_row_count(4 + 24 * 2 + 15, 4, 24, 5), 2);
        assert_eq!(bounded_mib_row_count(4 + 24 * 5, 4, 24, 2), 2);
        assert_eq!(bounded_mib_row_count(1024, 4, 0, 5), 0);

        #[repr(C)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct MockUdpRow {
            local_addr: u32,
            local_port: u32,
            owning_pid: u32,
        }

        #[repr(C)]
        struct MockUdpTable {
            num_entries: u32,
            table: [MockUdpRow; 1],
        }

        // Write a table claiming 999 entries into aligned u64 storage that only holds 2 full rows.
        let mut storage = vec![0u64; 8];
        let base = storage.as_mut_ptr().cast::<u8>();
        let row_offset = std::mem::offset_of!(MockUdpTable, table);
        let row_size = std::mem::size_of::<MockUdpRow>();
        let two_row_bytes = row_offset + row_size * 2;
        unsafe {
            std::ptr::write_unaligned(
                base.add(std::mem::offset_of!(MockUdpTable, num_entries))
                    .cast::<u32>(),
                999u32,
            );
            std::ptr::write(
                base.add(row_offset).cast::<MockUdpRow>(),
                MockUdpRow {
                    local_addr: 0,
                    local_port: u32::from(5353u16.to_be()),
                    owning_pid: 101,
                },
            );
            std::ptr::write(
                base.add(row_offset + row_size).cast::<MockUdpRow>(),
                MockUdpRow {
                    local_addr: u32::from_ne_bytes([192, 168, 1, 10]),
                    local_port: u32::from(5353u16.to_be()),
                    owning_pid: 202,
                },
            );
        }

        let clamped = unsafe {
            mib_table_rows::<MockUdpTable, MockUdpRow>(
                &storage,
                two_row_bytes + 5,
                std::mem::offset_of!(MockUdpTable, num_entries),
                row_offset,
            )
        };
        assert_eq!(clamped.len(), 2);
        assert_eq!(clamped[0].owning_pid, 101);
        assert_eq!(clamped[1].owning_pid, 202);

        // Truncated header (< 4 bytes) must return an empty slice safely.
        let truncated = unsafe {
            mib_table_rows::<MockUdpTable, MockUdpRow>(
                &storage,
                2,
                std::mem::offset_of!(MockUdpTable, num_entries),
                row_offset,
            )
        };
        assert!(truncated.is_empty());
    }

    #[test]
    fn query_aligned_mib_table_retries_insufficient_buffer_with_aligned_growth() {
        const NO_ERR: u32 = 0;
        const INSUFF: u32 = 122;

        let mut seen_sizes = Vec::new();
        let mut call_num = 0usize;
        let (buf, valid_bytes) = query_aligned_mib_table(NO_ERR, INSUFF, |ptr, size_ptr| {
            call_num += 1;
            if ptr.is_null() {
                unsafe {
                    *size_ptr = 128;
                }
                return INSUFF;
            }
            assert_eq!(
                (ptr as usize) % std::mem::align_of::<u64>(),
                0,
                "MIB buffer pointer must be 8-byte aligned"
            );
            let offered = unsafe { *size_ptr };
            seen_sizes.push(offered);
            if call_num <= 3 {
                // Simulate table growing faster than previous buffer on attempts 1 & 2.
                unsafe {
                    *size_ptr = offered.saturating_add(512);
                }
                return INSUFF;
            }
            unsafe {
                *size_ptr = 256;
            }
            NO_ERR
        })
        .expect("should succeed on retry after ERROR_INSUFFICIENT_BUFFER");

        assert_eq!(seen_sizes.len(), 3);
        assert!(seen_sizes[1] > seen_sizes[0]);
        assert!(seen_sizes[2] > seen_sizes[1]);
        assert_eq!(valid_bytes, 256);
        assert!(buf.len() * std::mem::size_of::<u64>() >= valid_bytes);

        // Exhausting all 5 retry attempts returns None cleanly.
        let mut attempts = 0usize;
        let exhausted = query_aligned_mib_table(NO_ERR, INSUFF, |ptr, size_ptr| {
            if ptr.is_null() {
                unsafe {
                    *size_ptr = 64;
                }
                return INSUFF;
            }
            attempts += 1;
            INSUFF
        });
        assert!(exhausted.is_none());
        assert_eq!(attempts, 5);
    }

    #[test]
    fn udp_pid_selection_prefers_exact_ip_over_wildcard_and_supports_dual_stack_v4_mapped() {
        let port_be = 5353u16.to_be();
        let other_port_be = 8080u16.to_be();
        let exact_v4 = u32::from_ne_bytes([192, 168, 1, 10]);

        // Wildcard 0.0.0.0:5353 (PID 100) appears BEFORE exact 192.168.1.10:5353 (PID 200).
        let v4_entries = [
            (0u32, port_be, 0u32), // PID 0 ignored
            (0u32, port_be, 100u32),
            (exact_v4, other_port_be, 999u32),
            (exact_v4, port_be, 200u32),
        ];
        assert_eq!(
            select_udp_pid_preferring_exact(v4_entries, exact_v4, 0u32, port_be),
            Some(200)
        );
        // When only wildcard matches the port, wildcard PID is returned.
        assert_eq!(
            select_udp_pid_preferring_exact(
                v4_entries,
                u32::from_ne_bytes([10, 0, 0, 5]),
                0u32,
                port_be
            ),
            Some(100)
        );

        // Dual-stack IPv4 query falls back to IPv6 table with IPv4-mapped `::ffff:192.168.1.10`.
        let target_v4 = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, 10), 5353);
        let mapped_octets = target_v4.ip().to_ipv6_mapped().octets();
        let v6_entries_with_exact = [
            ([0u8; 16], port_be, 300u32),
            (mapped_octets, port_be, 400u32),
        ];
        let pid_exact = resolve_udp4_with_dual_stack_fallback(
            target_v4,
            |_| None,
            |v6| {
                assert_eq!(v6.ip().to_ipv4_mapped(), Some(*target_v4.ip()));
                assert_eq!(v6.port(), 5353);
                select_udp_pid_preferring_exact(
                    v6_entries_with_exact,
                    v6.ip().octets(),
                    [0u8; 16],
                    v6.port().to_be(),
                )
            },
        );
        assert_eq!(pid_exact, Some(400));

        // Dual-stack socket bound to `[::]:5353` (`IPV6_V6ONLY = 0`) also matches IPv4 query.
        let v6_entries_wildcard_only = [([0u8; 16], port_be, 300u32)];
        let pid_wild = resolve_udp4_with_dual_stack_fallback(
            target_v4,
            |_| None,
            |v6| {
                select_udp_pid_preferring_exact(
                    v6_entries_wildcard_only,
                    v6.ip().octets(),
                    [0u8; 16],
                    v6.port().to_be(),
                )
            },
        );
        assert_eq!(pid_wild, Some(300));
    }

    #[tokio::test]
    async fn assigned_local_interface_ip_cache_discovers_host_interfaces_and_resolves_live_socket()
    {
        let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
        let mapped_loopback_v4: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let wan_v4: IpAddr = "8.8.8.8".parse().unwrap();
        let wan_v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();

        if cfg!(any(unix, target_os = "windows")) {
            assert!(
                is_assigned_local_interface_ip(loopback_v4),
                "127.0.0.1 must be discovered by OS interface enumeration"
            );
            assert!(
                is_assigned_local_interface_ip(mapped_loopback_v4),
                "::ffff:127.0.0.1 must match assigned 127.0.0.1 interface IP"
            );
            assert!(!is_assigned_local_interface_ip(wan_v4));
            assert!(!is_assigned_local_interface_ip(wan_v6));
        }

        // Verify a live local UDP socket bound to an assigned interface IP resolves our own PID.
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = udp.local_addr().unwrap();
        if cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        )) {
            let info = find_local_process(SocketTransport::Udp, local_addr)
                .expect("expected owning process for live local UDP socket");
            assert_eq!(info.pid, std::process::id());
        }
    }
}
