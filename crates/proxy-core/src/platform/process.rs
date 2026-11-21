#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::LazyLock,
    time::{Duration, Instant},
};

use lru::LruCache;
use parking_lot::Mutex;

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

/// Look up the owning local process for a client socket `local_addr`.
/// Only queries OS socket tables when `local_addr.ip()` is loopback or link-local/host-local
/// (remote LAN clients cannot have a local PID on the proxy host).
pub fn find_local_process(
    transport: SocketTransport,
    local_addr: SocketAddr,
) -> Option<LocalProcessInfo> {
    if local_addr.port() == 0 {
        return None;
    }
    if !is_potentially_local_ip(local_addr.ip()) {
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
        if local_addr.port() == 0 || !is_potentially_local_ip(local_addr.ip()) {
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

fn is_potentially_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
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
        (SocketTransport::Tcp, SocketAddr::V4(v4)) => find_win_tcp4_pid(v4),
        (SocketTransport::Tcp, SocketAddr::V6(v6)) => find_win_tcp6_pid(v6),
        (SocketTransport::Udp, SocketAddr::V4(v4)) => find_win_udp4_pid(v4),
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
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        },
        Networking::WinSock::AF_INET,
    };
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize + 256];
        size = buf.len() as u32;
        if GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ) != NO_ERROR
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        let want_port_be = target.port().to_be();
        let want_ip = u32::from_ne_bytes(target.ip().octets());
        for row in rows {
            if (row.dwLocalPort as u16) == want_port_be && row.dwLocalAddr == want_ip {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn find_win_tcp6_pid(target: std::net::SocketAddrV6) -> Option<u32> {
    use windows_sys::Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        },
        Networking::WinSock::AF_INET6,
    };
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize + 256];
        size = buf.len() as u32;
        if GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ) != NO_ERROR
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        let want_port_be = target.port().to_be();
        let want_octets = target.ip().octets();
        for row in rows {
            if (row.dwLocalPort as u16) == want_port_be && row.ucLocalAddr == want_octets {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn find_win_udp4_pid(target: std::net::SocketAddrV4) -> Option<u32> {
    use windows_sys::Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::AF_INET,
    };
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize + 256];
        size = buf.len() as u32;
        if GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ) != NO_ERROR
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        let want_port_be = target.port().to_be();
        let want_ip = u32::from_ne_bytes(target.ip().octets());
        for row in rows {
            if (row.dwLocalPort as u16) == want_port_be
                && (row.dwLocalAddr == want_ip || row.dwLocalAddr == 0)
            {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn find_win_udp6_pid(target: std::net::SocketAddrV6) -> Option<u32> {
    use windows_sys::Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDP6TABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::AF_INET6,
    };
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize + 256];
        size = buf.len() as u32;
        if GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ) != NO_ERROR
        {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        let want_port_be = target.port().to_be();
        let want_octets = target.ip().octets();
        for row in rows {
            if (row.dwLocalPort as u16) == want_port_be
                && (row.ucLocalAddr == want_octets || row.ucLocalAddr == [0u8; 16])
            {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
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
}
