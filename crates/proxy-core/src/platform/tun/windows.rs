use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use crate::platform::recovery::{
    RecoveryOutcome, WindowsDnsFamilySnapshot, WindowsDnsInterfaceBackup, WindowsRecoveryRecord,
};

/// Official Wintun v0.14.1 (`https://www.wintun.net/builds/wintun-0.14.1.zip`) archive & signed DLL SHA-256 digests.
pub const WINTUN_0_14_1_ZIP_SHA256: &str =
    "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

/// Locate `wintun.dll` securely: checks explicit configured path first, then the directory containing
/// the running executable (`current_exe().parent()/wintun.dll`) — NEVER untrusted `current_dir()`.
pub fn resolve_secure_wintun_dll_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit
        && p.is_absolute()
        && p.is_file()
    {
        return Some(p.to_path_buf());
    }
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    let candidate = exe_dir.join("wintun.dll");
    if candidate.is_file() {
        return Some(candidate);
    }
    let resources_candidate = exe_dir.join("resources").join("wintun.dll");
    if resources_candidate.is_file() {
        return Some(resources_candidate);
    }
    None
}

/// Split-tunnel prefix pairs (`0.0.0.0/1` + `128.0.0.0/1` for IPv4; `::/1` + `8000::/1` for IPv6)
/// capturing 100% of global unicast traffic at higher specificity than `/0` WITHOUT deleting or
/// overwriting Windows's physical `0.0.0.0/0` default gateway.
pub const WINDOWS_SPLIT_IPV4_PREFIXES: &[(&str, u8)] = &[("0.0.0.0", 1), ("128.0.0.0", 1)];
pub const WINDOWS_SPLIT_IPV6_PREFIXES: &[(&str, u8)] = &[("::", 1), ("8000::", 1)];

/// Format raw Win32 `GUID` fields into canonical braced uppercase `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn format_braced_guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        data1,
        data2,
        data3,
        data4[0],
        data4[1],
        data4[2],
        data4[3],
        data4[4],
        data4[5],
        data4[6],
        data4[7],
    )
}

/// Parse canonical braced or unbraced GUID string back into `(data1, data2, data3, data4)`.
pub fn parse_braced_guid(raw: &str) -> io::Result<(u32, u16, u16, [u8; 8])> {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(trimmed);
    let parts: Vec<&str> = inner.split('-').collect();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Windows interface GUID '{raw}'"),
        ));
    }
    let parse_err = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid hex in Windows interface GUID '{raw}'"),
        )
    };
    let d1 = u32::from_str_radix(parts[0], 16).map_err(|_| parse_err())?;
    let d2 = u16::from_str_radix(parts[1], 16).map_err(|_| parse_err())?;
    let d3 = u16::from_str_radix(parts[2], 16).map_err(|_| parse_err())?;
    let mut d4 = [0u8; 8];
    d4[0] = u8::from_str_radix(&parts[3][0..2], 16).map_err(|_| parse_err())?;
    d4[1] = u8::from_str_radix(&parts[3][2..4], 16).map_err(|_| parse_err())?;
    for i in 0..6 {
        d4[2 + i] = u8::from_str_radix(&parts[4][i * 2..i * 2 + 2], 16).map_err(|_| parse_err())?;
    }
    Ok((d1, d2, d3, d4))
}

/// Testable abstraction over Windows `iphlpapi.dll` interface DNS APIs (`ConvertInterfaceLuidToGuid`,
/// `GetInterfaceDnsSettings`, and `SetInterfaceDnsSettings`), enabling deterministic fault-injection
/// verification across all CI platforms while driving genuine Win32 syscalls on Windows.
pub trait WindowsDnsOps {
    fn resolve_luid_guid(&mut self, luid_value: u64) -> io::Result<String>;
    fn get_dns_settings(
        &mut self,
        interface_guid: &str,
        ipv6: bool,
    ) -> io::Result<WindowsDnsFamilySnapshot>;
    fn set_dns_settings(
        &mut self,
        interface_guid: &str,
        ipv6: bool,
        settings: &WindowsDnsFamilySnapshot,
    ) -> io::Result<()>;
}

/// Snapshot pre-existing IPv4 (and optional IPv6) interface DNS settings, apply `dns_v4` / `dns_v6`,
/// strictly check every Win32 result code, and automatically roll back IPv4 DNS if IPv6 DNS fails.
pub fn apply_windows_adapter_dns_transactional<B: WindowsDnsOps>(
    backend: &mut B,
    luid_value: u64,
    dns_v4: Ipv4Addr,
    dns_v6: Option<Ipv6Addr>,
) -> io::Result<WindowsDnsInterfaceBackup> {
    let guid = backend.resolve_luid_guid(luid_value)?;
    let prev_v4 = backend.get_dns_settings(&guid, false)?;
    let prev_v6 = if dns_v6.is_some() {
        Some(backend.get_dns_settings(&guid, true)?)
    } else {
        None
    };

    let desired_v4 = WindowsDnsFamilySnapshot {
        name_server: dns_v4.to_string(),
        domain: prev_v4.domain.clone(),
        search_list: prev_v4.search_list.clone(),
    };
    backend
        .set_dns_settings(&guid, false, &desired_v4)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("SetInterfaceDnsSettings(IPv4={dns_v4}) on {guid} failed: {e}"),
            )
        })?;

    if let Some(ip6) = dns_v6 {
        let desired_v6 = WindowsDnsFamilySnapshot {
            name_server: ip6.to_string(),
            domain: prev_v6.as_ref().and_then(|s| s.domain.clone()),
            search_list: prev_v6.as_ref().and_then(|s| s.search_list.clone()),
        };
        if let Err(v6_err) = backend.set_dns_settings(&guid, true, &desired_v6) {
            // Immediately roll back the IPv4 DNS mutation we just applied!
            let rb_note = match backend.set_dns_settings(&guid, false, &prev_v4) {
                Ok(()) => "IPv4 DNS rolled back cleanly".to_string(),
                Err(rb_err) => format!("IPv4 DNS rollback ALSO failed: {rb_err}"),
            };
            return Err(io::Error::new(
                v6_err.kind(),
                format!(
                    "SetInterfaceDnsSettings(IPv6={ip6}) on {guid} failed ({v6_err}); {rb_note}"
                ),
            ));
        }
    }

    Ok(WindowsDnsInterfaceBackup {
        interface_guid: guid,
        ipv4: prev_v4,
        ipv6: prev_v6,
    })
}

/// Restore backed-up Windows IPv4 and IPv6 DNS settings and record accurate results/warnings in `outcome`.
pub fn restore_windows_adapter_dns_with_ops<B: WindowsDnsOps>(
    backend: &mut B,
    rec: &WindowsRecoveryRecord,
    outcome: &mut RecoveryOutcome,
) {
    if let Some(backup) = &rec.dns_backup {
        let desc_v4 = format!(
            "RestoreInterfaceDnsSettings(IPv4='{}') on {}",
            backup.ipv4.name_server, backup.interface_guid
        );
        match backend.set_dns_settings(&backup.interface_guid, false, &backup.ipv4) {
            Ok(()) => outcome.actions_executed.push(desc_v4),
            Err(e) => outcome.warnings.push(format!("{desc_v4} failed: {e}")),
        }

        if let Some(v6_snap) = &backup.ipv6 {
            let desc_v6 = format!(
                "RestoreInterfaceDnsSettings(IPv6='{}') on {}",
                v6_snap.name_server, backup.interface_guid
            );
            match backend.set_dns_settings(&backup.interface_guid, true, v6_snap) {
                Ok(()) => outcome.actions_executed.push(desc_v6),
                Err(e) => outcome.warnings.push(format!("{desc_v6} failed: {e}")),
            }
        }
        return;
    }

    // Legacy recovery journal fallback (`dns_backup` absent, `previous_dns_servers` present)
    if let Some(prev_servers) = &rec.previous_dns_servers {
        let guid_res = match &rec.dns_interface_guid {
            Some(g) => Ok(g.clone()),
            None if rec.adapter_luid != 0 => backend.resolve_luid_guid(rec.adapter_luid),
            None => return,
        };
        match guid_res {
            Ok(guid) => {
                let snap = WindowsDnsFamilySnapshot {
                    name_server: prev_servers.join(","),
                    domain: None,
                    search_list: None,
                };
                let desc = format!(
                    "RestoreInterfaceDnsSettings(legacy IPv4='{}') on {}",
                    snap.name_server, guid
                );
                match backend.set_dns_settings(&guid, false, &snap) {
                    Ok(()) => outcome.actions_executed.push(desc),
                    Err(e) => outcome.warnings.push(format!("{desc} failed: {e}")),
                }
            }
            Err(e) => outcome.warnings.push(format!(
                "ConvertInterfaceLuidToGuid({}) failed during DNS recovery: {e}",
                rec.adapter_luid
            )),
        }
    }
}

#[cfg(windows)]
mod win_impl {
    use std::{
        ffi::c_void,
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::windows::ffi::OsStrExt,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread::JoinHandle,
        time::Duration,
    };

    use parking_lot::Mutex;
    use windows_sys::{
        Win32::{
            Foundation::{
                CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS,
                FreeLibrary, GetLastError, HANDLE, HMODULE,
            },
            NetworkManagement::{
                IpHelper::{
                    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid,
                    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
                    CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
                    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_DOMAIN, DNS_SETTING_IPV6,
                    DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST, DeleteIpForwardEntry2,
                    FreeInterfaceDnsSettings, GetBestRoute2, GetInterfaceDnsSettings,
                    GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeUnicastIpAddressEntry,
                    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
                    MibAddInstance, MibDeleteInstance, MibParameterNotification,
                    NotifyIpInterfaceChange, SetInterfaceDnsSettings, SetIpInterfaceEntry,
                },
                Ndis::NET_LUID_LH,
            },
            Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET},
            Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
            System::{
                LibraryLoader::{
                    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
                    LoadLibraryExW,
                },
                Threading::{
                    CreateEventW, GetCurrentProcess, OpenProcessToken, SetEvent,
                    WaitForMultipleObjects,
                },
            },
        },
        core::GUID,
    };

    use super::{
        WINDOWS_SPLIT_IPV4_PREFIXES, WINDOWS_SPLIT_IPV6_PREFIXES, WindowsDnsOps,
        apply_windows_adapter_dns_transactional, format_braced_guid, parse_braced_guid,
        resolve_secure_wintun_dll_path, restore_windows_adapter_dns_with_ops,
    };
    use crate::{
        inbound::tun::VirtualTunHandle,
        platform::{
            recovery::{
                RecoveryOutcome, WindowsDnsFamilySnapshot, WindowsRecoveryRecord,
                WindowsRouteRecord, update_current_journal,
            },
            socket_protect::{
                WindowsUnicastIfProtector, clear_global_socket_protector, global_socket_protector,
                set_global_socket_protector,
            },
            tun::{SystemTunSession, TunHealthSnapshot, TunLaunchSpec},
        },
    };

    /// Deterministic GUID for the `RustClash` Wintun adapter (`{7D81B34E-6C91-49D2-9B83-53C6E9041A21}`).
    static RUST_CLASH_WINTUN_GUID: GUID = GUID {
        data1: 0x7d81_b34e,
        data2: 0x6c91,
        data3: 0x49d2,
        data4: [0x9b, 0x83, 0x53, 0xc6, 0xe9, 0x04, 0x1a, 0x21],
    };

    const WINTUN_RING_CAPACITY: u32 = 0x0040_0000; // 4 MiB ring buffer (within official 128 KiB..64 MiB range)

    type WintunAdapterHandle = *mut c_void;
    type WintunSessionHandle = *mut c_void;

    type FnWintunCreateAdapter = unsafe extern "system" fn(
        name: *const u16,
        tunnel_type: *const u16,
        requested_guid: *const GUID,
    ) -> WintunAdapterHandle;
    type FnWintunOpenAdapter = unsafe extern "system" fn(name: *const u16) -> WintunAdapterHandle;
    type FnWintunCloseAdapter = unsafe extern "system" fn(adapter: WintunAdapterHandle);
    type FnWintunGetAdapterLuid =
        unsafe extern "system" fn(adapter: WintunAdapterHandle, luid: *mut NET_LUID_LH);
    type FnWintunGetRunningDriverVersion = unsafe extern "system" fn() -> u32;
    type FnWintunStartSession = unsafe extern "system" fn(
        adapter: WintunAdapterHandle,
        capacity: u32,
    ) -> WintunSessionHandle;
    type FnWintunEndSession = unsafe extern "system" fn(session: WintunSessionHandle);
    type FnWintunGetReadWaitEvent =
        unsafe extern "system" fn(session: WintunSessionHandle) -> HANDLE;
    type FnWintunReceivePacket =
        unsafe extern "system" fn(session: WintunSessionHandle, packet_size: *mut u32) -> *mut u8;
    type FnWintunReleaseReceivePacket =
        unsafe extern "system" fn(session: WintunSessionHandle, packet: *const u8);
    type FnWintunAllocateSendPacket =
        unsafe extern "system" fn(session: WintunSessionHandle, packet_size: u32) -> *mut u8;
    type FnWintunSendPacket =
        unsafe extern "system" fn(session: WintunSessionHandle, packet: *const u8);

    struct WintunApi {
        module: HMODULE,
        create_adapter: FnWintunCreateAdapter,
        open_adapter: FnWintunOpenAdapter,
        close_adapter: FnWintunCloseAdapter,
        get_adapter_luid: FnWintunGetAdapterLuid,
        get_running_driver_version: FnWintunGetRunningDriverVersion,
        start_session: FnWintunStartSession,
        end_session: FnWintunEndSession,
        get_read_wait_event: FnWintunGetReadWaitEvent,
        receive_packet: FnWintunReceivePacket,
        release_receive_packet: FnWintunReleaseReceivePacket,
        allocate_send_packet: FnWintunAllocateSendPacket,
        send_packet: FnWintunSendPacket,
    }

    // SAFETY: `WintunApi` holds an immutable `HMODULE` and thread-safe Wintun C function pointers.
    unsafe impl Send for WintunApi {}
    // SAFETY: All Wintun exports are thread-safe per Wintun header specification when session access is synchronized per direction.
    unsafe impl Sync for WintunApi {}

    impl Drop for WintunApi {
        fn drop(&mut self) {
            if !self.module.is_null() {
                // SAFETY: `self.module` was returned by `LoadLibraryExW` and all sessions/adapters are closed before `WintunApi` drops.
                unsafe {
                    let _ = FreeLibrary(self.module);
                }
            }
        }
    }

    fn to_wide_nul(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn to_wide_path(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    unsafe fn load_proc<T>(module: HMODULE, symbol: &[u8]) -> io::Result<T> {
        // SAFETY: `module` is valid and `symbol` is a NUL-terminated ASCII C symbol name.
        let raw = unsafe { GetProcAddress(module, symbol.as_ptr()) };
        let Some(f) = raw else {
            let name = String::from_utf8_lossy(&symbol[..symbol.len().saturating_sub(1)]);
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("wintun.dll missing required symbol '{name}'"),
            ));
        };
        // SAFETY: Caller specifies the exact `extern "system" fn` signature matching official `wintun.h`.
        Ok(unsafe { std::mem::transmute_copy(&f) })
    }

    impl WintunApi {
        fn load_secure(explicit_path: Option<&Path>) -> io::Result<Arc<Self>> {
            let dll_path = resolve_secure_wintun_dll_path(explicit_path).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Official signed wintun.dll not found next to rust-clash.exe (run scripts/fetch_wintun.py or bundle via release installer)",
                )
            })?;
            let wide = to_wide_path(&dll_path);
            // SAFETY: `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32` prevents CWD DLL hijacking.
            let module = unsafe {
                LoadLibraryExW(
                    wide.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            if module.is_null() {
                return Err(io::Error::last_os_error());
            }

            let load_all = || -> io::Result<Self> {
                // SAFETY: Each symbol matches official Wintun 0.14.1 `wintun.h` ABI.
                unsafe {
                    Ok(Self {
                        module,
                        create_adapter: load_proc(module, b"WintunCreateAdapter\0")?,
                        open_adapter: load_proc(module, b"WintunOpenAdapter\0")?,
                        close_adapter: load_proc(module, b"WintunCloseAdapter\0")?,
                        get_adapter_luid: load_proc(module, b"WintunGetAdapterLUID\0")?,
                        get_running_driver_version: load_proc(
                            module,
                            b"WintunGetRunningDriverVersion\0",
                        )?,
                        start_session: load_proc(module, b"WintunStartSession\0")?,
                        end_session: load_proc(module, b"WintunEndSession\0")?,
                        get_read_wait_event: load_proc(module, b"WintunGetReadWaitEvent\0")?,
                        receive_packet: load_proc(module, b"WintunReceivePacket\0")?,
                        release_receive_packet: load_proc(module, b"WintunReleaseReceivePacket\0")?,
                        allocate_send_packet: load_proc(module, b"WintunAllocateSendPacket\0")?,
                        send_packet: load_proc(module, b"WintunSendPacket\0")?,
                    })
                }
            };

            match load_all() {
                Ok(api) => Ok(Arc::new(api)),
                Err(e) => {
                    // SAFETY: Freeing `module` on symbol resolution failure.
                    unsafe {
                        let _ = FreeLibrary(module);
                    }
                    Err(e)
                }
            }
        }
    }

    /// Check whether the current Windows process holds an elevated Administrator token.
    pub fn is_windows_process_elevated() -> bool {
        // SAFETY: `OpenProcessToken` + `GetTokenInformation(TokenElevation)` on `GetCurrentProcess()` is read-only.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&raw mut elevation).cast::<c_void>(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &raw mut ret_len,
            );
            let _ = CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    fn sockaddr_inet_from_ip(ip: IpAddr) -> SOCKADDR_INET {
        // SAFETY: Zeroed `SOCKADDR_INET` union is valid for populating `Ipv4` or `Ipv6` member.
        let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        match ip {
            IpAddr::V4(v4) => {
                sa.Ipv4.sin_family = AF_INET;
                sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            }
            IpAddr::V6(v6) => {
                sa.Ipv6.sin6_family = AF_INET6;
                sa.Ipv6.sin6_addr.u.Byte = v6.octets();
            }
        }
        sa
    }

    fn ip_from_sockaddr_inet(sa: &SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: `si_family` is at offset 0 of every `SOCKADDR_INET` union arm.
        unsafe {
            if sa.si_family == AF_INET {
                let bytes = sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                Some(IpAddr::V4(Ipv4Addr::from(bytes)))
            } else if sa.si_family == AF_INET6 {
                Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte)))
            } else {
                None
            }
        }
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct PhysicalEgressInfo {
        pub v4_if_index: u32,
        pub v4_luid: u64,
        pub v4_gateway: Option<IpAddr>,
        pub v6_if_index: u32,
        pub v6_luid: u64,
        pub v6_gateway: Option<IpAddr>,
    }

    /// Detect the active physical egress `InterfaceIndex`, `InterfaceLuid`, and next-hop gateway
    /// via `GetBestRoute2`, explicitly ignoring `excluded_tun_luid` if Wintun is already active!
    pub fn detect_windows_physical_egress(excluded_tun_luid: u64) -> PhysicalEgressInfo {
        let mut info = PhysicalEgressInfo::default();

        // Probe IPv4 route toward `1.1.1.1`
        let dst_v4 = sockaddr_inet_from_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        // SAFETY: Zeroed `MIB_IPFORWARD_ROW2` and `SOCKADDR_INET` out-params match `GetBestRoute2` contract.
        unsafe {
            let mut best_row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            let mut best_src: SOCKADDR_INET = std::mem::zeroed();
            let status = GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &raw const dst_v4,
                0,
                &raw mut best_row,
                &raw mut best_src,
            );
            if status == 0 && best_row.InterfaceLuid.Value != excluded_tun_luid {
                info.v4_if_index = best_row.InterfaceIndex;
                info.v4_luid = best_row.InterfaceLuid.Value;
                info.v4_gateway = ip_from_sockaddr_inet(&best_row.NextHop);
            }
        }

        // Probe IPv6 route toward `2606:4700:4700::1111`
        let dst_v6 = sockaddr_inet_from_ip(IpAddr::V6(
            "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap(),
        ));
        // SAFETY: Same `GetBestRoute2` contract for IPv6.
        unsafe {
            let mut best_row6: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            let mut best_src6: SOCKADDR_INET = std::mem::zeroed();
            let status6 = GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &raw const dst_v6,
                0,
                &raw mut best_row6,
                &raw mut best_src6,
            );
            if status6 == 0 && best_row6.InterfaceLuid.Value != excluded_tun_luid {
                info.v6_if_index = best_row6.InterfaceIndex;
                info.v6_luid = best_row6.InterfaceLuid.Value;
                info.v6_gateway = ip_from_sockaddr_inet(&best_row6.NextHop);
            }
        }

        info
    }

    pub fn preflight_windows_tun(explicit_dll: Option<&Path>) -> TunHealthSnapshot {
        let elevated = is_windows_process_elevated();
        let dll_path = resolve_secure_wintun_dll_path(explicit_dll);
        let driver_loaded = dll_path.is_some();
        let egress = detect_windows_physical_egress(0);

        let hint = if !driver_loaded {
            Some(
                "Signed wintun.dll not found next to executable (bundle official Wintun 0.14.1 DLL)"
                    .to_string(),
            )
        } else if !elevated {
            Some(
                "Windows Wintun adapter & iphlpapi route configuration requires Administrator privileges (UAC)"
                    .to_string(),
            )
        } else {
            None
        };

        TunHealthSnapshot {
            platform: "windows".to_string(),
            backend: "windows-wintun".to_string(),
            active: false,
            device_name: None,
            mtu: 1500,
            ipv4_cidr: None,
            ipv6_cidr: None,
            auto_route_applied: false,
            strict_route_applied: false,
            route_table_id: None,
            default_egress_iface: (egress.v4_if_index != 0)
                .then(|| format!("ifIndex:{}", egress.v4_if_index)),
            default_egress_gateway: egress.v4_gateway.map(|g| g.to_string()),
            socket_protector: global_socket_protector().description(),
            privilege_ok: driver_loaded && elevated,
            privilege_hint: hint,
            driver_loaded,
            network_transitions: 0,
            rx_packets: 0,
            tx_packets: 0,
            last_error: None,
        }
    }

    fn set_adapter_unicast_ip(luid: NET_LUID_LH, ip: IpAddr, prefix_len: u8) -> io::Result<()> {
        // SAFETY: `InitializeUnicastIpAddressEntry` + `CreateUnicastIpAddressEntry` follow MSDN `iphlpapi` contract.
        unsafe {
            let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
            InitializeUnicastIpAddressEntry(&raw mut row);
            row.InterfaceLuid = luid;
            row.Address = sockaddr_inet_from_ip(ip);
            row.OnLinkPrefixLength = prefix_len;
            let status = CreateUnicastIpAddressEntry(&raw const row);
            if status != 0 && status != ERROR_OBJECT_ALREADY_EXISTS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        Ok(())
    }

    fn set_adapter_mtu(luid: NET_LUID_LH, family: u16, mtu: u32) -> io::Result<()> {
        // SAFETY: `GetIpInterfaceEntry` populates `row` for `(luid, family)` before `SetIpInterfaceEntry`.
        unsafe {
            let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            row.Family = family;
            row.InterfaceLuid = luid;
            let st = GetIpInterfaceEntry(&raw mut row);
            if st != 0 {
                return Err(io::Error::from_raw_os_error(st as i32));
            }
            if family == AF_INET {
                row.SitePrefixLength = 0;
            }
            row.NlMtu = mtu;
            let st_set = SetIpInterfaceEntry(&raw mut row);
            if st_set != 0 {
                return Err(io::Error::from_raw_os_error(st_set as i32));
            }
        }
        Ok(())
    }

    fn add_iphlpapi_route(
        luid_val: u64,
        dest: IpAddr,
        prefix_len: u8,
        next_hop: IpAddr,
        metric: u32,
    ) -> io::Result<WindowsRouteRecord> {
        // SAFETY: `InitializeIpForwardEntry` initializes defaults before populating `MIB_IPFORWARD_ROW2`.
        unsafe {
            let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            InitializeIpForwardEntry(&raw mut row);
            row.InterfaceLuid = NET_LUID_LH { Value: luid_val };
            let mut if_idx = 0u32;
            let _ = ConvertInterfaceLuidToIndex(&raw const row.InterfaceLuid, &raw mut if_idx);
            row.InterfaceIndex = if_idx;
            row.DestinationPrefix.Prefix = sockaddr_inet_from_ip(dest);
            row.DestinationPrefix.PrefixLength = prefix_len;
            row.NextHop = sockaddr_inet_from_ip(next_hop);
            row.Metric = metric;
            let status = CreateIpForwardEntry2(&raw const row);
            if status != 0 && status != ERROR_OBJECT_ALREADY_EXISTS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        Ok(WindowsRouteRecord {
            destination_prefix: dest.to_string(),
            prefix_length: prefix_len,
            next_hop: next_hop.to_string(),
            interface_luid: luid_val,
        })
    }

    fn delete_iphlpapi_route(rec: &WindowsRouteRecord) -> io::Result<()> {
        let Ok(dest) = rec.destination_prefix.parse::<IpAddr>() else {
            return Ok(());
        };
        let Ok(nh) = rec.next_hop.parse::<IpAddr>() else {
            return Ok(());
        };
        // SAFETY: Constructing `MIB_IPFORWARD_ROW2` key fields required by `DeleteIpForwardEntry2`.
        unsafe {
            let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            InitializeIpForwardEntry(&raw mut row);
            row.InterfaceLuid = NET_LUID_LH {
                Value: rec.interface_luid,
            };
            let _ = ConvertInterfaceLuidToIndex(
                &raw const row.InterfaceLuid,
                &raw mut row.InterfaceIndex,
            );
            row.DestinationPrefix.Prefix = sockaddr_inet_from_ip(dest);
            row.DestinationPrefix.PrefixLength = rec.prefix_length;
            row.NextHop = sockaddr_inet_from_ip(nh);
            let status = DeleteIpForwardEntry2(&raw const row);
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        Ok(())
    }

    unsafe fn wide_ptr_to_string(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        // SAFETY: `ptr` is a NUL-terminated UTF-16 string returned by `GetInterfaceDnsSettings` (bounded scan).
        unsafe {
            while len < 16_384 && *ptr.add(len) != 0 {
                len += 1;
            }
            if len == 0 {
                return Some(String::new());
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            Some(String::from_utf16_lossy(slice))
        }
    }

    fn guid_from_str(s: &str) -> io::Result<GUID> {
        let (data1, data2, data3, data4) = parse_braced_guid(s)?;
        Ok(GUID {
            data1,
            data2,
            data3,
            data4,
        })
    }

    struct IpHlpApiDnsBackend;

    impl WindowsDnsOps for IpHlpApiDnsBackend {
        fn resolve_luid_guid(&mut self, luid_value: u64) -> io::Result<String> {
            let luid = NET_LUID_LH { Value: luid_value };
            // SAFETY: Zero-initialized `GUID` populated by `ConvertInterfaceLuidToGuid`.
            unsafe {
                let mut guid: GUID = std::mem::zeroed();
                let rc = ConvertInterfaceLuidToGuid(&raw const luid, &raw mut guid);
                if rc != 0 {
                    return Err(io::Error::from_raw_os_error(rc as i32));
                }
                Ok(format_braced_guid(
                    guid.data1, guid.data2, guid.data3, guid.data4,
                ))
            }
        }

        fn get_dns_settings(
            &mut self,
            interface_guid: &str,
            ipv6: bool,
        ) -> io::Result<WindowsDnsFamilySnapshot> {
            let guid = guid_from_str(interface_guid)?;
            // SAFETY: `GetInterfaceDnsSettings` populates `settings` when `Version` and `Flags` are initialized;
            // any allocated `PWSTR` buffers are released via `FreeInterfaceDnsSettings` before returning.
            unsafe {
                let mut settings: DNS_INTERFACE_SETTINGS = std::mem::zeroed();
                settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
                settings.Flags = if ipv6 { u64::from(DNS_SETTING_IPV6) } else { 0 };
                let rc = GetInterfaceDnsSettings(guid, &raw mut settings);
                if rc != 0 {
                    if rc == ERROR_NOT_FOUND || rc == ERROR_FILE_NOT_FOUND {
                        return Ok(WindowsDnsFamilySnapshot::default());
                    }
                    return Err(io::Error::from_raw_os_error(rc as i32));
                }
                let name_server = wide_ptr_to_string(settings.NameServer).unwrap_or_default();
                let domain = wide_ptr_to_string(settings.Domain).filter(|s| !s.is_empty());
                let search_list = wide_ptr_to_string(settings.SearchList).filter(|s| !s.is_empty());
                FreeInterfaceDnsSettings(&raw mut settings);
                Ok(WindowsDnsFamilySnapshot {
                    name_server,
                    domain,
                    search_list,
                })
            }
        }

        fn set_dns_settings(
            &mut self,
            interface_guid: &str,
            ipv6: bool,
            snapshot: &WindowsDnsFamilySnapshot,
        ) -> io::Result<()> {
            let guid = guid_from_str(interface_guid)?;
            let mut flags = u64::from(DNS_SETTING_NAMESERVER);
            if ipv6 {
                flags |= u64::from(DNS_SETTING_IPV6);
            }
            let mut ns_wide = to_wide_nul(&snapshot.name_server);
            let mut domain_wide = snapshot.domain.as_deref().map(to_wide_nul);
            let mut search_wide = snapshot.search_list.as_deref().map(to_wide_nul);
            if domain_wide.is_some() {
                flags |= u64::from(DNS_SETTING_DOMAIN);
            }
            if search_wide.is_some() {
                flags |= u64::from(DNS_SETTING_SEARCHLIST);
            }

            // SAFETY: All `PWSTR` pointers reference stack-alive NUL-terminated UTF-16 `Vec<u16>` buffers
            // for the duration of the synchronous `SetInterfaceDnsSettings` call.
            unsafe {
                let mut raw: DNS_INTERFACE_SETTINGS = std::mem::zeroed();
                raw.Version = DNS_INTERFACE_SETTINGS_VERSION1;
                raw.Flags = flags;
                raw.NameServer = ns_wide.as_mut_ptr();
                raw.Domain = domain_wide
                    .as_mut()
                    .map_or(std::ptr::null_mut(), Vec::as_mut_ptr);
                raw.SearchList = search_wide
                    .as_mut()
                    .map_or(std::ptr::null_mut(), Vec::as_mut_ptr);

                let rc = SetInterfaceDnsSettings(guid, &raw const raw);
                if rc != 0 {
                    return Err(io::Error::from_raw_os_error(rc as i32));
                }
            }
            Ok(())
        }
    }

    pub fn recover_windows_tun_record(rec: &WindowsRecoveryRecord, outcome: &mut RecoveryOutcome) {
        for r in rec.owned_routes.iter().rev() {
            let desc = format!(
                "DeleteIpForwardEntry2 {}/{} -> {}",
                r.destination_prefix, r.prefix_length, r.next_hop
            );
            match delete_iphlpapi_route(r) {
                Ok(()) => outcome.actions_executed.push(desc),
                Err(e) => outcome.warnings.push(format!("{desc}: {e}")),
            }
        }
        let mut dns_backend = IpHlpApiDnsBackend;
        restore_windows_adapter_dns_with_ops(&mut dns_backend, rec, outcome);
    }

    struct NetChangeCallbackCtx {
        adapter_luid: u64,
        protector: Arc<WindowsUnicastIfProtector>,
        egress_state: Arc<Mutex<PhysicalEgressInfo>>,
        transitions: Arc<AtomicU64>,
        dns: Option<Arc<crate::dns::FakeIpDnsEngine>>,
        net_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    unsafe extern "system" fn on_ip_interface_change(
        caller_context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        notification_type: i32,
    ) {
        if caller_context.is_null() {
            return;
        }
        if notification_type != MibParameterNotification
            && notification_type != MibAddInstance
            && notification_type != MibDeleteInstance
        {
            return;
        }
        // SAFETY: `caller_context` points to a heap-pinned `NetChangeCallbackCtx` kept alive until `CancelMibChangeNotify2` returns!
        let ctx = unsafe { &*(caller_context.cast::<NetChangeCallbackCtx>()) };
        let latest = detect_windows_physical_egress(ctx.adapter_luid);
        if latest.v4_if_index == 0 && latest.v6_if_index == 0 {
            return;
        }
        let mut guard = ctx.egress_state.lock();
        if *guard != latest {
            *guard = latest.clone();
            drop(guard);
            ctx.protector
                .update_indices(latest.v4_if_index, latest.v6_if_index);
            ctx.transitions.fetch_add(1, Ordering::Relaxed);
            if let Some(hook) = &ctx.net_hook {
                hook();
            } else if let Some(dns) = &ctx.dns {
                dns.flush_cache();
            }
        }
    }

    #[derive(Clone, Copy)]
    struct RawSendPtr<T>(*mut T);
    impl<T> RawSendPtr<T> {
        fn ptr(self) -> *mut T {
            self.0
        }
    }
    // SAFETY: Used exclusively inside `WindowsWintunSession` with ordered lifecycle teardown.
    unsafe impl<T> Send for RawSendPtr<T> {}
    // SAFETY: Synchronized via `WindowsWintunSession` `&mut self` stop/drop semantics.
    unsafe impl<T> Sync for RawSendPtr<T> {}

    pub struct WindowsWintunSession {
        spec: TunLaunchSpec,
        api: Arc<WintunApi>,
        adapter_name: String,
        adapter: RawSendPtr<c_void>,
        session: RawSendPtr<c_void>,
        stop_event: RawSendPtr<c_void>,
        notify_handle: RawSendPtr<c_void>,
        notify_ctx: Option<Box<NetChangeCallbackCtx>>,
        recovery_record: WindowsRecoveryRecord,
        stop_flag: Arc<AtomicBool>,
        stop_watch_tx: tokio::sync::watch::Sender<bool>,
        stopped: bool,
        driver_version: u32,
        rx_packets: Arc<AtomicU64>,
        tx_packets: Arc<AtomicU64>,
        network_transitions: Arc<AtomicU64>,
        egress_state: Arc<Mutex<PhysicalEgressInfo>>,
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
    }

    impl WindowsWintunSession {
        pub fn start(spec: TunLaunchSpec, handle: VirtualTunHandle) -> io::Result<Self> {
            if !is_windows_process_elevated() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows Wintun requires Administrator privileges (approve UAC elevation or launch rust-clash as Administrator)",
                ));
            }

            let api = WintunApi::load_secure(spec.wintun_dll_path.as_deref())?;
            let adapter_name = if spec.device_name.trim().is_empty() {
                "RustClash".to_string()
            } else {
                spec.device_name.trim().to_string()
            };
            let wide_name = to_wide_nul(&adapter_name);
            let wide_type = to_wide_nul("RustClash");

            // 1. Detect active physical NIC & gateway BEFORE creating/routing Wintun!
            let initial_egress = detect_windows_physical_egress(0);
            let protector = Arc::new(WindowsUnicastIfProtector::new(
                initial_egress.v4_if_index,
                initial_egress.v6_if_index,
            ));
            set_global_socket_protector(Arc::clone(&protector) as _);

            // 2. Reuse existing Wintun adapter if present, otherwise create a new one
            // SAFETY: `wide_name`, `wide_type`, and `RUST_CLASH_WINTUN_GUID` satisfy Wintun C ABI.
            let adapter = unsafe {
                let opened = (api.open_adapter)(wide_name.as_ptr());
                if !opened.is_null() {
                    opened
                } else {
                    (api.create_adapter)(
                        wide_name.as_ptr(),
                        wide_type.as_ptr(),
                        &raw const RUST_CLASH_WINTUN_GUID,
                    )
                }
            };
            if adapter.is_null() {
                let err = io::Error::last_os_error();
                clear_global_socket_protector();
                return Err(io::Error::new(
                    err.kind(),
                    format!("WintunCreateAdapter('{adapter_name}') failed: {err}"),
                ));
            }

            let mut luid = NET_LUID_LH { Value: 0 };
            // SAFETY: `adapter` is non-null.
            let driver_version = unsafe {
                (api.get_adapter_luid)(adapter, &raw mut luid);
                (api.get_running_driver_version)()
            };

            // 3. Start 4 MiB Wintun ring-buffer session
            // SAFETY: `adapter` is valid and `WINTUN_RING_CAPACITY` is 4 MiB.
            let session = unsafe { (api.start_session)(adapter, WINTUN_RING_CAPACITY) };
            if session.is_null() {
                let err = io::Error::last_os_error();
                // SAFETY: Closing `adapter` on session start failure.
                unsafe { (api.close_adapter)(adapter) };
                clear_global_socket_protector();
                return Err(io::Error::new(
                    err.kind(),
                    format!("WintunStartSession failed: {err}"),
                ));
            }

            let mut rec = WindowsRecoveryRecord {
                adapter_name: adapter_name.clone(),
                adapter_luid: unsafe { luid.Value },
                owned_routes: Vec::new(),
                dns_interface_guid: None,
                previous_dns_servers: None,
                dns_backup: None,
            };

            // 4. Configure adapter IPv4, IPv6, MTU, split-tunnel routes, bypass routes, and DNS transactionally
            let setup_res = (|| -> io::Result<()> {
                let gw_v4 = spec.gateway_ipv4();
                set_adapter_unicast_ip(luid, IpAddr::V4(gw_v4), spec.fake_ip_net.prefix_len())?;
                let mtu_u32 = spec.mtu.clamp(1280, 65535) as u32;
                let _ = set_adapter_mtu(luid, AF_INET, mtu_u32);

                if spec.enable_ipv6 {
                    set_adapter_unicast_ip(
                        luid,
                        IpAddr::V6(spec.tun_ipv6_cidr.addr()),
                        spec.tun_ipv6_cidr.prefix_len(),
                    )?;
                    let _ = set_adapter_mtu(luid, AF_INET6, mtu_u32);
                }

                if !spec.auto_route {
                    return Ok(());
                }

                let metric = if spec.strict_route { 1 } else { 5 };
                let luid_val = unsafe { luid.Value };
                let zero_v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

                // Split-tunnel IPv4 (`0.0.0.0/1` + `128.0.0.0/1`) + Fake-IP subnet -> Wintun on-link
                for &(prefix_str, plen) in WINDOWS_SPLIT_IPV4_PREFIXES {
                    let r = add_iphlpapi_route(
                        luid_val,
                        prefix_str.parse().unwrap(),
                        plen,
                        zero_v4,
                        metric,
                    )?;
                    rec.owned_routes.push(r);
                }
                let r_fake = add_iphlpapi_route(
                    luid_val,
                    IpAddr::V4(spec.fake_ip_net.network()),
                    spec.fake_ip_net.prefix_len(),
                    zero_v4,
                    metric,
                )?;
                rec.owned_routes.push(r_fake);

                // Explicit `/32` bypass routes on the physical interface for proxy servers & bootstrap DNS
                if initial_egress.v4_luid != 0
                    && let Some(phys_gw) = initial_egress.v4_gateway
                {
                    for ip in &spec.bypass_ips {
                        if let IpAddr::V4(v4) = ip
                            && !v4.is_loopback()
                            && !spec.fake_ip_net.contains(v4)
                            && let Ok(r_byp) =
                                add_iphlpapi_route(initial_egress.v4_luid, *ip, 32, phys_gw, 1)
                        {
                            rec.owned_routes.push(r_byp);
                        }
                    }
                }

                if spec.enable_ipv6 {
                    let zero_v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
                    for &(prefix6_str, plen6) in WINDOWS_SPLIT_IPV6_PREFIXES {
                        let r6 = add_iphlpapi_route(
                            luid_val,
                            prefix6_str.parse().unwrap(),
                            plen6,
                            zero_v6,
                            metric,
                        )?;
                        rec.owned_routes.push(r6);
                    }
                }

                // Persist owned routes BEFORE mutating DNS so any hard crash mid-DNS-apply recovers routes
                let rec_routes_only = rec.clone();
                update_current_journal(&spec.state_dir, |j| j.windows_tun = Some(rec_routes_only))?;

                let dns_v6 = spec.enable_ipv6.then(|| {
                    Ipv6Addr::from(u128::from(spec.tun_ipv6_cidr.network()).saturating_add(2))
                });
                let mut dns_backend = IpHlpApiDnsBackend;
                let dns_backup = apply_windows_adapter_dns_transactional(
                    &mut dns_backend,
                    luid_val,
                    spec.dns_ipv4(),
                    dns_v6,
                )?;
                rec.dns_interface_guid = Some(dns_backup.interface_guid.clone());
                rec.previous_dns_servers = Some(
                    dns_backup
                        .ipv4
                        .name_server
                        .split([',', ' '])
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                );
                rec.dns_backup = Some(dns_backup);

                let rec_snap = rec.clone();
                update_current_journal(&spec.state_dir, |j| j.windows_tun = Some(rec_snap))?;
                Ok(())
            })();

            if let Err(err) = setup_res {
                let mut dummy = RecoveryOutcome::default();
                recover_windows_tun_record(&rec, &mut dummy);
                // SAFETY: Ending Wintun session and closing adapter on rollback.
                unsafe {
                    (api.end_session)(session);
                    (api.close_adapter)(adapter);
                }
                clear_global_socket_protector();
                let _ = update_current_journal(&spec.state_dir, |j| j.windows_tun = None);
                return Err(err);
            }

            // 5. Create manual-reset `stop_event` and launch Wintun ring-buffer RX / TX threads
            // SAFETY: Creating an unnamed manual-reset Win32 event.
            let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if stop_event.is_null() {
                let err = io::Error::last_os_error();
                let mut dummy = RecoveryOutcome::default();
                recover_windows_tun_record(&rec, &mut dummy);
                unsafe {
                    (api.end_session)(session);
                    (api.close_adapter)(adapter);
                }
                clear_global_socket_protector();
                let _ = update_current_journal(&spec.state_dir, |j| j.windows_tun = None);
                return Err(err);
            }

            let stop_flag = Arc::new(AtomicBool::new(false));
            let (stop_watch_tx, mut stop_watch_rx) = tokio::sync::watch::channel(false);
            let rx_packets = Arc::new(AtomicU64::new(0));
            let tx_packets = Arc::new(AtomicU64::new(0));
            let network_transitions = Arc::new(AtomicU64::new(0));
            let egress_state = Arc::new(Mutex::new(initial_egress));

            // Register `NotifyIpInterfaceChange` for instant Wi-Fi/Ethernet/sleep/wake recovery!
            let mut notify_ctx = Box::new(NetChangeCallbackCtx {
                adapter_luid: unsafe { luid.Value },
                protector: Arc::clone(&protector),
                egress_state: Arc::clone(&egress_state),
                transitions: Arc::clone(&network_transitions),
                dns: spec.dns_engine.clone(),
                net_hook: spec.network_change_hook.clone(),
            });
            let mut notify_handle: HANDLE = std::ptr::null_mut();
            // SAFETY: `notify_ctx` stays heap-pinned until `CancelMibChangeNotify2` completes in `stop()`.
            unsafe {
                let _ = NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(on_ip_interface_change),
                    (&raw mut *notify_ctx).cast::<c_void>(),
                    0,
                    &raw mut notify_handle,
                );
            }

            let VirtualTunHandle {
                ingress_tx,
                mut egress_rx,
            } = handle;

            let api_rx = Arc::clone(&api);
            let sess_rx = RawSendPtr(session);
            let stop_ev_rx = RawSendPtr(stop_event);
            let stop_rx = Arc::clone(&stop_flag);
            let rx_cnt = Arc::clone(&rx_packets);
            let rx_thread = std::thread::Builder::new()
                .name("tun-wintun-rx".into())
                .spawn(move || {
                    let sess_p = sess_rx.ptr();
                    let stop_p = stop_ev_rx.ptr();
                    // SAFETY: `sess_p` and `stop_p` remain valid until `stop()` joins `rx_thread` BEFORE `end_session`.
                    unsafe {
                        let read_event = (api_rx.get_read_wait_event)(sess_p);
                        let handles = [read_event, stop_p];
                        while !stop_rx.load(Ordering::Acquire) {
                            let mut pkt_size: u32 = 0;
                            let pkt_ptr = (api_rx.receive_packet)(sess_p, &raw mut pkt_size);
                            if !pkt_ptr.is_null() {
                                let slice =
                                    std::slice::from_raw_parts(pkt_ptr, pkt_size as usize).to_vec();
                                (api_rx.release_receive_packet)(sess_p, pkt_ptr);
                                rx_cnt.fetch_add(1, Ordering::Relaxed);
                                if ingress_tx.blocking_send(slice).is_err() {
                                    break;
                                }
                            } else {
                                let err = GetLastError();
                                // `ERROR_NO_MORE_ITEMS == 259` means ring buffer is currently empty; wait on kernel event!
                                if err == 259 {
                                    let wait_rc =
                                        WaitForMultipleObjects(2, handles.as_ptr(), 0, 250);
                                    if wait_rc == 1 {
                                        break;
                                    }
                                } else {
                                    std::thread::sleep(Duration::from_millis(5));
                                }
                            }
                        }
                    }
                })?;

            let api_tx = Arc::clone(&api);
            let sess_tx = RawSendPtr(session);
            let tx_cnt = Arc::clone(&tx_packets);
            let tx_thread = std::thread::Builder::new()
                .name("tun-wintun-tx".into())
                .spawn(move || {
                    let sess_p = sess_tx.ptr();
                    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    else {
                        return;
                    };
                    rt.block_on(async move {
                        loop {
                            tokio::select! {
                                biased;
                                _ = stop_watch_rx.wait_for(|&stopped| stopped) => break,
                                maybe_pkt = egress_rx.recv() => {
                                    let Some(pkt) = maybe_pkt else { break };
                                    if pkt.is_empty() || pkt.len() > 65535 {
                                        continue;
                                    }
                                    // SAFETY: `sess_p` remains valid until `stop()` joins `tx_thread` BEFORE `end_session`.
                                    unsafe {
                                        let buf_ptr = (api_tx.allocate_send_packet)(sess_p, pkt.len() as u32);
                                        if !buf_ptr.is_null() {
                                            std::ptr::copy_nonoverlapping(pkt.as_ptr(), buf_ptr, pkt.len());
                                            (api_tx.send_packet)(sess_p, buf_ptr);
                                            tx_cnt.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                    });
                })?;

            Ok(Self {
                spec,
                api,
                adapter_name,
                adapter: RawSendPtr(adapter),
                session: RawSendPtr(session),
                stop_event: RawSendPtr(stop_event),
                notify_handle: RawSendPtr(notify_handle),
                notify_ctx: Some(notify_ctx),
                recovery_record: rec,
                stop_flag,
                stop_watch_tx,
                stopped: false,
                driver_version,
                rx_packets,
                tx_packets,
                network_transitions,
                egress_state,
                rx_thread: Some(rx_thread),
                tx_thread: Some(tx_thread),
            })
        }
    }

    impl SystemTunSession for WindowsWintunSession {
        fn health(&self) -> TunHealthSnapshot {
            let eg = self.egress_state.lock().clone();
            TunHealthSnapshot {
                platform: "windows".to_string(),
                backend: format!(
                    "windows-wintun(v{}.{})",
                    self.driver_version >> 16,
                    self.driver_version & 0xFFFF
                ),
                active: !self.stopped,
                device_name: Some(self.adapter_name.clone()),
                mtu: self.spec.mtu,
                ipv4_cidr: Some(self.spec.ipv4_host_cidr_string()),
                ipv6_cidr: self
                    .spec
                    .enable_ipv6
                    .then(|| self.spec.tun_ipv6_cidr.to_string()),
                auto_route_applied: self.spec.auto_route,
                strict_route_applied: self.spec.auto_route && self.spec.strict_route,
                route_table_id: None,
                default_egress_iface: (eg.v4_if_index != 0)
                    .then(|| format!("ifIndex:{}", eg.v4_if_index)),
                default_egress_gateway: eg.v4_gateway.map(|g| g.to_string()),
                socket_protector: global_socket_protector().description(),
                privilege_ok: true,
                privilege_hint: None,
                driver_loaded: true,
                network_transitions: self.network_transitions.load(Ordering::Relaxed),
                rx_packets: self.rx_packets.load(Ordering::Relaxed),
                tx_packets: self.tx_packets.load(Ordering::Relaxed),
                last_error: None,
            }
        }

        fn stop(&mut self) {
            if self.stopped {
                return;
            }
            self.stopped = true;
            self.stop_flag.store(true, Ordering::Release);
            let _ = self.stop_watch_tx.send(true);

            // 1. Cancel `NotifyIpInterfaceChange` FIRST before dropping `notify_ctx`!
            if !self.notify_handle.0.is_null() {
                // SAFETY: `CancelMibChangeNotify2` blocks until any in-flight callback finishes.
                unsafe {
                    let _ = CancelMibChangeNotify2(self.notify_handle.0);
                }
                self.notify_handle.0 = std::ptr::null_mut();
            }
            let _ = self.notify_ctx.take();

            // 2. Signal `stop_event` and join RX/TX threads BEFORE calling `WintunEndSession`!
            if !self.stop_event.0.is_null() {
                // SAFETY: Signaling our valid Win32 manual-reset event.
                unsafe {
                    let _ = SetEvent(self.stop_event.0);
                }
            }
            if let Some(h) = self.rx_thread.take() {
                let _ = h.join();
            }
            if let Some(h) = self.tx_thread.take() {
                let _ = h.join();
            }

            // 3. Roll back routes & DNS overrides, end Wintun session, close adapter & event, clear journal
            let mut outcome = RecoveryOutcome::default();
            recover_windows_tun_record(&self.recovery_record, &mut outcome);
            for warn_msg in &outcome.warnings {
                tracing::warn!("Windows Wintun teardown recovery warning: {}", warn_msg);
            }

            // SAFETY: Worker threads have joined, so `session`, `adapter`, and `stop_event` have single ownership.
            unsafe {
                if !self.session.0.is_null() {
                    (self.api.end_session)(self.session.0);
                    self.session.0 = std::ptr::null_mut();
                }
                if !self.adapter.0.is_null() {
                    (self.api.close_adapter)(self.adapter.0);
                    self.adapter.0 = std::ptr::null_mut();
                }
                if !self.stop_event.0.is_null() {
                    let _ = CloseHandle(self.stop_event.0);
                    self.stop_event.0 = std::ptr::null_mut();
                }
            }

            clear_global_socket_protector();
            let _ = update_current_journal(&self.spec.state_dir, |j| j.windows_tun = None);
        }
    }

    impl Drop for WindowsWintunSession {
        fn drop(&mut self) {
            self.stop();
        }
    }
}

#[cfg(windows)]
pub use win_impl::{
    PhysicalEgressInfo, WindowsWintunSession, detect_windows_physical_egress,
    is_windows_process_elevated, preflight_windows_tun, recover_windows_tun_record,
};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct FaultInjectingDnsBackend {
        luid_to_guid: HashMap<u64, String>,
        v4_state: HashMap<String, WindowsDnsFamilySnapshot>,
        v6_state: HashMap<String, WindowsDnsFamilySnapshot>,
        fail_resolve_luid: bool,
        fail_get_v4: bool,
        fail_get_v6: bool,
        /// Fail the Nth (1-indexed) `set_dns_settings(ipv6=false)` call (`0` = never fail).
        fail_set_v4_on_call: usize,
        /// Fail the Nth (1-indexed) `set_dns_settings(ipv6=true)` call (`0` = never fail).
        fail_set_v6_on_call: usize,
        set_v4_calls: usize,
        set_v6_calls: usize,
        history: Vec<(String, bool, WindowsDnsFamilySnapshot)>,
    }

    impl FaultInjectingDnsBackend {
        fn with_adapter(
            luid: u64,
            guid: &str,
            initial_v4: WindowsDnsFamilySnapshot,
            initial_v6: WindowsDnsFamilySnapshot,
        ) -> Self {
            let mut b = Self::default();
            b.luid_to_guid.insert(luid, guid.to_string());
            b.v4_state.insert(guid.to_string(), initial_v4);
            b.v6_state.insert(guid.to_string(), initial_v6);
            b
        }
    }

    impl WindowsDnsOps for FaultInjectingDnsBackend {
        fn resolve_luid_guid(&mut self, luid_value: u64) -> io::Result<String> {
            if self.fail_resolve_luid {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "injected ConvertInterfaceLuidToGuid failure (ERROR_FILE_NOT_FOUND)",
                ));
            }
            self.luid_to_guid.get(&luid_value).cloned().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("unknown LUID {luid_value}"),
                )
            })
        }

        fn get_dns_settings(
            &mut self,
            interface_guid: &str,
            ipv6: bool,
        ) -> io::Result<WindowsDnsFamilySnapshot> {
            if !ipv6 && self.fail_get_v4 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected GetInterfaceDnsSettings(IPv4) failure",
                ));
            }
            if ipv6 && self.fail_get_v6 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected GetInterfaceDnsSettings(IPv6) failure",
                ));
            }
            let map = if ipv6 { &self.v6_state } else { &self.v4_state };
            Ok(map.get(interface_guid).cloned().unwrap_or_default())
        }

        fn set_dns_settings(
            &mut self,
            interface_guid: &str,
            ipv6: bool,
            settings: &WindowsDnsFamilySnapshot,
        ) -> io::Result<()> {
            if ipv6 {
                self.set_v6_calls += 1;
                if self.fail_set_v6_on_call != 0 && self.set_v6_calls == self.fail_set_v6_on_call {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "injected SetInterfaceDnsSettings(IPv6) failure (ERROR_ACCESS_DENIED=5)",
                    ));
                }
                self.v6_state
                    .insert(interface_guid.to_string(), settings.clone());
            } else {
                self.set_v4_calls += 1;
                if self.fail_set_v4_on_call != 0 && self.set_v4_calls == self.fail_set_v4_on_call {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "injected SetInterfaceDnsSettings(IPv4) failure (ERROR_ACCESS_DENIED=5)",
                    ));
                }
                self.v4_state
                    .insert(interface_guid.to_string(), settings.clone());
            }
            self.history
                .push((interface_guid.to_string(), ipv6, settings.clone()));
            Ok(())
        }
    }

    #[test]
    fn split_tunnel_prefixes_cover_full_address_space_without_overwriting_zero_prefix() {
        assert_eq!(
            WINDOWS_SPLIT_IPV4_PREFIXES,
            &[("0.0.0.0", 1), ("128.0.0.0", 1)]
        );
        assert_eq!(WINDOWS_SPLIT_IPV6_PREFIXES, &[("::", 1), ("8000::", 1)]);
        assert_eq!(WINTUN_0_14_1_ZIP_SHA256.len(), 64);
    }

    #[test]
    fn guid_format_and_parse_roundtrip_is_lossless() {
        let orig = (
            0xE924_5BC1,
            0xB8C1,
            0x44CA,
            [0xAB, 0x1D, 0xC6, 0xC4, 0xF1, 0x5B, 0x9C, 0x10],
        );
        let formatted = format_braced_guid(orig.0, orig.1, orig.2, orig.3);
        assert_eq!(formatted, "{E9245BC1-B8C1-44CA-AB1D-C6C4F15B9C10}");
        let parsed = parse_braced_guid(&formatted).expect("parse braced GUID");
        assert_eq!(parsed, orig);

        let unbraced = parse_braced_guid("e9245bc1-b8c1-44ca-ab1d-c6c4f15b9c10")
            .expect("parse lowercase unbraced GUID");
        assert_eq!(unbraced, orig);
        assert!(parse_braced_guid("not-a-guid").is_err());
    }

    #[test]
    fn dns_fault_injection_get_settings_failure_aborts_before_mutation() {
        let guid = "{E9245BC1-B8C1-44CA-AB1D-C6C4F15B9C10}";
        let prev_v4 = WindowsDnsFamilySnapshot {
            name_server: "1.1.1.1,8.8.8.8".to_string(),
            domain: Some("corp.internal".to_string()),
            search_list: Some("corp.internal,svc.internal".to_string()),
        };
        let mut backend = FaultInjectingDnsBackend::with_adapter(
            42,
            guid,
            prev_v4.clone(),
            WindowsDnsFamilySnapshot::default(),
        );
        backend.fail_get_v4 = true;

        let err = apply_windows_adapter_dns_transactional(
            &mut backend,
            42,
            Ipv4Addr::new(198, 18, 0, 2),
            Some("fdfe:dcba:9876::2".parse().unwrap()),
        )
        .expect_err("must fail closed when GetInterfaceDnsSettings fails");
        assert!(err.to_string().contains("GetInterfaceDnsSettings(IPv4)"));
        assert_eq!(backend.set_v4_calls, 0);
        assert_eq!(backend.set_v6_calls, 0);
        assert_eq!(backend.v4_state[guid], prev_v4);
    }

    #[test]
    fn dns_fault_injection_ipv4_set_failure_never_reports_success() {
        let guid = "{E9245BC1-B8C1-44CA-AB1D-C6C4F15B9C10}";
        let prev_v4 = WindowsDnsFamilySnapshot {
            name_server: "9.9.9.9".to_string(),
            domain: None,
            search_list: None,
        };
        let mut backend = FaultInjectingDnsBackend::with_adapter(
            77,
            guid,
            prev_v4.clone(),
            WindowsDnsFamilySnapshot::default(),
        );
        backend.fail_set_v4_on_call = 1;

        let err = apply_windows_adapter_dns_transactional(
            &mut backend,
            77,
            Ipv4Addr::new(198, 18, 0, 2),
            Some("fdfe:dcba:9876::2".parse().unwrap()),
        )
        .expect_err("must return error when SetInterfaceDnsSettings(IPv4) fails");
        assert!(
            err.to_string()
                .contains("SetInterfaceDnsSettings(IPv4=198.18.0.2)")
        );
        assert_eq!(backend.set_v4_calls, 1);
        assert_eq!(backend.set_v6_calls, 0);
        assert_eq!(backend.v4_state[guid], prev_v4);
    }

    #[test]
    fn dns_fault_injection_ipv6_set_failure_rolls_back_ipv4_immediately() {
        let guid = "{E9245BC1-B8C1-44CA-AB1D-C6C4F15B9C10}";
        let prev_v4 = WindowsDnsFamilySnapshot {
            name_server: "192.168.1.1,1.1.1.1".to_string(),
            domain: Some("lan.local".to_string()),
            search_list: Some("lan.local".to_string()),
        };
        let prev_v6 = WindowsDnsFamilySnapshot {
            name_server: "2606:4700:4700::1111".to_string(),
            domain: None,
            search_list: None,
        };
        let mut backend =
            FaultInjectingDnsBackend::with_adapter(99, guid, prev_v4.clone(), prev_v6.clone());
        backend.fail_set_v6_on_call = 1;

        let err = apply_windows_adapter_dns_transactional(
            &mut backend,
            99,
            Ipv4Addr::new(198, 18, 0, 2),
            Some("fdfe:dcba:9876::2".parse().unwrap()),
        )
        .expect_err("IPv6 DNS failure must abort and roll back IPv4 DNS");
        let msg = err.to_string();
        assert!(
            msg.contains("SetInterfaceDnsSettings(IPv6=fdfe:dcba:9876::2)"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("IPv4 DNS rolled back cleanly"),
            "unexpected error: {msg}"
        );
        // Call 1 applied 198.18.0.2; Call 2 rolled back to prev_v4!
        assert_eq!(backend.set_v4_calls, 2);
        assert_eq!(backend.set_v6_calls, 1);
        assert_eq!(backend.v4_state[guid], prev_v4);
        assert_eq!(backend.v6_state[guid], prev_v6);
    }

    #[test]
    fn dns_backup_apply_and_restore_roundtrips_custom_v4_v6_and_dhcp() {
        let guid = "{E9245BC1-B8C1-44CA-AB1D-C6C4F15B9C10}";
        // Case A: Custom static DNS + domain + search list on IPv4, DHCP (empty string) on IPv6
        let orig_v4 = WindowsDnsFamilySnapshot {
            name_server: "8.8.8.8,8.8.4.4".to_string(),
            domain: Some("hq.example.com".to_string()),
            search_list: Some("hq.example.com,eng.example.com".to_string()),
        };
        let orig_v6 = WindowsDnsFamilySnapshot {
            name_server: String::new(), // DHCPv6 / RA automatic DNS
            domain: None,
            search_list: None,
        };
        let mut backend =
            FaultInjectingDnsBackend::with_adapter(101, guid, orig_v4.clone(), orig_v6.clone());

        let backup = apply_windows_adapter_dns_transactional(
            &mut backend,
            101,
            Ipv4Addr::new(198, 18, 0, 2),
            Some("fdfe:dcba:9876::2".parse().unwrap()),
        )
        .expect("transactional DNS apply must succeed");

        assert_eq!(backup.interface_guid, guid);
        assert_eq!(backup.ipv4, orig_v4);
        assert_eq!(backup.ipv6.as_ref(), Some(&orig_v6));
        assert_eq!(backend.v4_state[guid].name_server, "198.18.0.2");
        assert_eq!(
            backend.v4_state[guid].domain.as_deref(),
            Some("hq.example.com")
        );
        assert_eq!(backend.v6_state[guid].name_server, "fdfe:dcba:9876::2");

        // Now restore from WindowsRecoveryRecord (covers normal teardown AND crash-recovery journal!)
        let rec = WindowsRecoveryRecord {
            adapter_name: "RustClash".to_string(),
            adapter_luid: 101,
            owned_routes: Vec::new(),
            dns_interface_guid: Some(guid.to_string()),
            previous_dns_servers: None,
            dns_backup: Some(backup),
        };
        let mut outcome = RecoveryOutcome::default();
        restore_windows_adapter_dns_with_ops(&mut backend, &rec, &mut outcome);
        assert!(
            outcome.warnings.is_empty(),
            "warnings: {:?}",
            outcome.warnings
        );
        assert_eq!(outcome.actions_executed.len(), 2);
        assert_eq!(backend.v4_state[guid], orig_v4);
        assert_eq!(backend.v6_state[guid], orig_v6);
    }

    #[test]
    fn dns_restore_failure_records_warning_never_false_success() {
        let guid = "{E9245BC1-B8C1-44CA-AB1D-C6C4F15B9C10}";
        let orig_v4 = WindowsDnsFamilySnapshot {
            name_server: "1.1.1.1".to_string(),
            domain: None,
            search_list: None,
        };
        let mut backend = FaultInjectingDnsBackend::with_adapter(
            202,
            guid,
            WindowsDnsFamilySnapshot {
                name_server: "198.18.0.2".to_string(),
                domain: None,
                search_list: None,
            },
            WindowsDnsFamilySnapshot::default(),
        );
        backend.fail_set_v4_on_call = 1;

        let rec = WindowsRecoveryRecord {
            adapter_name: "RustClash".to_string(),
            adapter_luid: 202,
            owned_routes: Vec::new(),
            dns_interface_guid: Some(guid.to_string()),
            previous_dns_servers: None,
            dns_backup: Some(WindowsDnsInterfaceBackup {
                interface_guid: guid.to_string(),
                ipv4: orig_v4,
                ipv6: None,
            }),
        };
        let mut outcome = RecoveryOutcome::default();
        restore_windows_adapter_dns_with_ops(&mut backend, &rec, &mut outcome);
        assert!(
            outcome.actions_executed.is_empty(),
            "must NOT claim action succeeded when SetInterfaceDnsSettings failed"
        );
        assert_eq!(outcome.warnings.len(), 1);
        assert!(outcome.warnings[0].contains("RestoreInterfaceDnsSettings(IPv4='1.1.1.1')"));
    }
}
