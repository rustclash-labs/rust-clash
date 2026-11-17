use std::{io, net::IpAddr};

/// Darwin `utun` 4-byte protocol family header constants (`<sys/socket.h>` on macOS/iOS).
pub const DARWIN_AF_INET: u32 = 2;
pub const DARWIN_AF_INET6: u32 = 30;

/// Prepend the 4-byte big-endian Darwin `utun` address-family header (`AF_INET=2` or `AF_INET6=30`)
/// to a raw L3 IPv4/IPv6 packet before writing to a macOS `PF_SYSTEM` `utun` socket.
pub fn encode_darwin_utun_packet(l3_packet: &[u8]) -> io::Result<Vec<u8>> {
    let Some(&first) = l3_packet.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty L3 packet cannot be framed for Darwin utun",
        ));
    };
    let af = match first >> 4 {
        4 => DARWIN_AF_INET,
        6 => DARWIN_AF_INET6,
        ver => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported IP version {ver} for Darwin utun framing"),
            ));
        }
    };
    let mut out = Vec::with_capacity(4 + l3_packet.len());
    out.extend_from_slice(&af.to_be_bytes());
    out.extend_from_slice(l3_packet);
    Ok(out)
}

/// Strip and validate the 4-byte big-endian Darwin `utun` header from a raw `utun` socket frame,
/// returning the inner L3 IPv4/IPv6 packet slice.
pub fn decode_darwin_utun_packet(utun_frame: &[u8]) -> io::Result<&[u8]> {
    if utun_frame.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Darwin utun frame shorter than 4-byte AF header + IP version byte",
        ));
    }
    let af = u32::from_be_bytes([utun_frame[0], utun_frame[1], utun_frame[2], utun_frame[3]]);
    let payload = &utun_frame[4..];
    let ip_ver = payload[0] >> 4;
    match (af, ip_ver) {
        (DARWIN_AF_INET, 4) | (DARWIN_AF_INET6, 6) => Ok(payload),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Darwin utun AF header ({af}) mismatches inner IPv{ip_ver} packet"),
        )),
    }
}

/// Parse `route -n get default` (or `route -n get -inet6 default`) output on macOS to extract `(interface, gateway)`.
pub fn parse_macos_route_get_default(output: &str) -> (Option<String>, Option<String>) {
    let mut iface = None;
    let mut gw = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            let v = rest.trim();
            if !v.is_empty() {
                iface = Some(v.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("gateway:") {
            let v = rest.trim();
            if !v.is_empty() {
                gw = Some(v.to_string());
            }
        }
    }
    (iface, gw)
}

/// Ensure link-local IPv6 gateways (`fe80:...`) include a BSD interface scope zone (`%en0`)
/// so `/sbin/route -n add -inet6 -host <dst> <gw>` succeeds on Darwin.
pub fn normalize_macos_ipv6_gateway(gw: &str, iface: Option<&str>) -> String {
    let trimmed = gw.trim();
    if trimmed.len() >= 5
        && trimmed[..5].eq_ignore_ascii_case("fe80:")
        && !trimmed.contains('%')
        && let Some(if_name) = iface.map(str::trim).filter(|s| !s.is_empty())
    {
        return format!("{trimmed}%{if_name}");
    }
    trimmed.to_string()
}

/// Resolve primary `(interface, gateway)` from macOS IPv4 `route -n get default` output,
/// falling back to `route -n get -inet6 default` on IPv6-only / NAT64 networks and ignoring `utun*`.
pub fn resolve_macos_default_egress_outputs(
    v4_route_out: Option<&str>,
    v6_route_out: Option<&str>,
) -> (Option<String>, Option<String>) {
    if let Some(out4) = v4_route_out {
        let (if4, gw4) = parse_macos_route_get_default(out4);
        if let Some(iface) = if4.filter(|s| !s.starts_with("utun")) {
            return (Some(iface), gw4);
        }
    }
    if let Some(out6) = v6_route_out {
        let (if6, gw6) = parse_macos_route_get_default(out6);
        if let Some(iface) = if6.filter(|s| !s.starts_with("utun")) {
            let norm_gw = gw6.map(|g| normalize_macos_ipv6_gateway(&g, Some(&iface)));
            return (Some(iface), norm_gw);
        }
    }
    (None, None)
}

/// Build `(add_args, delete_args)` pairs for `/sbin/route` covering both IPv4 `/32` (`-host`)
/// and IPv6 `/128` (`-inet6 -host`) physical bypass routes.
pub fn build_macos_bypass_route_commands(
    bypass_ips: &[IpAddr],
    fake_ip_net: ipnet::Ipv4Net,
    tun_ipv6_cidr: ipnet::Ipv6Net,
    v4_gw: Option<&str>,
    v6_gw: Option<&str>,
) -> Vec<(Vec<String>, Vec<String>)> {
    let mut cmds = Vec::new();
    for ip in bypass_ips {
        match ip {
            IpAddr::V4(v4)
                if !v4.is_loopback() && !v4.is_unspecified() && !fake_ip_net.contains(v4) =>
            {
                if let Some(gw) = v4_gw.filter(|s| !s.is_empty()) {
                    let host_s = v4.to_string();
                    let add_args = vec![
                        "-n".to_string(),
                        "add".to_string(),
                        "-host".to_string(),
                        host_s.clone(),
                        gw.to_string(),
                    ];
                    let del_args = vec![
                        "-n".to_string(),
                        "delete".to_string(),
                        "-host".to_string(),
                        host_s,
                        gw.to_string(),
                    ];
                    cmds.push((add_args, del_args));
                }
            }
            IpAddr::V6(v6)
                if !v6.is_loopback() && !v6.is_unspecified() && !tun_ipv6_cidr.contains(v6) =>
            {
                if let Some(gw6) = v6_gw.filter(|s| !s.is_empty()) {
                    let host_s = v6.to_string();
                    let add_args = vec![
                        "-n".to_string(),
                        "add".to_string(),
                        "-inet6".to_string(),
                        "-host".to_string(),
                        host_s.clone(),
                        gw6.to_string(),
                    ];
                    let del_args = vec![
                        "-n".to_string(),
                        "delete".to_string(),
                        "-inet6".to_string(),
                        "-host".to_string(),
                        host_s,
                        gw6.to_string(),
                    ];
                    cmds.push((add_args, del_args));
                }
            }
            _ => {}
        }
    }
    cmds
}

/// Parse `networksetup -listnetworkserviceorder` output to map BSD device `en0` -> macOS Service `"Wi-Fi"`.
pub fn map_bsd_device_to_network_service(output: &str, bsd_device: &str) -> Option<String> {
    let mut last_service: Option<String> = None;
    let needle = format!("Device: {bsd_device}");
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('(')
            && let Some((num_part, svc_part)) = rest.split_once(')')
            && !num_part.is_empty()
            && num_part.chars().all(|c| c.is_ascii_digit() || c == '*')
        {
            let svc = svc_part.trim();
            if !svc.is_empty() {
                last_service = Some(svc.to_string());
            }
        }
        if trimmed.contains(&needle) {
            return last_service;
        }
    }
    None
}

pub fn is_utun_split_route_del_arg(args: &[String], utun_name: &str) -> bool {
    !utun_name.is_empty()
        && args
            .windows(2)
            .any(|w| w[0] == "-interface" && w[1] == utun_name)
}

pub fn is_macos_benign_route_delete_error(msg: &str) -> bool {
    let low = msg.to_ascii_lowercase();
    low.contains("not in table")
        || low.contains("no such process")
        || low.contains("can't locate")
        || low.contains("network is unreachable")
}

pub fn is_macos_benign_dns_restore_error(msg: &str) -> bool {
    let low = msg.to_ascii_lowercase();
    low.contains("not a recognized network service")
}

/// Restore backed-up macOS `networksetup -setdnsservers` entries, returning ONLY entries whose
/// restoration genuinely failed (ignoring services that were unplugged/removed from the OS).
pub fn restore_macos_dns_backups_with_runner<F>(
    dns_backups: &[crate::platform::recovery::MacOsDnsBackup],
    outcome: &mut crate::platform::recovery::RecoveryOutcome,
    run_cmd: &mut F,
) -> Vec<crate::platform::recovery::MacOsDnsBackup>
where
    F: FnMut(&str, &[String]) -> io::Result<()>,
{
    let mut unrecovered = Vec::new();
    for dns in dns_backups {
        let mut args = vec!["-setdnsservers".to_string(), dns.service_name.clone()];
        if dns.previous_servers.is_empty() {
            args.push("Empty".to_string());
        } else {
            args.extend(dns.previous_servers.iter().cloned());
        }
        let desc = format!("networksetup {}", args.join(" "));
        match run_cmd("networksetup", &args) {
            Ok(()) => outcome.actions_executed.push(desc),
            Err(e) => {
                let msg = e.to_string();
                if !is_macos_benign_dns_restore_error(&msg) {
                    outcome.warnings.push(format!("{desc}: {e}"));
                    unrecovered.push(dns.clone());
                }
            }
        }
    }
    unrecovered
}

/// Roll back routes and DNS backups from a `MacOsRecoveryRecord`, returning `Some(remaining)`
/// containing ONLY physical routes / DNS backups whose rollback genuinely failed so they stay in
/// `network_recovery.json` for subsequent recovery instead of leaving broken host DNS behind.
pub fn rollback_macos_record_with_runner<F>(
    rec: &crate::platform::recovery::MacOsRecoveryRecord,
    outcome: &mut crate::platform::recovery::RecoveryOutcome,
    run_cmd: &mut F,
) -> Option<crate::platform::recovery::MacOsRecoveryRecord>
where
    F: FnMut(&str, &[String]) -> io::Result<()>,
{
    let mut failed_routes_rev = Vec::new();
    for args in rec.owned_route_del_args.iter().rev() {
        let desc = format!("route {}", args.join(" "));
        match run_cmd("route", args) {
            Ok(()) => outcome.actions_executed.push(desc),
            Err(e) => {
                let msg = e.to_string();
                let is_utun_route = is_utun_split_route_del_arg(args, &rec.utun_name);
                if is_utun_route {
                    // Darwin XNU destroys `utunN` and all `-interface utunN` routes automatically
                    // when the `utun` fd closes; never retain dynamic `utunN` route deletions across restarts.
                    let low = msg.to_ascii_lowercase();
                    if !is_macos_benign_route_delete_error(&msg)
                        && !low.contains("bad address")
                        && !low.contains("does not exist")
                    {
                        outcome.warnings.push(format!("{desc}: {e}"));
                    }
                } else if !is_macos_benign_route_delete_error(&msg) {
                    outcome.warnings.push(format!("{desc}: {e}"));
                    failed_routes_rev.push(args.clone());
                }
            }
        }
    }
    failed_routes_rev.reverse();
    let unrecovered_dns = restore_macos_dns_backups_with_runner(&rec.dns_backups, outcome, run_cmd);

    let remaining = crate::platform::recovery::MacOsRecoveryRecord {
        utun_name: rec.utun_name.clone(),
        owned_route_del_args: failed_routes_rev,
        dns_backups: unrecovered_dns,
    };
    (!remaining.is_empty()).then_some(remaining)
}

#[cfg(target_os = "macos")]
mod darwin_impl {
    use std::{
        ffi::CString,
        io,
        net::Ipv4Addr,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        path::Path,
        process::Command,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread::JoinHandle,
        time::Duration,
    };

    use parking_lot::Mutex;

    use super::{
        build_macos_bypass_route_commands, decode_darwin_utun_packet, encode_darwin_utun_packet,
        is_utun_split_route_del_arg, map_bsd_device_to_network_service,
        normalize_macos_ipv6_gateway, parse_macos_route_get_default,
        resolve_macos_default_egress_outputs, restore_macos_dns_backups_with_runner,
        rollback_macos_record_with_runner,
    };
    use crate::{
        inbound::tun::VirtualTunHandle,
        platform::{
            recovery::{
                MacOsDnsBackup, MacOsRecoveryRecord, RecoveryOutcome,
                finalize_macos_tun_teardown_journal, update_current_journal,
            },
            socket_protect::{
                MacOsBoundIfProtector, clear_global_socket_protector, global_socket_protector,
                set_global_socket_protector,
            },
            tun::{SystemTunSession, TunHealthSnapshot, TunLaunchSpec},
        },
    };

    const AF_SYSTEM: libc::c_int = 32;
    const PF_SYSTEM: libc::c_int = AF_SYSTEM;
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const AF_SYS_CONTROL: libc::c_ushort = 2;
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
    // `_IOWR('N', 3, struct ctl_info)` on 64-bit Darwin (`sizeof(ctl_info) == 100` -> `0xc064_4e03`).
    const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    #[repr(C)]
    struct SockAddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct MacOsDualStackEgress {
        primary_if: Option<String>,
        primary_gw: Option<String>,
        primary_idx: u32,
        v4_gw: Option<String>,
        v6_gw: Option<String>,
    }

    fn run_cmd(program: &str, args: &[&str]) -> io::Result<String> {
        let out = Command::new(program).args(args).output()?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            let se = String::from_utf8_lossy(&out.stderr);
            let so = String::from_utf8_lossy(&out.stdout);
            let detail = match (se.trim().is_empty(), so.trim().is_empty()) {
                (false, false) => format!("{}; {}", se.trim(), so.trim()),
                (false, true) => se.trim().to_string(),
                (true, false) => so.trim().to_string(),
                (true, true) => String::new(),
            };
            Err(io::Error::other(format!(
                "`{program} {}` failed ({}): {detail}",
                args.join(" "),
                out.status,
            )))
        }
    }

    fn lookup_if_index(if_name: &str) -> u32 {
        let Ok(cstr) = CString::new(if_name) else {
            return 0;
        };
        // SAFETY: `cstr` is a valid NUL-terminated C string.
        unsafe { libc::if_nametoindex(cstr.as_ptr()) }
    }

    fn detect_macos_dual_stack_egress() -> MacOsDualStackEgress {
        let out4 = run_cmd("/sbin/route", &["-n", "get", "default"]).ok();
        let out6 = run_cmd("/sbin/route", &["-n", "get", "-inet6", "default"]).ok();

        let (v4_if_raw, v4_gw_raw) = out4
            .as_deref()
            .map(parse_macos_route_get_default)
            .unwrap_or((None, None));
        let v4_gw = if v4_if_raw.as_deref().is_some_and(|s| !s.starts_with("utun")) {
            v4_gw_raw
        } else {
            None
        };

        let (v6_if_raw, v6_gw_raw) = out6
            .as_deref()
            .map(parse_macos_route_get_default)
            .unwrap_or((None, None));
        let v6_gw = if let Some(ref if6) = v6_if_raw
            && !if6.starts_with("utun")
        {
            v6_gw_raw.map(|g| normalize_macos_ipv6_gateway(&g, Some(if6)))
        } else {
            None
        };

        let (primary_if, primary_gw) =
            resolve_macos_default_egress_outputs(out4.as_deref(), out6.as_deref());
        let primary_idx = primary_if.as_deref().map(lookup_if_index).unwrap_or(0);

        MacOsDualStackEgress {
            primary_if,
            primary_gw,
            primary_idx,
            v4_gw,
            v6_gw,
        }
    }

    pub fn detect_macos_default_egress() -> (Option<String>, Option<String>, u32) {
        let out4 = run_cmd("/sbin/route", &["-n", "get", "default"]).ok();
        if let Some(ref s4) = out4 {
            let (iface, gw) = parse_macos_route_get_default(s4);
            if let Some(if_name) = iface.filter(|s| !s.starts_with("utun")) {
                let idx = lookup_if_index(&if_name);
                return (Some(if_name), gw, idx);
            }
        }
        // Fallback for IPv6-only / NAT64 networks where `route -n get default` has no interface!
        let out6 = run_cmd("/sbin/route", &["-n", "get", "-inet6", "default"]).ok();
        let (iface, gw) = resolve_macos_default_egress_outputs(None, out6.as_deref());
        let idx = iface.as_deref().map(lookup_if_index).unwrap_or(0);
        (iface, gw, idx)
    }

    pub fn preflight_macos_tun() -> TunHealthSnapshot {
        // SAFETY: `geteuid` has no preconditions.
        let is_root = unsafe { libc::geteuid() } == 0;
        let (egress_if, egress_gw, _) = detect_macos_default_egress();
        let hint = if !is_root {
            Some(
                "macOS utun system routing requires root privileges (`sudo ./rust-clash`) or signed NEPacketTunnelProvider System Extension"
                    .to_string(),
            )
        } else {
            None
        };

        TunHealthSnapshot {
            platform: "macos".to_string(),
            backend: "macos-utun".to_string(),
            active: false,
            device_name: None,
            mtu: 1500,
            ipv4_cidr: None,
            ipv6_cidr: None,
            auto_route_applied: false,
            strict_route_applied: false,
            route_table_id: None,
            default_egress_iface: egress_if,
            default_egress_gateway: egress_gw,
            socket_protector: global_socket_protector().description(),
            privilege_ok: is_root,
            privilege_hint: hint,
            driver_loaded: true,
            network_transitions: 0,
            rx_packets: 0,
            tx_packets: 0,
            last_error: None,
        }
    }

    fn parse_requested_utun_unit(device_name: &str) -> u32 {
        if let Some(num_str) = device_name.trim().strip_prefix("utun")
            && let Ok(n) = num_str.parse::<u32>()
        {
            return n.saturating_add(1);
        }
        0 // Kernel dynamically assigns next available `utunN`
    }

    fn open_darwin_utun_socket(device_name: &str) -> io::Result<(OwnedFd, String)> {
        // SAFETY: Creating a kernel `PF_SYSTEM` control socket uses documented Darwin XNU constants.
        let raw_fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw_fd` was just returned by `socket()` and is uniquely owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);

        // SAFETY: `fd` is valid and `info` has exact `ctl_info` layout expected by `CTLIOCGINFO`.
        if unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &raw mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let requested_unit = parse_requested_utun_unit(device_name);
        let units_to_try: &[u32] = if requested_unit > 0 {
            &[requested_unit, 0]
        } else {
            &[0]
        };

        let mut last_err = io::Error::other("utun connect failed");
        let mut connected = false;
        for &unit in units_to_try {
            let addr = SockAddrCtl {
                sc_len: std::mem::size_of::<SockAddrCtl>() as u8,
                sc_family: AF_SYSTEM as u8,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_id: info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };
            // SAFETY: `addr` matches Darwin `sockaddr_ctl` and `sc_len` equals `sizeof(SockAddrCtl)`.
            let rc = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    (&raw const addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<SockAddrCtl>() as libc::socklen_t,
                )
            };
            if rc == 0 {
                connected = true;
                break;
            }
            last_err = io::Error::last_os_error();
        }
        if !connected {
            return Err(last_err);
        }

        let mut ifname_buf = [0u8; 64];
        let mut ifname_len = ifname_buf.len() as libc::socklen_t;
        // SAFETY: `getsockopt` writes at most `ifname_len` bytes into `ifname_buf`.
        let grc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname_buf.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut ifname_len,
            )
        };
        if grc < 0 {
            return Err(io::Error::last_os_error());
        }
        let nul_pos = ifname_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ifname_len as usize);
        let assigned = String::from_utf8_lossy(&ifname_buf[..nul_pos]).into_owned();
        Ok((fd, assigned))
    }

    fn darwin_cmd_runner(program: &str, args: &[String]) -> io::Result<()> {
        let resolved = match program {
            "route" => "/sbin/route",
            "networksetup" => "/usr/sbin/networksetup",
            other => other,
        };
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_cmd(resolved, &refs).map(|_| ())
    }

    fn bind_macos_service_dns_for_iface(
        bsd_if: Option<&str>,
        dns_str: &str,
        rec: &mut MacOsRecoveryRecord,
        state_dir: &Path,
    ) {
        if let Some(if_name) = bsd_if
            && let Ok(order_out) = run_cmd("/usr/sbin/networksetup", &["-listnetworkserviceorder"])
            && let Some(svc) = map_bsd_device_to_network_service(&order_out, if_name)
        {
            // Never overwrite an earlier unrestored original DNS backup for the same service
            // (which would capture our own `198.18.0.2` TUN DNS instead of the user's true servers).
            if !rec.dns_backups.iter().any(|b| b.service_name == svc) {
                if let Ok(prev_dns_out) =
                    run_cmd("/usr/sbin/networksetup", &["-getdnsservers", &svc])
                {
                    let prev_servers: Vec<String> = prev_dns_out
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.contains("There aren't any DNS Servers"))
                        .map(ToOwned::to_owned)
                        .collect();
                    rec.dns_backups.push(MacOsDnsBackup {
                        service_name: svc.clone(),
                        previous_servers: prev_servers,
                    });
                } else {
                    let rec_snap = rec.clone();
                    let _ = update_current_journal(state_dir, |j| j.macos_tun = Some(rec_snap));
                    return;
                }
            }
            let rec_snap = rec.clone();
            let _ = update_current_journal(state_dir, |j| j.macos_tun = Some(rec_snap));
            let _ = run_cmd("/usr/sbin/networksetup", &["-setdnsservers", &svc, dns_str]);
        } else {
            let rec_snap = rec.clone();
            let _ = update_current_journal(state_dir, |j| j.macos_tun = Some(rec_snap));
        }
    }

    fn install_macos_bypass_routes(
        spec: &TunLaunchSpec,
        egress: &MacOsDualStackEgress,
        rec: &mut MacOsRecoveryRecord,
    ) {
        let cmds = build_macos_bypass_route_commands(
            &spec.bypass_ips,
            spec.fake_ip_net,
            spec.tun_ipv6_cidr,
            egress.v4_gw.as_deref(),
            egress.v6_gw.as_deref(),
        );
        for (add_args, del_args) in cmds {
            let add_refs: Vec<&str> = add_args.iter().map(String::as_str).collect();
            if run_cmd("/sbin/route", &add_refs).is_ok() {
                rec.owned_route_del_args.push(del_args);
            }
        }
    }

    fn rollback_macos_record_and_finalize(
        rec: &MacOsRecoveryRecord,
        state_dir: &Path,
    ) -> RecoveryOutcome {
        let mut outcome = RecoveryOutcome::default();
        let remaining =
            rollback_macos_record_with_runner(rec, &mut outcome, &mut darwin_cmd_runner);
        for warn_msg in &outcome.warnings {
            tracing::warn!("macOS utun teardown recovery warning: {}", warn_msg);
        }
        if let Err(e) = finalize_macos_tun_teardown_journal(state_dir, remaining) {
            let msg = format!("failed updating macOS recovery journal: {e}");
            tracing::warn!("{}", msg);
            outcome.warnings.push(msg);
        }
        outcome
    }

    pub struct MacOsUtunSession {
        spec: TunLaunchSpec,
        utun_name: String,
        recovery_record: Arc<Mutex<MacOsRecoveryRecord>>,
        stop_flag: Arc<AtomicBool>,
        stop_watch_tx: tokio::sync::watch::Sender<bool>,
        stopped: bool,
        rx_packets: Arc<AtomicU64>,
        tx_packets: Arc<AtomicU64>,
        network_transitions: Arc<AtomicU64>,
        egress_snapshot: Arc<Mutex<MacOsDualStackEgress>>,
        last_error: Arc<Mutex<Option<String>>>,
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
        watch_thread: Option<JoinHandle<()>>,
    }

    impl MacOsUtunSession {
        pub fn start(spec: TunLaunchSpec, handle: VirtualTunHandle) -> io::Result<Self> {
            let initial_egress = detect_macos_dual_stack_egress();
            let (utun_fd, utun_name) = open_darwin_utun_socket(&spec.device_name)?;

            let protector = Arc::new(MacOsBoundIfProtector::new(initial_egress.primary_idx));
            set_global_socket_protector(Arc::clone(&protector) as _);

            let mut rec = MacOsRecoveryRecord {
                utun_name: utun_name.clone(),
                owned_route_del_args: Vec::new(),
                dns_backups: Vec::new(),
            };

            let dns_str_for_watch = spec.dns_ipv4().to_string();

            let setup_res = (|| -> io::Result<()> {
                let gw_v4: Ipv4Addr = spec.gateway_ipv4();
                let dns_v4: Ipv4Addr = spec.dns_ipv4();
                let gw_str = gw_v4.to_string();
                let dns_str = dns_v4.to_string();
                let mask_str = spec.fake_ip_net.netmask().to_string();
                let mtu_str = spec.mtu.clamp(1280, 65535).to_string();

                run_cmd(
                    "/sbin/ifconfig",
                    &[
                        &utun_name, "inet", &gw_str, &dns_str, "netmask", &mask_str, "mtu",
                        &mtu_str, "up",
                    ],
                )?;

                if spec.enable_ipv6 {
                    let v6_addr = spec.tun_ipv6_cidr.addr().to_string();
                    let v6_plen = spec.tun_ipv6_cidr.prefix_len().to_string();
                    let _ = run_cmd(
                        "/sbin/ifconfig",
                        &[&utun_name, "inet6", &v6_addr, "prefixlen", &v6_plen],
                    );
                }

                if !spec.auto_route {
                    return Ok(());
                }

                // Split-tunnel routes (`0.0.0.0/1` + `128.0.0.0/1`) capture all traffic without
                // overwriting macOS's primary `default` route!
                let fake_cidr = spec.fake_ip_net.trunc().to_string();
                for net in ["0.0.0.0/1", "128.0.0.0/1", fake_cidr.as_str()] {
                    run_cmd(
                        "/sbin/route",
                        &["-n", "add", "-net", net, "-interface", &utun_name],
                    )?;
                    rec.owned_route_del_args.push(vec![
                        "-n".into(),
                        "delete".into(),
                        "-net".into(),
                        net.into(),
                        "-interface".into(),
                        utun_name.clone(),
                    ]);
                }

                // Install both IPv4 `/32` (`-host`) and IPv6 `/128` (`-inet6 -host`) physical bypass routes!
                install_macos_bypass_routes(&spec, &initial_egress, &mut rec);

                if spec.enable_ipv6 {
                    for net6 in ["::/1", "8000::/1"] {
                        if run_cmd(
                            "/sbin/route",
                            &["-n", "add", "-inet6", net6, "-interface", &utun_name],
                        )
                        .is_ok()
                        {
                            rec.owned_route_del_args.push(vec![
                                "-n".into(),
                                "delete".into(),
                                "-inet6".into(),
                                net6.into(),
                                "-interface".into(),
                                utun_name.clone(),
                            ]);
                        }
                    }
                }

                // Snapshot & point primary macOS network service DNS at `198.18.0.2` (hijacked in-band by `smoltcp`!)
                bind_macos_service_dns_for_iface(
                    initial_egress.primary_if.as_deref(),
                    &dns_str,
                    &mut rec,
                    &spec.state_dir,
                );

                Ok(())
            })();

            if let Err(err) = setup_res {
                clear_global_socket_protector();
                let _ = rollback_macos_record_and_finalize(&rec, &spec.state_dir);
                return Err(err);
            }

            // Duplicate fd for TX and put RX into `O_NONBLOCK`
            // SAFETY: `dup` on a valid `OwnedFd` returns a new independent descriptor or -1.
            let tx_raw = unsafe { libc::dup(utun_fd.as_raw_fd()) };
            if tx_raw < 0 {
                let err = io::Error::last_os_error();
                clear_global_socket_protector();
                let _ = rollback_macos_record_and_finalize(&rec, &spec.state_dir);
                return Err(err);
            }
            // SAFETY: `tx_raw >= 0` is newly duplicated and uniquely owned by `tx_fd`.
            let tx_fd = unsafe { OwnedFd::from_raw_fd(tx_raw) };
            // SAFETY: Setting `O_NONBLOCK` on `utun_fd` is standard POSIX `fcntl`.
            unsafe {
                let flags = libc::fcntl(utun_fd.as_raw_fd(), libc::F_GETFL);
                if flags >= 0 {
                    let _ =
                        libc::fcntl(utun_fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }

            let recovery_record = Arc::new(Mutex::new(rec));
            let stop_flag = Arc::new(AtomicBool::new(false));
            let (stop_watch_tx, mut stop_watch_rx) = tokio::sync::watch::channel(false);
            let rx_packets = Arc::new(AtomicU64::new(0));
            let tx_packets = Arc::new(AtomicU64::new(0));
            let network_transitions = Arc::new(AtomicU64::new(0));
            let egress_snapshot = Arc::new(Mutex::new(initial_egress));
            let last_error = Arc::new(Mutex::new(None));

            let VirtualTunHandle {
                ingress_tx,
                mut egress_rx,
            } = handle;

            let stop_rx = Arc::clone(&stop_flag);
            let rx_cnt = Arc::clone(&rx_packets);
            let rx_thread = match std::thread::Builder::new()
                .name("tun-macos-rx".into())
                .spawn(move || {
                    let mut buf = vec![0u8; 65539];
                    while !stop_rx.load(Ordering::Acquire) {
                        let mut pfd = libc::pollfd {
                            fd: utun_fd.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        // SAFETY: `pfd` references `utun_fd` which lives for the entire thread.
                        if unsafe { libc::poll(&raw mut pfd, 1, 50) } <= 0 {
                            continue;
                        }
                        loop {
                            if stop_rx.load(Ordering::Acquire) {
                                return;
                            }
                            // SAFETY: `read` into `buf` bounded by `buf.len()`.
                            let n = unsafe {
                                libc::read(
                                    utun_fd.as_raw_fd(),
                                    buf.as_mut_ptr().cast::<libc::c_void>(),
                                    buf.len(),
                                )
                            };
                            if n < 0 {
                                let err = io::Error::last_os_error();
                                if err.kind() == io::ErrorKind::WouldBlock {
                                    break;
                                }
                                return;
                            }
                            if n == 0 {
                                return;
                            }
                            if let Ok(l3) = decode_darwin_utun_packet(&buf[..n as usize]) {
                                rx_cnt.fetch_add(1, Ordering::Relaxed);
                                let mut pkt = l3.to_vec();
                                loop {
                                    if stop_rx.load(Ordering::Acquire) {
                                        return;
                                    }
                                    match ingress_tx.try_send(pkt) {
                                        Ok(()) => break,
                                        Err(tokio::sync::mpsc::error::TrySendError::Full(
                                            returned,
                                        )) => {
                                            pkt = returned;
                                            std::thread::sleep(Duration::from_millis(2));
                                        }
                                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }) {
                Ok(h) => h,
                Err(err) => {
                    stop_flag.store(true, Ordering::Release);
                    let _ = stop_watch_tx.send(true);
                    clear_global_socket_protector();
                    let _ = rollback_macos_record_and_finalize(
                        &recovery_record.lock(),
                        &spec.state_dir,
                    );
                    return Err(err);
                }
            };

            let stop_tx = Arc::clone(&stop_flag);
            let tx_cnt = Arc::clone(&tx_packets);
            let tx_thread = match std::thread::Builder::new()
                .name("tun-macos-tx".into())
                .spawn(move || {
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
                                    if let Ok(framed) = encode_darwin_utun_packet(&pkt) {
                                        if write_utun_packet_pollout_safe(tx_fd.as_raw_fd(), &framed, &stop_tx) {
                                            tx_cnt.fetch_add(1, Ordering::Relaxed);
                                        } else if stop_tx.load(Ordering::Acquire) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }) {
                Ok(h) => h,
                Err(err) => {
                    stop_flag.store(true, Ordering::Release);
                    let _ = stop_watch_tx.send(true);
                    let _ = rx_thread.join();
                    clear_global_socket_protector();
                    let _ =
                        rollback_macos_record_and_finalize(&recovery_record.lock(), &spec.state_dir);
                    return Err(err);
                }
            };

            let stop_watch = Arc::clone(&stop_flag);
            let egress_watch = Arc::clone(&egress_snapshot);
            let transitions_watch = Arc::clone(&network_transitions);
            let rec_watch = Arc::clone(&recovery_record);
            let last_err_watch = Arc::clone(&last_error);
            let spec_watch = spec.clone();
            let utun_name_watch = utun_name.clone();
            let dns_watch = spec.dns_engine.clone();
            let net_hook_watch = spec.network_change_hook.clone();
            let watch_thread = match std::thread::Builder::new()
                .name("tun-macos-netwatch".into())
                .spawn(move || {
                    while !stop_watch.load(Ordering::Acquire) {
                        for _ in 0..60 {
                            if stop_watch.load(Ordering::Acquire) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        if stop_watch.load(Ordering::Acquire) {
                            return;
                        }
                        let latest = detect_macos_dual_stack_egress();
                        if latest
                            .primary_if
                            .as_deref()
                            .is_some_and(|s| s.starts_with("utun"))
                            || latest.primary_idx == 0
                        {
                            continue;
                        }

                        let (if_changed, gw_changed) = {
                            let mut guard = egress_watch.lock();
                            if *guard == latest {
                                continue;
                            }
                            let if_chg = guard.primary_if != latest.primary_if;
                            let gw_chg =
                                (guard.v4_gw != latest.v4_gw) || (guard.v6_gw != latest.v6_gw);
                            *guard = latest.clone();
                            (if_chg, gw_chg)
                        };

                        protector.set_if_index(latest.primary_idx);

                        if spec_watch.auto_route && (if_changed || gw_changed) {
                            let mut rec_guard = rec_watch.lock();
                            if gw_changed && !spec_watch.bypass_ips.is_empty() {
                                let mut split_routes =
                                    Vec::with_capacity(rec_guard.owned_route_del_args.len());
                                let mut old_bypass = Vec::new();
                                for args in rec_guard.owned_route_del_args.drain(..) {
                                    if is_utun_split_route_del_arg(&args, &utun_name_watch) {
                                        split_routes.push(args);
                                    } else {
                                        old_bypass.push(args);
                                    }
                                }
                                for args in old_bypass.iter().rev() {
                                    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                                    let _ = run_cmd("/sbin/route", &refs);
                                }
                                rec_guard.owned_route_del_args = split_routes;
                                install_macos_bypass_routes(&spec_watch, &latest, &mut rec_guard);
                            }

                            if if_changed {
                                let prev_dns = std::mem::take(&mut rec_guard.dns_backups);
                                let mut handoff_outcome = RecoveryOutcome::default();
                                rec_guard.dns_backups = restore_macos_dns_backups_with_runner(
                                    &prev_dns,
                                    &mut handoff_outcome,
                                    &mut darwin_cmd_runner,
                                );
                                if !handoff_outcome.warnings.is_empty() {
                                    let joined = handoff_outcome.warnings.join("; ");
                                    tracing::warn!(
                                        "macOS DNS restore warning during interface switch: {}",
                                        joined
                                    );
                                    *last_err_watch.lock() = Some(joined);
                                }
                                bind_macos_service_dns_for_iface(
                                    latest.primary_if.as_deref(),
                                    &dns_str_for_watch,
                                    &mut rec_guard,
                                    &spec_watch.state_dir,
                                );
                            } else {
                                let rec_snap = rec_guard.clone();
                                let _ = update_current_journal(&spec_watch.state_dir, |j| {
                                    j.macos_tun = Some(rec_snap)
                                });
                            }
                        }

                        transitions_watch.fetch_add(1, Ordering::Relaxed);
                        if let Some(hook) = &net_hook_watch {
                            hook();
                        } else if let Some(dns) = &dns_watch {
                            dns.flush_cache();
                        }
                    }
                }) {
                Ok(h) => h,
                Err(err) => {
                    stop_flag.store(true, Ordering::Release);
                    let _ = stop_watch_tx.send(true);
                    let _ = rx_thread.join();
                    let _ = tx_thread.join();
                    clear_global_socket_protector();
                    let _ = rollback_macos_record_and_finalize(
                        &recovery_record.lock(),
                        &spec.state_dir,
                    );
                    return Err(err);
                }
            };

            Ok(Self {
                spec,
                utun_name,
                recovery_record,
                stop_flag,
                stop_watch_tx,
                stopped: false,
                rx_packets,
                tx_packets,
                network_transitions,
                egress_snapshot,
                last_error,
                rx_thread: Some(rx_thread),
                tx_thread: Some(tx_thread),
                watch_thread: Some(watch_thread),
            })
        }
    }

    impl SystemTunSession for MacOsUtunSession {
        fn health(&self) -> TunHealthSnapshot {
            let eg = self.egress_snapshot.lock().clone();
            TunHealthSnapshot {
                platform: "macos".to_string(),
                backend: "macos-utun".to_string(),
                active: !self.stopped,
                device_name: Some(self.utun_name.clone()),
                mtu: self.spec.mtu,
                ipv4_cidr: Some(self.spec.ipv4_host_cidr_string()),
                ipv6_cidr: self
                    .spec
                    .enable_ipv6
                    .then(|| self.spec.tun_ipv6_cidr.to_string()),
                auto_route_applied: self.spec.auto_route,
                strict_route_applied: self.spec.auto_route && self.spec.strict_route,
                route_table_id: None,
                default_egress_iface: eg.primary_if,
                default_egress_gateway: eg.primary_gw,
                socket_protector: global_socket_protector().description(),
                privilege_ok: true,
                privilege_hint: None,
                driver_loaded: true,
                network_transitions: self.network_transitions.load(Ordering::Relaxed),
                rx_packets: self.rx_packets.load(Ordering::Relaxed),
                tx_packets: self.tx_packets.load(Ordering::Relaxed),
                last_error: self.last_error.lock().clone(),
            }
        }

        fn stop(&mut self) {
            if self.stopped {
                return;
            }
            self.stopped = true;
            self.stop_flag.store(true, Ordering::Release);
            let _ = self.stop_watch_tx.send(true);

            if let Some(h) = self.watch_thread.take() {
                let _ = h.join();
            }
            if let Some(h) = self.rx_thread.take() {
                let _ = h.join();
            }
            if let Some(h) = self.tx_thread.take() {
                let _ = h.join();
            }

            let rec_final = self.recovery_record.lock().clone();
            clear_global_socket_protector();
            let outcome = rollback_macos_record_and_finalize(&rec_final, &self.spec.state_dir);
            if !outcome.warnings.is_empty() {
                *self.last_error.lock() = Some(outcome.warnings.join("; "));
            }
        }
    }

    impl Drop for MacOsUtunSession {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn write_utun_packet_pollout_safe(
        fd: std::os::fd::RawFd,
        pkt: &[u8],
        stop_flag: &AtomicBool,
    ) -> bool {
        let mut enobufs_retries: u32 = 0;
        loop {
            if stop_flag.load(Ordering::Acquire) {
                return false;
            }
            // SAFETY: `write` reads at most `pkt.len()` bytes from `pkt` on valid `fd`.
            let written =
                unsafe { libc::write(fd, pkt.as_ptr().cast::<libc::c_void>(), pkt.len()) };
            if written > 0 {
                return true;
            }
            if written == 0 {
                return false;
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: `pfd` borrows valid `fd` for the duration of `poll`.
                let prc = unsafe { libc::poll(&raw mut pfd, 1, 50) };
                if prc < 0 {
                    let perr = io::Error::last_os_error();
                    if perr.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return false;
                }
                if (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                    return false;
                }
                continue;
            }
            if err.raw_os_error() == Some(libc::ENOBUFS) && enobufs_retries < 4_000 {
                enobufs_retries += 1;
                std::thread::sleep(std::time::Duration::from_micros(250));
                continue;
            }
            return false;
        }
    }
}

#[cfg(target_os = "macos")]
pub use darwin_impl::{MacOsUtunSession, detect_macos_default_egress, preflight_macos_tun};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn darwin_utun_4byte_af_framing_roundtrips_ipv4_and_ipv6_and_rejects_mismatch() {
        let mut fake_v4 = vec![0u8; 20];
        fake_v4[0] = 0x45; // IPv4 IHL=5
        let framed_v4 = encode_darwin_utun_packet(&fake_v4).unwrap();
        assert_eq!(&framed_v4[..4], &[0, 0, 0, 2]);
        assert_eq!(decode_darwin_utun_packet(&framed_v4).unwrap(), &fake_v4[..]);

        let mut fake_v6 = vec![0u8; 40];
        fake_v6[0] = 0x60; // IPv6
        let framed_v6 = encode_darwin_utun_packet(&fake_v6).unwrap();
        assert_eq!(&framed_v6[..4], &[0, 0, 0, 30]);
        assert_eq!(decode_darwin_utun_packet(&framed_v6).unwrap(), &fake_v6[..]);

        // Mismatched AF_INET6 header with IPv4 payload must fail
        let mut bad = framed_v4;
        bad[3] = 30;
        assert!(decode_darwin_utun_packet(&bad).is_err());
    }

    #[test]
    fn parses_macos_route_and_networksetup_service_mapping() {
        let route_out = "   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        let (iface, gw) = parse_macos_route_get_default(route_out);
        assert_eq!(iface.as_deref(), Some("en0"));
        assert_eq!(gw.as_deref(), Some("192.168.1.1"));

        let ns_out = "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(2) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n";
        assert_eq!(
            map_bsd_device_to_network_service(ns_out, "en0").as_deref(),
            Some("Wi-Fi")
        );
    }

    #[test]
    fn ipv6_only_macos_default_egress_fallback_and_bypass_route_commands() {
        // IPv4 default missing -> falls back to `-inet6 default` and scopes link-local `fe80::` gateway
        let v6_out = "   route to: ::\ndestination: ::\n    gateway: fe80::1\n  interface: en0\n";
        let (iface, gw) = resolve_macos_default_egress_outputs(None, Some(v6_out));
        assert_eq!(iface.as_deref(), Some("en0"));
        assert_eq!(gw.as_deref(), Some("fe80::1%en0"));

        // Already-scoped `fe80::1%en0` is preserved verbatim
        assert_eq!(
            normalize_macos_ipv6_gateway("fe80::1%en0", Some("en0")),
            "fe80::1%en0"
        );

        let bypass_ips: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
            "198.18.0.2".parse().unwrap(), // inside fake_ip_net -> skipped
            "::1".parse().unwrap(),        // loopback -> skipped
        ];
        let fake_v4: ipnet::Ipv4Net = "198.18.0.0/15".parse().unwrap();
        let tun_v6: ipnet::Ipv6Net = "fdfe:dcba:9876::1/126".parse().unwrap();
        let cmds = build_macos_bypass_route_commands(
            &bypass_ips,
            fake_v4,
            tun_v6,
            Some("192.168.1.1"),
            Some("fe80::1%en0"),
        );
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            cmds[0].0,
            vec!["-n", "add", "-host", "1.1.1.1", "192.168.1.1"]
        );
        assert_eq!(
            cmds[0].1,
            vec!["-n", "delete", "-host", "1.1.1.1", "192.168.1.1"]
        );
        assert_eq!(
            cmds[1].0,
            vec![
                "-n",
                "add",
                "-inet6",
                "-host",
                "2606:4700:4700::1111",
                "fe80::1%en0"
            ]
        );
        assert_eq!(
            cmds[1].1,
            vec![
                "-n",
                "delete",
                "-inet6",
                "-host",
                "2606:4700:4700::1111",
                "fe80::1%en0"
            ]
        );
    }

    #[test]
    fn macos_rollback_retains_only_failed_dns_and_physical_routes_while_dropping_utun_and_unplugged_services()
     {
        use crate::platform::recovery::{MacOsDnsBackup, MacOsRecoveryRecord, RecoveryOutcome};

        let rec = MacOsRecoveryRecord {
            utun_name: "utun7".into(),
            owned_route_del_args: vec![
                // Dynamic `-interface utun7` split route already gone when utun7 fd closed -> benign!
                vec![
                    "-n".into(),
                    "delete".into(),
                    "-net".into(),
                    "0.0.0.0/1".into(),
                    "-interface".into(),
                    "utun7".into(),
                ],
                // Physical gateway bypass route that genuinely failed -> MUST be retained!
                vec![
                    "-n".into(),
                    "delete".into(),
                    "-host".into(),
                    "1.1.1.1".into(),
                    "192.168.1.1".into(),
                ],
                // Physical gateway bypass route that succeeded -> pruned!
                vec![
                    "-n".into(),
                    "delete".into(),
                    "-host".into(),
                    "8.8.8.8".into(),
                    "192.168.1.1".into(),
                ],
            ],
            dns_backups: vec![
                MacOsDnsBackup {
                    service_name: "USB 10/100/1000 LAN".into(),
                    previous_servers: vec!["Empty".into()],
                },
                MacOsDnsBackup {
                    service_name: "Thunderbolt Ethernet".into(),
                    previous_servers: vec!["9.9.9.9".into()],
                },
                MacOsDnsBackup {
                    service_name: "Wi-Fi".into(),
                    previous_servers: vec!["192.168.1.1".into()],
                },
            ],
        };

        let mut outcome = RecoveryOutcome::default();
        let remaining = rollback_macos_record_with_runner(&rec, &mut outcome, &mut |prog, args| {
            match prog {
                "route" => {
                    if args.iter().any(|a| a == "utun7") {
                        Err(io::Error::other("route: bad address: utun7"))
                    } else if args.iter().any(|a| a == "1.1.1.1") {
                        Err(io::Error::other("route: writing to routing socket: EPERM"))
                    } else {
                        Ok(())
                    }
                }
                "networksetup" => {
                    if args.iter().any(|a| a == "USB 10/100/1000 LAN") {
                        // macOS networksetup prints this to stdout on exit code 4 when an adapter was unplugged
                        Err(io::Error::other(
                            "USB 10/100/1000 LAN is not a recognized network service.\n** Error: The parameters were not valid.",
                        ))
                    } else if args.iter().any(|a| a == "Wi-Fi") {
                        Err(io::Error::other(
                            "** Error: Unable to commit changes to network database.",
                        ))
                    } else {
                        Ok(())
                    }
                }
                other => panic!("unexpected command {other}"),
            }
        });

        let rem = remaining.expect("failed Wi-Fi DNS and 1.1.1.1 route must be retained");
        assert_eq!(rem.dns_backups.len(), 1);
        assert_eq!(rem.dns_backups[0].service_name, "Wi-Fi");
        assert_eq!(rem.owned_route_del_args.len(), 1);
        assert_eq!(
            rem.owned_route_del_args[0],
            vec!["-n", "delete", "-host", "1.1.1.1", "192.168.1.1"]
        );
        assert_eq!(
            outcome.warnings.len(),
            2,
            "only real failures (Wi-Fi DNS + 1.1.1.1 route) should produce warnings: {:?}",
            outcome.warnings
        );
    }
}
