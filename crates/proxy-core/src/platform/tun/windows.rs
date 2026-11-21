use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use crate::platform::recovery::{
    RecoveryOutcome, WindowsDnsFamilySnapshot, WindowsDnsInterfaceBackup, WindowsRecoveryRecord,
    WindowsRouteRecord,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PhysicalEgressInfo {
    pub v4_if_index: u32,
    pub v4_luid: u64,
    pub v4_gateway: Option<IpAddr>,
    pub v6_if_index: u32,
    pub v6_luid: u64,
    pub v6_gateway: Option<IpAddr>,
}

/// Normalized snapshot of a `MIB_IPFORWARD_ROW2` + `MIB_IF_ROW2` + `MIB_IPINTERFACE_ROW` entry
/// used to select the active physical IPv4 and IPv6 default egress without trusting `/32` bypass routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardRouteCandidate {
    pub is_ipv6: bool,
    pub prefix_length: u8,
    pub loopback: bool,
    pub if_index: u32,
    pub luid: u64,
    pub oper_up: bool,
    pub ip_connected: bool,
    pub route_metric: u32,
    pub interface_metric: u32,
    pub next_hop: Option<IpAddr>,
}

/// Select the lowest-metric `IfOperStatusUp` physical `/0` default route separately for IPv4 and IPv6,
/// ignoring `/32` / `/128` static bypass routes, `/1` Wintun split routes, loopback, and `excluded_tun_luid`.
pub fn select_physical_default_egress(
    candidates: &[ForwardRouteCandidate],
    excluded_tun_luid: u64,
) -> PhysicalEgressInfo {
    let pick_pass = |require_ip_connected: bool| {
        let mut info = PhysicalEgressInfo::default();
        let mut best_v4_metric: Option<u32> = None;
        let mut best_v6_metric: Option<u32> = None;

        for c in candidates {
            if c.prefix_length != 0
                || c.loopback
                || c.if_index <= 1
                || c.luid == 0
                || c.luid == excluded_tun_luid
                || !c.oper_up
                || (require_ip_connected && !c.ip_connected)
            {
                continue;
            }
            let effective_metric = c.route_metric.saturating_add(c.interface_metric);
            if c.is_ipv6 {
                if best_v6_metric.is_none_or(|m| effective_metric < m) {
                    best_v6_metric = Some(effective_metric);
                    info.v6_if_index = c.if_index;
                    info.v6_luid = c.luid;
                    info.v6_gateway = c.next_hop;
                }
            } else if best_v4_metric.is_none_or(|m| effective_metric < m) {
                best_v4_metric = Some(effective_metric);
                info.v4_if_index = c.if_index;
                info.v4_luid = c.luid;
                info.v4_gateway = c.next_hop;
            }
        }
        info
    };

    let mut info = pick_pass(true);
    if info.v4_if_index == 0 || info.v6_if_index == 0 {
        let fallback = pick_pass(false);
        if info.v4_if_index == 0 {
            info.v4_if_index = fallback.v4_if_index;
            info.v4_luid = fallback.v4_luid;
            info.v4_gateway = fallback.v4_gateway;
        }
        if info.v6_if_index == 0 {
            info.v6_if_index = fallback.v6_if_index;
            info.v6_luid = fallback.v6_luid;
            info.v6_gateway = fallback.v6_gateway;
        }
    }
    info
}

/// Merge updated physical interface indices for `WindowsUnicastIfProtector`, never overwriting a
/// previously valid non-zero index with `0` (which would turn `IPV6_UNICAST_IF` / `IP_UNICAST_IF`
/// into a no-op and loop outbound sockets into Wintun).
pub fn merge_non_zero_protector_indices(
    prev_v4: u32,
    prev_v6: u32,
    latest_v4: u32,
    latest_v6: u32,
) -> (u32, u32) {
    let next_v4 = if latest_v4 != 0 { latest_v4 } else { prev_v4 };
    let next_v6 = if latest_v6 != 0 { latest_v6 } else { prev_v6 };
    (next_v4, next_v6)
}

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

/// Lowest valid manual Windows `MIB_IPINTERFACE_ROW.Metric` (`0` is reserved for automatic metric).
/// Setting Wintun to `UseAutomaticMetric = 0, Metric = 1` keeps Wintun strictly lower than physical
/// Ethernet/Wi-Fi adapters (typically `5..35`), so Windows `Dnscache` & SMHNR prefer Wintun DNS.
pub const WINTUN_LOWEST_INTERFACE_METRIC: u32 = 1;

/// Compute `(interface_metric, split_route_metric)` for Wintun's IPv4/IPv6 interface and
/// `0.0.0.0/1` + `128.0.0.0/1` / `198.18.0.0/15` split routes so total route metric (`1` or `2`)
/// stays strictly below physical default routes.
pub fn compute_wintun_route_metrics(strict_route: bool) -> (u32, u32) {
    let route_metric = if strict_route { 0 } else { 1 };
    (WINTUN_LOWEST_INTERFACE_METRIC, route_metric)
}

/// Select the IP addresses that should receive global `/32` / `/128` bypass routes on the physical
/// Windows NIC.
///
/// Proxy server literal IPs are always included as belt-and-suspenders protection. Upstream/public
/// DNS server IPs (`1.1.1.1`, `8.8.8.8`, `223.5.5.5`, `119.29.29.29`, etc.) are **omitted** for any
/// address family where `WindowsUnicastIfProtector` (`IP_UNICAST_IF` / `IPV6_UNICAST_IF`) is active
/// and `dns_hijack` is enabled—otherwise global `/32` routes allow *other* Windows processes to
/// escape Wintun's `any:53` Fake-IP DNS hijack!
pub fn select_windows_physical_bypass_ips(
    proxy_bypass_ips: &[IpAddr],
    dns_bypass_ips: &[IpAddr],
    dns_hijack: bool,
    has_v4_unicast_protector: bool,
    has_v6_unicast_protector: bool,
) -> Vec<IpAddr> {
    let mut out = Vec::with_capacity(proxy_bypass_ips.len() + dns_bypass_ips.len());
    for &ip in proxy_bypass_ips {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    for &ip in dns_bypass_ips {
        let protected_by_unicast_if = match ip {
            IpAddr::V4(_) => has_v4_unicast_protector,
            IpAddr::V6(_) => has_v6_unicast_protector,
        };
        if dns_hijack && protected_by_unicast_if {
            continue;
        }
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// Metric used for `tun.route-exclude-address` bypass routes on the physical Windows NIC.
/// Set above Windows's default on-link metric (`256`) so any pre-existing direct on-link subnet
/// route of identical prefix length keeps precedence (preserving direct LAN ARP), while still
/// strictly beating Wintun's `/1` split-tunnel routes via longest-prefix match.
pub const WINDOWS_EXCLUDE_ROUTE_METRIC: u32 = 300;

/// Planned static route for installation on Windows via `CreateIpForwardEntry2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedWindowsRoute {
    pub interface_luid: u64,
    pub dest: IpAddr,
    pub prefix_len: u8,
    pub next_hop: IpAddr,
    pub metric: u32,
}

/// Plan `/32` (IPv4) and `/128` (IPv6) bypass routes on the active physical Windows NIC.
pub fn plan_windows_physical_bypass_routes(
    egress: &PhysicalEgressInfo,
    bypass_ips: &[IpAddr],
    fake_ip_net: ipnet::Ipv4Net,
    tun_ipv6_cidr: ipnet::Ipv6Net,
) -> Vec<PlannedWindowsRoute> {
    let mut routes = Vec::new();
    for &ip in bypass_ips {
        match ip {
            IpAddr::V4(v4)
                if !v4.is_loopback()
                    && !v4.is_unspecified()
                    && !fake_ip_net.contains(&v4)
                    && egress.v4_luid != 0 =>
            {
                let nh = egress
                    .v4_gateway
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let candidate = PlannedWindowsRoute {
                    interface_luid: egress.v4_luid,
                    dest: ip,
                    prefix_len: 32,
                    next_hop: nh,
                    metric: 1,
                };
                if !routes.contains(&candidate) {
                    routes.push(candidate);
                }
            }
            IpAddr::V6(v6)
                if !v6.is_loopback()
                    && !v6.is_unspecified()
                    && !tun_ipv6_cidr.contains(&v6)
                    && egress.v6_luid != 0 =>
            {
                let nh6 = egress
                    .v6_gateway
                    .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
                let candidate = PlannedWindowsRoute {
                    interface_luid: egress.v6_luid,
                    dest: ip,
                    prefix_len: 128,
                    next_hop: nh6,
                    metric: 1,
                };
                if !routes.contains(&candidate) {
                    routes.push(candidate);
                }
            }
            _ => {}
        }
    }
    routes
}

/// Plan more-specific physical NIC static bypass routes for `tun.route-exclude-address` CIDRs.
///
/// Automatically skips prefixes with length `<= 1` (which cannot beat Wintun `/1` split routes),
/// IPv4 CIDRs overlapping `fake_ip_net`, and IPv6 CIDRs at least as specific as `tun_ipv6_cidr`
/// that overlap it (preserving broad ULA excludes such as `fc00::/7`, since Wintun's `/126` stays
/// more specific).
pub fn plan_windows_physical_exclude_routes(
    egress: &PhysicalEgressInfo,
    exclude_cidrs: &[ipnet::IpNet],
    fake_ip_net: ipnet::Ipv4Net,
    tun_ipv6_cidr: ipnet::Ipv6Net,
    enable_ipv6: bool,
) -> Vec<PlannedWindowsRoute> {
    let mut routes = Vec::new();
    for &cidr in exclude_cidrs {
        match cidr {
            ipnet::IpNet::V4(v4net) => {
                let net = v4net.trunc();
                if net.prefix_len() <= 1
                    || crate::config::ipv4_nets_overlap(net, fake_ip_net)
                    || egress.v4_luid == 0
                {
                    continue;
                }
                let nh = egress
                    .v4_gateway
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let candidate = PlannedWindowsRoute {
                    interface_luid: egress.v4_luid,
                    dest: IpAddr::V4(net.network()),
                    prefix_len: net.prefix_len(),
                    next_hop: nh,
                    metric: WINDOWS_EXCLUDE_ROUTE_METRIC,
                };
                if !routes.iter().any(|r: &PlannedWindowsRoute| {
                    r.interface_luid == candidate.interface_luid
                        && r.dest == candidate.dest
                        && r.prefix_len == candidate.prefix_len
                        && r.next_hop == candidate.next_hop
                }) {
                    routes.push(candidate);
                }
            }
            ipnet::IpNet::V6(v6net) => {
                if !enable_ipv6 {
                    continue;
                }
                let net = v6net.trunc();
                if net.prefix_len() <= 1
                    || (net.prefix_len() >= tun_ipv6_cidr.prefix_len()
                        && crate::config::ipv6_nets_overlap(net, tun_ipv6_cidr))
                    || egress.v6_luid == 0
                {
                    continue;
                }
                let nh6 = egress
                    .v6_gateway
                    .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
                let candidate = PlannedWindowsRoute {
                    interface_luid: egress.v6_luid,
                    dest: IpAddr::V6(net.network()),
                    prefix_len: net.prefix_len(),
                    next_hop: nh6,
                    metric: WINDOWS_EXCLUDE_ROUTE_METRIC,
                };
                if !routes.iter().any(|r: &PlannedWindowsRoute| {
                    r.interface_luid == candidate.interface_luid
                        && r.dest == candidate.dest
                        && r.prefix_len == candidate.prefix_len
                        && r.next_hop == candidate.next_hop
                }) {
                    routes.push(candidate);
                }
            }
        }
    }
    routes
}

/// Install both `/32`/`/128` physical bypass routes and `route-exclude-address` CIDR routes via `add_route`,
/// deduplicating identical `(interface_luid, dest, prefix_len, next_hop)` entries.
pub fn install_windows_physical_routes_with_ops<F>(
    egress: &PhysicalEgressInfo,
    bypass_ips: &[IpAddr],
    exclude_cidrs: &[ipnet::IpNet],
    fake_ip_net: ipnet::Ipv4Net,
    tun_ipv6_cidr: ipnet::Ipv6Net,
    enable_ipv6: bool,
    mut add_route: F,
) -> Vec<WindowsRouteRecord>
where
    F: FnMut(u64, IpAddr, u8, IpAddr, u32) -> io::Result<WindowsRouteRecord>,
{
    let mut planned =
        plan_windows_physical_bypass_routes(egress, bypass_ips, fake_ip_net, tun_ipv6_cidr);
    for ex in plan_windows_physical_exclude_routes(
        egress,
        exclude_cidrs,
        fake_ip_net,
        tun_ipv6_cidr,
        enable_ipv6,
    ) {
        if !planned.iter().any(|r| {
            r.interface_luid == ex.interface_luid
                && r.dest == ex.dest
                && r.prefix_len == ex.prefix_len
                && r.next_hop == ex.next_hop
        }) {
            planned.push(ex);
        }
    }

    let mut installed = Vec::with_capacity(planned.len());
    for route in planned {
        if let Ok(rec) = add_route(
            route.interface_luid,
            route.dest,
            route.prefix_len,
            route.next_hop,
            route.metric,
        ) {
            installed.push(rec);
        }
    }
    installed
}

/// Reconcile owned physical bypass + `route-exclude-address` routes on a Windows network handoff
/// (`NotifyIpInterfaceChange`): preserves Wintun split/fake-ip routes on `adapter_luid`, deletes
/// all prior physical NIC routes, and installs fresh physical routes on `effective_egress`.
#[allow(clippy::too_many_arguments)]
pub fn reconcile_windows_handoff_routes_with_ops<D, A>(
    rec: &mut WindowsRecoveryRecord,
    adapter_luid: u64,
    effective_egress: &PhysicalEgressInfo,
    effective_bypass_ips: &[IpAddr],
    exclude_cidrs: &[ipnet::IpNet],
    fake_ip_net: ipnet::Ipv4Net,
    tun_ipv6_cidr: ipnet::Ipv6Net,
    enable_ipv6: bool,
    mut delete_route: D,
    add_route: A,
) where
    D: FnMut(&WindowsRouteRecord) -> io::Result<()>,
    A: FnMut(u64, IpAddr, u8, IpAddr, u32) -> io::Result<WindowsRouteRecord>,
{
    let mut kept_wintun_routes = Vec::with_capacity(rec.owned_routes.len());
    for r in rec.owned_routes.drain(..) {
        if r.interface_luid == adapter_luid {
            kept_wintun_routes.push(r);
        } else {
            let _ = delete_route(&r);
        }
    }
    let new_physical = install_windows_physical_routes_with_ops(
        effective_egress,
        effective_bypass_ips,
        exclude_cidrs,
        fake_ip_net,
        tun_ipv6_cidr,
        enable_ipv6,
        add_route,
    );
    kept_wintun_routes.extend(new_physical);
    rec.owned_routes = kept_wintun_routes;
}

/// Parse Windows DNS server list strings (`NameServer` / `DhcpNameServer` / `GetInterfaceDnsSettings`),
/// which may be comma-, semicolon-, whitespace-, or NUL-delimited, stripping any IPv6 `%zone` suffix.
pub fn parse_windows_dns_server_list(raw: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for token in raw.split([',', ';', ' ', '\t', '\r', '\n', '\0']) {
        let clean = token.trim().split('%').next().unwrap_or("").trim();
        if clean.is_empty() {
            continue;
        }
        if let Ok(ip) = clean.parse::<IpAddr>()
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
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
        restore_ipv4: true,
    })
}

/// Returns `true` when a Windows route/DNS rollback error indicates the target route or network
/// adapter has already vanished (`ERROR_FILE_NOT_FOUND=2`, `ERROR_NOT_FOUND=1168`, `ERROR_OBJECT_NOT_FOUND=5010`).
pub fn is_windows_benign_absent_error(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::NotFound {
        return true;
    }
    if matches!(err.raw_os_error(), Some(2 | 1168 | 5010)) {
        return true;
    }
    let low = err.to_string().to_ascii_lowercase();
    low.contains("element not found")
        || low.contains("object not found")
        || low.contains("not found")
}

/// Restore backed-up Windows IPv4 and IPv6 DNS settings, returning a pruned `WindowsRecoveryRecord`
/// (without routes) if any family genuinely failed so it stays in `network_recovery.json` for retry.
pub fn restore_windows_adapter_dns_pruning_with_ops<B: WindowsDnsOps>(
    backend: &mut B,
    rec: &WindowsRecoveryRecord,
    outcome: &mut RecoveryOutcome,
) -> Option<WindowsRecoveryRecord> {
    if let Some(backup) = &rec.dns_backup {
        let mut v4_still_pending = backup.restore_ipv4;
        if backup.restore_ipv4 {
            let desc_v4 = format!(
                "RestoreInterfaceDnsSettings(IPv4='{}') on {}",
                backup.ipv4.name_server, backup.interface_guid
            );
            match backend.set_dns_settings(&backup.interface_guid, false, &backup.ipv4) {
                Ok(()) => {
                    outcome.actions_executed.push(desc_v4);
                    v4_still_pending = false;
                }
                Err(e) if is_windows_benign_absent_error(&e) => {
                    v4_still_pending = false;
                }
                Err(e) => {
                    outcome.warnings.push(format!("{desc_v4} failed: {e}"));
                }
            }
        }

        let mut remaining_v6 = None;
        if let Some(v6_snap) = &backup.ipv6 {
            let desc_v6 = format!(
                "RestoreInterfaceDnsSettings(IPv6='{}') on {}",
                v6_snap.name_server, backup.interface_guid
            );
            match backend.set_dns_settings(&backup.interface_guid, true, v6_snap) {
                Ok(()) => outcome.actions_executed.push(desc_v6),
                Err(e) if is_windows_benign_absent_error(&e) => {}
                Err(e) => {
                    outcome.warnings.push(format!("{desc_v6} failed: {e}"));
                    remaining_v6 = Some(v6_snap.clone());
                }
            }
        }

        if v4_still_pending || remaining_v6.is_some() {
            return Some(WindowsRecoveryRecord {
                adapter_name: rec.adapter_name.clone(),
                adapter_luid: rec.adapter_luid,
                owned_routes: Vec::new(),
                dns_interface_guid: Some(backup.interface_guid.clone()),
                previous_dns_servers: v4_still_pending
                    .then(|| rec.previous_dns_servers.clone())
                    .flatten(),
                dns_backup: Some(WindowsDnsInterfaceBackup {
                    interface_guid: backup.interface_guid.clone(),
                    ipv4: backup.ipv4.clone(),
                    ipv6: remaining_v6,
                    restore_ipv4: v4_still_pending,
                }),
            });
        }
        return None;
    }

    // Legacy recovery journal fallback (`dns_backup` absent, `previous_dns_servers` present)
    if let Some(prev_servers) = &rec.previous_dns_servers {
        let guid_res = match &rec.dns_interface_guid {
            Some(g) => Ok(g.clone()),
            None if rec.adapter_luid != 0 => backend.resolve_luid_guid(rec.adapter_luid),
            None => return None,
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
                    Ok(()) => {
                        outcome.actions_executed.push(desc);
                        return None;
                    }
                    Err(e) if is_windows_benign_absent_error(&e) => {
                        return None;
                    }
                    Err(e) => {
                        outcome.warnings.push(format!("{desc} failed: {e}"));
                        return Some(WindowsRecoveryRecord {
                            adapter_name: rec.adapter_name.clone(),
                            adapter_luid: rec.adapter_luid,
                            owned_routes: Vec::new(),
                            dns_interface_guid: Some(guid),
                            previous_dns_servers: Some(prev_servers.clone()),
                            dns_backup: None,
                        });
                    }
                }
            }
            Err(e) if is_windows_benign_absent_error(&e) => return None,
            Err(e) => {
                outcome.warnings.push(format!(
                    "ConvertInterfaceLuidToGuid({}) failed during DNS recovery: {e}",
                    rec.adapter_luid
                ));
                return Some(WindowsRecoveryRecord {
                    adapter_name: rec.adapter_name.clone(),
                    adapter_luid: rec.adapter_luid,
                    owned_routes: Vec::new(),
                    dns_interface_guid: rec.dns_interface_guid.clone(),
                    previous_dns_servers: Some(prev_servers.clone()),
                    dns_backup: None,
                });
            }
        }
    }

    None
}

/// Restore backed-up Windows IPv4 and IPv6 DNS settings and record accurate results/warnings in `outcome`.
pub fn restore_windows_adapter_dns_with_ops<B: WindowsDnsOps>(
    backend: &mut B,
    rec: &WindowsRecoveryRecord,
    outcome: &mut RecoveryOutcome,
) {
    let _ = restore_windows_adapter_dns_pruning_with_ops(backend, rec, outcome);
}

/// Roll back owned Windows routes and DNS overrides, returning `Some(remaining)` containing ONLY
/// physical routes / DNS settings whose restoration genuinely failed.
pub fn rollback_windows_record_with_ops<B, R>(
    rec: &WindowsRecoveryRecord,
    backend: &mut B,
    mut delete_route: R,
    outcome: &mut RecoveryOutcome,
) -> Option<WindowsRecoveryRecord>
where
    B: WindowsDnsOps,
    R: FnMut(&WindowsRouteRecord) -> io::Result<()>,
{
    let mut failed_routes_rev = Vec::new();
    for r in rec.owned_routes.iter().rev() {
        let desc = format!(
            "DeleteIpForwardEntry2 {}/{} -> {}",
            r.destination_prefix, r.prefix_length, r.next_hop
        );
        match delete_route(r) {
            Ok(()) => outcome.actions_executed.push(desc),
            Err(e) => {
                let on_wintun = rec.adapter_luid != 0 && r.interface_luid == rec.adapter_luid;
                if !is_windows_benign_absent_error(&e) {
                    outcome.warnings.push(format!("{desc}: {e}"));
                    if !on_wintun {
                        failed_routes_rev.push(r.clone());
                    }
                }
            }
        }
    }
    failed_routes_rev.reverse();

    let dns_rem = restore_windows_adapter_dns_pruning_with_ops(backend, rec, outcome);
    let remaining = WindowsRecoveryRecord {
        adapter_name: rec.adapter_name.clone(),
        adapter_luid: rec.adapter_luid,
        owned_routes: failed_routes_rev,
        dns_interface_guid: dns_rem.as_ref().and_then(|d| d.dns_interface_guid.clone()),
        previous_dns_servers: dns_rem
            .as_ref()
            .and_then(|d| d.previous_dns_servers.clone()),
        dns_backup: dns_rem.and_then(|d| d.dns_backup),
    };
    (!remaining.is_empty()).then_some(remaining)
}

#[cfg(windows)]
mod win_impl {
    use std::{
        ffi::c_void,
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::windows::ffi::OsStrExt,
        path::{Path, PathBuf},
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
                ERROR_SUCCESS, FreeLibrary, GetLastError, HANDLE, HMODULE,
            },
            NetworkManagement::{
                IpHelper::{
                    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid,
                    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
                    CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
                    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_DOMAIN, DNS_SETTING_IPV6,
                    DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST, DeleteIpForwardEntry2,
                    FreeInterfaceDnsSettings, FreeMibTable, GetIfEntry2, GetInterfaceDnsSettings,
                    GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry,
                    InitializeUnicastIpAddressEntry, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
                    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
                    MibAddInstance, MibDeleteInstance, MibParameterNotification,
                    NotifyIpInterfaceChange, SetInterfaceDnsSettings, SetIpInterfaceEntry,
                },
                Ndis::{IfOperStatusUp, NET_LUID_LH},
            },
            Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET},
            Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
            System::{
                LibraryLoader::{
                    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
                    LoadLibraryExW,
                },
                Registry::{
                    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
                    RegQueryValueExW,
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
        ForwardRouteCandidate, PhysicalEgressInfo, WINDOWS_SPLIT_IPV4_PREFIXES,
        WINDOWS_SPLIT_IPV6_PREFIXES, WindowsDnsOps, apply_windows_adapter_dns_transactional,
        compute_wintun_route_metrics, format_braced_guid, install_windows_physical_routes_with_ops,
        merge_non_zero_protector_indices, parse_braced_guid, parse_windows_dns_server_list,
        reconcile_windows_handoff_routes_with_ops, resolve_secure_wintun_dll_path,
        rollback_windows_record_with_ops, select_physical_default_egress,
        select_windows_physical_bypass_ips,
    };
    use crate::{
        inbound::tun::VirtualTunHandle,
        platform::{
            recovery::{
                RecoveryOutcome, WindowsDnsFamilySnapshot, WindowsRecoveryRecord,
                WindowsRouteRecord, finalize_windows_tun_teardown_journal, update_current_journal,
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

    /// LUID of the currently active RustClash Wintun adapter (`0` when stopped) so
    /// `discover_windows_physical_dns_servers()` always excludes the TUN adapter.
    static ACTIVE_WINTUN_LUID: AtomicU64 = AtomicU64::new(0);

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

    /// Detect the active physical egress `InterfaceIndex`, `InterfaceLuid`, and next-hop gateway
    /// directly from `GetIpForwardTable2(AF_UNSPEC)` `/0` default routes whose adapter is
    /// `IfOperStatusUp` (`GetIfEntry2`) and IP-connected (`GetIpInterfaceEntry`).
    ///
    /// Never probes `GetBestRoute2` toward `1.1.1.1` / `2606:4700:4700::1111`, because our own
    /// `/32` / `/128` static bypass routes on a still-associated Wi-Fi NIC would beat a newly
    /// plugged-in Ethernet NIC's `0.0.0.0/0` default route via longest-prefix match!
    pub fn detect_windows_physical_egress(excluded_tun_luid: u64) -> PhysicalEgressInfo {
        // SAFETY: `GetIpForwardTable2` allocates `table` which is freed via `FreeMibTable` before return.
        unsafe {
            let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
            let status = GetIpForwardTable2(AF_UNSPEC, &raw mut table);
            if status != 0 || table.is_null() {
                return PhysicalEgressInfo::default();
            }
            let num_entries = (*table).NumEntries as usize;
            let rows_ptr = std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>();
            let rows = std::slice::from_raw_parts(rows_ptr, num_entries);

            let mut candidates = Vec::new();
            for row in rows {
                if row.DestinationPrefix.PrefixLength != 0
                    || row.Loopback != 0
                    || row.InterfaceIndex <= 1
                {
                    continue;
                }
                let luid_val = row.InterfaceLuid.Value;
                if luid_val == 0 || luid_val == excluded_tun_luid {
                    continue;
                }
                let family = row.DestinationPrefix.Prefix.si_family;
                let is_ipv6 = if family == AF_INET {
                    false
                } else if family == AF_INET6 {
                    true
                } else {
                    continue;
                };

                let mut if_entry: MIB_IF_ROW2 = std::mem::zeroed();
                if_entry.InterfaceLuid = row.InterfaceLuid;
                let oper_up =
                    GetIfEntry2(&raw mut if_entry) == 0 && if_entry.OperStatus == IfOperStatusUp;
                if !oper_up {
                    continue;
                }

                let mut ip_if: MIB_IPINTERFACE_ROW = std::mem::zeroed();
                ip_if.Family = family;
                ip_if.InterfaceLuid = row.InterfaceLuid;
                let (ip_connected, if_metric) = if GetIpInterfaceEntry(&raw mut ip_if) == 0 {
                    (ip_if.Connected != 0, ip_if.Metric)
                } else {
                    (true, 0)
                };

                candidates.push(ForwardRouteCandidate {
                    is_ipv6,
                    prefix_length: row.DestinationPrefix.PrefixLength,
                    loopback: row.Loopback != 0,
                    if_index: row.InterfaceIndex,
                    luid: luid_val,
                    oper_up,
                    ip_connected,
                    route_metric: row.Metric,
                    interface_metric: if_metric,
                    next_hop: ip_from_sockaddr_inet(&row.NextHop),
                });
            }

            FreeMibTable(table.cast::<c_void>());
            select_physical_default_egress(&candidates, excluded_tun_luid)
        }
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

        let (default_egress_iface, default_egress_gateway) = if egress.v4_if_index != 0 {
            (
                Some(format!("ifIndex:{}", egress.v4_if_index)),
                egress.v4_gateway.map(|g| g.to_string()),
            )
        } else if egress.v6_if_index != 0 {
            (
                Some(format!("ifIndex:{}", egress.v6_if_index)),
                egress.v6_gateway.map(|g| g.to_string()),
            )
        } else {
            (None, None)
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
            default_egress_iface,
            default_egress_gateway,
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

    fn configure_adapter_ip_interface(
        luid: NET_LUID_LH,
        family: u16,
        mtu: u32,
        manual_metric: Option<u32>,
    ) -> io::Result<()> {
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
            match manual_metric {
                Some(metric) => {
                    row.UseAutomaticMetric = 0;
                    row.Metric = metric.max(1);
                }
                None => {
                    row.UseAutomaticMetric = 1;
                }
            }
            let st_set = SetIpInterfaceEntry(&raw mut row);
            if st_set != 0 {
                return Err(io::Error::from_raw_os_error(st_set as i32));
            }
        }
        Ok(())
    }

    /// Best-effort call to Windows `dnsapi.dll!DnsFlushResolverCache` so stale pre-TUN real/poisoned
    /// DNS entries (on TUN start) or stale `198.18.x.x` Fake-IP entries (on TUN stop) are purged
    /// immediately from Windows `Dnscache`.
    fn flush_windows_dns_resolver_cache() {
        type FnDnsFlushResolverCache = unsafe extern "system" fn() -> i32;
        let dll_wide = to_wide_nul("dnsapi.dll");
        // SAFETY: Loading signed system `dnsapi.dll` strictly from System32, calling its no-arg
        // `DnsFlushResolverCache` export if present, and releasing the module handle immediately.
        unsafe {
            let module = LoadLibraryExW(
                dll_wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if module.is_null() {
                return;
            }
            if let Ok(flush_fn) =
                load_proc::<FnDnsFlushResolverCache>(module, b"DnsFlushResolverCache\0")
            {
                let _ = flush_fn();
            }
            let _ = FreeLibrary(module);
        }
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

    pub fn recover_windows_tun_record_pruning(
        rec: &WindowsRecoveryRecord,
        outcome: &mut RecoveryOutcome,
    ) -> Option<WindowsRecoveryRecord> {
        let mut dns_backend = IpHlpApiDnsBackend;
        rollback_windows_record_with_ops(rec, &mut dns_backend, delete_iphlpapi_route, outcome)
    }

    pub fn recover_windows_tun_record(rec: &WindowsRecoveryRecord, outcome: &mut RecoveryOutcome) {
        let _ = recover_windows_tun_record_pruning(rec, outcome);
    }

    fn rollback_windows_record_and_finalize(
        rec: &WindowsRecoveryRecord,
        state_dir: &Path,
    ) -> RecoveryOutcome {
        let mut outcome = RecoveryOutcome::default();
        let remaining = recover_windows_tun_record_pruning(rec, &mut outcome);
        for warn_msg in &outcome.warnings {
            tracing::warn!("Windows Wintun teardown recovery warning: {}", warn_msg);
        }
        if let Err(e) = finalize_windows_tun_teardown_journal(state_dir, remaining) {
            let msg = format!("failed updating Windows recovery journal: {e}");
            tracing::warn!("{}", msg);
            outcome.warnings.push(msg);
        }
        // Purge stale `198.18.x.x` Fake-IP entries from Windows `Dnscache` immediately after DNS rollback.
        flush_windows_dns_resolver_cache();
        outcome
    }

    unsafe fn query_reg_dns_string(hkey: HKEY, name: &str) -> Option<String> {
        let name_w = to_wide_nul(name);
        let mut byte_len: u32 = 0;
        // SAFETY: `hkey` is an open registry key handle and `name_w` is NUL-terminated UTF-16.
        let rc0 = unsafe {
            RegQueryValueExW(
                hkey,
                name_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut byte_len,
            )
        };
        if rc0 != ERROR_SUCCESS || byte_len == 0 || byte_len > 65_536 {
            return None;
        }
        let mut wbuf = vec![0u16; (byte_len as usize).div_ceil(2) + 1];
        // SAFETY: `wbuf` has capacity >= `byte_len` bytes.
        let rc1 = unsafe {
            RegQueryValueExW(
                hkey,
                name_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                wbuf.as_mut_ptr().cast::<u8>(),
                &raw mut byte_len,
            )
        };
        if rc1 != ERROR_SUCCESS {
            return None;
        }
        let u16_len = ((byte_len as usize) / 2).min(wbuf.len());
        let mut trimmed_end = u16_len;
        while trimmed_end > 0 && wbuf[trimmed_end - 1] == 0 {
            trimmed_end -= 1;
        }
        if trimmed_end == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&wbuf[..trimmed_end]))
    }

    fn read_windows_interface_registry_dns(guid: &str, ipv6: bool) -> (Vec<IpAddr>, Vec<IpAddr>) {
        let service = if ipv6 { "Tcpip6" } else { "Tcpip" };
        let subkey = to_wide_nul(&format!(
            "SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters\\Interfaces\\{guid}"
        ));
        let mut hkey: HKEY = std::ptr::null_mut();
        // SAFETY: Read-only HKLM registry lookup using NUL-terminated UTF-16 subkey.
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                KEY_READ,
                &raw mut hkey,
            )
        };
        if rc != ERROR_SUCCESS || hkey.is_null() {
            return (Vec::new(), Vec::new());
        }

        let mut static_ips = Vec::new();
        let mut dhcp_ips = Vec::new();
        // SAFETY: `hkey` was opened above and is closed before returning.
        unsafe {
            for key_name in ["NameServer", "ProfileNameServer"] {
                if let Some(raw) = query_reg_dns_string(hkey, key_name) {
                    for ip in parse_windows_dns_server_list(&raw) {
                        if !static_ips.contains(&ip) {
                            static_ips.push(ip);
                        }
                    }
                }
            }
            if let Some(raw) = query_reg_dns_string(hkey, "DhcpNameServer") {
                for ip in parse_windows_dns_server_list(&raw) {
                    if !dhcp_ips.contains(&ip) {
                        dhcp_ips.push(ip);
                    }
                }
            }
            let _ = RegCloseKey(hkey);
        }
        (static_ips, dhcp_ips)
    }

    /// Discover OS / DHCP DNS servers on the active physical default-egress Windows NIC
    /// (excluding the active Wintun adapter LUID). Prefers configured static DNS on each family
    /// before falling back to DHCP DNS (`DhcpNameServer`), matching Windows `Dnscache` precedence.
    pub fn discover_windows_physical_dns_servers() -> Vec<IpAddr> {
        let excluded_luid = ACTIVE_WINTUN_LUID.load(Ordering::Acquire);
        let egress = detect_windows_physical_egress(excluded_luid);
        let mut dns_backend = IpHlpApiDnsBackend;
        let mut out = Vec::new();

        let mut collect_family = |luid: u64, ipv6: bool| {
            if luid == 0 || luid == excluded_luid {
                return;
            }
            let Ok(guid) = dns_backend.resolve_luid_guid(luid) else {
                return;
            };
            let mut static_ips = Vec::new();
            if let Ok(snap) = dns_backend.get_dns_settings(&guid, ipv6) {
                for ip in parse_windows_dns_server_list(&snap.name_server) {
                    if !static_ips.contains(&ip) {
                        static_ips.push(ip);
                    }
                }
            }
            let (reg_static, reg_dhcp) = read_windows_interface_registry_dns(&guid, ipv6);
            for ip in reg_static {
                if !static_ips.contains(&ip) {
                    static_ips.push(ip);
                }
            }
            let chosen = if !static_ips.is_empty() {
                static_ips
            } else {
                reg_dhcp
            };
            for ip in chosen {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        };

        collect_family(egress.v4_luid, false);
        collect_family(egress.v6_luid, true);
        out
    }

    struct NetChangeCallbackCtx {
        adapter_luid: u64,
        auto_route: bool,
        enable_ipv6: bool,
        dns_hijack: bool,
        proxy_bypass_ips: Vec<IpAddr>,
        dns_bypass_ips: Vec<IpAddr>,
        route_exclude_cidrs: Vec<ipnet::IpNet>,
        fake_ip_net: ipnet::Ipv4Net,
        tun_ipv6_cidr: ipnet::Ipv6Net,
        state_dir: PathBuf,
        recovery_record: Arc<Mutex<WindowsRecoveryRecord>>,
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

        let (effective, routes_handoff_needed) = {
            let mut guard = ctx.egress_state.lock();
            let prev = guard.clone();
            let (eff_v4_idx, eff_v6_idx) = merge_non_zero_protector_indices(
                prev.v4_if_index,
                prev.v6_if_index,
                latest.v4_if_index,
                latest.v6_if_index,
            );
            let effective = PhysicalEgressInfo {
                v4_if_index: eff_v4_idx,
                v4_luid: if latest.v4_if_index != 0 {
                    latest.v4_luid
                } else {
                    prev.v4_luid
                },
                v4_gateway: if latest.v4_if_index != 0 {
                    latest.v4_gateway
                } else {
                    prev.v4_gateway
                },
                v6_if_index: eff_v6_idx,
                v6_luid: if latest.v6_if_index != 0 {
                    latest.v6_luid
                } else {
                    prev.v6_luid
                },
                v6_gateway: if latest.v6_if_index != 0 {
                    latest.v6_gateway
                } else {
                    prev.v6_gateway
                },
            };
            if prev == effective {
                return;
            }
            let handoff = (prev.v4_luid, prev.v4_gateway)
                != (effective.v4_luid, effective.v4_gateway)
                || (prev.v6_luid, prev.v6_gateway) != (effective.v6_luid, effective.v6_gateway);
            *guard = effective.clone();
            (effective, handoff)
        };

        // Never overwrite a valid non-zero interface index with `0` (which would turn
        // `WindowsUnicastIfProtector` into a no-op and loop outbound sockets into Wintun!).
        ctx.protector
            .update_indices(effective.v4_if_index, effective.v6_if_index);

        let effective_bypass = select_windows_physical_bypass_ips(
            &ctx.proxy_bypass_ips,
            &ctx.dns_bypass_ips,
            ctx.dns_hijack,
            effective.v4_if_index != 0,
            effective.v6_if_index != 0,
        );
        if ctx.auto_route && routes_handoff_needed {
            let rec_snap = {
                let mut rec_guard = ctx.recovery_record.lock();
                reconcile_windows_handoff_routes_with_ops(
                    &mut rec_guard,
                    ctx.adapter_luid,
                    &effective,
                    &effective_bypass,
                    &ctx.route_exclude_cidrs,
                    ctx.fake_ip_net,
                    ctx.tun_ipv6_cidr,
                    ctx.enable_ipv6,
                    delete_iphlpapi_route,
                    add_iphlpapi_route,
                );
                rec_guard.clone()
            };
            let _ = update_current_journal(&ctx.state_dir, |j| j.windows_tun = Some(rec_snap));
        }

        flush_windows_dns_resolver_cache();
        ctx.transitions.fetch_add(1, Ordering::Relaxed);
        if let Some(hook) = &ctx.net_hook {
            hook();
        } else if let Some(dns) = &ctx.dns {
            dns.flush_cache();
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
        recovery_record: Arc<Mutex<WindowsRecoveryRecord>>,
        stop_flag: Arc<AtomicBool>,
        stop_watch_tx: tokio::sync::watch::Sender<bool>,
        stopped: bool,
        driver_version: u32,
        rx_packets: Arc<AtomicU64>,
        tx_packets: Arc<AtomicU64>,
        network_transitions: Arc<AtomicU64>,
        egress_state: Arc<Mutex<PhysicalEgressInfo>>,
        last_error: Arc<Mutex<Option<String>>>,
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
            let tun_luid_val = unsafe { luid.Value };
            ACTIVE_WINTUN_LUID.store(tun_luid_val, Ordering::Release);
            // Re-verify physical egress excluding this Wintun adapter's own LUID (defends against
            // any stale pre-existing RustClash Wintun adapter with leftover routes).
            let refined_egress = detect_windows_physical_egress(tun_luid_val);
            let initial_egress =
                if refined_egress.v4_if_index != 0 || refined_egress.v6_if_index != 0 {
                    refined_egress
                } else {
                    initial_egress
                };
            protector.update_indices(initial_egress.v4_if_index, initial_egress.v6_if_index);

            // 3. Start 4 MiB Wintun ring-buffer session
            // SAFETY: `adapter` is valid and `WINTUN_RING_CAPACITY` is 4 MiB.
            let session = unsafe { (api.start_session)(adapter, WINTUN_RING_CAPACITY) };
            if session.is_null() {
                let err = io::Error::last_os_error();
                // SAFETY: Closing `adapter` on session start failure.
                unsafe { (api.close_adapter)(adapter) };
                ACTIVE_WINTUN_LUID.store(0, Ordering::Release);
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

            // 4. Configure adapter IPv4, IPv6, MTU, lowest InterfaceMetric, split-tunnel routes,
            //    selective bypass routes, `route-exclude-address` bypass routes, and DNS transactionally
            let setup_res = (|| -> io::Result<()> {
                let gw_v4 = spec.gateway_ipv4();
                set_adapter_unicast_ip(luid, IpAddr::V4(gw_v4), spec.fake_ip_net.prefix_len())?;
                let mtu_u32 = spec.mtu.clamp(1280, 65535) as u32;
                let (iface_metric, route_metric) = compute_wintun_route_metrics(spec.strict_route);
                let manual_metric = spec.auto_route.then_some(iface_metric);
                if let Err(err) =
                    configure_adapter_ip_interface(luid, AF_INET, mtu_u32, manual_metric)
                {
                    tracing::warn!(
                        "Windows Wintun IPv4 interface MTU/metric configuration failed: {err}"
                    );
                }

                if spec.enable_ipv6 {
                    set_adapter_unicast_ip(
                        luid,
                        IpAddr::V6(spec.tun_ipv6_cidr.addr()),
                        spec.tun_ipv6_cidr.prefix_len(),
                    )?;
                    if let Err(err) =
                        configure_adapter_ip_interface(luid, AF_INET6, mtu_u32, manual_metric)
                    {
                        tracing::warn!(
                            "Windows Wintun IPv6 interface MTU/metric configuration failed: {err}"
                        );
                    }
                }

                if !spec.auto_route {
                    return Ok(());
                }

                let luid_val = unsafe { luid.Value };
                let zero_v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

                // Split-tunnel IPv4 (`0.0.0.0/1` + `128.0.0.0/1`) + Fake-IP subnet -> Wintun on-link
                for &(prefix_str, plen) in WINDOWS_SPLIT_IPV4_PREFIXES {
                    let r = add_iphlpapi_route(
                        luid_val,
                        prefix_str.parse().unwrap(),
                        plen,
                        zero_v4,
                        route_metric,
                    )?;
                    rec.owned_routes.push(r);
                }
                let r_fake = add_iphlpapi_route(
                    luid_val,
                    IpAddr::V4(spec.fake_ip_net.network()),
                    spec.fake_ip_net.prefix_len(),
                    zero_v4,
                    route_metric,
                )?;
                rec.owned_routes.push(r_fake);

                // Explicit `/32`/`/128` physical bypass routes + `tun.route-exclude-address` CIDR bypasses:
                // keep literal proxy server IPs and user-excluded LAN CIDRs, but omit public/upstream
                // DNS servers when `WindowsUnicastIfProtector` (`IP_UNICAST_IF`) + `dns_hijack` are active
                // so other Windows processes cannot bypass Wintun's `any:53` Fake-IP hijack!
                let effective_bypass = select_windows_physical_bypass_ips(
                    &spec.bypass_ips,
                    &spec.dns_bypass_ips,
                    spec.dns_hijack,
                    initial_egress.v4_if_index != 0,
                    initial_egress.v6_if_index != 0,
                );
                rec.owned_routes
                    .extend(install_windows_physical_routes_with_ops(
                        &initial_egress,
                        &effective_bypass,
                        &spec.route_exclude_cidrs,
                        spec.fake_ip_net,
                        spec.tun_ipv6_cidr,
                        spec.enable_ipv6,
                        add_iphlpapi_route,
                    ));

                if spec.enable_ipv6 {
                    let zero_v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
                    for &(prefix6_str, plen6) in WINDOWS_SPLIT_IPV6_PREFIXES {
                        let r6 = add_iphlpapi_route(
                            luid_val,
                            prefix6_str.parse().unwrap(),
                            plen6,
                            zero_v6,
                            route_metric,
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

                // Purge stale pre-TUN / poisoned DNS entries from Windows `Dnscache` so apps
                // immediately resolve through Wintun's lowest-metric DNS (`spec.dns_ipv4()`).
                flush_windows_dns_resolver_cache();
                Ok(())
            })();

            if let Err(err) = setup_res {
                let outcome = rollback_windows_record_and_finalize(&rec, &spec.state_dir);
                let _ = outcome;
                // SAFETY: Ending Wintun session and closing adapter on rollback.
                unsafe {
                    (api.end_session)(session);
                    (api.close_adapter)(adapter);
                }
                ACTIVE_WINTUN_LUID.store(0, Ordering::Release);
                clear_global_socket_protector();
                return Err(err);
            }

            // 5. Create manual-reset `stop_event` and launch Wintun ring-buffer RX / TX threads
            // SAFETY: Creating an unnamed manual-reset Win32 event.
            let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if stop_event.is_null() {
                let err = io::Error::last_os_error();
                let _ = rollback_windows_record_and_finalize(&rec, &spec.state_dir);
                unsafe {
                    (api.end_session)(session);
                    (api.close_adapter)(adapter);
                }
                ACTIVE_WINTUN_LUID.store(0, Ordering::Release);
                clear_global_socket_protector();
                return Err(err);
            }

            let recovery_record = Arc::new(Mutex::new(rec));
            let stop_flag = Arc::new(AtomicBool::new(false));
            let (stop_watch_tx, mut stop_watch_rx) = tokio::sync::watch::channel(false);
            let rx_packets = Arc::new(AtomicU64::new(0));
            let tx_packets = Arc::new(AtomicU64::new(0));
            let network_transitions = Arc::new(AtomicU64::new(0));
            let egress_state = Arc::new(Mutex::new(initial_egress));
            let last_error = Arc::new(Mutex::new(None));

            // Register `NotifyIpInterfaceChange` for instant Wi-Fi/Ethernet/sleep/wake recovery!
            let mut notify_ctx = Box::new(NetChangeCallbackCtx {
                adapter_luid: unsafe { luid.Value },
                auto_route: spec.auto_route,
                enable_ipv6: spec.enable_ipv6,
                dns_hijack: spec.dns_hijack,
                proxy_bypass_ips: spec.bypass_ips.clone(),
                dns_bypass_ips: spec.dns_bypass_ips.clone(),
                route_exclude_cidrs: spec.route_exclude_cidrs.clone(),
                fake_ip_net: spec.fake_ip_net,
                tun_ipv6_cidr: spec.tun_ipv6_cidr,
                state_dir: spec.state_dir.clone(),
                recovery_record: Arc::clone(&recovery_record),
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
            let rx_thread = match std::thread::Builder::new()
                .name("tun-wintun-rx".into())
                .spawn(move || {
                    let sess_p = sess_rx.ptr();
                    let stop_p = stop_ev_rx.ptr();
                    // SAFETY: `sess_p` and `stop_p` remain valid until `stop()` joins `rx_thread` BEFORE `end_session`.
                    unsafe {
                        let read_event = (api_rx.get_read_wait_event)(sess_p);
                        let handles = [read_event, stop_p];
                        let stop_handles = [stop_p];
                        'outer: while !stop_rx.load(Ordering::Acquire) {
                            loop {
                                if stop_rx.load(Ordering::Acquire) {
                                    break 'outer;
                                }
                                let mut pkt_size: u32 = 0;
                                let pkt_ptr = (api_rx.receive_packet)(sess_p, &raw mut pkt_size);
                                if pkt_ptr.is_null() {
                                    break;
                                }
                                let mut slice =
                                    std::slice::from_raw_parts(pkt_ptr, pkt_size as usize).to_vec();
                                (api_rx.release_receive_packet)(sess_p, pkt_ptr);
                                rx_cnt.fetch_add(1, Ordering::Relaxed);
                                loop {
                                    if stop_rx.load(Ordering::Acquire) {
                                        break 'outer;
                                    }
                                    match ingress_tx.try_send(slice) {
                                        Ok(()) => break,
                                        Err(tokio::sync::mpsc::error::TrySendError::Full(
                                            returned,
                                        )) => {
                                            slice = returned;
                                            let wait_rc = WaitForMultipleObjects(
                                                1,
                                                stop_handles.as_ptr(),
                                                0,
                                                2,
                                            );
                                            if wait_rc == 0 {
                                                break 'outer;
                                            }
                                        }
                                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                            break 'outer;
                                        }
                                    }
                                }
                            }
                            let err = GetLastError();
                            // `ERROR_NO_MORE_ITEMS == 259` means ring buffer is currently empty; wait on kernel event!
                            if err == 259 {
                                let wait_rc = WaitForMultipleObjects(2, handles.as_ptr(), 0, 250);
                                if wait_rc == 1 {
                                    break;
                                }
                            } else {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        }
                    }
                }) {
                Ok(h) => h,
                Err(err) => {
                    stop_flag.store(true, Ordering::Release);
                    let _ = stop_watch_tx.send(true);
                    // SAFETY: Cancel MIB callback BEFORE `notify_ctx` drops on scope exit!
                    unsafe {
                        if !notify_handle.is_null() {
                            let _ = CancelMibChangeNotify2(notify_handle);
                        }
                    }
                    drop(notify_ctx);
                    let rec_final = recovery_record.lock().clone();
                    let _ = rollback_windows_record_and_finalize(&rec_final, &spec.state_dir);
                    // SAFETY: No worker thread spawned; safe to end session, close adapter, and close event.
                    unsafe {
                        (api.end_session)(session);
                        (api.close_adapter)(adapter);
                        let _ = CloseHandle(stop_event);
                    }
                    ACTIVE_WINTUN_LUID.store(0, Ordering::Release);
                    clear_global_socket_protector();
                    return Err(err);
                }
            };

            let api_tx = Arc::clone(&api);
            let sess_tx = RawSendPtr(session);
            let tx_cnt = Arc::clone(&tx_packets);
            let tx_thread = match std::thread::Builder::new()
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
                }) {
                Ok(h) => h,
                Err(err) => {
                    stop_flag.store(true, Ordering::Release);
                    let _ = stop_watch_tx.send(true);
                    // SAFETY: Cancel MIB callback FIRST before dropping `notify_ctx`, then signal `stop_event` and join `rx_thread` BEFORE `end_session`.
                    unsafe {
                        if !notify_handle.is_null() {
                            let _ = CancelMibChangeNotify2(notify_handle);
                        }
                        let _ = SetEvent(stop_event);
                    }
                    drop(notify_ctx);
                    let _ = rx_thread.join();
                    let rec_final = recovery_record.lock().clone();
                    let _ = rollback_windows_record_and_finalize(&rec_final, &spec.state_dir);
                    unsafe {
                        (api.end_session)(session);
                        (api.close_adapter)(adapter);
                        let _ = CloseHandle(stop_event);
                    }
                    ACTIVE_WINTUN_LUID.store(0, Ordering::Release);
                    clear_global_socket_protector();
                    return Err(err);
                }
            };

            Ok(Self {
                spec,
                api,
                adapter_name,
                adapter: RawSendPtr(adapter),
                session: RawSendPtr(session),
                stop_event: RawSendPtr(stop_event),
                notify_handle: RawSendPtr(notify_handle),
                notify_ctx: Some(notify_ctx),
                recovery_record,
                stop_flag,
                stop_watch_tx,
                stopped: false,
                driver_version,
                rx_packets,
                tx_packets,
                network_transitions,
                egress_state,
                last_error,
                rx_thread: Some(rx_thread),
                tx_thread: Some(tx_thread),
            })
        }
    }

    impl SystemTunSession for WindowsWintunSession {
        fn health(&self) -> TunHealthSnapshot {
            let eg = self.egress_state.lock().clone();
            let (default_egress_iface, default_egress_gateway) = if eg.v4_if_index != 0 {
                (
                    Some(format!("ifIndex:{}", eg.v4_if_index)),
                    eg.v4_gateway.map(|g| g.to_string()),
                )
            } else if eg.v6_if_index != 0 {
                (
                    Some(format!("ifIndex:{}", eg.v6_if_index)),
                    eg.v6_gateway.map(|g| g.to_string()),
                )
            } else {
                (None, None)
            };
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
                default_egress_iface,
                default_egress_gateway,
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
            // Signal `stop_event` immediately so `rx_thread` halts packet ingestion before we wait
            // on `CancelMibChangeNotify2` or join worker threads.
            if !self.stop_event.0.is_null() {
                // SAFETY: Signaling our valid Win32 manual-reset event.
                unsafe {
                    let _ = SetEvent(self.stop_event.0);
                }
            }

            // 1. Cancel `NotifyIpInterfaceChange` FIRST before dropping `notify_ctx`!
            if !self.notify_handle.0.is_null() {
                // SAFETY: `CancelMibChangeNotify2` blocks until any in-flight callback finishes.
                unsafe {
                    let _ = CancelMibChangeNotify2(self.notify_handle.0);
                }
                self.notify_handle.0 = std::ptr::null_mut();
            }
            let _ = self.notify_ctx.take();

            // 2. Join RX/TX threads BEFORE calling `WintunEndSession`!
            if let Some(h) = self.rx_thread.take() {
                let _ = h.join();
            }
            if let Some(h) = self.tx_thread.take() {
                let _ = h.join();
            }

            // 3. Roll back routes & DNS overrides, end Wintun session, close adapter & event, finalize journal
            let rec_final = self.recovery_record.lock().clone();
            let outcome = rollback_windows_record_and_finalize(&rec_final, &self.spec.state_dir);
            if !outcome.warnings.is_empty() {
                *self.last_error.lock() = Some(outcome.warnings.join("; "));
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

            ACTIVE_WINTUN_LUID.store(0, Ordering::Release);
            clear_global_socket_protector();
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
    WindowsWintunSession, detect_windows_physical_egress, discover_windows_physical_dns_servers,
    is_windows_process_elevated, preflight_windows_tun, recover_windows_tun_record,
    recover_windows_tun_record_pruning,
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
                restore_ipv4: true,
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

    #[test]
    fn select_physical_default_egress_ignores_bypass_and_split_routes_and_picks_lowest_metric_up_nic()
     {
        let tun_luid = 9001u64;
        let wifi_luid = 1001u64;
        let eth_luid = 1002u64;
        let down_luid = 1003u64;

        let candidates = vec![
            // Our own 1.1.1.1/32 bypass route still sitting on associated Wi-Fi (metric 1, /32)
            ForwardRouteCandidate {
                is_ipv6: false,
                prefix_length: 32,
                loopback: false,
                if_index: 11,
                luid: wifi_luid,
                oper_up: true,
                ip_connected: true,
                route_metric: 1,
                interface_metric: 1,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            },
            // Wintun 0.0.0.0/1 split route AND hypothetical /0 route on excluded Wintun LUID
            ForwardRouteCandidate {
                is_ipv6: false,
                prefix_length: 1,
                loopback: false,
                if_index: 42,
                luid: tun_luid,
                oper_up: true,
                ip_connected: true,
                route_metric: 1,
                interface_metric: 1,
                next_hop: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            },
            ForwardRouteCandidate {
                is_ipv6: false,
                prefix_length: 0,
                loopback: false,
                if_index: 42,
                luid: tun_luid,
                oper_up: true,
                ip_connected: true,
                route_metric: 0,
                interface_metric: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            },
            // Disconnected / down adapter with low metric must be skipped
            ForwardRouteCandidate {
                is_ipv6: false,
                prefix_length: 0,
                loopback: false,
                if_index: 9,
                luid: down_luid,
                oper_up: false,
                ip_connected: true,
                route_metric: 1,
                interface_metric: 5,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            },
            // Associated Wi-Fi 0.0.0.0/0 default route (higher combined metric: 0 + 50 = 50)
            ForwardRouteCandidate {
                is_ipv6: false,
                prefix_length: 0,
                loopback: false,
                if_index: 11,
                luid: wifi_luid,
                oper_up: true,
                ip_connected: true,
                route_metric: 0,
                interface_metric: 50,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            },
            // Newly plugged-in Ethernet 0.0.0.0/0 default route (lower combined metric: 0 + 25 = 25)
            ForwardRouteCandidate {
                is_ipv6: false,
                prefix_length: 0,
                loopback: false,
                if_index: 15,
                luid: eth_luid,
                oper_up: true,
                ip_connected: true,
                route_metric: 0,
                interface_metric: 25,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1))),
            },
            // IPv6 ::/0 default route on Wi-Fi (Ethernet lacks IPv6 RA yet)
            ForwardRouteCandidate {
                is_ipv6: true,
                prefix_length: 0,
                loopback: false,
                if_index: 11,
                luid: wifi_luid,
                oper_up: true,
                ip_connected: true,
                route_metric: 256,
                interface_metric: 50,
                next_hop: Some("fe80::1".parse().unwrap()),
            },
        ];

        let selected = select_physical_default_egress(&candidates, tun_luid);
        assert_eq!(selected.v4_if_index, 15);
        assert_eq!(selected.v4_luid, eth_luid);
        assert_eq!(
            selected.v4_gateway,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1)))
        );
        assert_eq!(selected.v6_if_index, 11);
        assert_eq!(selected.v6_luid, wifi_luid);
        assert_eq!(selected.v6_gateway, Some("fe80::1".parse().unwrap()));
    }

    #[test]
    fn merge_non_zero_protector_indices_never_zeros_active_family() {
        // Initial dual-stack indices (11, 11), then v6-only update or temporary v4 route drop -> keep v4=11!
        assert_eq!(merge_non_zero_protector_indices(11, 11, 0, 15), (11, 15));
        // v4 switches to Ethernet (15) while v6 temporarily reports 0 -> keep v6=11 rather than 0!
        assert_eq!(merge_non_zero_protector_indices(11, 11, 15, 0), (15, 11));
        // Both families switch to 15 -> (15, 15).
        assert_eq!(merge_non_zero_protector_indices(11, 11, 15, 15), (15, 15));
        // Initially IPv4-only (11, 0), then IPv6 comes online (11, 11) -> (11, 11).
        assert_eq!(merge_non_zero_protector_indices(11, 0, 11, 11), (11, 11));
    }

    #[test]
    fn windows_dns_partial_rollback_retains_only_unrestored_family_and_treats_absent_adapter_as_benign()
     {
        use crate::platform::recovery::{
            RecoveryOutcome, WindowsDnsFamilySnapshot, WindowsDnsInterfaceBackup,
            WindowsRecoveryRecord, WindowsRouteRecord,
        };

        struct PartialFailDnsOps {
            fail_ipv6: bool,
            v4_calls: usize,
            v6_calls: usize,
        }

        impl WindowsDnsOps for PartialFailDnsOps {
            fn resolve_luid_guid(&mut self, _luid_value: u64) -> io::Result<String> {
                Ok("{11111111-2222-3333-4444-555555555555}".to_string())
            }
            fn get_dns_settings(
                &mut self,
                _interface_guid: &str,
                _ipv6: bool,
            ) -> io::Result<WindowsDnsFamilySnapshot> {
                unreachable!("not used during rollback")
            }
            fn set_dns_settings(
                &mut self,
                _interface_guid: &str,
                ipv6: bool,
                _settings: &WindowsDnsFamilySnapshot,
            ) -> io::Result<()> {
                if ipv6 {
                    self.v6_calls += 1;
                    if self.fail_ipv6 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Access is denied (os error 5)",
                        ));
                    }
                } else {
                    self.v4_calls += 1;
                }
                Ok(())
            }
        }

        let guid = "{11111111-2222-3333-4444-555555555555}".to_string();
        let rec = WindowsRecoveryRecord {
            adapter_name: "RustClash".to_string(),
            adapter_luid: 0x0006_0000_0000_0099,
            owned_routes: vec![
                // Wintun split route that already disappeared with adapter (`ERROR_NOT_FOUND = 1168`)
                WindowsRouteRecord {
                    destination_prefix: "0.0.0.0".to_string(),
                    prefix_length: 1,
                    next_hop: "198.18.0.1".to_string(),
                    interface_luid: 0x0006_0000_0000_0099,
                },
            ],
            dns_interface_guid: Some(guid.clone()),
            previous_dns_servers: Some(vec!["192.168.1.1".to_string()]),
            dns_backup: Some(WindowsDnsInterfaceBackup {
                interface_guid: guid.clone(),
                ipv4: WindowsDnsFamilySnapshot {
                    name_server: "192.168.1.1".to_string(),
                    domain: None,
                    search_list: None,
                },
                ipv6: Some(WindowsDnsFamilySnapshot {
                    name_server: "fe80::1".to_string(),
                    domain: None,
                    search_list: None,
                }),
                restore_ipv4: true,
            }),
        };

        // Pass 1: route delete returns benign `ERROR_NOT_FOUND (1168)`, IPv4 DNS succeeds, IPv6 DNS fails.
        let mut ops = PartialFailDnsOps {
            fail_ipv6: true,
            v4_calls: 0,
            v6_calls: 0,
        };
        let mut outcome1 = RecoveryOutcome::default();
        let rem1 = rollback_windows_record_with_ops(
            &rec,
            &mut ops,
            |_r| Err(io::Error::from_raw_os_error(1168)),
            &mut outcome1,
        )
        .expect("failed IPv6 DNS restore must retain pruned WindowsRecoveryRecord");
        assert_eq!(ops.v4_calls, 1);
        assert_eq!(ops.v6_calls, 1);
        assert_eq!(outcome1.warnings.len(), 1);
        assert!(rem1.owned_routes.is_empty());
        let rem_backup = rem1.dns_backup.as_ref().unwrap();
        assert!(
            !rem_backup.restore_ipv4,
            "already-restored IPv4 DNS must not be re-applied on retry"
        );
        assert!(rem_backup.ipv6.is_some());

        // Pass 2: retry restores ONLY IPv6 DNS (`v4_calls` stays 1) and returns `None`.
        ops.fail_ipv6 = false;
        let mut outcome2 = RecoveryOutcome::default();
        let rem2 = rollback_windows_record_with_ops(
            &rem1,
            &mut ops,
            |_r| unreachable!("no remaining routes"),
            &mut outcome2,
        );
        assert!(rem2.is_none());
        assert!(outcome2.warnings.is_empty());
        assert_eq!(ops.v4_calls, 1);
        assert_eq!(ops.v6_calls, 2);
    }

    #[test]
    fn wintun_metrics_beat_physical_ethernet_for_windows_dnscache_priority() {
        let (iface_normal, route_normal) = compute_wintun_route_metrics(false);
        assert_eq!(iface_normal, WINTUN_LOWEST_INTERFACE_METRIC);
        assert_eq!(iface_normal, 1);
        assert_eq!(route_normal, 1);
        assert!(
            iface_normal + route_normal < 5,
            "Wintun effective metric must stay strictly below physical Ethernet metric (5)"
        );

        let (iface_strict, route_strict) = compute_wintun_route_metrics(true);
        assert_eq!(iface_strict, 1);
        assert_eq!(route_strict, 0);
        assert_eq!(iface_strict + route_strict, 1);
    }

    #[test]
    fn windows_physical_bypass_omits_public_dns_when_unicast_protector_and_dns_hijack_active() {
        let proxy_ips: Vec<IpAddr> = vec!["198.51.100.42".parse().unwrap()];
        let dns_ips: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "223.5.5.5".parse().unwrap(),
            "119.29.29.29".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];

        // Normal Windows Wintun + IP_UNICAST_IF + dns_hijack=true: never leak public DNS via global /32 routes!
        let selected = select_windows_physical_bypass_ips(&proxy_ips, &dns_ips, true, true, true);
        assert_eq!(selected, proxy_ips);

        // IPv4 protector active, IPv6 protector absent: keep proxy IP + IPv6 DNS fallback only.
        let v4_only_prot =
            select_windows_physical_bypass_ips(&proxy_ips, &dns_ips, true, true, false);
        assert_eq!(
            v4_only_prot,
            vec![
                "198.51.100.42".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            ]
        );

        // When dns_hijack is disabled or no unicast protector exists, include DNS bypass IPs.
        let no_hijack = select_windows_physical_bypass_ips(&proxy_ips, &dns_ips, false, true, true);
        assert_eq!(no_hijack.len(), 6);
        let no_prot = select_windows_physical_bypass_ips(&proxy_ips, &dns_ips, true, false, false);
        assert_eq!(no_prot.len(), 6);
    }

    #[test]
    fn windows_route_exclude_address_plans_installs_hands_off_and_rolls_back_cleanly() {
        let fake_net: ipnet::Ipv4Net = "198.18.0.0/15".parse().unwrap();
        let tun_v6: ipnet::Ipv6Net = "fdfe:dcba:9876::1/126".parse().unwrap();
        let wintun_luid = 9000u64;
        let wifi_egress = PhysicalEgressInfo {
            v4_if_index: 12,
            v4_luid: 1001,
            v4_gateway: Some("192.168.1.1".parse().unwrap()),
            v6_if_index: 12,
            v6_luid: 1001,
            v6_gateway: Some("fe80::1".parse().unwrap()),
        };
        let eth_egress = PhysicalEgressInfo {
            v4_if_index: 20,
            v4_luid: 2002,
            v4_gateway: Some("10.10.0.1".parse().unwrap()),
            v6_if_index: 20,
            v6_luid: 2002,
            v6_gateway: Some("fe80::2".parse().unwrap()),
        };

        let exclude_cidrs: Vec<ipnet::IpNet> = vec![
            "192.168.0.0/16".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
            "198.18.10.0/24".parse().unwrap(), // overlaps fake-ip -> skipped
            "198.16.0.0/13".parse().unwrap(),  // contains fake-ip -> skipped
            "0.0.0.0/1".parse().unwrap(),      // prefix <= 1 -> skipped
            "fc00::/7".parse().unwrap(),       // broader than TUN /126 -> kept
            "fdfe:dcba:9876::/126".parse().unwrap(), // overlaps TUN /126 at >=126 -> skipped
        ];
        let proxy_bypass: Vec<IpAddr> = vec!["203.0.113.5".parse().unwrap()];

        let planned = plan_windows_physical_exclude_routes(
            &wifi_egress,
            &exclude_cidrs,
            fake_net,
            tun_v6,
            true,
        );
        assert_eq!(planned.len(), 4);
        assert_eq!(planned[0].dest, "192.168.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(planned[0].prefix_len, 16);
        assert_eq!(planned[0].metric, WINDOWS_EXCLUDE_ROUTE_METRIC);
        assert_eq!(planned[3].dest, "fc00::".parse::<IpAddr>().unwrap());
        assert_eq!(planned[3].prefix_len, 7);

        // Install initial Wintun + physical bypass + exclude routes
        let mut rec = WindowsRecoveryRecord {
            adapter_name: "RustClash".to_string(),
            adapter_luid: wintun_luid,
            owned_routes: vec![
                WindowsRouteRecord {
                    destination_prefix: "0.0.0.0".to_string(),
                    prefix_length: 1,
                    next_hop: "0.0.0.0".to_string(),
                    interface_luid: wintun_luid,
                },
                WindowsRouteRecord {
                    destination_prefix: "128.0.0.0".to_string(),
                    prefix_length: 1,
                    next_hop: "0.0.0.0".to_string(),
                    interface_luid: wintun_luid,
                },
            ],
            dns_interface_guid: None,
            previous_dns_servers: None,
            dns_backup: None,
        };

        let mut added_metrics: Vec<(String, u8, u32)> = Vec::new();
        let initial_phys = install_windows_physical_routes_with_ops(
            &wifi_egress,
            &proxy_bypass,
            &exclude_cidrs,
            fake_net,
            tun_v6,
            true,
            |luid, dest, plen, nh, metric| {
                added_metrics.push((dest.to_string(), plen, metric));
                Ok(WindowsRouteRecord {
                    destination_prefix: dest.to_string(),
                    prefix_length: plen,
                    next_hop: nh.to_string(),
                    interface_luid: luid,
                })
            },
        );
        assert_eq!(initial_phys.len(), 5); // 1 proxy /32 + 3 IPv4 exclude + 1 IPv6 exclude
        assert_eq!(added_metrics[0], ("203.0.113.5".to_string(), 32, 1));
        assert_eq!(
            added_metrics[1],
            ("192.168.0.0".to_string(), 16, WINDOWS_EXCLUDE_ROUTE_METRIC)
        );
        rec.owned_routes.extend(initial_phys);

        // Network handoff Wi-Fi -> Ethernet: deletes all 5 Wi-Fi routes, preserves 2 Wintun routes, installs 5 Ethernet routes
        let mut deleted_handoff = Vec::new();
        reconcile_windows_handoff_routes_with_ops(
            &mut rec,
            wintun_luid,
            &eth_egress,
            &proxy_bypass,
            &exclude_cidrs,
            fake_net,
            tun_v6,
            true,
            |r| {
                deleted_handoff.push((
                    r.interface_luid,
                    r.destination_prefix.clone(),
                    r.prefix_length,
                ));
                Ok(())
            },
            |luid, dest, plen, nh, _metric| {
                Ok(WindowsRouteRecord {
                    destination_prefix: dest.to_string(),
                    prefix_length: plen,
                    next_hop: nh.to_string(),
                    interface_luid: luid,
                })
            },
        );
        assert_eq!(deleted_handoff.len(), 5);
        assert!(deleted_handoff.iter().all(|(luid, _, _)| *luid == 1001));
        assert_eq!(rec.owned_routes.len(), 7);
        assert_eq!(
            rec.owned_routes
                .iter()
                .filter(|r| r.interface_luid == wintun_luid)
                .count(),
            2
        );
        assert_eq!(
            rec.owned_routes
                .iter()
                .filter(|r| r.interface_luid == 2002)
                .count(),
            5
        );

        // Teardown rollback deletes all 7 routes cleanly (including every exclude CIDR route!)
        let mut dns_ops = FaultInjectingDnsBackend::default();
        let mut deleted_rollback = Vec::new();
        let mut outcome = RecoveryOutcome::default();
        let rem = rollback_windows_record_with_ops(
            &rec,
            &mut dns_ops,
            |r| {
                deleted_rollback.push((
                    r.interface_luid,
                    r.destination_prefix.clone(),
                    r.prefix_length,
                ));
                Ok(())
            },
            &mut outcome,
        );
        assert!(rem.is_none());
        assert!(outcome.warnings.is_empty());
        assert_eq!(deleted_rollback.len(), 7);
        assert!(
            deleted_rollback
                .iter()
                .any(|(_, d, p)| d == "192.168.0.0" && *p == 16)
        );
        assert!(
            deleted_rollback
                .iter()
                .any(|(_, d, p)| d == "fc00::" && *p == 7)
        );
    }

    #[test]
    fn parse_windows_dns_server_list_handles_commas_spaces_nuls_and_ipv6_zones() {
        let raw = "192.168.1.1, 10.0.0.53;fe80::1%12\x00192.168.1.1\0 2001:4860:4860::8888 ";
        let parsed = parse_windows_dns_server_list(raw);
        assert_eq!(
            parsed,
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "10.0.0.53".parse::<IpAddr>().unwrap(),
                "fe80::1".parse::<IpAddr>().unwrap(),
                "2001:4860:4860::8888".parse::<IpAddr>().unwrap(),
            ]
        );
    }
}
