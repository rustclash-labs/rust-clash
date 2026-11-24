#[cfg(target_os = "linux")]
use std::{
    collections::HashSet,
    fs,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr},
    os::fd::AsRawFd,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

#[cfg(target_os = "linux")]
use parking_lot::Mutex;

#[cfg(target_os = "linux")]
use crate::{
    inbound::tun::VirtualTunHandle,
    platform::{
        recovery::{
            LinuxRecoveryRecord, RecoveryOutcome, finalize_linux_tun_teardown_journal,
            update_current_journal,
        },
        socket_protect::{
            DEFAULT_LINUX_FWMARK, LinuxFwmarkProtector, clear_global_socket_protector,
            global_socket_protector, set_global_socket_protector,
        },
        tun::{SystemTunSession, TunHealthSnapshot, TunLaunchSpec},
    },
};

/// Parse `default via <gw> dev <ifname> ...` from `ip -4 route show default table main`.
pub fn parse_linux_default_route(output: &str) -> (Option<String>, Option<String>) {
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first().copied() != Some("default") {
            continue;
        }
        let mut gw = None;
        let mut dev = None;
        let mut idx = 1;
        while idx < tokens.len() {
            match tokens[idx] {
                "via" if idx + 1 < tokens.len() => {
                    gw = Some(tokens[idx + 1].to_string());
                    idx += 2;
                }
                "dev" if idx + 1 < tokens.len() => {
                    dev = Some(tokens[idx + 1].to_string());
                    idx += 2;
                }
                _ => idx += 1,
            }
        }
        if dev.is_some() || gw.is_some() {
            return (dev, gw);
        }
    }
    (None, None)
}

/// Extract numeric table IDs reserved in `/etc/iproute2/rt_tables`.
pub fn parse_rt_tables_ids(contents: &str) -> std::collections::HashSet<u32> {
    let mut out = std::collections::HashSet::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(first) = trimmed.split_whitespace().next()
            && let Ok(id) = first.parse::<u32>()
        {
            out.insert(id);
        }
    }
    out
}

pub const RESOLVECTL_CANDIDATE_PATHS: &[&str] = &[
    "/usr/bin/resolvectl",
    "/bin/resolvectl",
    "/usr/local/bin/resolvectl",
    "/run/current-system/sw/bin/resolvectl",
];

/// Locate `resolvectl` across standard FHS / NixOS locations and `PATH`.
pub fn resolve_resolvectl_binary_with_paths(
    candidates: &[&str],
    path_env: Option<&std::ffi::OsStr>,
) -> Option<std::path::PathBuf> {
    for candidate in candidates {
        let p = std::path::Path::new(candidate);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    if let Some(paths) = path_env {
        for dir in std::env::split_paths(paths) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let p = dir.join("resolvectl");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn resolve_resolvectl_binary() -> Option<std::path::PathBuf> {
    resolve_resolvectl_binary_with_paths(
        RESOLVECTL_CANDIDATE_PATHS,
        std::env::var_os("PATH").as_deref(),
    )
}

/// Parse `nameserver <ip>` entries from `/etc/resolv.conf` read-only.
pub fn parse_resolv_conf_nameservers(contents: &str) -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let before_comment = line.split(['#', ';']).next().unwrap_or("").trim();
        if before_comment.is_empty() {
            continue;
        }
        let mut parts = before_comment.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        if let Some(raw_ip) = parts.next() {
            let clean_ip = raw_ip.split('%').next().unwrap_or(raw_ip);
            if let Ok(ip) = clean_ip.parse::<std::net::IpAddr>() {
                out.push(ip);
            }
        }
    }
    out
}

/// Parse `resolvectl dns <ifname>` output (e.g. `Link 2 (eth0): 192.168.1.1 192.168.1.2#router` or
/// `Global: 8.8.8.8`) into unique `IpAddr`s.
pub fn parse_resolvectl_dns_output(output: &str) -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    for line in output.lines() {
        let rhs = match line.split_once(':') {
            Some((_, rest)) => rest,
            None => line,
        };
        for raw_tok in rhs.split_whitespace() {
            let no_sni = raw_tok.split('#').next().unwrap_or(raw_tok);
            let no_zone = no_sni.split('%').next().unwrap_or(no_sni);
            let clean = no_zone.trim_matches(|c| c == '[' || c == ']');
            if let Ok(ip) = clean.parse::<std::net::IpAddr>()
                && !out.contains(&ip)
            {
                out.push(ip);
            }
        }
    }
    out
}

/// Filter and normalize `tun.route-exclude-address` CIDRs into Linux IPv4 and IPv6 policy-rule
/// target strings (`pref 8995 to <cidr> lookup main`), skipping `prefix_len <= 1`, Fake-IP
/// overlaps, and exact TUN IPv6 subnet overlaps.
pub fn plan_linux_exclude_cidr_rules(
    exclude_cidrs: &[ipnet::IpNet],
    fake_ip_net: ipnet::Ipv4Net,
    tun_ipv6_cidr: ipnet::Ipv6Net,
    enable_ipv6: bool,
) -> (Vec<String>, Vec<String>) {
    let mut v4_out = Vec::new();
    let mut v6_out = Vec::new();
    for &cidr in exclude_cidrs {
        match cidr {
            ipnet::IpNet::V4(v4net) => {
                let net = v4net.trunc();
                if net.prefix_len() <= 1 || crate::config::ipv4_nets_overlap(net, fake_ip_net) {
                    continue;
                }
                let s = net.to_string();
                if !v4_out.contains(&s) {
                    v4_out.push(s);
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
                {
                    continue;
                }
                let s = net.to_string();
                if !v6_out.contains(&s) {
                    v6_out.push(s);
                }
            }
        }
    }
    (v4_out, v6_out)
}

/// Discover physical default-egress DNS servers on Linux for `system` / `dhcp://system` DNS upstreams.
/// Queries `resolvectl dns <egress_if>` first, then falls back to `/run/systemd/resolve/resolv.conf`
/// and `/etc/resolv.conf`. Callers apply anti-loop filtering (`198.18.0.0/15`, loopback, etc.).
#[cfg(target_os = "linux")]
pub fn discover_linux_physical_dns_servers() -> Vec<IpAddr> {
    fn extend_unique(out: &mut Vec<IpAddr>, ips: Vec<IpAddr>) {
        for ip in ips {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }

    let mut out = Vec::new();

    if let (Some(resolvectl_bin), (Some(egress_if), _)) =
        (resolve_resolvectl_binary(), detect_linux_default_egress())
        && let Ok(output) = std::process::Command::new(&resolvectl_bin)
            .args(["dns", &egress_if])
            .output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        extend_unique(&mut out, parse_resolvectl_dns_output(&stdout));
    }

    if out.is_empty()
        && let Ok(contents) = fs::read_to_string("/run/systemd/resolve/resolv.conf")
    {
        extend_unique(&mut out, parse_resolv_conf_nameservers(&contents));
    }

    if out.is_empty()
        && let Ok(contents) = fs::read_to_string("/etc/resolv.conf")
    {
        extend_unique(&mut out, parse_resolv_conf_nameservers(&contents));
    }

    out
}

/// Select explicit `pref 8990 ... lookup main` bypass IPs for Linux policy routing.
/// Always includes proxy server IPs (`proxy_bypass_ips`) as defense-in-depth alongside `SO_MARK`.
/// Omits upstream `dns_bypass_ips` when `dns_hijack` is enabled because RustClash's own upstream
/// DNS sockets are marked with `SO_MARK` (`LinuxFwmarkProtector`) and bypass `pref 9020 not fwmark`;
/// keeping global `pref 8990 to <dns_ip> lookup main` rules would let *other* Linux processes send
/// port-53 queries directly to public resolvers (e.g. `1.1.1.1`/`8.8.8.8`), escaping Fake-IP hijack.
pub fn select_linux_policy_bypass_ips(
    proxy_bypass_ips: &[std::net::IpAddr],
    dns_bypass_ips: &[std::net::IpAddr],
    dns_hijack: bool,
) -> Vec<std::net::IpAddr> {
    let mut out = Vec::with_capacity(proxy_bypass_ips.len() + dns_bypass_ips.len());
    for &ip in proxy_bypass_ips {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    if !dns_hijack {
        for &ip in dns_bypass_ips {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn flush_linux_resolved_cache() {
    if let Some(resolvectl_bin) = resolve_resolvectl_binary() {
        let _ = std::process::Command::new(&resolvectl_bin)
            .args(["flush-caches"])
            .output();
    }
}

/// Return `true` when `/etc/resolv.conf` has at least one nameserver and EVERY configured
/// nameserver matches a Linux TUN bypass policy rule (`pref 8990` explicit bypass or `pref 9000`
/// loopback / link-local / RFC1918 / CGNAT), meaning unmarked system DNS queries would bypass TUN.
pub fn all_nameservers_bypass_tun(
    nameservers: &[std::net::IpAddr],
    bypass_ips: &[std::net::IpAddr],
    strict_route: bool,
) -> bool {
    if nameservers.is_empty() {
        return false;
    }
    nameservers.iter().all(|ns| {
        if bypass_ips.contains(ns) {
            return true;
        }
        match ns {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                let is_cgnat = octets[0] == 100 && (octets[1] & 0xc0) == 64;
                v4.is_loopback()
                    || v4.is_link_local()
                    || (!strict_route && (v4.is_private() || is_cgnat))
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80,
        }
    })
}

/// Returns `true` when a Linux `ip` rule/route/link deletion error indicates the target rule,
/// route, or TUN interface is already absent (`ENOENT` / `ESRCH` / missing device), while
/// explicitly returning `false` for permission errors (`EPERM` / `EACCES` / `"Operation not permitted"`).
pub fn is_linux_benign_absent_error(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return false;
    }
    #[cfg(unix)]
    if matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
        return false;
    }
    let low = err.to_string().to_ascii_lowercase();
    if low.contains("operation not permitted") || low.contains("permission denied") {
        return false;
    }
    if err.kind() == std::io::ErrorKind::NotFound {
        return true;
    }
    #[cfg(unix)]
    if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) {
        return true;
    }
    low.contains("no such file or directory")
        || low.contains("no such process")
        || low.contains("cannot find device")
        || low.contains("rtnetlink answers: no such file")
        || low.contains("rtnetlink answers: no such process")
        || (low.contains("device") && low.contains("does not exist"))
}

/// Roll back owned Linux policy rules, routes, and TUN link from a `LinuxRecoveryRecord`,
/// pruning items that succeeded or were already absent while returning `Some(remaining)` for any
/// genuinely failed mutations (e.g. non-root `EPERM`) so they stay in `network_recovery.json`
/// for subsequent recovery instead of leaving orphaned host routing state behind.
pub fn rollback_linux_record_with_runner<F>(
    rec: &crate::platform::recovery::LinuxRecoveryRecord,
    outcome: &mut crate::platform::recovery::RecoveryOutcome,
    run_cmd: &mut F,
) -> Option<crate::platform::recovery::LinuxRecoveryRecord>
where
    F: FnMut(&str, &[String]) -> std::io::Result<()>,
{
    let mut failed_v4_rev = Vec::new();
    for args in rec.owned_v4_rule_del_args.iter().rev() {
        let desc = format!("ip {}", args.join(" "));
        match run_cmd("ip", args) {
            Ok(()) => outcome.actions_executed.push(desc),
            Err(e) => {
                if !is_linux_benign_absent_error(&e) {
                    outcome.warnings.push(format!("{desc}: {e}"));
                    failed_v4_rev.push(args.clone());
                }
            }
        }
    }
    failed_v4_rev.reverse();

    let mut failed_v6_rev = Vec::new();
    for args in rec.owned_v6_rule_del_args.iter().rev() {
        let desc = format!("ip {}", args.join(" "));
        match run_cmd("ip", args) {
            Ok(()) => outcome.actions_executed.push(desc),
            Err(e) => {
                if !is_linux_benign_absent_error(&e) {
                    outcome.warnings.push(format!("{desc}: {e}"));
                    failed_v6_rev.push(args.clone());
                }
            }
        }
    }
    failed_v6_rev.reverse();

    let mut failed_routes_rev = Vec::new();
    for args in rec.owned_route_del_args.iter().rev() {
        let desc = format!("ip {}", args.join(" "));
        match run_cmd("ip", args) {
            Ok(()) => outcome.actions_executed.push(desc),
            Err(e) => {
                if !is_linux_benign_absent_error(&e) {
                    outcome.warnings.push(format!("{desc}: {e}"));
                    failed_routes_rev.push(args.clone());
                }
            }
        }
    }
    failed_routes_rev.reverse();

    let mut remaining_device_name = String::new();
    if !rec.device_name.is_empty() {
        let del_link = vec![
            "link".to_string(),
            "delete".to_string(),
            "dev".to_string(),
            rec.device_name.clone(),
        ];
        let desc = format!("ip link delete dev {}", rec.device_name);
        match run_cmd("ip", &del_link) {
            Ok(()) => outcome.actions_executed.push(desc),
            Err(e) => {
                if !is_linux_benign_absent_error(&e) {
                    outcome.warnings.push(format!("{desc}: {e}"));
                    remaining_device_name = rec.device_name.clone();
                }
            }
        }
    }

    let remaining = crate::platform::recovery::LinuxRecoveryRecord {
        device_name: remaining_device_name,
        route_table_id: rec.route_table_id,
        fwmark: rec.fwmark,
        owned_v4_rule_del_args: failed_v4_rev,
        owned_v6_rule_del_args: failed_v6_rev,
        owned_route_del_args: failed_routes_rev,
    };
    (!remaining.is_empty()).then_some(remaining)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ParsedLinuxIpRule {
    priority: Option<u32>,
    negated: bool,
    src: Option<ipnet::IpNet>,
    dst: Option<ipnet::IpNet>,
    fwmark: Option<(u32, u32)>,
    table: Option<String>,
    suppress_prefixlength: Option<u32>,
    extra: Vec<String>,
}

fn parse_rule_prefix(raw: &str) -> Option<Option<ipnet::IpNet>> {
    if raw.eq_ignore_ascii_case("all") {
        return Some(None);
    }
    let net = if let Ok(net) = raw.parse::<ipnet::IpNet>() {
        net.trunc()
    } else if let Ok(v4) = raw.parse::<std::net::Ipv4Addr>() {
        ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4, 32).ok()?)
    } else if let Ok(v6) = raw.parse::<std::net::Ipv6Addr>() {
        ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6, 128).ok()?)
    } else {
        return None;
    };
    if net.prefix_len() == 0 {
        Some(None)
    } else {
        Some(Some(net))
    }
}

fn parse_u32_hex_or_dec(raw: &str) -> Option<u32> {
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<u32>().ok()
    }
}

fn parse_rule_fwmark(raw: &str) -> Option<(u32, u32)> {
    if let Some((mark_s, mask_s)) = raw.split_once('/') {
        let mark = parse_u32_hex_or_dec(mark_s)?;
        let mask = parse_u32_hex_or_dec(mask_s)?;
        Some((mark, mask))
    } else {
        let mark = parse_u32_hex_or_dec(raw)?;
        Some((mark, u32::MAX))
    }
}

fn normalize_rule_table(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "255" | "local" => "local".to_string(),
        "254" | "main" => "main".to_string(),
        "253" | "default" => "default".to_string(),
        "0" | "unspec" => "unspec".to_string(),
        other => other.to_string(),
    }
}

fn parse_linux_ip_rule_tokens(tokens: &[&str]) -> Option<ParsedLinuxIpRule> {
    if tokens.is_empty() {
        return None;
    }
    let mut rule = ParsedLinuxIpRule::default();
    let mut idx = 0;

    if let Some(prio_str) = tokens[0].strip_suffix(':')
        && let Ok(prio) = prio_str.parse::<u32>()
    {
        rule.priority = Some(prio);
        idx = 1;
    }

    while idx < tokens.len() {
        match tokens[idx] {
            "not" => {
                rule.negated = true;
                idx += 1;
            }
            "pref" | "priority" | "order" => {
                let val = tokens.get(idx + 1)?;
                rule.priority = Some(val.parse::<u32>().ok()?);
                idx += 2;
            }
            "from" => {
                let val = tokens.get(idx + 1)?;
                rule.src = parse_rule_prefix(val)?;
                idx += 2;
            }
            "to" => {
                let val = tokens.get(idx + 1)?;
                rule.dst = parse_rule_prefix(val)?;
                idx += 2;
            }
            "fwmark" | "mark" => {
                let val = tokens.get(idx + 1)?;
                rule.fwmark = Some(parse_rule_fwmark(val)?);
                idx += 2;
            }
            "lookup" | "table" => {
                let val = tokens.get(idx + 1)?;
                rule.table = Some(normalize_rule_table(val));
                idx += 2;
            }
            "suppress_prefixlength" | "suppress_prefixlen" => {
                let val = tokens.get(idx + 1)?;
                rule.suppress_prefixlength = Some(val.parse::<u32>().ok()?);
                idx += 2;
            }
            other => {
                rule.extra.push(other.to_ascii_lowercase());
                idx += 1;
            }
        }
    }
    Some(rule)
}

/// Returns `true` if `ip [-4|-6] rule show` output (`show_output`) already contains a rule
/// semantically equivalent to `rule_spec`, handling real iproute2 formatting (`<pref>:\tfrom all`,
/// omitted `/32` or `/128` host masks, `not` placement, hex/decimal `fwmark` and implied
/// `/0xffffffff` mask, `lookup`/`table`, `pref`/`priority`, and `suppress_prefixlength`).
pub fn linux_ip_rule_exists(show_output: &str, rule_spec: &[&str]) -> bool {
    let Some(target) = parse_linux_ip_rule_tokens(rule_spec) else {
        return false;
    };
    show_output.lines().any(|line| {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(existing) = parse_linux_ip_rule_tokens(&tokens) else {
            return false;
        };
        let prio_matches = target.priority.is_none() || existing.priority == target.priority;
        prio_matches
            && existing.negated == target.negated
            && existing.src == target.src
            && existing.dst == target.dst
            && existing.fwmark == target.fwmark
            && existing.table == target.table
            && existing.suppress_prefixlength == target.suppress_prefixlength
            && existing.extra == target.extra
    })
}

/// Add a Linux policy rule only when no semantically equivalent rule already exists in
/// `ip <family> rule show`. Persists the planned `del` command into `network_recovery.json`
/// BEFORE invoking `ip <family> rule add` so an abrupt `SIGKILL` mid-setup leaves full
/// rollback commands on disk.
pub fn add_owned_rule_with_runner<F>(
    state_dir: &std::path::Path,
    rec: &mut crate::platform::recovery::LinuxRecoveryRecord,
    family_flag: &str,
    rule_spec: &[&str],
    run_ip_fn: &mut F,
) -> std::io::Result<()>
where
    F: FnMut(&[&str]) -> std::io::Result<String>,
{
    // Check if an identical rule already exists so we NEVER delete pre-existing host rules on teardown!
    let existing = run_ip_fn(&[family_flag, "rule", "show"]).unwrap_or_default();
    if linux_ip_rule_exists(&existing, rule_spec) {
        return Ok(());
    }

    let mut del_args = Vec::with_capacity(rule_spec.len() + 3);
    del_args.push(family_flag.to_string());
    del_args.push("rule".to_string());
    del_args.push("del".to_string());
    del_args.extend(rule_spec.iter().map(|s| (*s).to_string()));

    let is_v6 = family_flag == "-6";
    if is_v6 {
        rec.owned_v6_rule_del_args.push(del_args);
    } else {
        rec.owned_v4_rule_del_args.push(del_args);
    }

    // Persist planned rollback command BEFORE mutating kernel policy rules.
    let rec_snap = rec.clone();
    if let Err(err) = crate::platform::recovery::update_current_journal(state_dir, |j| {
        j.linux_tun = Some(rec_snap);
    }) {
        tracing::warn!("Linux TUN: failed persisting recovery journal before rule add: {err}");
    }

    let mut add_args = Vec::with_capacity(rule_spec.len() + 3);
    add_args.push(family_flag);
    add_args.push("rule");
    add_args.push("add");
    add_args.extend_from_slice(rule_spec);
    if let Err(err) = run_ip_fn(&add_args) {
        if is_v6 {
            rec.owned_v6_rule_del_args.pop();
        } else {
            rec.owned_v4_rule_del_args.pop();
        }
        let rec_after = rec.clone();
        let _ = crate::platform::recovery::update_current_journal(state_dir, |j| {
            j.linux_tun = Some(rec_after);
        });
        return Err(err);
    }
    Ok(())
}

/// Add/replace a Linux route, persisting its planned `del` command into `network_recovery.json`
/// BEFORE invoking `ip <family> route replace` so an abrupt `SIGKILL` mid-setup leaves full
/// rollback commands on disk.
pub fn add_owned_route_with_runner<F>(
    state_dir: &std::path::Path,
    rec: &mut crate::platform::recovery::LinuxRecoveryRecord,
    family_flag: &str,
    route_spec: &[&str],
    del_spec: &[&str],
    run_ip_fn: &mut F,
) -> std::io::Result<()>
where
    F: FnMut(&[&str]) -> std::io::Result<String>,
{
    let mut del_args = Vec::with_capacity(del_spec.len() + 3);
    del_args.push(family_flag.to_string());
    del_args.push("route".to_string());
    del_args.push("del".to_string());
    del_args.extend(del_spec.iter().map(|s| (*s).to_string()));
    rec.owned_route_del_args.push(del_args);

    // Persist planned rollback command BEFORE mutating kernel routing tables.
    let rec_snap = rec.clone();
    if let Err(err) = crate::platform::recovery::update_current_journal(state_dir, |j| {
        j.linux_tun = Some(rec_snap);
    }) {
        tracing::warn!("Linux TUN: failed persisting recovery journal before route replace: {err}");
    }

    let mut add_args = Vec::with_capacity(route_spec.len() + 3);
    add_args.push(family_flag);
    add_args.push("route");
    add_args.push("replace");
    add_args.extend_from_slice(route_spec);
    if let Err(err) = run_ip_fn(&add_args) {
        rec.owned_route_del_args.pop();
        let rec_after = rec.clone();
        let _ = crate::platform::recovery::update_current_journal(state_dir, |j| {
            j.linux_tun = Some(rec_after);
        });
        return Err(err);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn has_cap_net_admin() -> bool {
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }

    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_NET_ADMIN_BIT: u32 = 12;

    let mut hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData::default(); 2];
    // SAFETY: `SYS_capget` reads process capabilities into two 32-bit `CapUserData` structs per v3 ABI.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    (data[0].effective & (1u32 << CAP_NET_ADMIN_BIT)) != 0
}

#[cfg(target_os = "linux")]
fn resolve_ip_binary() -> &'static str {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if Path::new(candidate).exists() {
            return candidate;
        }
    }
    "ip"
}

#[cfg(target_os = "linux")]
fn run_ip(args: &[&str]) -> io::Result<String> {
    let bin = resolve_ip_binary();
    let out = std::process::Command::new(bin).args(args).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(io::Error::other(format!(
            "`{bin} {}` failed ({}): {}",
            args.join(" "),
            out.status,
            stderr.trim()
        )))
    }
}

#[cfg(target_os = "linux")]
fn run_ip_owned(args: &[String]) -> io::Result<String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ip(&refs)
}

#[cfg(target_os = "linux")]
pub fn detect_linux_default_egress() -> (Option<String>, Option<String>) {
    match run_ip(&["-4", "route", "show", "default", "table", "main"]) {
        Ok(stdout) => parse_linux_default_route(&stdout),
        Err(_) => (None, None),
    }
}

#[cfg(target_os = "linux")]
pub fn preflight_linux_tun() -> TunHealthSnapshot {
    let tun_dev_exists = Path::new("/dev/net/tun").exists();
    let cap_ok = has_cap_net_admin();
    let (egress_if, egress_gw) = detect_linux_default_egress();
    let hint = if !tun_dev_exists {
        Some("Kernel /dev/net/tun character device is missing (`modprobe tun`)".to_string())
    } else if !cap_ok {
        Some(
            "Grant minimal CAP_NET_ADMIN capability: `sudo setcap cap_net_admin+ep ./rust-clash` (or run via pkexec/root)"
                .to_string(),
        )
    } else {
        None
    };

    TunHealthSnapshot {
        platform: "linux".to_string(),
        backend: "linux-tun-policy-route".to_string(),
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
        privilege_ok: tun_dev_exists && cap_ok,
        privilege_hint: hint,
        driver_loaded: tun_dev_exists,
        network_transitions: 0,
        rx_packets: 0,
        tx_packets: 0,
        last_error: None,
    }
}

#[cfg(target_os = "linux")]
fn allocate_free_route_table() -> io::Result<u32> {
    let reserved: HashSet<u32> = fs::read_to_string("/etc/iproute2/rt_tables")
        .map(|s| parse_rt_tables_ids(&s))
        .unwrap_or_default();

    for candidate in 20220u32..=20320u32 {
        if reserved.contains(&candidate) {
            continue;
        }
        let c_str = candidate.to_string();
        let v4_empty = run_ip(&["-4", "route", "show", "table", &c_str])
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        let v6_empty = run_ip(&["-6", "route", "show", "table", &c_str])
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        if v4_empty && v6_empty {
            return Ok(candidate);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "unable to find an unused Linux policy routing table in 20220..=20320",
    ))
}

#[cfg(target_os = "linux")]
fn linux_ip_cmd_runner(program: &str, args: &[String]) -> io::Result<()> {
    if program == "ip" {
        run_ip_owned(args).map(|_| ())
    } else {
        let out = std::process::Command::new(program).args(args).output()?;
        if out.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(io::Error::other(format!(
                "`{program} {}` failed ({}): {}",
                args.join(" "),
                out.status,
                stderr.trim()
            )))
        }
    }
}

#[cfg(target_os = "linux")]
fn rollback_linux_record_and_finalize(
    rec: &LinuxRecoveryRecord,
    state_dir: &Path,
) -> RecoveryOutcome {
    let mut outcome = RecoveryOutcome::default();
    let remaining = rollback_linux_record_with_runner(rec, &mut outcome, &mut linux_ip_cmd_runner);
    for warn_msg in &outcome.warnings {
        tracing::warn!("Linux TUN teardown recovery warning: {warn_msg}");
    }
    if let Err(e) = finalize_linux_tun_teardown_journal(state_dir, remaining) {
        let msg = format!("failed updating Linux recovery journal: {e}");
        tracing::warn!("{msg}");
        outcome.warnings.push(msg);
    }
    outcome
}

#[cfg(target_os = "linux")]
fn add_owned_rule(
    state_dir: &Path,
    rec: &mut LinuxRecoveryRecord,
    family_flag: &str,
    rule_spec: &[&str],
) -> io::Result<()> {
    add_owned_rule_with_runner(state_dir, rec, family_flag, rule_spec, &mut run_ip)
}

#[cfg(target_os = "linux")]
fn add_owned_route(
    state_dir: &Path,
    rec: &mut LinuxRecoveryRecord,
    family_flag: &str,
    route_spec: &[&str],
    del_spec: &[&str],
) -> io::Result<()> {
    add_owned_route_with_runner(
        state_dir,
        rec,
        family_flag,
        route_spec,
        del_spec,
        &mut run_ip,
    )
}

#[cfg(target_os = "linux")]
pub struct LinuxSystemTunSession {
    spec: TunLaunchSpec,
    actual_device_name: String,
    route_table_id: Option<u32>,
    recovery_record: LinuxRecoveryRecord,
    stop_flag: Arc<AtomicBool>,
    stop_watch_tx: tokio::sync::watch::Sender<bool>,
    stopped: bool,
    rx_packets: Arc<AtomicU64>,
    tx_packets: Arc<AtomicU64>,
    network_transitions: Arc<AtomicU64>,
    egress_snapshot: Arc<Mutex<(Option<String>, Option<String>)>>,
    rx_thread: Option<JoinHandle<()>>,
    tx_thread: Option<JoinHandle<()>>,
    watch_thread: Option<JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl LinuxSystemTunSession {
    pub fn start(spec: TunLaunchSpec, handle: VirtualTunHandle) -> io::Result<Self> {
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;

        let dev_trimmed = spec.device_name.trim();
        if dev_trimmed.is_empty() || dev_trimmed.len() > 15 || !dev_trimmed.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Linux TUN interface name must be 1..=15 ASCII characters",
            ));
        }
        if !has_cap_net_admin() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Linux system TUN requires CAP_NET_ADMIN (`sudo setcap cap_net_admin+ep ./rust-clash`)",
            ));
        }

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        #[repr(C)]
        struct IfReq {
            ifr_name: [u8; 16],
            ifr_flags: libc::c_short,
            _pad: [u8; 22],
        }

        let mut ifr = IfReq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        ifr.ifr_name[..dev_trimmed.len()].copy_from_slice(dev_trimmed.as_bytes());

        // SAFETY: `file` is a valid `/dev/net/tun` descriptor and `ifr` matches Linux `struct ifreq`.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &raw mut ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let name_len = ifr
            .ifr_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ifr.ifr_name.len());
        let actual_name = String::from_utf8_lossy(&ifr.ifr_name[..name_len]).into_owned();

        // Install `SO_MARK` (`fwmark`) loop-prevention protector BEFORE enabling TUN routes!
        set_global_socket_protector(Arc::new(LinuxFwmarkProtector::new(
            DEFAULT_LINUX_FWMARK,
            spec.strict_route,
        )));

        let initial_egress = detect_linux_default_egress();
        let mut rec = LinuxRecoveryRecord {
            device_name: actual_name.clone(),
            route_table_id: 0,
            fwmark: DEFAULT_LINUX_FWMARK,
            owned_v4_rule_del_args: Vec::new(),
            owned_v6_rule_del_args: Vec::new(),
            owned_route_del_args: Vec::new(),
        };

        let setup_res = (|| -> io::Result<Option<u32>> {
            let gw_v4: Ipv4Addr = spec.gateway_ipv4();
            let v4_cidr = format!("{gw_v4}/{}", spec.fake_ip_net.prefix_len());
            let mtu_str = spec.mtu.clamp(1280, 65535).to_string();

            run_ip(&["-4", "addr", "replace", &v4_cidr, "dev", &actual_name])?;
            if spec.enable_ipv6 {
                let v6_str = spec.tun_ipv6_cidr.to_string();
                let _ = run_ip(&[
                    "-6",
                    "addr",
                    "replace",
                    &v6_str,
                    "dev",
                    &actual_name,
                    "nodad",
                ])
                .or_else(|_| run_ip(&["-6", "addr", "replace", &v6_str, "dev", &actual_name]));
            }
            run_ip(&["link", "set", "dev", &actual_name, "mtu", &mtu_str, "up"])?;

            if !spec.auto_route {
                return Ok(None);
            }

            let table_id = allocate_free_route_table()?;
            rec.route_table_id = table_id;
            let table_str = table_id.to_string();
            let mark_hex = format!("0x{DEFAULT_LINUX_FWMARK:x}");
            let fake_cidr = spec.fake_ip_net.trunc().to_string();

            // Persist initial journal BEFORE adding routing rules so an abrupt SIGKILL mid-setup recovers cleanly!
            let rec_snap = rec.clone();
            if let Err(err) =
                update_current_journal(&spec.state_dir, |j| j.linux_tun = Some(rec_snap))
            {
                tracing::warn!("Linux TUN: failed writing initial recovery journal: {err}");
            }

            // 1. Populate our dedicated collision-free policy table `<table_id>`
            add_owned_route(
                &spec.state_dir,
                &mut rec,
                "-4",
                &["default", "dev", &actual_name, "table", &table_str],
                &["default", "dev", &actual_name, "table", &table_str],
            )?;
            add_owned_route(
                &spec.state_dir,
                &mut rec,
                "-4",
                &[&fake_cidr, "dev", &actual_name],
                &[&fake_cidr, "dev", &actual_name],
            )?;

            // 2. High-priority explicit bypasses for proxy server IPs (plus upstream DNS IPs only
            //    when `dns_hijack` is disabled; when `dns_hijack` is active, RustClash's own upstream
            //    DNS sockets are `SO_MARK`-protected and bypass `pref 9020` without letting other
            //    Linux processes escape Fake-IP hijacking).
            let mut ipv6_bypass_ok = true;
            let all_bypass = select_linux_policy_bypass_ips(
                &spec.bypass_ips,
                &spec.dns_bypass_ips,
                spec.dns_hijack,
            );
            for ip in &all_bypass {
                match ip {
                    IpAddr::V4(v4) if !v4.is_loopback() && !spec.fake_ip_net.contains(v4) => {
                        let host_cidr = format!("{v4}/32");
                        add_owned_rule(
                            &spec.state_dir,
                            &mut rec,
                            "-4",
                            &["pref", "8990", "to", &host_cidr, "lookup", "main"],
                        )?;
                    }
                    IpAddr::V6(v6) if spec.enable_ipv6 && !v6.is_loopback() => {
                        let host_cidr = format!("{v6}/128");
                        if let Err(err) = add_owned_rule(
                            &spec.state_dir,
                            &mut rec,
                            "-6",
                            &["pref", "8990", "to", &host_cidr, "lookup", "main"],
                        ) {
                            tracing::warn!(
                                "Linux TUN: failed adding IPv6 bypass rule for {host_cidr} ({err}); IPv6 catch-all TUN capture will be skipped to prevent routing loops"
                            );
                            ipv6_bypass_ok = false;
                        }
                    }
                    _ => {}
                }
            }

            // 2b. User-configured `tun.route-exclude-address` CIDR bypasses (`pref 8995` -> `main`).
            let (exclude_v4, exclude_v6) = plan_linux_exclude_cidr_rules(
                &spec.route_exclude_cidrs,
                spec.fake_ip_net,
                spec.tun_ipv6_cidr,
                spec.enable_ipv6,
            );
            for cidr in &exclude_v4 {
                add_owned_rule(
                    &spec.state_dir,
                    &mut rec,
                    "-4",
                    &["pref", "8995", "to", cidr, "lookup", "main"],
                )?;
            }
            for cidr in &exclude_v6 {
                if let Err(err) = add_owned_rule(
                    &spec.state_dir,
                    &mut rec,
                    "-6",
                    &["pref", "8995", "to", cidr, "lookup", "main"],
                ) {
                    tracing::warn!(
                        "Linux TUN: failed adding IPv6 route-exclude-address rule for {cidr} ({err})"
                    );
                    ipv6_bypass_ok = false;
                }
            }

            // 3. Bypass loopback & RFC1918 private subnets (in `strict_route`, only loopback & link-local bypass)
            let v4_bypasses: &[&str] = if spec.strict_route {
                &["127.0.0.0/8", "169.254.0.0/16"]
            } else {
                &[
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "100.64.0.0/10",
                    "169.254.0.0/16",
                ]
            };
            for cidr in v4_bypasses {
                add_owned_rule(
                    &spec.state_dir,
                    &mut rec,
                    "-4",
                    &["pref", "9000", "to", cidr, "lookup", "main"],
                )?;
            }

            // 4. Route Fake-IP range unconditionally to `<table_id>`
            add_owned_rule(
                &spec.state_dir,
                &mut rec,
                "-4",
                &["pref", "9010", "to", &fake_cidr, "lookup", &table_str],
            )?;

            // 5. Consult `main` for all non-default local subnet routes (`suppress_prefixlength 0`),
            //    then capture all unmarked (`not fwmark 0x1a5`) default IPv4 traffic into `<table_id>`!
            add_owned_rule(
                &spec.state_dir,
                &mut rec,
                "-4",
                &[
                    "pref",
                    "9015",
                    "lookup",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
            )?;
            add_owned_rule(
                &spec.state_dir,
                &mut rec,
                "-4",
                &[
                    "pref", "9020", "not", "fwmark", &mark_hex, "lookup", &table_str,
                ],
            )?;

            // 6. IPv6 default-route interception when `tun.ipv6: true`
            //    Install bypass & suppress rules FIRST; if any fail, skip the catch-all IPv6
            //    default route and `pref 9020` capture rule so an unguarded IPv6 loop never occurs.
            if spec.enable_ipv6 {
                for v6_local in ["::1/128", "fe80::/10"] {
                    if let Err(err) = add_owned_rule(
                        &spec.state_dir,
                        &mut rec,
                        "-6",
                        &["pref", "9000", "to", v6_local, "lookup", "main"],
                    ) {
                        tracing::warn!(
                            "Linux TUN: failed adding IPv6 local bypass rule for {v6_local} ({err})"
                        );
                        ipv6_bypass_ok = false;
                    }
                }
                if let Err(err) = add_owned_rule(
                    &spec.state_dir,
                    &mut rec,
                    "-6",
                    &[
                        "pref",
                        "9015",
                        "lookup",
                        "main",
                        "suppress_prefixlength",
                        "0",
                    ],
                ) {
                    tracing::warn!(
                        "Linux TUN: failed adding IPv6 suppress_prefixlength 0 rule ({err})"
                    );
                    ipv6_bypass_ok = false;
                }

                if ipv6_bypass_ok {
                    add_owned_route(
                        &spec.state_dir,
                        &mut rec,
                        "-6",
                        &["default", "dev", &actual_name, "table", &table_str],
                        &["default", "dev", &actual_name, "table", &table_str],
                    )?;
                    add_owned_rule(
                        &spec.state_dir,
                        &mut rec,
                        "-6",
                        &[
                            "pref", "9020", "not", "fwmark", &mark_hex, "lookup", &table_str,
                        ],
                    )?;
                } else {
                    tracing::warn!(
                        "Linux TUN: skipping IPv6 catch-all default route and pref 9020 rule because one or more IPv6 bypass/suppress rules failed"
                    );
                }
            }

            // 7. Per-link DNS registration with `systemd-resolved` (`spec.dns_ipv4()`, domain `~.`)
            //    Automatically purged by `systemd-resolved` when the TUN kernel interface closes.
            let dns_peer = spec.dns_ipv4().to_string();
            let mut resolved_registered = false;
            let mut resolved_err_detail: Option<String> = None;
            if let Some(resolvectl_bin) = resolve_resolvectl_binary() {
                let dns_res = std::process::Command::new(&resolvectl_bin)
                    .args(["dns", &actual_name, &dns_peer])
                    .output();
                let dom_res = std::process::Command::new(&resolvectl_bin)
                    .args(["domain", &actual_name, "~."])
                    .output();
                match (dns_res, dom_res) {
                    (Ok(d_out), Ok(m_out)) if d_out.status.success() && m_out.status.success() => {
                        resolved_registered = true;
                        flush_linux_resolved_cache();
                    }
                    (dns_r, dom_r) => {
                        let fmt_out = |res: io::Result<std::process::Output>| match res {
                            Ok(o) if o.status.success() => "ok".to_string(),
                            Ok(o) => {
                                let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                                if stderr.is_empty() {
                                    format!("exit {}", o.status)
                                } else {
                                    format!("{} ({stderr})", o.status)
                                }
                            }
                            Err(e) => e.to_string(),
                        };
                        resolved_err_detail = Some(format!(
                            "`{}` failed (dns: {}, domain: {})",
                            resolvectl_bin.display(),
                            fmt_out(dns_r),
                            fmt_out(dom_r),
                        ));
                    }
                }
            }
            if !resolved_registered {
                let resolv_nameservers = fs::read_to_string("/etc/resolv.conf")
                    .map(|s| parse_resolv_conf_nameservers(&s))
                    .unwrap_or_default();
                let bypass_note = if all_nameservers_bypass_tun(
                    &resolv_nameservers,
                    &all_bypass,
                    spec.strict_route,
                ) {
                    format!(
                        "; `/etc/resolv.conf` nameservers ({resolv_nameservers:?}) match TUN bypass rules, so system DNS queries may bypass `{actual_name}` unless system DNS points to `{dns_peer}` (or `dns.listen`)"
                    )
                } else {
                    String::new()
                };
                match resolved_err_detail {
                    Some(detail) => tracing::warn!(
                        "Linux TUN: `systemd-resolved` is not active or rejected per-link DNS on `{actual_name}` ({detail}){bypass_note}"
                    ),
                    None => tracing::warn!(
                        "Linux TUN: `resolvectl` was not found in `/usr/bin`, `/bin`, `/run/current-system/sw/bin`, or `PATH` (`systemd-resolved` is not active){bypass_note}"
                    ),
                }
            }

            let rec_final = rec.clone();
            update_current_journal(&spec.state_dir, |j| j.linux_tun = Some(rec_final))?;
            Ok(Some(table_id))
        })();

        let route_table_id = match setup_res {
            Ok(id) => id,
            Err(err) => {
                drop(file);
                clear_global_socket_protector();
                let _ = rollback_linux_record_and_finalize(&rec, &spec.state_dir);
                return Err(err);
            }
        };

        let writer_file = match file.try_clone() {
            Ok(wf) => wf,
            Err(err) => {
                drop(file);
                clear_global_socket_protector();
                let _ = rollback_linux_record_and_finalize(&rec, &spec.state_dir);
                return Err(err);
            }
        };

        // Put reader fd into `O_NONBLOCK` and poll with 200ms timeout so `stop()` joins promptly!
        // SAFETY: `file` is a valid open descriptor; `F_GETFL`/`F_SETFL` with `O_NONBLOCK` is POSIX-safe.
        unsafe {
            let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (stop_watch_tx, mut stop_watch_rx) = tokio::sync::watch::channel(false);
        let rx_packets = Arc::new(AtomicU64::new(0));
        let tx_packets = Arc::new(AtomicU64::new(0));
        let network_transitions = Arc::new(AtomicU64::new(0));
        let egress_snapshot = Arc::new(Mutex::new(initial_egress));

        let VirtualTunHandle {
            ingress_tx,
            mut egress_rx,
        } = handle;

        let stop_rx = Arc::clone(&stop_flag);
        let rx_cnt = Arc::clone(&rx_packets);
        let rx_thread = match std::thread::Builder::new()
            .name("tun-linux-rx".into())
            .spawn(move || {
                let mut f = file;
                let mut buf = vec![0u8; 65535];
                while !stop_rx.load(Ordering::Acquire) {
                    let mut pfd = libc::pollfd {
                        fd: f.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: `pfd` references `f`'s valid fd for the duration of `poll`.
                    let prc = unsafe { libc::poll(&raw mut pfd, 1, 50) };
                    if prc <= 0 {
                        continue;
                    }
                    loop {
                        if stop_rx.load(Ordering::Acquire) {
                            return;
                        }
                        match f.read(&mut buf) {
                            Ok(0) => return,
                            Ok(n) => {
                                rx_cnt.fetch_add(1, Ordering::Relaxed);
                                let mut pkt = buf[..n].to_vec();
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
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => return,
                        }
                    }
                }
            }) {
            Ok(h) => h,
            Err(err) => {
                stop_flag.store(true, Ordering::Release);
                let _ = stop_watch_tx.send(true);
                drop(writer_file);
                clear_global_socket_protector();
                let _ = rollback_linux_record_and_finalize(&rec, &spec.state_dir);
                return Err(err);
            }
        };

        let stop_tx = Arc::clone(&stop_flag);
        let tx_cnt = Arc::clone(&tx_packets);
        let tx_thread = match std::thread::Builder::new()
            .name("tun-linux-tx".into())
            .spawn(move || {
                let f = writer_file;
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
                                if pkt.is_empty() {
                                    continue;
                                }
                                if write_tun_packet_pollout_safe(f.as_raw_fd(), &pkt, &stop_tx) {
                                    tx_cnt.fetch_add(1, Ordering::Relaxed);
                                } else if stop_tx.load(Ordering::Acquire) {
                                    break;
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
                let _ = rollback_linux_record_and_finalize(&rec, &spec.state_dir);
                return Err(err);
            }
        };

        let stop_watch = Arc::clone(&stop_flag);
        let egress_watch = Arc::clone(&egress_snapshot);
        let transitions_watch = Arc::clone(&network_transitions);
        let dns_watch = spec.dns_engine.clone();
        let net_hook_watch = spec.network_change_hook.clone();
        let watch_thread = match std::thread::Builder::new()
            .name("tun-linux-netwatch".into())
            .spawn(move || {
                while !stop_watch.load(Ordering::Acquire) {
                    for _ in 0..60 {
                        if stop_watch.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    let latest = detect_linux_default_egress();
                    let mut guard = egress_watch.lock();
                    if *guard != latest {
                        *guard = latest;
                        drop(guard);
                        flush_linux_resolved_cache();
                        transitions_watch.fetch_add(1, Ordering::Relaxed);
                        if let Some(hook) = &net_hook_watch {
                            hook();
                        } else if let Some(dns) = &dns_watch {
                            dns.flush_cache();
                        }
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
                let _ = rollback_linux_record_and_finalize(&rec, &spec.state_dir);
                return Err(err);
            }
        };

        Ok(Self {
            spec,
            actual_device_name: actual_name,
            route_table_id,
            recovery_record: rec,
            stop_flag,
            stop_watch_tx,
            stopped: false,
            rx_packets,
            tx_packets,
            network_transitions,
            egress_snapshot,
            rx_thread: Some(rx_thread),
            tx_thread: Some(tx_thread),
            watch_thread: Some(watch_thread),
        })
    }
}

#[cfg(target_os = "linux")]
impl SystemTunSession for LinuxSystemTunSession {
    fn health(&self) -> TunHealthSnapshot {
        let (egress_if, egress_gw) = self.egress_snapshot.lock().clone();
        TunHealthSnapshot {
            platform: "linux".to_string(),
            backend: "linux-tun-policy-route".to_string(),
            active: !self.stopped,
            device_name: Some(self.actual_device_name.clone()),
            mtu: self.spec.mtu,
            ipv4_cidr: Some(self.spec.ipv4_host_cidr_string()),
            ipv6_cidr: self
                .spec
                .enable_ipv6
                .then(|| self.spec.tun_ipv6_cidr.to_string()),
            auto_route_applied: self.spec.auto_route,
            strict_route_applied: self.spec.auto_route && self.spec.strict_route,
            route_table_id: self.route_table_id,
            default_egress_iface: egress_if,
            default_egress_gateway: egress_gw,
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
        if let Some(h) = self.watch_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.rx_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.tx_thread.take() {
            let _ = h.join();
        }
        let _ = rollback_linux_record_and_finalize(&self.recovery_record, &self.spec.state_dir);
        flush_linux_resolved_cache();
        clear_global_socket_protector();
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxSystemTunSession {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(target_os = "linux")]
fn write_tun_packet_pollout_safe(
    fd: std::os::fd::RawFd,
    pkt: &[u8],
    stop_flag: &AtomicBool,
) -> bool {
    loop {
        if stop_flag.load(Ordering::Acquire) {
            return false;
        }
        // SAFETY: `write` reads at most `pkt.len()` bytes from `pkt` on valid `fd`.
        let written = unsafe { libc::write(fd, pkt.as_ptr().cast::<libc::c_void>(), pkt.len()) };
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
        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_default_route_and_rt_tables_cleanly() {
        let sample = "default via 192.168.50.1 dev wlan0 proto dhcp src 192.168.50.42 metric 600\n";
        let (dev, gw) = parse_linux_default_route(sample);
        assert_eq!(dev.as_deref(), Some("wlan0"));
        assert_eq!(gw.as_deref(), Some("192.168.50.1"));

        let rt = "# comment\n255\tlocal\n254\tmain\n20220\twg0\n";
        let ids = parse_rt_tables_ids(rt);
        assert!(ids.contains(&254));
        assert!(ids.contains(&20220));
        assert!(!ids.contains(&20221));
    }

    #[test]
    fn resolves_resolvectl_from_nixos_or_path_and_detects_bypassed_resolv_conf() {
        let base = std::env::temp_dir().join(format!("rc-linux-dns-test-{}", uuid::Uuid::new_v4()));
        let nixos_sw = base.join("nixos-sw").join("bin");
        let custom_path_dir = base.join("custom-bin");
        std::fs::create_dir_all(&nixos_sw).unwrap();
        std::fs::create_dir_all(&custom_path_dir).unwrap();

        let nixos_bin = nixos_sw.join("resolvectl");
        let path_bin = custom_path_dir.join("resolvectl");
        std::fs::write(&nixos_bin, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&path_bin, b"#!/bin/sh\nexit 0\n").unwrap();

        let missing = base.join("missing").join("resolvectl");
        let missing_s = missing.to_string_lossy().into_owned();
        let nixos_s = nixos_bin.to_string_lossy().into_owned();

        // Candidate list hit (e.g. `/run/current-system/sw/bin/resolvectl` on NixOS)
        let found_cand =
            resolve_resolvectl_binary_with_paths(&[&missing_s, &nixos_s], None).unwrap();
        assert_eq!(found_cand, nixos_bin);

        // `PATH` fallback hit when standard candidate paths do not exist
        let joined_path = std::env::join_paths([&custom_path_dir]).unwrap();
        let found_path =
            resolve_resolvectl_binary_with_paths(&[&missing_s], Some(&joined_path)).unwrap();
        assert_eq!(found_path, path_bin);

        // Absent everywhere -> `None`
        assert!(resolve_resolvectl_binary_with_paths(&[&missing_s], None).is_none());

        // `/etc/resolv.conf` parsing and TUN bypass detection
        let resolv = "\
            # Generated by NetworkManager\n\
            search lan\n\
            nameserver 192.168.1.1 # router\n\
            nameserver 1.1.1.1\n\
            nameserver fe80::1%wlan0\n";
        let ns = parse_resolv_conf_nameservers(resolv);
        assert_eq!(
            ns,
            vec![
                "192.168.1.1".parse::<std::net::IpAddr>().unwrap(),
                "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
                "fe80::1".parse::<std::net::IpAddr>().unwrap(),
            ]
        );

        let bypass_ips = vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()];
        // `192.168.1.1` (RFC1918), `1.1.1.1` (`pref 8990` bypass_ips), `fe80::1` (link-local) all bypass when !strict_route
        assert!(all_nameservers_bypass_tun(&ns, &bypass_ips, false));
        // Under `strict_route`, RFC1918 `192.168.1.1` is captured into TUN (`!all_nameservers_bypass_tun`)
        assert!(!all_nameservers_bypass_tun(&ns, &bypass_ips, true));
        // With `8.8.8.8` (not in `bypass_ips`), DNS will enter TUN and be hijacked by Fake-IP DNS
        let ns_public = parse_resolv_conf_nameservers("nameserver 8.8.8.8\n");
        assert!(!all_nameservers_bypass_tun(&ns_public, &bypass_ips, false));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn select_linux_policy_bypass_ips_omits_dns_when_hijack_is_active() {
        let proxy_v4: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let proxy_v6: std::net::IpAddr = "2001:db8::10".parse().unwrap();
        let dns_v4: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        let dns_v6: std::net::IpAddr = "2606:4700:4700::1111".parse().unwrap();

        // With `dns_hijack = true`, `SO_MARK` protects RustClash's own DNS sockets, so public DNS
        // resolvers MUST NOT receive global `pref 8990` bypass rules that other apps could exploit.
        let hijacked = select_linux_policy_bypass_ips(
            &[proxy_v4, proxy_v6],
            &[dns_v4, dns_v6, proxy_v4],
            true,
        );
        assert_eq!(hijacked, vec![proxy_v4, proxy_v6]);

        // With `dns_hijack = false`, deduplicated DNS bypass IPs are included alongside proxy IPs.
        let no_hijack = select_linux_policy_bypass_ips(
            &[proxy_v4, proxy_v6],
            &[dns_v4, dns_v6, proxy_v4],
            false,
        );
        assert_eq!(no_hijack, vec![proxy_v4, proxy_v6, dns_v4, dns_v6]);
    }

    #[test]
    fn parse_resolvectl_and_plan_linux_exclude_cidrs() {
        let out = "Link 2 (enp3s0): 192.168.50.1 10.0.0.53#corp.dns fe80::1%enp3s0 192.168.50.1\n";
        let ips = parse_resolvectl_dns_output(out);
        assert_eq!(
            ips,
            vec![
                "192.168.50.1".parse::<std::net::IpAddr>().unwrap(),
                "10.0.0.53".parse::<std::net::IpAddr>().unwrap(),
                "fe80::1".parse::<std::net::IpAddr>().unwrap(),
            ]
        );

        let fake_net: ipnet::Ipv4Net = "198.18.0.0/15".parse().unwrap();
        let tun_v6: ipnet::Ipv6Net = "fdfe:dcba:9876::1/126".parse().unwrap();
        let cidrs: Vec<ipnet::IpNet> = vec![
            "192.168.0.0/16".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
            "198.18.1.0/24".parse().unwrap(), // overlaps fake-ip -> dropped
            "0.0.0.0/1".parse().unwrap(),     // prefix <= 1 -> dropped
            "fc00::/7".parse().unwrap(),      // broader than /126 -> kept
            "fdfe:dcba:9876::/126".parse().unwrap(), // exact TUN v6 overlap -> dropped
        ];
        let (v4, v6) = plan_linux_exclude_cidr_rules(&cidrs, fake_net, tun_v6, true);
        assert_eq!(v4, vec!["192.168.0.0/16", "10.0.0.0/8"]);
        assert_eq!(v6, vec!["fc00::/7"]);

        let (v4_only, v6_disabled) = plan_linux_exclude_cidr_rules(&cidrs, fake_net, tun_v6, false);
        assert_eq!(v4_only, vec!["192.168.0.0/16", "10.0.0.0/8"]);
        assert!(v6_disabled.is_empty());
    }

    #[test]
    fn linux_ip_rule_exists_matches_real_iproute2_v4_and_v6_formats() {
        let show_v4 = "\
0:\tfrom all lookup local
8990:\tfrom all to 1.2.3.4 lookup main
8995:\tfrom all to 192.168.0.0/16 lookup main
9000:\tfrom all to 127.0.0.0/8 lookup main
9010:\tfrom all to 198.18.0.0/15 lookup 20220
9015:\tfrom all lookup main suppress_prefixlength 0
9020:\tnot from all fwmark 0x1a5 lookup 20220
9021:\tnot from all fwmark 0x1a5/0xffff lookup 20220
9025:\tfrom 10.0.0.1 to 1.2.3.4 lookup main
9026:\tfrom all to 1.2.3.40 lookup main
9027:\tfrom all to 1.2.3.4 iif eth0 lookup main
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";
        let show_v6 = "\
0:\tfrom all lookup local
8990:\tfrom all to 2001:db8::1 lookup main
8995:\tfrom all to fc00::/7 lookup main
9000:\tfrom all to ::1 lookup main
9000:\tfrom all to fe80::/10 lookup main
9015:\tfrom all lookup main suppress_prefixlength 0
9020:\tnot from all fwmark 0x1a5/0xffffffff lookup 20220
32766:\tfrom all lookup main
";

        // Positive matches normalizing bare `/32`, `/128`, `from all`, `not`, hex/dec fwmark & mask,
        // `pref`/`priority`, `lookup`/`table`, `254`/`main`, and `suppress_prefixlength`.
        assert!(linux_ip_rule_exists(
            show_v4,
            &["pref", "8990", "to", "1.2.3.4/32", "lookup", "main"]
        ));
        assert!(linux_ip_rule_exists(
            show_v4,
            &["priority", "8990", "to", "1.2.3.4/32", "table", "254"]
        ));
        assert!(linux_ip_rule_exists(
            show_v4,
            &["pref", "9010", "to", "198.18.0.0/15", "lookup", "20220"]
        ));
        assert!(linux_ip_rule_exists(
            show_v4,
            &[
                "pref",
                "9015",
                "lookup",
                "main",
                "suppress_prefixlength",
                "0"
            ]
        ));
        assert!(linux_ip_rule_exists(
            show_v4,
            &["pref", "9020", "not", "fwmark", "0x1a5", "lookup", "20220"]
        ));
        assert!(linux_ip_rule_exists(
            show_v4,
            &["pref", "9020", "not", "fwmark", "421", "lookup", "20220"]
        ));
        assert!(linux_ip_rule_exists(
            show_v4,
            &[
                "pref",
                "9020",
                "not",
                "fwmark",
                "0x1a5/0xffffffff",
                "lookup",
                "20220"
            ]
        ));
        assert!(linux_ip_rule_exists(
            show_v4,
            &[
                "pref",
                "9021",
                "not",
                "fwmark",
                "421/65535",
                "lookup",
                "20220"
            ]
        ));

        // IPv6 canonicalization (`2001:0db8::1/128` == `2001:db8::1`, `::1/128` == `::1`)
        assert!(linux_ip_rule_exists(
            show_v6,
            &["pref", "8990", "to", "2001:0db8::1/128", "lookup", "main"]
        ));
        assert!(linux_ip_rule_exists(
            show_v6,
            &["pref", "9000", "to", "::1/128", "lookup", "main"]
        ));
        assert!(linux_ip_rule_exists(
            show_v6,
            &["pref", "9000", "to", "fe80::/10", "lookup", "main"]
        ));
        assert!(linux_ip_rule_exists(
            show_v6,
            &["pref", "9020", "not", "fwmark", "0x1a5", "lookup", "20220"]
        ));

        // Negative cases: MUST NOT produce false positives!
        assert!(!linux_ip_rule_exists(
            show_v4,
            &["pref", "8991", "to", "1.2.3.4/32", "lookup", "main"]
        ));
        assert!(!linux_ip_rule_exists(
            show_v4,
            &["pref", "9026", "to", "1.2.3.4/32", "lookup", "main"]
        ));
        assert!(!linux_ip_rule_exists(
            show_v4,
            &["pref", "9025", "to", "1.2.3.4/32", "lookup", "main"]
        ));
        assert!(!linux_ip_rule_exists(
            show_v4,
            &["pref", "9027", "to", "1.2.3.4/32", "lookup", "main"]
        ));
        assert!(!linux_ip_rule_exists(
            show_v4,
            &["pref", "9020", "fwmark", "0x1a5", "lookup", "20220"]
        ));
        assert!(!linux_ip_rule_exists(
            show_v4,
            &["pref", "9021", "not", "fwmark", "0x1a5", "lookup", "20220"]
        ));
        assert!(!linux_ip_rule_exists(
            show_v4,
            &[
                "pref",
                "9015",
                "lookup",
                "main",
                "suppress_prefixlength",
                "1"
            ]
        ));
        assert!(!linux_ip_rule_exists(
            show_v4,
            &["pref", "9015", "lookup", "main"]
        ));
        assert!(!linux_ip_rule_exists(show_v4, &[]));
    }

    #[test]
    fn is_linux_benign_absent_error_distinguishes_absent_from_eperm() {
        assert!(is_linux_benign_absent_error(&std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No such file or directory",
        )));
        assert!(is_linux_benign_absent_error(&std::io::Error::other(
            "RTNETLINK answers: No such file or directory",
        )));
        assert!(is_linux_benign_absent_error(&std::io::Error::other(
            "RTNETLINK answers: No such process",
        )));
        assert!(is_linux_benign_absent_error(&std::io::Error::other(
            "Cannot find device \"Clash0\"",
        )));
        assert!(is_linux_benign_absent_error(&std::io::Error::other(
            "Device \"Clash0\" does not exist.",
        )));

        assert!(!is_linux_benign_absent_error(&std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        )));
        assert!(!is_linux_benign_absent_error(&std::io::Error::other(
            "RTNETLINK answers: Operation not permitted",
        )));
        assert!(!is_linux_benign_absent_error(&std::io::Error::other(
            "RTNETLINK answers: File exists",
        )));
        #[cfg(unix)]
        {
            assert!(is_linux_benign_absent_error(
                &std::io::Error::from_raw_os_error(libc::ENOENT)
            ));
            assert!(is_linux_benign_absent_error(
                &std::io::Error::from_raw_os_error(libc::ESRCH)
            ));
            assert!(!is_linux_benign_absent_error(
                &std::io::Error::from_raw_os_error(libc::EPERM)
            ));
            assert!(!is_linux_benign_absent_error(
                &std::io::Error::from_raw_os_error(libc::EACCES)
            ));
        }
    }

    #[test]
    fn rollback_linux_record_with_runner_prunes_succeeded_and_benign_absent_retains_eperm() {
        let r1 = vec![
            "-4".into(),
            "rule".into(),
            "del".into(),
            "pref".into(),
            "8990".into(),
        ];
        let r2 = vec![
            "-4".into(),
            "rule".into(),
            "del".into(),
            "pref".into(),
            "9020".into(),
        ];
        let r6 = vec![
            "-6".into(),
            "rule".into(),
            "del".into(),
            "pref".into(),
            "9020".into(),
        ];
        let rt = vec![
            "-4".into(),
            "route".into(),
            "del".into(),
            "default".into(),
            "dev".into(),
            "Clash0".into(),
            "table".into(),
            "20220".into(),
        ];
        let rec = crate::platform::recovery::LinuxRecoveryRecord {
            device_name: "Clash0".into(),
            route_table_id: 20220,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: vec![r1.clone(), r2.clone()],
            owned_v6_rule_del_args: vec![r6.clone()],
            owned_route_del_args: vec![rt.clone()],
        };

        let mut outcome = crate::platform::recovery::RecoveryOutcome::default();
        let mut seen = Vec::new();
        let rem = rollback_linux_record_with_runner(&rec, &mut outcome, &mut |prog, args| {
            let cmd = format!("{prog} {}", args.join(" "));
            seen.push(cmd.clone());
            if cmd.contains("pref 9020") && cmd.contains("-4") {
                Err(std::io::Error::other(
                    "RTNETLINK answers: Operation not permitted",
                ))
            } else if cmd.contains("pref 8990") {
                Ok(())
            } else if cmd.contains("-6") {
                Err(std::io::Error::other("RTNETLINK answers: No such process"))
            } else {
                Err(std::io::Error::other("Cannot find device \"Clash0\""))
            }
        })
        .expect("EPERM rule must remain");

        // LIFO order for v4 rules (`9020` before `8990`), followed by v6, routes, and link delete.
        assert_eq!(seen[0], "ip -4 rule del pref 9020");
        assert_eq!(seen[1], "ip -4 rule del pref 8990");
        assert_eq!(seen[2], "ip -6 rule del pref 9020");
        assert_eq!(seen[3], "ip -4 route del default dev Clash0 table 20220");
        assert_eq!(seen[4], "ip link delete dev Clash0");

        assert_eq!(rem.owned_v4_rule_del_args, vec![r2]);
        assert!(rem.owned_v6_rule_del_args.is_empty());
        assert!(rem.owned_route_del_args.is_empty());
        assert!(rem.device_name.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert_eq!(outcome.actions_executed, vec!["ip -4 rule del pref 8990"]);
    }

    #[test]
    fn add_owned_rule_and_route_persist_journal_before_mutation_and_dedup_existing() {
        let dir = std::env::temp_dir().join(format!(
            "rc-linux-prepersist-journal-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut rec = crate::platform::recovery::LinuxRecoveryRecord {
            device_name: "Clash0".into(),
            route_table_id: 20220,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: Vec::new(),
            owned_v6_rule_del_args: Vec::new(),
            owned_route_del_args: Vec::new(),
        };

        // 1. Pre-existing host rule formatted as real `ip -4 rule show` output MUST be deduplicated
        //    without running `rule add` or recording into `rec` / `network_recovery.json`.
        let mut add_called = false;
        add_owned_rule_with_runner(
            &dir,
            &mut rec,
            "-4",
            &["pref", "8990", "to", "1.2.3.4/32", "lookup", "main"],
            &mut |args| {
                if args == ["-4", "rule", "show"] {
                    Ok("8990:\tfrom all to 1.2.3.4 lookup main\n".into())
                } else {
                    add_called = true;
                    Ok(String::new())
                }
            },
        )
        .unwrap();
        assert!(
            !add_called,
            "existing host rule must not be re-added or recorded as owned"
        );
        assert!(rec.owned_v4_rule_del_args.is_empty());

        // 2. Adding a new route MUST persist its `del` command on disk BEFORE `route replace` executes!
        let mut saw_route_on_disk_before_exec = false;
        add_owned_route_with_runner(
            &dir,
            &mut rec,
            "-4",
            &["default", "dev", "Clash0", "table", "20220"],
            &["default", "dev", "Clash0", "table", "20220"],
            &mut |args| {
                assert_eq!(args[1], "route");
                assert_eq!(args[2], "replace");
                let on_disk = crate::platform::recovery::RecoveryJournal::load_from(&dir)
                    .unwrap()
                    .expect("journal must already exist on disk before route replace executes");
                let lt = on_disk.linux_tun.expect("linux_tun present on disk");
                saw_route_on_disk_before_exec = lt.owned_route_del_args.iter().any(|d| {
                    d == &vec![
                        "-4".to_string(),
                        "route".to_string(),
                        "del".to_string(),
                        "default".to_string(),
                        "dev".to_string(),
                        "Clash0".to_string(),
                        "table".to_string(),
                        "20220".to_string(),
                    ]
                });
                Ok(String::new())
            },
        )
        .unwrap();
        assert!(saw_route_on_disk_before_exec);

        // 3. Adding a new rule MUST persist its `del` command on disk BEFORE `rule add` executes!
        let mut saw_rule_on_disk_before_exec = false;
        add_owned_rule_with_runner(
            &dir,
            &mut rec,
            "-4",
            &["pref", "9020", "not", "fwmark", "0x1a5", "lookup", "20220"],
            &mut |args| {
                if args == ["-4", "rule", "show"] {
                    return Ok("0:\tfrom all lookup local\n32766:\tfrom all lookup main\n".into());
                }
                assert_eq!(args[1], "rule");
                assert_eq!(args[2], "add");
                let on_disk = crate::platform::recovery::RecoveryJournal::load_from(&dir)
                    .unwrap()
                    .expect("journal must already exist on disk before rule add executes");
                let lt = on_disk.linux_tun.expect("linux_tun present on disk");
                saw_rule_on_disk_before_exec = lt.owned_v4_rule_del_args.iter().any(|d| {
                    d == &vec![
                        "-4".to_string(),
                        "rule".to_string(),
                        "del".to_string(),
                        "pref".to_string(),
                        "9020".to_string(),
                        "not".to_string(),
                        "fwmark".to_string(),
                        "0x1a5".to_string(),
                        "lookup".to_string(),
                        "20220".to_string(),
                    ]
                });
                Ok(String::new())
            },
        )
        .unwrap();
        assert!(saw_rule_on_disk_before_exec);

        // 4. If `rule add` fails cleanly, the un-added `del_args` is popped and re-synced cleanly.
        let err = add_owned_rule_with_runner(
            &dir,
            &mut rec,
            "-6",
            &["pref", "9000", "to", "::1/128", "lookup", "main"],
            &mut |args| {
                if args == ["-6", "rule", "show"] {
                    return Ok(String::new());
                }
                Err(std::io::Error::other("EAFNOSUPPORT"))
            },
        );
        assert!(err.is_err());
        assert!(rec.owned_v6_rule_del_args.is_empty());
        let on_disk_after_fail = crate::platform::recovery::RecoveryJournal::load_from(&dir)
            .unwrap()
            .unwrap()
            .linux_tun
            .unwrap();
        assert!(on_disk_after_fail.owned_v6_rule_del_args.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
