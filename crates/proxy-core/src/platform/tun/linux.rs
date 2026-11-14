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
        recovery::{LinuxRecoveryRecord, update_current_journal},
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
fn rollback_linux_record(rec: &LinuxRecoveryRecord) {
    for args in rec.owned_v4_rule_del_args.iter().rev() {
        let _ = run_ip_owned(args);
    }
    for args in rec.owned_v6_rule_del_args.iter().rev() {
        let _ = run_ip_owned(args);
    }
    for args in rec.owned_route_del_args.iter().rev() {
        let _ = run_ip_owned(args);
    }
    if !rec.device_name.is_empty() {
        let _ = run_ip(&["link", "set", "dev", &rec.device_name, "down"]);
    }
}

#[cfg(target_os = "linux")]
fn add_owned_rule(
    family_flag: &str,
    rule_spec: &[&str],
    ledger: &mut Vec<Vec<String>>,
) -> io::Result<()> {
    // Check if an identical rule already exists so we NEVER delete pre-existing host rules on teardown!
    let existing = run_ip(&[family_flag, "rule", "show"]).unwrap_or_default();
    let needle = rule_spec.join(" ");
    if existing.lines().any(|l| l.contains(&needle)) {
        return Ok(());
    }

    let mut add_args = Vec::with_capacity(rule_spec.len() + 3);
    add_args.push(family_flag);
    add_args.push("rule");
    add_args.push("add");
    add_args.extend_from_slice(rule_spec);
    run_ip(&add_args)?;

    let mut del_args = Vec::with_capacity(rule_spec.len() + 3);
    del_args.push(family_flag.to_string());
    del_args.push("rule".to_string());
    del_args.push("del".to_string());
    del_args.extend(rule_spec.iter().map(|s| (*s).to_string()));
    ledger.push(del_args);
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_owned_route(
    family_flag: &str,
    route_spec: &[&str],
    del_spec: &[&str],
    ledger: &mut Vec<Vec<String>>,
) -> io::Result<()> {
    let mut add_args = Vec::with_capacity(route_spec.len() + 3);
    add_args.push(family_flag);
    add_args.push("route");
    add_args.push("replace");
    add_args.extend_from_slice(route_spec);
    run_ip(&add_args)?;

    let mut del_args = Vec::with_capacity(del_spec.len() + 3);
    del_args.push(family_flag.to_string());
    del_args.push("route".to_string());
    del_args.push("del".to_string());
    del_args.extend(del_spec.iter().map(|s| (*s).to_string()));
    ledger.push(del_args);
    Ok(())
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
                "-4",
                &["default", "dev", &actual_name, "table", &table_str],
                &["default", "dev", &actual_name, "table", &table_str],
                &mut rec.owned_route_del_args,
            )?;
            add_owned_route(
                "-4",
                &[&fake_cidr, "dev", &actual_name],
                &[&fake_cidr, "dev", &actual_name],
                &mut rec.owned_route_del_args,
            )?;

            // 2. High-priority explicit bypasses for proxy server & upstream DNS IPs
            let mut ipv6_bypass_ok = true;
            for ip in &spec.bypass_ips {
                match ip {
                    IpAddr::V4(v4) if !v4.is_loopback() && !spec.fake_ip_net.contains(v4) => {
                        let host_cidr = format!("{v4}/32");
                        add_owned_rule(
                            "-4",
                            &["pref", "8990", "to", &host_cidr, "lookup", "main"],
                            &mut rec.owned_v4_rule_del_args,
                        )?;
                    }
                    IpAddr::V6(v6) if spec.enable_ipv6 && !v6.is_loopback() => {
                        let host_cidr = format!("{v6}/128");
                        if let Err(err) = add_owned_rule(
                            "-6",
                            &["pref", "8990", "to", &host_cidr, "lookup", "main"],
                            &mut rec.owned_v6_rule_del_args,
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
                    "-4",
                    &["pref", "9000", "to", cidr, "lookup", "main"],
                    &mut rec.owned_v4_rule_del_args,
                )?;
            }

            // 4. Route Fake-IP range unconditionally to `<table_id>`
            add_owned_rule(
                "-4",
                &["pref", "9010", "to", &fake_cidr, "lookup", &table_str],
                &mut rec.owned_v4_rule_del_args,
            )?;

            // 5. Consult `main` for all non-default local subnet routes (`suppress_prefixlength 0`),
            //    then capture all unmarked (`not fwmark 0x1a5`) default IPv4 traffic into `<table_id>`!
            add_owned_rule(
                "-4",
                &[
                    "pref",
                    "9015",
                    "lookup",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
                &mut rec.owned_v4_rule_del_args,
            )?;
            add_owned_rule(
                "-4",
                &[
                    "pref", "9020", "not", "fwmark", &mark_hex, "lookup", &table_str,
                ],
                &mut rec.owned_v4_rule_del_args,
            )?;

            // 6. IPv6 default-route interception when `tun.ipv6: true`
            //    Install bypass & suppress rules FIRST; if any fail, skip the catch-all IPv6
            //    default route and `pref 9020` capture rule so an unguarded IPv6 loop never occurs.
            if spec.enable_ipv6 {
                for v6_local in ["::1/128", "fe80::/10"] {
                    if let Err(err) = add_owned_rule(
                        "-6",
                        &["pref", "9000", "to", v6_local, "lookup", "main"],
                        &mut rec.owned_v6_rule_del_args,
                    ) {
                        tracing::warn!(
                            "Linux TUN: failed adding IPv6 local bypass rule for {v6_local} ({err})"
                        );
                        ipv6_bypass_ok = false;
                    }
                }
                if let Err(err) = add_owned_rule(
                    "-6",
                    &[
                        "pref",
                        "9015",
                        "lookup",
                        "main",
                        "suppress_prefixlength",
                        "0",
                    ],
                    &mut rec.owned_v6_rule_del_args,
                ) {
                    tracing::warn!(
                        "Linux TUN: failed adding IPv6 suppress_prefixlength 0 rule ({err})"
                    );
                    ipv6_bypass_ok = false;
                }

                if ipv6_bypass_ok {
                    add_owned_route(
                        "-6",
                        &["default", "dev", &actual_name, "table", &table_str],
                        &["default", "dev", &actual_name, "table", &table_str],
                        &mut rec.owned_route_del_args,
                    )?;
                    add_owned_rule(
                        "-6",
                        &[
                            "pref", "9020", "not", "fwmark", &mark_hex, "lookup", &table_str,
                        ],
                        &mut rec.owned_v6_rule_del_args,
                    )?;
                } else {
                    tracing::warn!(
                        "Linux TUN: skipping IPv6 catch-all default route and pref 9020 rule because one or more IPv6 bypass/suppress rules failed"
                    );
                }
            }

            // 7. Best-effort per-link DNS registration with `systemd-resolved` (`198.18.0.2`, domain `~.`)
            //    Automatically purged by `systemd-resolved` when the TUN kernel interface closes.
            if Path::new("/usr/bin/resolvectl").exists() {
                let dns_peer = spec.dns_ipv4().to_string();
                let _ = std::process::Command::new("/usr/bin/resolvectl")
                    .args(["dns", &actual_name, &dns_peer])
                    .output();
                let _ = std::process::Command::new("/usr/bin/resolvectl")
                    .args(["domain", &actual_name, "~."])
                    .output();
            }

            let rec_final = rec.clone();
            update_current_journal(&spec.state_dir, |j| j.linux_tun = Some(rec_final))?;
            Ok(Some(table_id))
        })();

        let route_table_id = match setup_res {
            Ok(id) => id,
            Err(err) => {
                rollback_linux_record(&rec);
                clear_global_socket_protector();
                let _ = update_current_journal(&spec.state_dir, |j| j.linux_tun = None);
                return Err(err);
            }
        };

        let writer_file = match file.try_clone() {
            Ok(wf) => wf,
            Err(err) => {
                rollback_linux_record(&rec);
                clear_global_socket_protector();
                let _ = update_current_journal(&spec.state_dir, |j| j.linux_tun = None);
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
        let rx_thread = std::thread::Builder::new()
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
                    let prc = unsafe { libc::poll(&raw mut pfd, 1, 200) };
                    if prc <= 0 {
                        continue;
                    }
                    loop {
                        match f.read(&mut buf) {
                            Ok(0) => return,
                            Ok(n) => {
                                rx_cnt.fetch_add(1, Ordering::Relaxed);
                                if ingress_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                    return;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => return,
                        }
                    }
                }
            })?;

        let stop_tx = Arc::clone(&stop_flag);
        let tx_cnt = Arc::clone(&tx_packets);
        let tx_thread = std::thread::Builder::new()
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
            })?;

        let stop_watch = Arc::clone(&stop_flag);
        let egress_watch = Arc::clone(&egress_snapshot);
        let transitions_watch = Arc::clone(&network_transitions);
        let dns_watch = spec.dns_engine.clone();
        let net_hook_watch = spec.network_change_hook.clone();
        let watch_thread = std::thread::Builder::new()
            .name("tun-linux-netwatch".into())
            .spawn(move || {
                while !stop_watch.load(Ordering::Acquire) {
                    for _ in 0..15 {
                        if stop_watch.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    let latest = detect_linux_default_egress();
                    let mut guard = egress_watch.lock();
                    if *guard != latest {
                        *guard = latest;
                        drop(guard);
                        transitions_watch.fetch_add(1, Ordering::Relaxed);
                        if let Some(hook) = &net_hook_watch {
                            hook();
                        } else if let Some(dns) = &dns_watch {
                            dns.flush_cache();
                        }
                    }
                }
            })?;

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
        rollback_linux_record(&self.recovery_record);
        clear_global_socket_protector();
        if let Err(err) = update_current_journal(&self.spec.state_dir, |j| j.linux_tun = None) {
            tracing::warn!("Linux TUN: failed clearing recovery journal on stop: {err}");
        }

        if let Some(h) = self.rx_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.tx_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.watch_thread.take() {
            let _ = h.join();
        }
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
}
