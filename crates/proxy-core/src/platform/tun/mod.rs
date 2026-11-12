pub mod linux;
pub mod macos;
pub mod windows;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::{dns::FakeIpDnsEngine, inbound::tun::VirtualTunHandle};

/// Default ULA IPv6 subnet assigned to `rust-clash` system TUN adapters when `tun.ipv6_enable` is active.
pub const DEFAULT_TUN_IPV6_CIDR: &str = "fdfe:dcba:9876::1/126";

/// Platform-neutral launch specification passed into `attach_platform_system_tun`.
#[derive(Clone)]
pub struct TunLaunchSpec {
    pub device_name: String,
    pub mtu: usize,
    pub auto_route: bool,
    pub strict_route: bool,
    pub enable_ipv6: bool,
    pub auto_detect_interface: bool,
    pub fake_ip_net: Ipv4Net,
    pub tun_ipv4_cidr: Ipv4Net,
    pub tun_ipv6_cidr: Ipv6Net,
    pub bypass_ips: Vec<IpAddr>,
    pub local_dns_addr: Option<SocketAddr>,
    pub wintun_dll_path: Option<PathBuf>,
    pub state_dir: PathBuf,
    pub dns_engine: Option<Arc<FakeIpDnsEngine>>,
    pub network_change_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl TunLaunchSpec {
    pub fn gateway_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.fake_ip_net.network()).saturating_add(1))
    }

    /// Dedicated in-band TUN peer DNS address (`broadcast - 1`, e.g. `198.19.255.254`) distinct from
    /// both the OS kernel's local TUN interface address (`198.18.0.1`) and the Fake-IP pool (`198.18.0.2..`),
    /// ensuring OS routing tables send DNS packets into the TUN device rather than `RTN_LOCAL`.
    pub fn dns_ipv4(&self) -> Ipv4Addr {
        let bcast = u32::from(self.fake_ip_net.broadcast());
        let min_peer = u32::from(self.gateway_ipv4()).saturating_add(1);
        Ipv4Addr::from(bcast.saturating_sub(1).max(min_peer))
    }

    pub fn ipv4_host_cidr_string(&self) -> String {
        format!("{}/{}", self.gateway_ipv4(), self.fake_ip_net.prefix_len())
    }
}

/// Live platform health & status telemetry surfaced to the Desktop / Mobile GUI (`/configs` & `/tun/status`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunHealthSnapshot {
    pub platform: String,
    pub backend: String,
    pub active: bool,
    pub device_name: Option<String>,
    pub mtu: usize,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub auto_route_applied: bool,
    pub strict_route_applied: bool,
    pub route_table_id: Option<u32>,
    pub default_egress_iface: Option<String>,
    pub default_egress_gateway: Option<String>,
    pub socket_protector: String,
    pub privilege_ok: bool,
    pub privilege_hint: Option<String>,
    pub driver_loaded: bool,
    pub network_transitions: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub last_error: Option<String>,
}

impl Default for TunHealthSnapshot {
    fn default() -> Self {
        Self {
            platform: std::env::consts::OS.to_string(),
            backend: default_backend_label().to_string(),
            active: false,
            device_name: None,
            mtu: 1500,
            ipv4_cidr: None,
            ipv6_cidr: None,
            auto_route_applied: false,
            strict_route_applied: false,
            route_table_id: None,
            default_egress_iface: None,
            default_egress_gateway: None,
            socket_protector: crate::platform::socket_protect::global_socket_protector()
                .description(),
            privilege_ok: false,
            privilege_hint: None,
            driver_loaded: false,
            network_transitions: 0,
            rx_packets: 0,
            tx_packets: 0,
            last_error: None,
        }
    }
}

pub fn default_backend_label() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux-tun-policy-route"
    }
    #[cfg(windows)]
    {
        "windows-wintun"
    }
    #[cfg(target_os = "macos")]
    {
        "macos-utun"
    }
    #[cfg(target_os = "android")]
    {
        "android-vpnservice"
    }
    #[cfg(not(any(
        target_os = "linux",
        windows,
        target_os = "macos",
        target_os = "android"
    )))]
    {
        "unsupported"
    }
}

/// Platform-independent lifecycle trait for an active OS system TUN adapter + routing session.
/// Implementations guarantee idempotent restoration of routes, DNS, `SocketProtector`, and
/// `RecoveryJournal` on both explicit `stop()` and `Drop`.
pub trait SystemTunSession: Send + Sync {
    fn health(&self) -> TunHealthSnapshot;
    fn stop(&mut self);
}

/// Inspect OS TUN driver availability, required capabilities/elevation, and active physical egress
/// interface WITHOUT mutating host routes or opening a TUN device.
pub fn preflight_system_tun(wintun_dll_path: Option<&std::path::Path>) -> TunHealthSnapshot {
    #[cfg(target_os = "linux")]
    {
        let _ = wintun_dll_path;
        linux::preflight_linux_tun()
    }
    #[cfg(windows)]
    {
        windows::preflight_windows_tun(wintun_dll_path)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = wintun_dll_path;
        macos::preflight_macos_tun()
    }
    #[cfg(target_os = "android")]
    {
        let _ = wintun_dll_path;
        TunHealthSnapshot {
            platform: "android".to_string(),
            backend: "android-vpnservice".to_string(),
            privilege_ok: true,
            driver_loaded: true,
            ..TunHealthSnapshot::default()
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        windows,
        target_os = "macos",
        target_os = "android"
    )))]
    {
        let _ = wintun_dll_path;
        TunHealthSnapshot::default()
    }
}

/// Attach `handle` (`VirtualTunHandle`) onto a real OS TUN adapter and configure system routes/DNS
/// transactionally. On ANY error, rolls back all intermediate mutations before returning `Err`.
pub fn attach_platform_system_tun(
    spec: TunLaunchSpec,
    handle: VirtualTunHandle,
) -> io::Result<Box<dyn SystemTunSession>> {
    #[cfg(target_os = "linux")]
    {
        let session = linux::LinuxSystemTunSession::start(spec, handle)?;
        Ok(Box::new(session))
    }
    #[cfg(windows)]
    {
        let session = windows::WindowsWintunSession::start(spec, handle)?;
        Ok(Box::new(session))
    }
    #[cfg(target_os = "macos")]
    {
        let session = macos::MacOsUtunSession::start(spec, handle)?;
        Ok(Box::new(session))
    }
    #[cfg(target_os = "android")]
    {
        let _ = (spec, handle);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "On Android, pass the VpnService Builder fd via proxy-ffi attach_android_vpn_fd()",
        ))
    }
    #[cfg(not(any(
        target_os = "linux",
        windows,
        target_os = "macos",
        target_os = "android"
    )))]
    {
        let _ = (spec, handle);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "System TUN is not supported on this target OS",
        ))
    }
}
