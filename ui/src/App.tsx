import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  androidBridge,
  ApiHttpError,
  buildWsUrl,
  clashApi,
  ensureRuntimeApiReady,
  loadControllerSettings,
  probeControllerSettings,
  saveControllerSettings,
  toggleDemoMode,
} from "./api";
import {
  CheckIcon,
  CloseIcon,
  DashboardGridIcon,
  GlobeIcon,
  MoonIcon,
  NetworkNodesIcon,
  ProfileDocIcon,
  RefreshIcon,
  ShieldCheckIcon,
  SidebarToggleIcon,
  SunIcon,
  ToolboxIcon,
} from "./components/Icons";
import { ErrorBoundary } from "./components/ErrorBoundary";
import {
  loadInitialTheme,
  saveThemePreference,
  useI18n,
} from "./i18n";
import type {
  AndroidPlatformInfo,
  ConfigSnapshot,
  ConnectionsResponse,
  LogEntry,
  ProfilesSnapshot,
  ProxyInfo,
  RuleItem,
  TrafficPoint,
  VersionInfo,
} from "./types";
import { createGuardedPoller } from "./utils/asyncGuards.mjs";
import { verifyAndCommitControllerSecret } from "./utils/controllerAuth.mjs";
import { formatBytes } from "./utils/format";
import { ConnectionsView } from "./views/ConnectionsView";
import { DashboardView } from "./views/DashboardView";
import { ProfilesView } from "./views/ProfilesView";
import { ProxiesView } from "./views/ProxiesView";
import { ToolsView, type ToolsSubTab } from "./views/ToolsView";

type NavTab = "dashboard" | "proxies" | "profiles" | "connections" | "tools";

const SIDEBAR_COLLAPSED_KEY = "rust_clash_sidebar_collapsed_v1";

function loadInitialSidebarCollapsed(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "1";
  } catch {
    return false;
  }
}

export const App: React.FC = () => {
  const { lang, toggleLang, tr } = useI18n();

  const [tab, setTab] = useState<NavTab>("dashboard");
  const [theme, setTheme] = useState<"light" | "dark">(() => loadInitialTheme());
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() =>
    loadInitialSidebarCollapsed(),
  );
  const [focusGroup, setFocusGroup] = useState<string | null>(null);
  const [toolsSubTab, setToolsSubTab] = useState<ToolsSubTab>("settings");
  const [siteDoctorTarget, setSiteDoctorTarget] = useState<string>("chatgpt.com");
  const [healthOpen, setHealthOpen] = useState(false);
  const healthWrapRef = useRef<HTMLDivElement | null>(null);

  const [online, setOnline] = useState(true);
  const [authRequired, setAuthRequired] = useState(false);
  const [apiReady, setApiReady] = useState(false);
  const [pageVisible, setPageVisible] = useState(() =>
    typeof document === "undefined" ? true : !document.hidden,
  );
  const [secretInput, setSecretInput] = useState(
    () => loadControllerSettings().secret,
  );
  const [wsEpoch, setWsEpoch] = useState(0);

  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [config, setConfig] = useState<ConfigSnapshot | null>(null);
  const [profilesSnapshot, setProfilesSnapshot] =
    useState<ProfilesSnapshot | null>(null);
  const [proxies, setProxies] = useState<Record<string, ProxyInfo>>({});
  const [proxyGroupOrder, setProxyGroupOrder] = useState<string[]>([]);
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [connections, setConnections] = useState<ConnectionsResponse | null>(
    null,
  );
  const [trafficHistory, setTrafficHistory] = useState<TrafficPoint[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [androidInfo, setAndroidInfo] = useState<AndroidPlatformInfo | null>(
    () => androidBridge.getPlatformInfo(),
  );

  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [demoExitBusy, setDemoExitBusy] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const handleApiError = useCallback((err: unknown) => {
    if (err instanceof ApiHttpError && err.status === 401) {
      setAuthRequired(true);
      setOnline(true);
      setLoadError(null);
      return;
    }
    const msg = err instanceof Error ? err.message : String(err);
    setLoadError(msg);
    if (!(err instanceof ApiHttpError)) {
      setOnline(false);
    }
  }, []);

  const handleChangeTheme = useCallback((next: "light" | "dark") => {
    setTheme(next);
    saveThemePreference(next);
  }, []);

  const handleToggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(SIDEBAR_COLLAPSED_KEY, next ? "1" : "0");
      } catch {
        // ignore storage errors
      }
      return next;
    });
  }, []);

  const clearFocusGroup = useCallback(() => {
    setFocusGroup(null);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    if (!healthOpen) return;
    const onDocPointerDown = (ev: MouseEvent) => {
      if (
        healthWrapRef.current &&
        !healthWrapRef.current.contains(ev.target as Node)
      ) {
        setHealthOpen(false);
      }
    };
    document.addEventListener("mousedown", onDocPointerDown);
    return () => document.removeEventListener("mousedown", onDocPointerDown);
  }, [healthOpen]);

  const refreshCore = useCallback(async () => {
    try {
      const [ver, cfg, prx, rls, conns] = await Promise.all([
        clashApi.getVersion(),
        clashApi.getConfigs(),
        clashApi.getProxies(),
        clashApi.getRules(),
        clashApi.getConnections(),
      ]);
      setVersion(ver);
      setConfig(cfg);
      setProxies(prx.proxies);
      setProxyGroupOrder(prx["group-order"] ?? []);
      setRules(rls.rules);
      setConnections(conns);
      setAuthRequired(false);
      setOnline(true);
      setLoadError(null);

      try {
        const prof = await clashApi.getProfiles();
        setProfilesSnapshot(prof);
      } catch {
        // optional profile endpoint on read-only/minimal cores
      }
    } catch (err) {
      handleApiError(err);
    }
  }, [handleApiError]);

  const refreshProxies = useCallback(async () => {
    try {
      const [cfg, prx] = await Promise.all([
        clashApi.getConfigs(),
        clashApi.getProxies(),
      ]);
      setConfig(cfg);
      setProxies(prx.proxies);
      setProxyGroupOrder(prx["group-order"] ?? []);
      setAuthRequired(false);
      setOnline(true);
      setLoadError(null);
    } catch (err) {
      handleApiError(err);
    }
  }, [handleApiError]);

  useEffect(() => {
    let cancelled = false;
    void ensureRuntimeApiReady().finally(() => {
      if (!cancelled) {
        setApiReady(true);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onVisibility = () => {
      setPageVisible(!document.hidden);
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);

  useEffect(() => {
    const onNativeSync = () => {
      void refreshCore();
    };
    window.addEventListener("rustclash:native-import", onNativeSync);
    return () =>
      window.removeEventListener("rustclash:native-import", onNativeSync);
  }, [refreshCore]);

  useEffect(() => {
    if (!apiReady) return;
    let disposed = false;
    void refreshCore();
    void clashApi
      .getTrafficSnapshot()
      .then((snap) => {
        if (disposed) return;
        setTrafficHistory(snap.history);
      })
      .catch((err) => {
        if (disposed) return;
        handleApiError(err);
      });
    void clashApi
      .getLogsSnapshot()
      .then((snap) => {
        if (disposed) return;
        setLogs(snap.logs);
      })
      .catch((err) => {
        if (disposed) return;
        handleApiError(err);
      });
    return () => {
      disposed = true;
    };
  }, [apiReady, handleApiError, refreshCore, wsEpoch]);

  useEffect(() => {
    if (!pageVisible || !androidBridge.isAvailable()) return;
    setAndroidInfo(androidBridge.getPlatformInfo());
    const timer = window.setInterval(() => {
      setAndroidInfo(androidBridge.getPlatformInfo());
    }, 2500);
    return () => window.clearInterval(timer);
  }, [pageVisible]);

  // Live WebSocket stream for `/traffic` with HTTP fallback
  useEffect(() => {
    if (!apiReady || !pageVisible || authRequired) return;

    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let backoffMs = 1000;
    let disposed = false;

    const poller = createGuardedPoller({
      intervalMs: 2000,
      isHidden: () => document.hidden,
      poll: () => clashApi.getTrafficSnapshot(),
      onSuccess: (snap) => {
        if (disposed) return;
        setTrafficHistory(snap.history);
        setOnline(true);
        setLoadError(null);
      },
      onError: (err) => {
        if (disposed) return;
        handleApiError(err);
      },
      setIntervalFn: (fn, ms) => window.setInterval(fn, ms),
      clearIntervalFn: (id) => window.clearInterval(id),
    });

    const startFallbackPolling = () => {
      if (disposed) return;
      poller.start();
    };

    const stopFallbackPolling = () => {
      poller.stop();
    };

    const connect = () => {
      if (disposed) return;
      try {
        if (ws) {
          ws.onopen = null;
          ws.onmessage = null;
          ws.onerror = null;
          ws.onclose = null;
          ws.close();
          ws = null;
        }
        const socket = new WebSocket(buildWsUrl("/traffic"));
        ws = socket;
        socket.onopen = () => {
          if (disposed) return;
          if (ws !== socket) return;
          backoffMs = 1000;
          stopFallbackPolling();
        };
        socket.onmessage = (ev) => {
          if (disposed) return;
          if (ws !== socket) return;
          try {
            const pt = JSON.parse(String(ev.data)) as TrafficPoint;
            setTrafficHistory((prev) => [...prev.slice(-119), pt]);
          } catch {
            // ignore malformed frame
          }
        };
        socket.onerror = () => {
          if (disposed) return;
          if (ws !== socket) return;
          startFallbackPolling();
        };
        socket.onclose = () => {
          if (disposed) return;
          if (ws !== socket) return;
          startFallbackPolling();
          if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
          reconnectTimer = window.setTimeout(() => {
            reconnectTimer = null;
            if (disposed) return;
            backoffMs = Math.min(backoffMs * 2, 10_000);
            connect();
          }, backoffMs);
        };
      } catch {
        startFallbackPolling();
      }
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      poller.dispose();
      if (ws) {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        ws.close();
        ws = null;
      }
    };
  }, [apiReady, pageVisible, authRequired, wsEpoch, handleApiError]);

  // Live WebSocket stream for `/connections` with HTTP fallback
  useEffect(() => {
    if (!apiReady || !pageVisible || authRequired) return;

    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let backoffMs = 1000;
    let disposed = false;

    const poller = createGuardedPoller({
      intervalMs: 2500,
      isHidden: () => document.hidden,
      poll: () => clashApi.getConnections(),
      onSuccess: (c) => {
        if (disposed) return;
        setConnections(c);
        setAuthRequired(false);
        setOnline(true);
        setLoadError(null);
      },
      onError: (err) => {
        if (disposed) return;
        handleApiError(err);
      },
      setIntervalFn: (fn, ms) => window.setInterval(fn, ms),
      clearIntervalFn: (id) => window.clearInterval(id),
    });

    const startFallbackPolling = () => {
      if (disposed) return;
      poller.start();
    };

    const stopFallbackPolling = () => {
      poller.stop();
    };

    const connect = () => {
      if (disposed) return;
      try {
        if (ws) {
          ws.onopen = null;
          ws.onmessage = null;
          ws.onerror = null;
          ws.onclose = null;
          ws.close();
          ws = null;
        }
        const socket = new WebSocket(buildWsUrl("/connections"));
        ws = socket;
        socket.onopen = () => {
          if (disposed) return;
          if (ws !== socket) return;
          backoffMs = 1000;
          setOnline(true);
          stopFallbackPolling();
        };
        socket.onmessage = (ev) => {
          if (disposed) return;
          if (ws !== socket) return;
          try {
            const snap = JSON.parse(String(ev.data)) as ConnectionsResponse;
            setConnections(snap);
            setOnline(true);
          } catch {
            // ignore malformed frame
          }
        };
        socket.onerror = () => {
          if (disposed) return;
          if (ws !== socket) return;
          startFallbackPolling();
        };
        socket.onclose = () => {
          if (disposed) return;
          if (ws !== socket) return;
          startFallbackPolling();
          if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
          reconnectTimer = window.setTimeout(() => {
            reconnectTimer = null;
            if (disposed) return;
            backoffMs = Math.min(backoffMs * 2, 10_000);
            connect();
          }, backoffMs);
        };
      } catch {
        startFallbackPolling();
      }
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      poller.dispose();
      if (ws) {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        ws.close();
        ws = null;
      }
    };
  }, [apiReady, pageVisible, authRequired, wsEpoch, handleApiError]);

  // Live WebSocket stream for `/logs`
  useEffect(() => {
    if (!apiReady || !pageVisible || authRequired) return;

    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let backoffMs = 1000;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      try {
        if (ws) {
          ws.onopen = null;
          ws.onmessage = null;
          ws.onerror = null;
          ws.onclose = null;
          ws.close();
          ws = null;
        }
        const socket = new WebSocket(buildWsUrl("/logs"));
        ws = socket;
        socket.onopen = () => {
          if (disposed) return;
          if (ws !== socket) return;
          backoffMs = 1000;
        };
        socket.onmessage = (ev) => {
          if (disposed) return;
          if (ws !== socket) return;
          try {
            const item = JSON.parse(String(ev.data)) as LogEntry;
            setLogs((prev) => {
              const dup = prev.some(
                (p) =>
                  p.timestamp_ms === item.timestamp_ms &&
                  p.payload === item.payload,
              );
              if (dup) return prev;
              return [...prev.slice(-299), item];
            });
          } catch {
            // ignore malformed frame
          }
        };
        socket.onerror = () => {
          if (disposed) return;
          if (ws !== socket) return;
        };
        socket.onclose = () => {
          if (disposed) return;
          if (ws !== socket) return;
          if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
          reconnectTimer = window.setTimeout(() => {
            reconnectTimer = null;
            if (disposed) return;
            backoffMs = Math.min(backoffMs * 2, 10_000);
            connect();
          }, backoffMs);
        };
      } catch {
        // initial snapshot already loaded
      }
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (ws) {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        ws.close();
        ws = null;
      }
    };
  }, [apiReady, pageVisible, authRequired, wsEpoch]);

  const handleSaveSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    if (authBusy) return;
    setAuthBusy(true);
    setAuthError(null);
    try {
      await verifyAndCommitControllerSecret({
        loadSettings: loadControllerSettings,
        probeSettings: probeControllerSettings,
        saveSettings: saveControllerSettings,
        candidateSecret: secretInput,
      });
      setAuthRequired(false);
      setWsEpoch((n) => n + 1);
      await refreshCore();
    } catch (err) {
      if (err instanceof ApiHttpError && err.status === 401) {
        setAuthRequired(true);
        setAuthError(
          tr("密钥不正确（401 未授权）", "Invalid Bearer Secret (401)."),
        );
      } else {
        setAuthError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setAuthBusy(false);
    }
  };

  const handleExitDemo = async () => {
    if (demoExitBusy) return;
    setDemoExitBusy(true);
    try {
      await toggleDemoMode(false);
      await refreshCore();
    } catch (err) {
      setToastMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setDemoExitBusy(false);
    }
  };

  const latestTraffic: TrafficPoint = trafficHistory[
    trafficHistory.length - 1
  ] ?? {
    timestamp_ms: 0,
    up: 0,
    down: 0,
    total_up: 0,
    total_down: 0,
  };

  const navItems: Array<{
    id: NavTab;
    label: string;
    shortLabel: string;
    renderIcon: (active: boolean) => React.ReactNode;
  }> = [
    {
      id: "dashboard",
      label: tr("仪表盘", "Dashboard"),
      shortLabel: tr("仪表盘", "Home"),
      renderIcon: (active) => <DashboardGridIcon size={18} active={active} />,
    },
    {
      id: "proxies",
      label: tr("代理节点", "Proxies"),
      shortLabel: tr("节点", "Proxies"),
      renderIcon: () => <GlobeIcon size={18} />,
    },
    {
      id: "profiles",
      label: tr("订阅配置", "Profiles"),
      shortLabel: tr("订阅", "Profiles"),
      renderIcon: () => <ProfileDocIcon size={18} />,
    },
    {
      id: "connections",
      label: tr("实时连接", "Live connections"),
      shortLabel: tr("连接", "Streams"),
      renderIcon: () => <NetworkNodesIcon size={18} />,
    },
    {
      id: "tools",
      label: tr("工具与设置", "Tools"),
      shortLabel: tr("工具", "Tools"),
      renderIcon: () => <ToolboxIcon size={18} />,
    },
  ];

  const pageTitles: Record<NavTab, string> = {
    dashboard: tr("仪表盘", "Dashboard"),
    proxies: tr("代理节点", "Proxies"),
    profiles: tr("订阅配置", "Profiles"),
    connections: tr("实时连接", "Live connections"),
    tools: tr("工具与设置", "Tools"),
  };

  const sysProxyOn = Boolean(config?.sysproxy?.enabled);
  const tunOn = Boolean(config?.["tun-active"] ?? config?.tun?.enable);
  const coreRssBytes = config?.["process-rss-bytes"] ?? connections?.memory ?? null;
  const mixedPortNum = config?.["mixed-port"] ?? 7890;
  const verLabel = version?.version
    ? /^(v|rust-clash)/i.test(version.version)
      ? version.version
      : `v${version.version}`
    : "Pure Rust";

  return (
    <div
      className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}
    >
      <aside className="sidebar">
        <div className="sidebar-top">
          {!sidebarCollapsed && (
            <div className="sidebar-brand">
              <span className="sidebar-brand-mark" aria-hidden="true">R</span>
              <div className="sidebar-brand-meta">
                <span className="sidebar-brand-name">RustClash</span>
                <span className="sidebar-brand-ver tabular">{verLabel}</span>
              </div>
            </div>
          )}
          <button
            id="sidebar-collapse-btn"
            type="button"
            className="sidebar-collapse-btn"
            onClick={handleToggleSidebar}
            title={
              sidebarCollapsed
                ? tr("展开侧边栏", "Expand sidebar")
                : tr("收起侧边栏", "Collapse sidebar")
            }
            aria-label={
              sidebarCollapsed
                ? tr("展开侧边栏", "Expand sidebar")
                : tr("收起侧边栏", "Collapse sidebar")
            }
          >
            <SidebarToggleIcon size={18} />
          </button>
        </div>

        <nav className="nav-list" aria-label={tr("主导航", "Main Navigation")}>
          {navItems.map((item) => {
            const active = tab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-${item.id}`}
                type="button"
                className={`nav-btn ${active ? "active" : ""}`}
                title={sidebarCollapsed ? item.label : undefined}
                onClick={() => {
                  if (item.id === "proxies") {
                    setFocusGroup(null);
                  }
                  setTab(item.id);
                }}
              >
                <span className="nav-icon">{item.renderIcon(active)}</span>
                <span className="nav-label">{item.label}</span>
              </button>
            );
          })}
        </nav>

        {!sidebarCollapsed && (
          <div className="sidebar-kernel-foot">
            <div className="sidebar-kernel-row">
              <span className="sidebar-kernel-status">
                <span
                  className={`sidebar-kernel-dot ${
                    online && !authRequired ? "online" : "offline"
                  }`}
                />
                <span>
                  {online && !authRequired
                    ? tr("内核运行中", "Core Online")
                    : tr("内核重连中", "Reconnecting")}
                </span>
              </span>
              <span className="mono tabular" style={{ color: "var(--text-muted)", fontSize: 11 }}>
                :{mixedPortNum}
              </span>
            </div>
            {coreRssBytes != null && coreRssBytes > 0 && (
              <div className="sidebar-kernel-row" style={{ color: "var(--text-muted)", fontSize: 11 }}>
                <span>{tr("常驻内存", "Core RSS")}</span>
                <span className="tabular" style={{ color: "var(--text-secondary)", fontWeight: 600 }}>
                  {formatBytes(coreRssBytes)}
                </span>
              </div>
            )}
          </div>
        )}
      </aside>

      <div className="workspace">
        {androidInfo && (
          <div className="android-native-bar">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="badge badge-emerald">
                Android VPN: {androidInfo.vpnState}
              </span>
              {androidInfo.lockdownWarning && (
                <span className="badge badge-amber">
                  {androidInfo.lockdownWarning}
                </span>
              )}
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => androidBridge.openPerAppSelector()}
              >
                {tr("分应用代理", "Per-App Split Tunnel")}
              </button>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                onClick={() => androidBridge.disconnectVpn()}
              >
                {tr("断开 VPN", "Stop VPN")}
              </button>
            </div>
          </div>
        )}

        <header className="topbar">
          <div className="topbar-title-group">
            <h1 className="topbar-title">{pageTitles[tab]}</h1>
            {tab === "dashboard" && (
              <span className="topbar-mode-pill">
                {config?.mode === "global"
                  ? tr("全局代理", "Global")
                  : config?.mode === "direct"
                    ? tr("全局直连", "Direct")
                    : tr("智能分流", "Smart Rule")}
                {" · "}
                {sysProxyOn && tunOn
                  ? tr("系统代理 + TUN", "SysProxy + TUN")
                  : tunOn
                    ? "TUN"
                    : sysProxyOn
                      ? tr("系统代理", "SysProxy")
                      : tr("待机", "Standby")}
              </span>
            )}
          </div>

          <div className="topbar-actions" ref={healthWrapRef}>
            {config?.demo?.enabled && (
              <button
                type="button"
                className="header-pill-btn"
                disabled={demoExitBusy}
                onClick={() => void handleExitDemo()}
                title={tr(
                  "当前处于演示模式，点击切换回真实代理环境",
                  "Demo mode active — click to return to real proxy mode",
                )}
              >
                <span
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: "50%",
                    background: "var(--accent-amber)",
                  }}
                />
                <span>
                  {demoExitBusy
                    ? tr("切换中...", "Switching...")
                    : tr("演示模式 · 退出", "Demo · Exit")}
                </span>
              </button>
            )}

            {!online && (
              <button
                type="button"
                className="header-pill-btn"
                onClick={() => void refreshCore()}
                title={tr("点击立即重连核心", "Click to reconnect now")}
              >
                <span
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: "50%",
                    background: "var(--accent-amber)",
                  }}
                />
                <span>{tr("正在重连...", "Reconnecting...")}</span>
              </button>
            )}

            <button
              id="open-site-doctor-btn"
              type="button"
              className="header-pill-btn"
              onClick={() => {
                setSiteDoctorTarget("chatgpt.com");
                setToolsSubTab("diagnostics");
                setTab("tools");
              }}
              title={tr(
                "网站打不开一键排障：按网址诊断分流路径、DNS 与 TLS 握手",
                "Site Connectivity Doctor: diagnose route, DNS & TLS for any site",
              )}
            >
              <ShieldCheckIcon size={14} />
              <span>{tr("网络诊断", "Site Doctor")}</span>
            </button>

            <button
              id="lang-toggle-btn"
              type="button"
              className="header-pill-btn"
              onClick={toggleLang}
              title={tr("切换语言 (简体中文 / English)", "Switch language (中文 / EN)")}
            >
              <span
                style={{
                  color:
                    lang === "zh" ? "var(--accent-blue)" : "var(--text-muted)",
                  fontWeight: lang === "zh" ? 700 : 500,
                }}
              >
                中
              </span>
              <span style={{ opacity: 0.35 }}>/</span>
              <span
                style={{
                  color:
                    lang === "en" ? "var(--accent-blue)" : "var(--text-muted)",
                  fontWeight: lang === "en" ? 700 : 500,
                }}
              >
                EN
              </span>
            </button>

            <button
              id="theme-toggle-btn"
              type="button"
              className="header-icon-btn"
              onClick={() =>
                handleChangeTheme(theme === "light" ? "dark" : "light")
              }
              title={
                theme === "light"
                  ? tr("切换深色外观", "Switch to Dark theme")
                  : tr("切换浅色外观", "Switch to Light theme")
              }
              aria-label={tr("切换外观主题", "Toggle theme")}
            >
              {theme === "light" ? (
                <MoonIcon size={15} />
              ) : (
                <SunIcon size={15} />
              )}
            </button>

            <button
              id="health-status-btn"
              type="button"
              className={`health-check-btn ${
                !online || authRequired ? "offline" : ""
              }`}
              onClick={() => setHealthOpen((o) => !o)}
              title={
                online && !authRequired
                  ? tr("核心运行正常", "Engine healthy")
                  : authRequired
                    ? tr("需要访问密钥", "Authentication required")
                    : tr("核心未连接", "Engine offline")
              }
              aria-label={tr("核心状态概览", "Engine status")}
            >
              {online && !authRequired ? (
                <CheckIcon size={17} />
              ) : (
                <RefreshIcon size={15} />
              )}
            </button>

            {healthOpen && (
              <div className="health-popover" role="dialog">
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 7,
                      fontWeight: 600,
                      fontSize: 13,
                    }}
                  >
                    <span
                      style={{
                        width: 8,
                        height: 8,
                        borderRadius: "50%",
                        background:
                          online && !authRequired
                            ? "#22c55e"
                            : "var(--accent-amber)",
                      }}
                    />
                    <span>
                      {authRequired
                        ? tr("需要密钥认证", "Auth Required")
                        : online
                          ? tr("核心引擎已连接", "Engine Connected")
                          : tr("核心离线重连中", "Reconnecting")}
                    </span>
                  </div>
                  <span
                    className="tabular"
                    style={{ fontSize: 11.5, color: "var(--text-muted)" }}
                  >
                    {version?.version
                      ? /^(v|rust-clash)/i.test(version.version)
                        ? version.version
                        : `v${version.version}`
                      : "RustClash"}
                  </span>
                </div>

                <div
                  style={{
                    background: "var(--bg-subcard)",
                    borderRadius: 11,
                    padding: "9px 11px",
                    display: "flex",
                    flexDirection: "column",
                    gap: 5,
                    fontSize: 12,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      color: "var(--text-secondary)",
                    }}
                  >
                    <span>{tr("混合端口", "Mixed Port")}</span>
                    <strong className="tabular" style={{ color: "var(--text-primary)" }}>
                      {config?.["mixed-listen"] ||
                        `127.0.0.1:${config?.["mixed-port"] ?? 7890}`}
                    </strong>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      color: "var(--text-secondary)",
                    }}
                  >
                    <span>{tr("出站模式", "Outbound Mode")}</span>
                    <strong style={{ color: "var(--text-primary)" }}>
                      {config?.mode === "global"
                        ? tr("全局 (Global)", "Global")
                        : config?.mode === "direct"
                          ? tr("直连 (Direct)", "Direct")
                          : tr("规则 (Rule)", "Rule")}
                    </strong>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      color: "var(--text-secondary)",
                    }}
                  >
                    <span>{tr("接管状态", "Takeover")}</span>
                    <strong style={{ color: "var(--text-primary)" }}>
                      {tunOn && sysProxyOn
                        ? tr("TUN + 系统代理", "TUN + System Proxy")
                        : tunOn
                          ? "TUN"
                          : sysProxyOn
                            ? tr("系统代理", "System Proxy")
                            : tr("待机", "Standby")}
                    </strong>
                  </div>
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <button
                    type="button"
                    className="btn btn-sm"
                    style={{ flex: 1 }}
                    onClick={() => void refreshCore()}
                  >
                    <RefreshIcon size={13} />
                    <span>{tr("刷新状态", "Refresh")}</span>
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => {
                      setHealthOpen(false);
                      setToolsSubTab("settings");
                      setTab("tools");
                    }}
                  >
                    {tr("更多设置", "Settings")}
                  </button>
                </div>
              </div>
            )}
          </div>
        </header>

        <main
          className={`content-scroll ${tab === "dashboard" ? "dashboard-content" : ""}`}
        >
          {toastMsg && (
            <div
              className="bento-card bento-card-compact"
              style={{
                borderColor: "var(--accent-amber)",
                background: "var(--accent-amber-soft)",
              }}
            >
              <span style={{ fontSize: 12.5 }}>{toastMsg}</span>
              <button
                type="button"
                className="bento-icon-action"
                onClick={() => setToastMsg(null)}
                aria-label={tr("关闭提示", "Dismiss")}
              >
                <CloseIcon size={13} />
              </button>
            </div>
          )}

          {loadError && !authRequired && (
            <div
              className="banner banner-err"
              role="alert"
            >
              <span>
                <strong>
                  {tr("控制器连接异常：", "Controller connection error: ")}
                </strong>
                {loadError}
              </span>
              <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void refreshCore()}
                >
                  <RefreshIcon size={12} />
                  <span>{tr("重试", "Retry")}</span>
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => setLoadError(null)}
                >
                  {tr("关闭", "Dismiss")}
                </button>
              </div>
            </div>
          )}

          {authRequired && (
            <form
              onSubmit={handleSaveSecret}
              className="bento-card"
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                <strong style={{ fontSize: 13.5 }}>
                  {tr(
                    "核心已开启接口密钥保护，请输入 Bearer Secret",
                    "Controller requires a Bearer Secret",
                  )}
                </strong>
                {authError && (
                  <span
                    style={{
                      fontSize: 12,
                      color: "var(--accent-rose)",
                      fontWeight: 500,
                    }}
                  >
                    {authError}
                  </span>
                )}
              </div>
              <div
                style={{
                  display: "flex",
                  gap: 8,
                  alignItems: "center",
                  flexWrap: "wrap",
                }}
              >
                <input
                  id="controller-secret-input"
                  type="password"
                  className="input"
                  style={{ width: 210 }}
                  placeholder={tr("输入访问密钥...", "Enter controller secret...")}
                  value={secretInput}
                  onChange={(ev) => setSecretInput(ev.target.value)}
                />
                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={authBusy}
                >
                  {authBusy
                    ? tr("验证中...", "Verifying...")
                    : tr("连接", "Connect")}
                </button>
              </div>
            </form>
          )}

          <ErrorBoundary resetKey={tab} scope={tab}>
            {tab === "dashboard" && (
              <DashboardView
                online={online}
                config={config}
                profilesSnapshot={profilesSnapshot}
                proxies={proxies}
                groupOrder={proxyGroupOrder}
                rules={rules}
                connections={connections}
                trafficHistory={trafficHistory}
                latestTraffic={latestTraffic}
                onRefreshAll={refreshCore}
                onOpenProfiles={() => setTab("profiles")}
                onOpenProxies={(groupName) => {
                  setFocusGroup(groupName ?? null);
                  setTab("proxies");
                }}
                onOpenTools={() => {
                  setToolsSubTab("settings");
                  setTab("tools");
                }}
                onOpenSiteDoctor={(target) => {
                  setSiteDoctorTarget(target ?? "chatgpt.com");
                  setToolsSubTab("diagnostics");
                  setTab("tools");
                }}
              />
            )}

            {tab === "proxies" && (
              <ProxiesView
                config={config}
                proxies={proxies}
                groupOrder={proxyGroupOrder}
                onRefreshProxies={refreshProxies}
                focusGroup={focusGroup}
                onClearFocusGroup={clearFocusGroup}
                onOpenProfiles={() => setTab("profiles")}
              />
            )}

            {tab === "profiles" && (
              <ProfilesView
                profilesSnapshot={profilesSnapshot}
                onReloaded={refreshCore}
              />
            )}

            {tab === "connections" && (
              <ConnectionsView
                connections={connections}
                latestTraffic={latestTraffic}
                onRefresh={async () => {
                  try {
                    const c = await clashApi.getConnections();
                    setConnections(c);
                    setLoadError(null);
                  } catch (err) {
                    handleApiError(err);
                  }
                }}
              />
            )}

            {tab === "tools" && (
              <ToolsView
                version={version}
                config={config}
                proxies={proxies}
                rules={rules}
                logs={logs}
                theme={theme}
                onChangeTheme={handleChangeTheme}
                onRefreshCore={refreshCore}
                onClearLogs={() => setLogs([])}
                onControllerUpdated={() => {
                  setSecretInput(loadControllerSettings().secret);
                  setWsEpoch((n) => n + 1);
                  void refreshCore();
                }}
                initialSubTab={toolsSubTab}
                initialSiteTarget={siteDoctorTarget}
                onOpenProxies={() => {
                  setFocusGroup(null);
                  setTab("proxies");
                }}
                onOpenProfiles={() => setTab("profiles")}
              />
            )}
          </ErrorBoundary>
        </main>

        <nav
          className="mobile-bottom-nav"
          aria-label={tr("底部导航", "Mobile Navigation")}
        >
          {navItems.map((item) => {
            const active = tab === item.id;
            return (
              <button
                key={item.id}
                id={`mobile-nav-${item.id}`}
                type="button"
                className={`mobile-nav-btn ${active ? "active" : ""}`}
                onClick={() => {
                  if (item.id === "proxies") {
                    setFocusGroup(null);
                  }
                  setTab(item.id);
                }}
              >
                {item.renderIcon(active)}
                <span>{item.shortLabel}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </div>
  );
};
