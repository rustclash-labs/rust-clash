import React, { useCallback, useEffect, useState } from "react";
import {
  androidBridge,
  ApiHttpError,
  buildWsUrl,
  clashApi,
  ensureRuntimeApiReady,
  loadControllerSettings,
  saveControllerSettings,
} from "./api";
import type {
  AndroidPlatformInfo,
  ConfigSnapshot,
  ConnectionsResponse,
  LogEntry,
  ProfilesSnapshot,
  ProxyInfo,
  RuleItem,
  RunMode,
  TrafficPoint,
  VersionInfo,
} from "./types";
import { formatSpeed } from "./utils/format";
import { ConnectionsView } from "./views/ConnectionsView";
import { LogsView } from "./views/LogsView";
import { OverviewView } from "./views/OverviewView";
import { ProxiesView } from "./views/ProxiesView";
import { RulesDnsView } from "./views/RulesDnsView";
import { StudioView } from "./views/StudioView";

type NavTab =
  | "overview"
  | "proxies"
  | "connections"
  | "rules"
  | "studio"
  | "logs";

export const App: React.FC = () => {
  const [tab, setTab] = useState<NavTab>("overview");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
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
  const [openAddModalSignal, setOpenAddModalSignal] = useState(0);

  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [config, setConfig] = useState<ConfigSnapshot | null>(null);
  const [profilesSnapshot, setProfilesSnapshot] =
    useState<ProfilesSnapshot | null>(null);
  const [proxies, setProxies] = useState<Record<string, ProxyInfo>>({});
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [connections, setConnections] = useState<ConnectionsResponse | null>(
    null,
  );
  const [trafficHistory, setTrafficHistory] = useState<TrafficPoint[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [androidInfo, setAndroidInfo] = useState<AndroidPlatformInfo | null>(
    () => androidBridge.getPlatformInfo(),
  );

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
      setRules(rls.rules);
      setConnections(conns);
      setAuthRequired(false);
      setOnline(true);

      try {
        const prof = await clashApi.getProfiles();
        setProfilesSnapshot(prof);
      } catch {
        // older or embedded read-only core without profile manager
      }
    } catch (err) {
      if (err instanceof ApiHttpError && err.status === 401) {
        setAuthRequired(true);
        setOnline(true);
      } else {
        setOnline(false);
      }
    }
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

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
    void refreshCore();
    void clashApi
      .getTrafficSnapshot()
      .then((snap) => setTrafficHistory(snap.history))
      .catch(() => undefined);
    void clashApi
      .getLogsSnapshot()
      .then((snap) => setLogs(snap.logs))
      .catch(() => undefined);
  }, [apiReady, refreshCore, wsEpoch]);

  useEffect(() => {
    if (!pageVisible || !androidBridge.isAvailable()) return;
    setAndroidInfo(androidBridge.getPlatformInfo());
    const timer = window.setInterval(() => {
      setAndroidInfo(androidBridge.getPlatformInfo());
    }, 2500);
    return () => window.clearInterval(timer);
  }, [pageVisible]);

  // Live WebSocket stream for `/traffic` with visibility-aware exponential backoff & HTTP fallback
  useEffect(() => {
    if (!apiReady || !pageVisible || authRequired) return;

    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let fallbackInterval: number | null = null;
    let backoffMs = 1000;
    let disposed = false;

    const startFallbackPolling = () => {
      if (disposed || fallbackInterval !== null) return;
      fallbackInterval = window.setInterval(() => {
        if (document.hidden) return;
        void clashApi
          .getTrafficSnapshot()
          .then((snap) => setTrafficHistory(snap.history))
          .catch(() => undefined);
      }, 2000);
    };

    const stopFallbackPolling = () => {
      if (fallbackInterval !== null) {
        window.clearInterval(fallbackInterval);
        fallbackInterval = null;
      }
    };

    const connect = () => {
      if (disposed) return;
      try {
        ws = new WebSocket(buildWsUrl("/traffic"));
        ws.onopen = () => {
          backoffMs = 1000;
          stopFallbackPolling();
        };
        ws.onmessage = (ev) => {
          try {
            const pt = JSON.parse(String(ev.data)) as TrafficPoint;
            setTrafficHistory((prev) => [...prev.slice(-119), pt]);
          } catch {
            // ignore malformed frame
          }
        };
        ws.onerror = () => {
          startFallbackPolling();
        };
        ws.onclose = () => {
          if (disposed) return;
          reconnectTimer = window.setTimeout(() => {
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
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      stopFallbackPolling();
      if (ws) ws.close();
    };
  }, [apiReady, pageVisible, authRequired, wsEpoch]);

  // Live WebSocket stream for `/connections` with automatic HTTP fallback
  useEffect(() => {
    if (!apiReady || !pageVisible || authRequired) return;

    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let fallbackInterval: number | null = null;
    let backoffMs = 1000;
    let disposed = false;

    const startFallbackPolling = () => {
      if (disposed || fallbackInterval !== null) return;
      fallbackInterval = window.setInterval(() => {
        if (document.hidden) return;
        void clashApi
          .getConnections()
          .then((c) => {
            setConnections(c);
            setAuthRequired(false);
            setOnline(true);
          })
          .catch((err) => {
            if (err instanceof ApiHttpError && err.status === 401) {
              setAuthRequired(true);
            } else {
              setOnline(false);
            }
          });
      }, 2500);
    };

    const stopFallbackPolling = () => {
      if (fallbackInterval !== null) {
        window.clearInterval(fallbackInterval);
        fallbackInterval = null;
      }
    };

    const connect = () => {
      if (disposed) return;
      try {
        ws = new WebSocket(buildWsUrl("/connections"));
        ws.onopen = () => {
          backoffMs = 1000;
          setOnline(true);
          stopFallbackPolling();
        };
        ws.onmessage = (ev) => {
          try {
            const snap = JSON.parse(String(ev.data)) as ConnectionsResponse;
            setConnections(snap);
            setOnline(true);
          } catch {
            // ignore malformed frame
          }
        };
        ws.onerror = () => {
          startFallbackPolling();
        };
        ws.onclose = () => {
          if (disposed) return;
          startFallbackPolling();
          reconnectTimer = window.setTimeout(() => {
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
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      stopFallbackPolling();
      if (ws) ws.close();
    };
  }, [apiReady, pageVisible, authRequired, wsEpoch]);

  // Live WebSocket stream for `/logs` with exponential backoff reconnect
  useEffect(() => {
    if (!apiReady || !pageVisible || authRequired) return;

    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let backoffMs = 1000;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      try {
        ws = new WebSocket(buildWsUrl("/logs"));
        ws.onopen = () => {
          backoffMs = 1000;
        };
        ws.onmessage = (ev) => {
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
            // ignore
          }
        };
        ws.onclose = () => {
          if (disposed) return;
          reconnectTimer = window.setTimeout(() => {
            backoffMs = Math.min(backoffMs * 2, 10_000);
            connect();
          }, backoffMs);
        };
      } catch {
        // initial HTTP snapshot already loaded
      }
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, [apiReady, pageVisible, authRequired, wsEpoch]);

  const [modeBusy, setModeBusy] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [appError, setAppError] = useState<string | null>(null);

  const handleSaveSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthBusy(true);
    setAuthError(null);
    const cur = loadControllerSettings();
    saveControllerSettings({ ...cur, secret: secretInput });
    try {
      await clashApi.getVersion();
      setAuthRequired(false);
      setWsEpoch((n) => n + 1);
      await refreshCore();
    } catch (err) {
      if (err instanceof ApiHttpError && err.status === 401) {
        setAuthRequired(true);
        setAuthError("Invalid Bearer Secret — authentication rejected (401).");
      } else {
        setAuthError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setAuthBusy(false);
    }
  };

  const handleModeChange = async (mode: RunMode) => {
    if (modeBusy || config?.mode === mode) return;
    setModeBusy(true);
    setAppError(null);
    try {
      await clashApi.patchConfigs({ mode });
      await refreshCore();
    } catch (err) {
      setAppError(err instanceof Error ? err.message : String(err));
    } finally {
      setModeBusy(false);
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

  const GROUP_PROXY_TYPES = new Set([
    "Selector",
    "URLTest",
    "Fallback",
    "LoadBalance",
  ]);
  const concreteNodeCount = Object.values(proxies).filter(
    (p) =>
      !GROUP_PROXY_TYPES.has(p.type) &&
      p.name !== "DIRECT" &&
      p.name !== "REJECT",
  ).length;
  const activeCount = connections?.connections.length ?? 0;
  const tabMeta: Record<NavTab, { title: string; subtitle: string }> = {
    overview: {
      title: "System Telemetry & OS Integration",
      subtitle:
        "Real-time kernel throughput, OS TUN & System Proxy controls, and diagnostics",
    },
    proxies: {
      title: "Outbounds & Policy Groups",
      subtitle:
        "Selector, URLTest, Fallback, and LoadBalance groups across SS, VLESS, Trojan, AnyTLS, SOCKS5 & HTTP",
    },
    connections: {
      title: "Active Connections & Stream Diagnostics",
      subtitle:
        "Live TCP/UDP stream tracking, Fake-IP domain restoration, and recent route/exit diagnostics",
    },
    rules: {
      title: "Routing Presets, Custom Rules, GeoData & Fake-IP DNS",
      subtitle:
        "One-tap Smart-CN / Custom rule presets, GeoSite/GeoIP updater, explainer, and DNS inspector",
    },
    studio: {
      title: "Profiles, Subscriptions & PQ Studio",
      subtitle:
        "Keystore-backed HTTPS subscriptions, URI importer, PQ keygen, and YAML reload",
    },
    logs: {
      title: "Engine Event Stream",
      subtitle: "Structured kernel telemetry and connection audit logs",
    },
  };

  const mobileTabs: Array<{ id: NavTab; label: string; badge?: number }> = [
    { id: "overview", label: "Home" },
    { id: "proxies", label: "Proxies", badge: concreteNodeCount },
    { id: "connections", label: "Streams", badge: activeCount },
    { id: "rules", label: "Rules" },
    { id: "studio", label: "Profiles" },
    { id: "logs", label: "Logs" },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-header">
          <div className="brand-mark" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <path
                d="M5 19L12 5L19 19"
                stroke="#10b981"
                strokeWidth="2.4"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M8 15H16"
                stroke="#38bdf8"
                strokeWidth="2.2"
                strokeLinecap="round"
              />
            </svg>
          </div>
          <div>
            <div className="brand-title">RustClash</div>
            <div className="brand-subtitle">
              {config?.demo.enabled ? "Demo Sandbox" : "Real User Mode"}
            </div>
          </div>
        </div>

        <nav className="nav-list" aria-label="Main Navigation">
          <button
            id="nav-overview"
            type="button"
            className={`nav-btn ${tab === "overview" ? "active" : ""}`}
            onClick={() => setTab("overview")}
          >
            <span className="nav-btn-left">Overview</span>
          </button>

          <button
            id="nav-proxies"
            type="button"
            className={`nav-btn ${tab === "proxies" ? "active" : ""}`}
            onClick={() => setTab("proxies")}
            title={`${concreteNodeCount} proxy node(s), ${Object.keys(proxies).length} total outbounds/groups`}
          >
            <span className="nav-btn-left">Proxies &amp; Groups</span>
            <span className="nav-count">{concreteNodeCount}</span>
          </button>

          <button
            id="nav-connections"
            type="button"
            className={`nav-btn ${tab === "connections" ? "active" : ""}`}
            onClick={() => setTab("connections")}
          >
            <span className="nav-btn-left">Connections</span>
            <span className="nav-count">{activeCount}</span>
          </button>

          <button
            id="nav-rules"
            type="button"
            className={`nav-btn ${tab === "rules" ? "active" : ""}`}
            onClick={() => setTab("rules")}
          >
            <span className="nav-btn-left">Rules &amp; Fake-IP</span>
            <span className="nav-count">{rules.length}</span>
          </button>

          <button
            id="nav-studio"
            type="button"
            className={`nav-btn ${tab === "studio" ? "active" : ""}`}
            onClick={() => setTab("studio")}
          >
            <span className="nav-btn-left">Profiles &amp; PQ Studio</span>
            {profilesSnapshot && (
              <span className="nav-count">
                {profilesSnapshot.profiles.length}
              </span>
            )}
          </button>

          <button
            id="nav-logs"
            type="button"
            className={`nav-btn ${tab === "logs" ? "active" : ""}`}
            onClick={() => setTab("logs")}
          >
            <span className="nav-btn-left">Live Logs</span>
            <span className="nav-count">{logs.length}</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-speed-box tabular mono">
            <div className="speed-row">
              <span style={{ color: "var(--text-muted)" }}>DL</span>
              <span className="speed-down">
                {formatSpeed(latestTraffic.down)}
              </span>
            </div>
            <div className="speed-row">
              <span style={{ color: "var(--text-muted)" }}>UL</span>
              <span className="speed-up">{formatSpeed(latestTraffic.up)}</span>
            </div>
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              fontSize: 11.5,
              color: "var(--text-muted)",
              padding: "2px 4px",
            }}
          >
            <span>
              <span className={`status-dot ${online ? "" : "offline"}`} />
              {online ? "Engine Connected" : "Reconnecting..."}
            </span>
            <span className="mono">:{config?.["mixed-port"] ?? 7890}</span>
          </div>
        </div>
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
                Per-App Split Tunnel
              </button>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                onClick={() => androidBridge.disconnectVpn()}
              >
                Stop VPN
              </button>
            </div>
          </div>
        )}

        <header className="topbar">
          <div className="topbar-title-group">
            <h1 className="topbar-title">{tabMeta[tab].title}</h1>
            <span className="topbar-meta">{tabMeta[tab].subtitle}</span>
          </div>

          <div className="topbar-actions">
            <div className="segmented" role="group" aria-label="Routing Mode">
              {(["rule", "global", "direct"] as RunMode[]).map((m) => (
                <button
                  key={m}
                  id={`mode-${m}-btn`}
                  type="button"
                  disabled={modeBusy}
                  className={`seg-btn ${config?.mode === m ? "active" : ""}`}
                  onClick={() => void handleModeChange(m)}
                >
                  {m.charAt(0).toUpperCase() + m.slice(1)}
                </button>
              ))}
            </div>

            <button
              id="theme-toggle-btn"
              type="button"
              className="btn btn-sm"
              onClick={() =>
                setTheme((prev) => (prev === "dark" ? "light" : "dark"))
              }
            >
              {theme === "dark" ? "Light" : "Dark"}
            </button>
          </div>
        </header>

        <main className="content-scroll">
          {appError && (
            <div className="banner banner-err">
              <span>{appError}</span>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setAppError(null)}
              >
                Dismiss
              </button>
            </div>
          )}
          {authRequired && (
            <form
              onSubmit={handleSaveSecret}
              className="banner banner-err"
              style={{
                marginBottom: 4,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <span>
                  Control API requires a <strong>Bearer Secret</strong> to
                  access management endpoints.
                </span>
                {authError && (
                  <span style={{ fontSize: 12, fontWeight: 600 }}>
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
                  placeholder="Enter controller secret..."
                  value={secretInput}
                  onChange={(ev) => setSecretInput(ev.target.value)}
                />
                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={authBusy}
                >
                  {authBusy ? "Verifying..." : "Authenticate"}
                </button>
              </div>
            </form>
          )}
          {tab === "overview" && (
            <OverviewView
              version={version}
              config={config}
              profilesSnapshot={profilesSnapshot}
              connections={connections}
              trafficHistory={trafficHistory}
              latestTraffic={latestTraffic}
              onRefreshAll={refreshCore}
              onOpenProfiles={() => setTab("studio")}
              onOpenAddNode={() => {
                setTab("proxies");
                setOpenAddModalSignal((n) => n + 1);
              }}
            />
          )}

          {tab === "proxies" && (
            <ProxiesView
              config={config}
              proxies={proxies}
              onRefreshProxies={refreshCore}
              openAddModalSignal={openAddModalSignal}
            />
          )}

          {tab === "connections" && (
            <ConnectionsView
              items={connections?.connections ?? []}
              onRefresh={async () => {
                const c = await clashApi.getConnections();
                setConnections(c);
              }}
            />
          )}

          {tab === "rules" && (
            <RulesDnsView
              rules={rules}
              onRefreshRules={refreshCore}
            />
          )}

          {tab === "studio" && (
            <StudioView
              profilesSnapshot={profilesSnapshot}
              onReloaded={refreshCore}
            />
          )}

          {tab === "logs" && (
            <LogsView logs={logs} onClear={() => setLogs([])} />
          )}
        </main>

        <nav className="mobile-bottom-nav" aria-label="Mobile Navigation">
          {mobileTabs.map((item) => (
            <button
              key={item.id}
              id={`mobile-nav-${item.id}`}
              type="button"
              className={`mobile-nav-btn ${tab === item.id ? "active" : ""}`}
              onClick={() => setTab(item.id)}
            >
              <span>{item.label}</span>
              {item.badge !== undefined && (
                <span className="tabular" style={{ fontSize: 10, opacity: 0.8 }}>
                  {item.badge}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>
    </div>
  );
};
