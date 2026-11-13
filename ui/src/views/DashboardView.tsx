import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  clashApi,
  fetchExitIp,
  patchConfig,
  setSysProxy,
  testProxyDelay,
} from "../api";
import {
  ActivityPulseIcon,
  ArrowDownIcon,
  ArrowUpIcon,
  CheckIcon,
  ChevronRightIcon,
  ChipMemoryIcon,
  CloseIcon,
  CopyIcon,
  DirectTargetIcon,
  GithubMarkIcon,
  GlobeIcon,
  GoogleGIcon,
  LayersGroupIcon,
  MonitorIpIcon,
  ProfileDocIcon,
  RefreshIcon,
  RuleListIcon,
  ScallopedMasterShape,
  ScallopedShieldBadge,
  ShieldCheckIcon,
  SplitRouteIcon,
  SysProxyIcon,
  WifiIcon,
} from "../components/Icons";
import { Sparkline } from "../components/Sparkline";
import { useI18n } from "../i18n";
import type {
  ConfigSnapshot,
  ConnectionItem,
  ConnectionsResponse,
  ExitIpInfo,
  FakeIpPoolResponse,
  ProfilesSnapshot,
  ProxyInfo,
  RuleItem,
  RunMode,
  TrafficPoint,
} from "../types";
import {
  extractBadgeInitial,
  formatBytes,
  formatCompactCount,
  formatDurationHms,
  formatSpeed,
  prettyProtocolLabel,
  splitBytesParts,
  splitSpeedParts,
} from "../utils/format";

interface DashboardViewProps {
  online: boolean;
  config: ConfigSnapshot | null;
  profilesSnapshot: ProfilesSnapshot | null;
  proxies: Record<string, ProxyInfo>;
  rules: RuleItem[];
  connections: ConnectionsResponse | null;
  trafficHistory: TrafficPoint[];
  latestTraffic: TrafficPoint;
  onRefreshAll: () => Promise<void>;
  onOpenProfiles: () => void;
  onOpenProxies: (focusGroup?: string) => void;
  onOpenTools: () => void;
}

const GROUP_TYPES = new Set(["Selector", "URLTest", "Fallback", "LoadBalance"]);

function inferCountryCodeFromText(text: string): string {
  const u = text.toUpperCase();
  if (u.includes("SG") || text.includes("新") || text.includes("狮城")) return "SG";
  if (u.includes("HK") || text.includes("港")) return "HK";
  if (u.includes("JP") || text.includes("日") || text.includes("东京")) return "JP";
  if (u.includes("US") || text.includes("美") || text.includes("洛杉矶")) return "US";
  if (u.includes("TW") || text.includes("台")) return "TW";
  if (u.includes("KR") || text.includes("韩") || text.includes("首尔")) return "KR";
  if (u.includes("DE") || text.includes("德")) return "DE";
  if (u.includes("UK") || u.includes("GB") || text.includes("英")) return "UK";
  if (u.includes("DIRECT")) return "CN";
  return "IP";
}

function getBrowserHeapBytes(): number {
  if (typeof performance === "undefined") return 0;
  const mem = (
    performance as Performance & {
      memory?: { usedJSHeapSize?: number };
    }
  ).memory;
  return typeof mem?.usedJSHeapSize === "number" ? mem.usedJSHeapSize : 0;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  online,
  config,
  profilesSnapshot,
  proxies,
  rules,
  connections,
  trafficHistory,
  latestTraffic,
  onRefreshAll,
  onOpenProfiles,
  onOpenProxies,
  onOpenTools,
}) => {
  const { tr } = useI18n();

  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);
  const [tunPrivilegeHint, setTunPrivilegeHint] = useState<string | null>(null);
  const [ipCopied, setIpCopied] = useState(false);

  // Exit IP state (`GET /tools/ip`)
  const [exitIp, setExitIp] = useState<ExitIpInfo | null>(null);
  const [ipLoading, setIpLoading] = useState(false);

  // Service connectivity probe state
  const [serviceLatency, setServiceLatency] = useState<{
    google?: number | null;
    github?: number | null;
    probing: boolean;
  }>({ probing: false });

  // Activity tab state (`live` | `recent` | `dns`)
  const [activityTab, setActivityTab] = useState<"live" | "recent" | "dns">(
    "live",
  );
  const [recentDiagnostics, setRecentDiagnostics] = useState<ConnectionItem[]>(
    [],
  );
  const [fakeIpPool, setFakeIpPool] = useState<FakeIpPoolResponse | null>(null);

  // Quick group node picker modal
  const [quickPickerGroup, setQuickPickerGroup] = useState<string | null>(null);

  // Live 1s uptime ticker
  const bootMsRef = useRef<number>(Date.now());
  const [nowMs, setNowMs] = useState<number>(() => Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  // Peak speeds tracking across session
  const peakUpRef = useRef<number>(0);
  const peakDownRef = useRef<number>(0);
  for (const pt of trafficHistory) {
    if (pt.up > peakUpRef.current) peakUpRef.current = pt.up;
    if (pt.down > peakDownRef.current) peakDownRef.current = pt.down;
  }
  if (latestTraffic.up > peakUpRef.current) peakUpRef.current = latestTraffic.up;
  if (latestTraffic.down > peakDownRef.current) {
    peakDownRef.current = latestTraffic.down;
  }

  const groups = useMemo(() => {
    const list = Object.values(proxies).filter(
      (p) => GROUP_TYPES.has(p.type) && p.all && p.all.length > 0,
    );
    list.sort((a, b) => {
      if (a.name === "GLOBAL") return 1;
      if (b.name === "GLOBAL") return -1;
      return 0;
    });
    return list;
  }, [proxies]);

  const concreteNodeCount = useMemo(
    () =>
      Object.values(proxies).filter(
        (p) =>
          !GROUP_TYPES.has(p.type) &&
          p.name !== "DIRECT" &&
          p.name !== "REJECT",
      ).length,
    [proxies],
  );

  const primaryGroup = useMemo(
    () =>
      groups.find(
        (g) =>
          g.type === "Selector" &&
          (g.name === "PROXY" || g.name === "🚀 Proxy"),
      ) ?? groups.find((g) => g.type === "Selector" && g.name !== "GLOBAL"),
    [groups],
  );

  const effectiveOutbound =
    config?.["effective-outbound"]?.effective_outbound ??
    primaryGroup?.effective_outbound ??
    primaryGroup?.now ??
    "DIRECT";
  const effectiveProto =
    config?.["effective-outbound"]?.effective_protocol ??
    primaryGroup?.effective_protocol ??
    "DIRECT";

  const probeTargetName =
    primaryGroup?.name ??
    (effectiveOutbound && proxies[effectiveOutbound]
      ? effectiveOutbound
      : "DIRECT");

  const loadExitIp = useCallback(async (forceRefresh = false) => {
    setIpLoading(true);
    try {
      const info = await fetchExitIp(forceRefresh);
      if (info && info.ip) {
        setExitIp(info);
      }
    } catch {
      // graceful fallback if endpoint not ready or offline
    } finally {
      setIpLoading(false);
    }
  }, []);

  const probeConnectivity = useCallback(async () => {
    if (!online) return;
    setServiceLatency((prev) => ({ ...prev, probing: true }));
    const demoOrigin =
      config?.demo.enabled && config.demo.http_benchmark_origin
        ? `${config.demo.http_benchmark_origin}/generate_204`
        : null;
    const googleUrl = demoOrigin ?? "https://www.gstatic.com/generate_204";
    const githubUrl = demoOrigin ?? "https://api.github.com/";

    const [gRes, ghRes] = await Promise.allSettled([
      testProxyDelay(probeTargetName, googleUrl, 4000),
      testProxyDelay(probeTargetName, githubUrl, 4000),
    ]);

    setServiceLatency({
      google: gRes.status === "fulfilled" ? gRes.value.delay : null,
      github: ghRes.status === "fulfilled" ? ghRes.value.delay : null,
      probing: false,
    });
  }, [online, config?.demo.enabled, config?.demo.http_benchmark_origin, probeTargetName]);

  const loadAuxActivity = useCallback(async () => {
    if (!online) return;
    const [diagRes, fakeRes] = await Promise.allSettled([
      clashApi.getConnectionDiagnostics(80),
      clashApi.getFakeIpPool(),
    ]);
    if (diagRes.status === "fulfilled") {
      setRecentDiagnostics(diagRes.value.diagnostics);
    }
    if (fakeRes.status === "fulfilled") {
      setFakeIpPool(fakeRes.value);
    }
  }, [online]);

  useEffect(() => {
    if (!online) return;
    void loadExitIp(false);
    void probeConnectivity();
    void loadAuxActivity();
  }, [online, effectiveOutbound, config?.mode, loadExitIp, probeConnectivity, loadAuxActivity]);

  useEffect(() => {
    if (!online) return;
    if (activityTab === "recent" || activityTab === "dns") {
      void loadAuxActivity();
    }
  }, [activityTab, online, loadAuxActivity]);

  const sysproxyEnabled = Boolean(config?.sysproxy?.enabled);
  const tunEnabled = Boolean(config?.tun.enable || config?.["tun-active"]);
  const proxyRunning = sysproxyEnabled || tunEnabled;

  // Compute live uptime seconds
  const uptimeSecs = useMemo(() => {
    if (config?.["started-at-ms"] && config["started-at-ms"] > 0) {
      return Math.max(0, Math.floor((nowMs - config["started-at-ms"]) / 1000));
    }
    if (typeof config?.["uptime-secs"] === "number") {
      return Math.max(0, Math.floor(config["uptime-secs"]));
    }
    return Math.max(0, Math.floor((nowMs - bootMsRef.current) / 1000));
  }, [config, nowMs]);

  const runControl = async (key: string, fn: () => Promise<void>) => {
    setBusyKey(key);
    setToast(null);
    try {
      await fn();
      await onRefreshAll();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setToast({ ok: false, text: msg });
      await onRefreshAll();
    } finally {
      setBusyKey(null);
    }
  };

  const handleMasterToggle = async () => {
    if (busyKey) return;
    if (!proxyRunning && concreteNodeCount === 0 && !config?.demo.enabled) {
      setToast({
        ok: false,
        text: tr(
          "尚未配置节点，请先在「订阅配置」中导入订阅或手动添加节点",
          "No proxy nodes yet — import a subscription or add a node first",
        ),
      });
      onOpenProfiles();
      return;
    }

    await runControl("master", async () => {
      if (proxyRunning) {
        if (sysproxyEnabled) {
          await setSysProxy(false);
        }
        if (tunEnabled) {
          await patchConfig({ tun: { enable: false } });
        }
      } else {
        if (config?.mode === "direct") {
          await patchConfig({ mode: "rule" });
        }
        if (config?.sysproxy?.supported !== false) {
          await setSysProxy(true);
        } else {
          await patchConfig({ tun: { enable: true } });
        }
      }
      void loadExitIp(true);
    });
  };

  const handleModeSwitch = (mode: RunMode) => {
    if (busyKey || config?.mode === mode) return;
    void runControl(`mode-${mode}`, async () => {
      await patchConfig({ mode });
      void loadExitIp(true);
    });
  };

  const handleSysProxySwitch = () => {
    if (busyKey) return;
    void runControl("sysproxy", async () => {
      await setSysProxy(!sysproxyEnabled);
    });
  };

  const handleTunSwitch = () => {
    if (busyKey || !config) return;
    const nextEnable = !tunEnabled;
    setTunPrivilegeHint(null);
    setBusyKey("tun");
    setToast(null);
    void (async () => {
      try {
        await patchConfig({ tun: { enable: nextEnable } });
        await onRefreshAll();
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const hint = config.tun.health?.privilege_hint;
        if (hint) {
          setTunPrivilegeHint(hint);
        } else {
          setToast({ ok: false, text: msg });
        }
        await onRefreshAll();
      } finally {
        setBusyKey(null);
      }
    })();
  };

  const handleAllowLanSwitch = () => {
    if (busyKey || !config) return;
    void runControl("allow-lan", async () => {
      await patchConfig({ "allow-lan": !config["allow-lan"] });
    });
  };

  const intranetIp =
    config?.["intranet-ip"] ||
    config?.["lan-ip"] ||
    config?.["tun-ip"] ||
    config?.tun.health?.ipv4_cidr?.split("/")[0] ||
    "198.18.0.1";

  const handleCopyIntranetIp = async () => {
    try {
      await navigator.clipboard?.writeText(intranetIp);
      setIpCopied(true);
      window.setTimeout(() => setIpCopied(false), 1800);
    } catch {
      // ignore clipboard restriction
    }
  };

  const activeProfile = useMemo(() => {
    if (!profilesSnapshot) return null;
    return (
      profilesSnapshot.profiles.find(
        (p) => p.id === profilesSnapshot.active_profile_id,
      ) ??
      profilesSnapshot.profiles[0] ??
      null
    );
  }, [profilesSnapshot]);

  const groupCount =
    config?.["group-count"] ?? activeProfile?.group_count ?? groups.length;
  const proxyCount =
    config?.["proxy-count"] ?? activeProfile?.proxy_count ?? concreteNodeCount;
  const ruleCount =
    config?.["rule-count"] ?? activeProfile?.rule_count ?? rules.length;

  // Upload & Download speeds & sparklines
  const upParts = splitSpeedParts(latestTraffic.up);
  const downParts = splitSpeedParts(latestTraffic.down);
  const totalUp = connections?.uploadTotal ?? latestTraffic.total_up;
  const totalDown = connections?.downloadTotal ?? latestTraffic.total_down;
  const upSeries = useMemo(
    () => trafficHistory.slice(-36).map((p) => p.up),
    [trafficHistory],
  );
  const downSeries = useMemo(
    () => trafficHistory.slice(-36).map((p) => p.down),
    [trafficHistory],
  );

  // Memory calculation
  const coreRssBytes =
    config?.["process-rss-bytes"] ?? connections?.memory ?? 0;
  const jsHeapBytes = getBrowserHeapBytes();
  const effectiveCoreBytes = coreRssBytes > 0 ? coreRssBytes : 28 * 1024 * 1024;
  const effectiveUiBytes =
    jsHeapBytes > 0 ? jsHeapBytes : Math.round(effectiveCoreBytes * 0.36);
  const totalMemBytes = effectiveCoreBytes + effectiveUiBytes;
  const totalMemParts = splitBytesParts(totalMemBytes);
  const corePct = Math.max(
    18,
    Math.min(86, Math.round((effectiveCoreBytes / totalMemBytes) * 100)),
  );
  const uiPct = 100 - corePct;

  // Exit IP display fields with graceful fallbacks
  const hasResolvedExitIp = Boolean(
    exitIp && exitIp.ok !== false && exitIp.ip && exitIp.ip !== "--",
  );
  const countryCode =
    (hasResolvedExitIp ? exitIp?.country_code?.trim().toUpperCase() : "") ||
    inferCountryCodeFromText(effectiveOutbound);
  const displayIp = hasResolvedExitIp
    ? exitIp!.ip
    : config?.demo.enabled
      ? "198.51.100.42"
      : effectiveOutbound === "DIRECT"
        ? intranetIp
        : effectiveOutbound;
  const nodeTypeTag =
    (hasResolvedExitIp ? exitIp?.node_type || exitIp?.ip_type : "") ||
    (effectiveProto !== "DIRECT"
      ? prettyProtocolLabel(effectiveProto)
      : tr("直连网络", "Direct"));
  const qualityTag =
    (hasResolvedExitIp && exitIp?.latency_ms
      ? `${exitIp.latency_ms} ms`
      : hasResolvedExitIp
        ? exitIp?.quality
        : "") || tr("质量正常", "Quality Normal");
  const orgLabel =
    (hasResolvedExitIp ? exitIp?.organization || exitIp?.isp : "") ||
    (config?.demo.enabled
      ? "RustClash Loopback Sandbox"
      : effectiveOutbound || "Direct Network");

  // Activity counts
  const liveConns = connections?.connections ?? [];
  const totalReqCount =
    connections?.totalConnections ??
    Math.max(liveConns.length, recentDiagnostics.length);
  const dnsQueryCount =
    fakeIpPool?.total_queries ??
    fakeIpPool?.count ??
    config?.dns["fake-ip-entries"] ??
    0;

  const pickerGroupObj = quickPickerGroup ? proxies[quickPickerGroup] : null;

  return (
    <>
      {toast && (
        <div className={`banner ${toast.ok ? "banner-ok" : "banner-err"}`}>
          <span>{toast.text}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setToast(null)}
          >
            {tr("知道了", "Dismiss")}
          </button>
        </div>
      )}

      {tunPrivilegeHint && (
        <div className="banner banner-warn">
          <span>
            <strong>{tr("开启 TUN 需要系统网络权限：", "TUN requires network privilege: ")}</strong>
            {tunPrivilegeHint}
          </span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setTunPrivilegeHint(null)}
          >
            {tr("关闭", "Close")}
          </button>
        </div>
      )}

      <div className="bento-grid">
        {/* ROW 1: Status Hero (6) + Upload (3) + Download (3) */}
        <section className="bento-card hero-card col-6">
          <svg
            className="hero-wave-bg"
            viewBox="0 0 280 200"
            preserveAspectRatio="none"
            aria-hidden="true"
          >
            <path
              d="M78,0 C60,28 84,56 64,86 C44,116 68,154 96,176 C124,198 164,194 205,200 L280,200 L280,0 Z"
              fill="var(--hero-wave-fill)"
            />
          </svg>

          <div className="hero-content">
            <div className="hero-left">
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span className="bento-card-label">
                  <ActivityPulseIcon size={16} />
                  <span>{tr("状态", "Status")}</span>
                </span>
                <span
                  className={`status-pill ${
                    !online
                      ? "offline"
                      : proxyRunning
                        ? "running"
                        : "direct"
                  }`}
                >
                  <span className="status-pill-dot" />
                  {!online
                    ? tr("未连接", "Offline")
                    : proxyRunning
                      ? tr("运行中", "Running")
                      : tr("直连待机", "Direct")}
                </span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
                <button
                  type="button"
                  className="country-badge-btn"
                  onClick={() => void loadExitIp(true)}
                  title={tr("点击刷新出口 IP 信息", "Click to refresh exit IP")}
                >
                  {ipLoading ? <RefreshIcon size={15} spinning /> : countryCode}
                </button>
                <div style={{ minWidth: 0 }}>
                  <div
                    className="hero-ip-text tabular"
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {displayIp}
                  </div>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      marginTop: 5,
                      flexWrap: "wrap",
                    }}
                  >
                    <span className="hero-meta-tag">{nodeTypeTag}</span>
                    <span className="hero-meta-tag tabular">{qualityTag}</span>
                  </div>
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "flex-end",
                  gap: 24,
                  minWidth: 0,
                }}
              >
                <div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {tr("运行时间", "Run time")}
                  </div>
                  <div
                    className="tabular"
                    style={{ fontSize: 13.5, fontWeight: 650, marginTop: 1 }}
                  >
                    {formatDurationHms(uptimeSecs)}
                  </div>
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {tr("运营商 / 出站", "Organization")}
                  </div>
                  <div
                    style={{
                      fontSize: 13.5,
                      fontWeight: 600,
                      marginTop: 1,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={orgLabel}
                  >
                    {orgLabel}
                  </div>
                </div>
              </div>
            </div>

            <button
              id="master-proxy-switch-btn"
              type="button"
              className="master-switch-btn"
              disabled={busyKey === "master"}
              onClick={() => void handleMasterToggle()}
              title={
                proxyRunning
                  ? tr("点击暂停系统代理与 TUN", "Pause System Proxy & TUN")
                  : tr("点击一键开启系统代理", "Enable System Proxy in 1 click")
              }
              aria-label={
                proxyRunning
                  ? tr("暂停代理", "Pause proxy")
                  : tr("启动代理", "Start proxy")
              }
            >
              <ScallopedMasterShape
                running={proxyRunning}
                busy={busyKey === "master"}
                size={68}
              />
            </button>
          </div>
        </section>

        <section className="bento-card speed-card col-3">
          <div>
            <div className="bento-card-head" style={{ marginBottom: 4 }}>
              <span className="bento-card-label">
                <ArrowUpIcon size={14} color="var(--text-secondary)" />
                <span>{tr("上传", "Upload")}</span>
              </span>
              <span
                className="tabular"
                style={{ fontSize: 11, color: "var(--text-muted)" }}
              >
                {tr("峰值", "Peak")} {formatSpeed(peakUpRef.current)}
              </span>
            </div>
            <div className="speed-big-row tabular">
              <span className="speed-big-num">{upParts.value}</span>
              <span className="speed-big-unit">{upParts.unit}</span>
            </div>
            <div className="speed-total-sub tabular">
              {tr("总计", "Total")} {formatBytes(totalUp)}
            </div>
          </div>
          <div className="sparkline-wrap">
            <Sparkline values={upSeries} strokeColor="#3b82f6" height={52} />
          </div>
        </section>

        <section className="bento-card speed-card col-3">
          <div>
            <div className="bento-card-head" style={{ marginBottom: 4 }}>
              <span className="bento-card-label">
                <ArrowDownIcon size={14} color="var(--accent-blue)" />
                <span>{tr("下载", "Download")}</span>
              </span>
              <span
                className="tabular"
                style={{ fontSize: 11, color: "var(--text-muted)" }}
              >
                {tr("峰值", "Peak")} {formatSpeed(peakDownRef.current)}
              </span>
            </div>
            <div className="speed-big-row tabular">
              <span className="speed-big-num">{downParts.value}</span>
              <span className="speed-big-unit">{downParts.unit}</span>
            </div>
            <div className="speed-total-sub tabular">
              {tr("总计", "Total")} {formatBytes(totalDown)}
            </div>
          </div>
          <div className="sparkline-wrap">
            <Sparkline values={downSeries} strokeColor="#1677ff" height={52} />
          </div>
        </section>

        {/* ROW 2: Outbound mode (6) + System proxy (3) + TUN (3) */}
        <section className="bento-card bento-card-compact col-6">
          <span className="bento-card-label" style={{ fontWeight: 600, color: "var(--text-primary)" }}>
            <SplitRouteIcon size={16} />
            <span>{tr("出站模式", "Outbound mode")}</span>
          </span>
          <div className="mode-pills" role="group" aria-label={tr("出站模式", "Outbound mode")}>
            <button
              id="mode-rule-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`mode-pill-btn ${(config?.mode ?? "rule") === "rule" ? "active" : ""}`}
              onClick={() => handleModeSwitch("rule")}
            >
              <RuleListIcon size={14} />
              <span>{tr("规则", "Rule")}</span>
            </button>
            <button
              id="mode-global-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`mode-pill-btn ${config?.mode === "global" ? "active" : ""}`}
              onClick={() => handleModeSwitch("global")}
            >
              <GlobeIcon size={14} />
              <span>{tr("全局", "Global")}</span>
            </button>
            <button
              id="mode-direct-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`mode-pill-btn ${config?.mode === "direct" ? "active" : ""}`}
              onClick={() => handleModeSwitch("direct")}
            >
              <DirectTargetIcon size={14} />
              <span>{tr("直连", "Direct")}</span>
            </button>
          </div>
        </section>

        <section className="bento-card bento-card-compact col-3">
          <span className="bento-card-label" style={{ fontWeight: 600, color: "var(--text-primary)" }}>
            <SysProxyIcon size={16} />
            <span>{tr("系统代理", "System proxy")}</span>
          </span>
          <button
            id="toggle-sysproxy-btn"
            type="button"
            role="switch"
            aria-checked={sysproxyEnabled}
            aria-label={tr("系统代理开关", "Toggle System proxy")}
            disabled={busyKey === "sysproxy" || config?.sysproxy?.supported === false}
            className={`pill-switch ${sysproxyEnabled ? "checked" : ""}`}
            onClick={handleSysProxySwitch}
          />
        </section>

        <section className="bento-card bento-card-compact col-3">
          <span
            className="bento-card-label"
            style={{ fontWeight: 600, color: "var(--text-primary)", gap: 9 }}
          >
            <ScallopedShieldBadge size={28} active={tunEnabled} />
            <span>{tr("TUN 虚拟网卡", "TUN")}</span>
          </span>
          <button
            id="toggle-tun-btn"
            type="button"
            role="switch"
            aria-checked={tunEnabled}
            aria-label={tr("TUN 虚拟网卡开关", "Toggle TUN")}
            disabled={busyKey === "tun" || !config}
            className={`pill-switch ${tunEnabled ? "checked" : ""}`}
            onClick={handleTunSwitch}
          />
        </section>

        {/* ROW 3: Intranet IP (3) + Profile (3) + Service status (3) + Memory info (3) */}
        <section
          className="bento-card col-3"
          style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", gap: 10 }}
        >
          <div>
            <div className="bento-card-head" style={{ marginBottom: 6 }}>
              <span className="bento-card-label">
                <MonitorIpIcon size={16} />
                <span>{tr("内网地址", "Intranet IP")}</span>
              </span>
              <button
                type="button"
                className="bento-icon-action"
                onClick={() => void handleCopyIntranetIp()}
                title={ipCopied ? tr("已复制", "Copied") : tr("复制地址", "Copy IP")}
              >
                {ipCopied ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
              </button>
            </div>
            <div
              className="tabular"
              style={{ fontSize: 20, fontWeight: 700, letterSpacing: "-0.02em" }}
            >
              {intranetIp}
            </div>
          </div>

          <div
            className="sub-pill-box"
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 8,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 9, minWidth: 0 }}>
              <span
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: "50%",
                  background: "var(--bg-card)",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "var(--text-secondary)",
                  flexShrink: 0,
                }}
              >
                <WifiIcon size={15} />
              </span>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12.5, fontWeight: 600 }}>
                  {tr("局域网共享", "Allow LAN")}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                  {config?.["allow-lan"]
                    ? tr("已开启", "Enabled")
                    : tr("已关闭", "Disabled")}
                </div>
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={Boolean(config?.["allow-lan"])}
              aria-label={tr("允许局域网连接", "Allow LAN")}
              disabled={busyKey === "allow-lan" || !config}
              className={`pill-switch ${config?.["allow-lan"] ? "checked" : ""}`}
              onClick={handleAllowLanSwitch}
            />
          </div>
        </section>

        <section
          className="bento-card col-3"
          style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", gap: 10 }}
        >
          <div>
            <div className="bento-card-head" style={{ marginBottom: 6 }}>
              <span className="bento-card-label">
                <ProfileDocIcon size={16} />
                <span>{tr("当前配置", "Profile")}</span>
              </span>
              <button
                type="button"
                className="bento-icon-action"
                onClick={onOpenProfiles}
                title={tr("管理订阅配置", "Manage Profiles")}
              >
                <ChevronRightIcon size={15} />
              </button>
            </div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                minWidth: 0,
              }}
            >
              <span
                style={{
                  fontSize: 15,
                  fontWeight: 650,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  flex: 1,
                }}
                title={activeProfile?.name ?? "Default"}
              >
                {activeProfile?.name ?? tr("默认配置", "Default Profile")}
              </span>
              <span
                style={{
                  fontSize: 11,
                  color: "var(--text-muted)",
                  flexShrink: 0,
                }}
              >
                {activeProfile?.kind === "subscription"
                  ? tr("订阅", "Sub")
                  : tr("本地", "Local")}
              </span>
              {(activeProfile?.manual_proxy_count ?? 0) > 0 && (
                <span className="badge badge-emerald tabular">
                  +{activeProfile?.manual_proxy_count} {tr("手动", "Manual")}
                </span>
              )}
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
              gap: 6,
              paddingTop: 4,
            }}
          >
            <div>
              <div className="tabular" style={{ fontSize: 15.5, fontWeight: 700 }}>
                {groupCount}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {tr("策略组", "Proxy group")}
              </div>
            </div>
            <div>
              <div className="tabular" style={{ fontSize: 15.5, fontWeight: 700 }}>
                {proxyCount}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {tr("节点", "Proxies")}
              </div>
            </div>
            <div>
              <div className="tabular" style={{ fontSize: 15.5, fontWeight: 700 }}>
                {ruleCount.toLocaleString()}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {tr("规则", "Rules")}
              </div>
            </div>
          </div>
        </section>

        <section
          className="bento-card col-3"
          style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", gap: 8 }}
        >
          <div className="bento-card-head" style={{ marginBottom: 2 }}>
            <span className="bento-card-label">
              <ShieldCheckIcon size={16} />
              <span>{tr("连通性检测", "Service status")}</span>
            </span>
            <button
              type="button"
              className="bento-icon-action"
              onClick={() => void probeConnectivity()}
              title={tr("重新检测连通性", "Re-test connectivity")}
            >
              <RefreshIcon size={14} spinning={serviceLatency.probing} />
            </button>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div className="service-pill-row">
              <span className="service-icon-wrap">
                <GoogleGIcon size={16} />
                <span
                  className={`service-dot ${
                    serviceLatency.google == null
                      ? "idle"
                      : serviceLatency.google < 400
                        ? ""
                        : "warn"
                  }`}
                />
              </span>
              <span className="tabular" style={{ fontSize: 12.5, fontWeight: 600 }}>
                {serviceLatency.probing && serviceLatency.google === undefined
                  ? tr("检测中...", "Testing...")
                  : serviceLatency.google != null
                    ? `${serviceLatency.google} ms`
                    : tr("未检测", "—")}
              </span>
              <span
                style={{
                  marginLeft: "auto",
                  fontSize: 11,
                  color: "var(--text-muted)",
                }}
              >
                Google
              </span>
            </div>

            <div className="service-pill-row">
              <span className="service-icon-wrap">
                <GithubMarkIcon size={16} />
                <span
                  className={`service-dot ${
                    serviceLatency.github == null
                      ? "idle"
                      : serviceLatency.github < 400
                        ? ""
                        : "warn"
                  }`}
                />
              </span>
              <span className="tabular" style={{ fontSize: 12.5, fontWeight: 600 }}>
                {serviceLatency.probing && serviceLatency.github === undefined
                  ? tr("检测中...", "Testing...")
                  : serviceLatency.github != null
                    ? `${serviceLatency.github} ms`
                    : tr("未检测", "—")}
              </span>
              <span
                style={{
                  marginLeft: "auto",
                  fontSize: 11,
                  color: "var(--text-muted)",
                }}
              >
                GitHub
              </span>
            </div>
          </div>
        </section>

        <section
          className="bento-card col-3"
          style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}
        >
          <div>
            <div className="bento-card-head" style={{ marginBottom: 4 }}>
              <span className="bento-card-label">
                <ChipMemoryIcon size={16} />
                <span>{tr("内存占用", "Memory info")}</span>
              </span>
              <button
                type="button"
                className="bento-icon-action"
                onClick={onOpenTools}
                title={tr("打开工具与设置", "Open Tools")}
              >
                <ChevronRightIcon size={15} />
              </button>
            </div>

            <div className="speed-big-row tabular" style={{ marginTop: 0 }}>
              <span style={{ fontSize: 22, fontWeight: 700, letterSpacing: "-0.02em" }}>
                {totalMemParts.value}
              </span>
              <span className="speed-big-unit">{totalMemParts.unit}</span>
            </div>

            <div className="mem-bar-track">
              <div className="mem-bar-core" style={{ width: `${corePct}%` }} />
              <div className="mem-bar-ui" style={{ width: `${uiPct}%` }} />
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 3, fontSize: 11.5 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: "var(--accent-blue)",
                }}
              />
              <span style={{ color: "var(--text-muted)" }}>
                {tr("核心引擎", "Core")}
              </span>
              <span className="tabular" style={{ fontWeight: 650 }}>
                {formatBytes(effectiveCoreBytes)}
              </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: "#60a5fa",
                }}
              />
              <span style={{ color: "var(--text-muted)" }}>
                {tr("界面缓存", "UI Cache")}
              </span>
              <span className="tabular" style={{ fontWeight: 650 }}>
                {formatBytes(effectiveUiBytes)}
              </span>
            </div>
          </div>
        </section>

        {/* ROW 4: Tabbed Activity Card (7) + Proxy group Card (5) */}
        <section className="bento-card col-7">
          <div className="activity-tabs">
            <button
              type="button"
              className={`activity-tab-btn ${activityTab === "live" ? "active" : ""}`}
              onClick={() => setActivityTab("live")}
            >
              <span className="activity-tab-count tabular">
                {formatCompactCount(liveConns.length)}
              </span>
              <span>{tr("实时连接", "Live connections")}</span>
            </button>
            <button
              type="button"
              className={`activity-tab-btn ${activityTab === "recent" ? "active" : ""}`}
              onClick={() => setActivityTab("recent")}
            >
              <span className="activity-tab-count tabular">
                {formatCompactCount(totalReqCount)}
              </span>
              <span>{tr("历史连接", "Recent requests")}</span>
            </button>
            <button
              type="button"
              className={`activity-tab-btn ${activityTab === "dns" ? "active" : ""}`}
              onClick={() => setActivityTab("dns")}
            >
              <span className="activity-tab-count tabular">
                {formatCompactCount(dnsQueryCount)}
              </span>
              <span>{tr("DNS 查询", "DNS queries")}</span>
            </button>
          </div>

          <div className="bento-table-scroll">
            {activityTab === "dns" ? (
              <table className="bento-table">
                <thead>
                  <tr>
                    <th>{tr("域名", "Domain")}</th>
                    <th>Fake-IP</th>
                    <th>{tr("真实 IP", "Real IP")}</th>
                    <th style={{ textAlign: "right" }}>TTL</th>
                  </tr>
                </thead>
                <tbody>
                  {!fakeIpPool || fakeIpPool.entries.length === 0 ? (
                    <tr>
                      <td
                        colSpan={4}
                        style={{
                          textAlign: "center",
                          padding: "26px 8px",
                          color: "var(--text-muted)",
                        }}
                      >
                        {tr("暂无 Fake-IP DNS 解析记录", "No Fake-IP DNS entries yet")}
                      </td>
                    </tr>
                  ) : (
                    fakeIpPool.entries.slice(0, 30).map((entry) => (
                      <tr key={`${entry.ip}-${entry.domain}`}>
                        <td
                          style={{
                            maxWidth: 220,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            fontWeight: 550,
                          }}
                          title={entry.domain}
                        >
                          {entry.domain}
                        </td>
                        <td className="tabular" style={{ color: "var(--text-secondary)" }}>
                          {entry.ip}
                        </td>
                        <td className="tabular" style={{ color: "var(--text-muted)" }}>
                          {entry.real_ip || "—"}
                        </td>
                        <td
                          className="tabular"
                          style={{ textAlign: "right", color: "var(--text-muted)" }}
                        >
                          {entry.ttl_secs ? `${entry.ttl_secs}s` : "LRU"}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            ) : (
              <table className="bento-table">
                <thead>
                  <tr>
                    <th>{tr("来源", "Source")}</th>
                    <th>{tr("目标", "Target")}</th>
                    <th>{tr("出站", "Exit")}</th>
                    <th style={{ textAlign: "right" }}>{tr("下载", "Download")}</th>
                    <th style={{ textAlign: "right" }}>{tr("上传", "Upload")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(activityTab === "live" ? liveConns : recentDiagnostics)
                    .length === 0 ? (
                    <tr>
                      <td
                        colSpan={5}
                        style={{
                          textAlign: "center",
                          padding: "26px 8px",
                          color: "var(--text-muted)",
                        }}
                      >
                        {activityTab === "live"
                          ? tr("当前没有活跃连接", "No active connections right now")
                          : tr("暂无最近请求记录", "No recent requests recorded")}
                      </td>
                    </tr>
                  ) : (
                    (activityTab === "live" ? liveConns : recentDiagnostics)
                      .slice(0, 30)
                      .map((conn) => {
                        const procLabel =
                          conn.metadata.process?.trim() ||
                          conn.metadata.type ||
                          conn.metadata.source;
                        const targetLabel = `${
                          conn.metadata.host || conn.metadata.destination_ip || "*"
                        }:${conn.metadata.destination_port}`;
                        const exitHop =
                          conn.effective_outbound ||
                          conn.chains[conn.chains.length - 1] ||
                          conn.chains[0] ||
                          "DIRECT";
                        return (
                          <tr key={`${conn.id}-${conn.start_epoch_ms}`}>
                            <td>
                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: 8,
                                  maxWidth: 145,
                                }}
                              >
                                <span className="source-avatar">
                                  {extractBadgeInitial(procLabel)}
                                </span>
                                <span
                                  style={{
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    fontWeight: 550,
                                  }}
                                  title={procLabel}
                                >
                                  {procLabel}
                                </span>
                              </div>
                            </td>
                            <td
                              style={{
                                maxWidth: 185,
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                color: "var(--text-secondary)",
                              }}
                              title={targetLabel}
                            >
                              {targetLabel}
                            </td>
                            <td
                              style={{
                                maxWidth: 120,
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                color: "var(--text-secondary)",
                              }}
                              title={exitHop}
                            >
                              {exitHop}
                            </td>
                            <td
                              className="tabular"
                              style={{ textAlign: "right", color: "var(--text-secondary)" }}
                            >
                              {formatBytes(conn.download)}
                            </td>
                            <td
                              className="tabular"
                              style={{ textAlign: "right", color: "var(--text-secondary)" }}
                            >
                              {formatBytes(conn.upload)}
                            </td>
                          </tr>
                        );
                      })
                  )}
                </tbody>
              </table>
            )}
          </div>
        </section>

        <section className="bento-card col-5">
          <div className="bento-card-head" style={{ marginBottom: 10 }}>
            <span className="bento-card-label">
              <LayersGroupIcon size={16} />
              <span>{tr("策略组", "Proxy group")}</span>
              <span className="badge badge-neutral tabular">{groups.length}</span>
            </span>
            <button
              type="button"
              className="bento-icon-action"
              onClick={() => onOpenProxies()}
              title={tr("前往代理节点页", "Open Proxies")}
            >
              <ChevronRightIcon size={15} />
            </button>
          </div>

          {groups.length === 0 ? (
            <div
              className="sub-pill-box"
              style={{
                padding: "20px 14px",
                textAlign: "center",
                color: "var(--text-muted)",
              }}
            >
              <div style={{ marginBottom: 8 }}>
                {tr("尚未添加代理策略组或订阅", "No proxy groups configured yet")}
              </div>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={onOpenProfiles}
              >
                {tr("去导入订阅", "Import Subscription")}
              </button>
            </div>
          ) : (
            <div className="proxy-mini-grid">
              {groups.map((grp) => {
                const selectedNode = grp.now || grp.effective_outbound || "DIRECT";
                return (
                  <button
                    key={grp.name}
                    type="button"
                    className={`proxy-mini-card ${
                      quickPickerGroup === grp.name ? "active-popover" : ""
                    }`}
                    onClick={() => {
                      if (grp.type === "Selector") {
                        setQuickPickerGroup(grp.name);
                      } else {
                        onOpenProxies(grp.name);
                      }
                    }}
                    title={`${grp.name} → ${selectedNode}`}
                  >
                    <span className="proxy-mini-avatar">
                      {extractBadgeInitial(grp.name)}
                    </span>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div
                        style={{
                          fontSize: 12.5,
                          fontWeight: 650,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {grp.name}
                      </div>
                      <div
                        style={{
                          fontSize: 11,
                          color: "var(--text-muted)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          marginTop: 1,
                        }}
                      >
                        {selectedNode}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </section>
      </div>

      {/* Quick Group Node Picker Modal */}
      {pickerGroupObj && (
        <div
          className="modal-backdrop"
          onClick={() => setQuickPickerGroup(null)}
        >
          <div
            className="modal-card"
            style={{ maxWidth: 480 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
              }}
            >
              <div>
                <div style={{ fontSize: 15.5, fontWeight: 650 }}>
                  {pickerGroupObj.name}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {tr("快速切换当前策略组出站节点", "Quickly switch node for this group")}
                </div>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => {
                    const target = pickerGroupObj.name;
                    setQuickPickerGroup(null);
                    onOpenProxies(target);
                  }}
                >
                  {tr("完整列表", "Full View")}
                </button>
                <button
                  type="button"
                  className="bento-icon-action"
                  onClick={() => setQuickPickerGroup(null)}
                >
                  <CloseIcon size={15} />
                </button>
              </div>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(185px, 1fr))",
                gap: 8,
                maxHeight: 320,
                overflowY: "auto",
              }}
            >
              {(pickerGroupObj.all ?? []).map((memberName) => {
                const isSelected = pickerGroupObj.now === memberName;
                const info = proxies[memberName];
                const delay =
                  info && info.history.length > 0
                    ? info.history[info.history.length - 1]?.delay
                    : undefined;
                return (
                  <button
                    key={memberName}
                    type="button"
                    className={`node-tile ${isSelected ? "selected" : ""}`}
                    onClick={() => {
                      void (async () => {
                        try {
                          await clashApi.selectProxy(
                            pickerGroupObj.name,
                            memberName,
                          );
                          await onRefreshAll();
                          setQuickPickerGroup(null);
                        } catch (err) {
                          setToast({
                            ok: false,
                            text:
                              err instanceof Error ? err.message : String(err),
                          });
                        }
                      })();
                    }}
                  >
                    <div className="node-name" title={memberName}>
                      {memberName}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        fontSize: 11,
                        color: "var(--text-muted)",
                      }}
                    >
                      <span>{prettyProtocolLabel(info?.type ?? "Node")}</span>
                      {delay && delay > 0 ? (
                        <span
                          className="tabular"
                          style={{
                            color:
                              delay < 150
                                ? "#16a34a"
                                : delay < 400
                                  ? "#d97706"
                                  : "#e11d48",
                            fontWeight: 600,
                          }}
                        >
                          {delay} ms
                        </span>
                      ) : null}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </>
  );
};
