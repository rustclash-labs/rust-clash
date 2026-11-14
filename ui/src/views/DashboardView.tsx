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
  ChevronDownIcon,
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
import {
  deriveExitIpDisplay,
  deriveMemoryDisplay,
  deriveThreeLayerStatus,
  planMasterToggle,
  resolveIntranetIpDisplay,
  type TakeoverPref,
} from "../utils/statusModel.mjs";

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
  onOpenSiteDoctor: (initialTarget?: string) => void;
}

const GROUP_TYPES = new Set(["Selector", "URLTest", "Fallback", "LoadBalance"]);
const TAKEOVER_PREF_KEY = "rust_clash_takeover_pref_v1";

function loadSavedTakeoverPref(): Partial<TakeoverPref> | null {
  try {
    const raw = window.localStorage.getItem(TAKEOVER_PREF_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<TakeoverPref>;
    return typeof parsed === "object" && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}

function saveTakeoverPref(pref: TakeoverPref): void {
  try {
    window.localStorage.setItem(TAKEOVER_PREF_KEY, JSON.stringify(pref));
  } catch {
    // ignore storage restriction
  }
}

function getBrowserHeapBytes(): number | null {
  if (typeof performance === "undefined") return null;
  const mem = (
    performance as Performance & {
      memory?: { usedJSHeapSize?: number };
    }
  ).memory;
  return typeof mem?.usedJSHeapSize === "number" && mem.usedJSHeapSize > 0
    ? mem.usedJSHeapSize
    : null;
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
  onOpenSiteDoctor,
}) => {
  const { lang, tr } = useI18n();

  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);
  const [tunPrivilegeHint, setTunPrivilegeHint] = useState<string | null>(null);
  const [ipCopied, setIpCopied] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  // Exit IP state (`GET /tools/ip`) — null means not yet checked
  const [exitIp, setExitIp] = useState<ExitIpInfo | null>(null);
  const [ipLoading, setIpLoading] = useState(false);

  // Service connectivity probe state (`undefined` = unchecked, `null` = failed)
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
      if (info && info.ip && info.ok !== false) {
        setExitIp(info);
      } else {
        setExitIp({ ip: "", country_code: "", country: "", ok: false });
      }
    } catch {
      setExitIp({ ip: "", country_code: "", country: "", ok: false });
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
      google:
        gRes.status === "fulfilled" && gRes.value.delay > 0
          ? gRes.value.delay
          : null,
      github:
        ghRes.status === "fulfilled" && ghRes.value.delay > 0
          ? ghRes.value.delay
          : null,
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
  }, [online, effectiveOutbound, config?.mode, loadExitIp, probeConnectivity]);

  useEffect(() => {
    if (!online || !advancedOpen) return;
    void loadAuxActivity();
  }, [advancedOpen, activityTab, online, loadAuxActivity]);

  const sysproxyEnabled = Boolean(config?.sysproxy?.enabled);
  const tunEnabled = Boolean(config?.tun.enable || config?.["tun-active"]);
  const proxyRunning = sysproxyEnabled || tunEnabled;

  // Auto-expand Advanced Network section if TUN privilege error occurs
  useEffect(() => {
    if (tunPrivilegeHint) {
      setAdvancedOpen(true);
    }
  }, [tunPrivilegeHint]);

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
    if (
      !proxyRunning &&
      concreteNodeCount === 0 &&
      !config?.demo.enabled &&
      config?.mode !== "direct"
    ) {
      setToast({
        ok: false,
        text: tr(
          "尚未配置代理节点，请先在「订阅配置」中导入订阅或手动添加节点",
          "No proxy nodes configured yet — import a subscription or add a node first",
        ),
      });
      onOpenProfiles();
      return;
    }

    const plan = planMasterToggle(
      {
        sysproxyEnabled,
        tunEnabled,
        sysproxySupported: config?.sysproxy?.supported !== false,
      },
      loadSavedTakeoverPref(),
    );

    setBusyKey("master");
    setToast(null);
    setTunPrivilegeHint(null);

    try {
      if (plan.action === "disable") {
        let sysproxyDisabled = false;
        try {
          if (sysproxyEnabled) {
            await setSysProxy(false);
            sysproxyDisabled = true;
          }
          if (tunEnabled) {
            await patchConfig({ tun: { enable: false } });
          }
          saveTakeoverPref(plan.nextSavedPref);
        } catch (stepErr) {
          // Roll back partial SysProxy mutation if TUN teardown failed
          if (sysproxyDisabled) {
            await setSysProxy(true).catch(() => {});
          }
          throw stepErr;
        }
      } else {
        // Predictable enable: NEVER mutates `config.mode` (`Rule` / `Global` / `Direct`)
        let sysproxyTurnedOn = false;
        try {
          if (plan.targetSysproxy && !sysproxyEnabled) {
            await setSysProxy(true);
            sysproxyTurnedOn = true;
          }
          if (plan.targetTun && !tunEnabled) {
            await patchConfig({ tun: { enable: true } });
          }
          saveTakeoverPref(plan.nextSavedPref);
        } catch (stepErr) {
          // Roll back SysProxy if TUN privilege / setup failed in a multi-step enable
          if (sysproxyTurnedOn) {
            await setSysProxy(false).catch(() => {});
          }
          const hint = config?.tun.health?.privilege_hint;
          if (plan.targetTun && hint) {
            setTunPrivilegeHint(hint);
          }
          throw stepErr;
        }
      }

      await onRefreshAll();
      void loadExitIp(true);
      void probeConnectivity();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setToast({
        ok: false,
        text: tr(
          `操作未完成（已自动回滚部分网络变更）：${msg}`,
          `Operation failed (partial network changes rolled back): ${msg}`,
        ),
      });
      await onRefreshAll();
    } finally {
      setBusyKey(null);
    }
  };

  const handleModeSwitch = (mode: RunMode) => {
    if (busyKey || config?.mode === mode) return;
    void runControl(`mode-${mode}`, async () => {
      await patchConfig({ mode });
      void loadExitIp(true);
      void probeConnectivity();
    });
  };

  const handleSysProxySwitch = () => {
    if (busyKey) return;
    const nextSys = !sysproxyEnabled;
    void runControl("sysproxy", async () => {
      await setSysProxy(nextSys);
      if (nextSys || tunEnabled) {
        saveTakeoverPref({ sysproxy: nextSys, tun: tunEnabled });
      }
      void loadExitIp(true);
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
        if (sysproxyEnabled || nextEnable) {
          saveTakeoverPref({ sysproxy: sysproxyEnabled, tun: nextEnable });
        }
        await onRefreshAll();
        void loadExitIp(true);
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

  const intranetIp = resolveIntranetIpDisplay(config);

  const handleCopyIntranetIp = async () => {
    if (!intranetIp) return;
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

  // Honest Memory Model (zero fabricated 28 MiB / 0.36x fallback)
  const rawCoreRss =
    config?.["process-rss-bytes"] ?? connections?.memory ?? null;
  const rawJsHeap = getBrowserHeapBytes();
  const memModel = deriveMemoryDisplay(rawCoreRss, rawJsHeap);
  const totalMemParts =
    memModel.available && memModel.totalBytes != null
      ? splitBytesParts(memModel.totalBytes)
      : null;

  // Honest 3-Layer Connection Status & Exit IP Display
  const threeLayer = deriveThreeLayerStatus({
    online,
    sysproxyEnabled,
    tunEnabled,
    mixedPort: config?.["mixed-port"] ?? 7890,
    mode: config?.mode ?? "rule",
    demoEnabled: Boolean(config?.demo.enabled),
    probing: serviceLatency.probing,
    googleMs: serviceLatency.google,
    githubMs: serviceLatency.github,
    exitIpOk: exitIp === null ? undefined : exitIp.ok !== false && Boolean(exitIp.ip),
  });

  const exitDisplay = deriveExitIpDisplay({
    online,
    ipLoading,
    exitIp,
    demoEnabled: Boolean(config?.demo.enabled),
    effectiveOutbound,
    effectiveProto,
  });

  const nodeTypeTag =
    (exitDisplay.verified ? exitIp?.node_type || exitIp?.ip_type : "") ||
    (effectiveProto !== "DIRECT"
      ? prettyProtocolLabel(effectiveProto)
      : tr("直连出站", "Direct"));
  const qualityTag = lang === "zh" ? exitDisplay.qualityZh : exitDisplay.qualityEn;
  const orgLabel = lang === "zh" ? exitDisplay.orgZh : exitDisplay.orgEn;
  const displayIp =
    lang === "zh" ? exitDisplay.headlineZh : exitDisplay.headlineEn;

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
            <strong>
              {tr(
                "开启 TUN 需要系统网络权限：",
                "TUN requires network privilege: ",
              )}
            </strong>
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

      {threeLayer.hero.directModeWarning && (
        <div className="banner banner-warn">
          <span>
            {tr(
              "提示：当前系统接管已开启，但路由模式为「直连 (Direct)」，所有流量将直接走本地网络而不经过代理节点。",
              "Note: System takeover is enabled, but Outbound Mode is set to Direct — traffic bypasses proxy nodes.",
            )}
          </span>
          <button
            type="button"
            className="btn btn-sm"
            disabled={Boolean(busyKey)}
            onClick={() => handleModeSwitch("rule")}
          >
            {tr("切换为规则分流", "Switch to Rule")}
          </button>
        </div>
      )}

      <div className="bento-grid">
        {/* ROW 1: Three-Layer Status Hero (6) + Upload (3) + Download (3) */}
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
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span className="bento-card-label">
                  <ActivityPulseIcon size={16} />
                  <span>{tr("连接状态", "Status")}</span>
                </span>
                <span className={`status-pill ${threeLayer.hero.pillClass}`}>
                  <span className="status-pill-dot" />
                  {lang === "zh" ? threeLayer.hero.zh : threeLayer.hero.en}
                </span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
                <button
                  type="button"
                  className="country-badge-btn"
                  onClick={() => {
                    void loadExitIp(true);
                    void probeConnectivity();
                  }}
                  title={
                    exitDisplay.verified
                      ? tr(
                          "已通过出口探测验证地区，点击重新检测",
                          "Verified exit region — click to re-verify",
                        )
                      : tr(
                          "尚未验证出口地区，点击立即探测真实出口 IP",
                          "Exit region unverified — click to probe real exit IP",
                        )
                  }
                >
                  {ipLoading ? (
                    <RefreshIcon size={15} spinning />
                  ) : (
                    exitDisplay.badgeCode
                  )}
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
                  gap: 20,
                  minWidth: 0,
                }}
              >
                <div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {tr("运行时间", "Uptime")}
                  </div>
                  <div
                    className="tabular"
                    style={{ fontSize: 13, fontWeight: 650, marginTop: 1 }}
                  >
                    {online ? formatDurationHms(uptimeSecs) : "—"}
                  </div>
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {exitDisplay.verified
                      ? tr("已验证运营商", "Verified ASN / ISP")
                      : tr("当前出站说明", "Outbound Info")}
                  </div>
                  <div
                    style={{
                      fontSize: 13,
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
                  ? tr(
                      "暂停当前系统接管（保持路由模式不变）",
                      "Pause active system takeover (preserves routing mode)",
                    )
                  : tr(
                      "开启系统接管（自动恢复上次的系统代理 / TUN 组合，不改变路由模式）",
                      "Enable system takeover (restores preferred SysProxy / TUN without changing mode)",
                    )
              }
              aria-label={
                proxyRunning
                  ? tr("暂停系统接管", "Pause takeover")
                  : tr("开启系统接管", "Enable takeover")
              }
            >
              <ScallopedMasterShape
                running={proxyRunning}
                busy={busyKey === "master"}
                size={68}
              />
            </button>
          </div>

          {/* Explicit Three-Layer Status Separation */}
          <div className="three-layer-strip">
            <div className="three-layer-cell">
              <span className="three-layer-title">
                {tr("1. 代理内核", "1. Core Engine")}
              </span>
              <span className="three-layer-val">
                <span className={`layer-dot ${threeLayer.core.tone}`} />
                <span>
                  {lang === "zh" ? threeLayer.core.zh : threeLayer.core.en}
                </span>
              </span>
            </div>

            <div className="three-layer-cell">
              <span className="three-layer-title">
                {tr("2. 系统代理 / TUN", "2. System Takeover")}
              </span>
              <span
                className="three-layer-val"
                title={
                  lang === "zh"
                    ? threeLayer.takeover.zh
                    : threeLayer.takeover.en
                }
              >
                <span className={`layer-dot ${threeLayer.takeover.tone}`} />
                <span>
                  {lang === "zh"
                    ? threeLayer.takeover.zh
                    : threeLayer.takeover.en}
                </span>
              </span>
            </div>

            <div className="three-layer-cell">
              <span className="three-layer-title">
                {tr("3. 互联网连通性", "3. Connectivity")}
              </span>
              <span
                className="three-layer-val"
                title={
                  lang === "zh"
                    ? threeLayer.connectivity.zh
                    : threeLayer.connectivity.en
                }
              >
                <span
                  className={`layer-dot ${threeLayer.connectivity.tone}`}
                />
                <span>
                  {lang === "zh"
                    ? threeLayer.connectivity.zh
                    : threeLayer.connectivity.en}
                </span>
              </span>
            </div>
          </div>
        </section>

        <section className="bento-card speed-card col-3">
          <div>
            <div className="bento-card-head" style={{ marginBottom: 4 }}>
              <span className="bento-card-label">
                <ArrowUpIcon size={14} color="var(--text-secondary)" />
                <span>{tr("上传速度", "Upload")}</span>
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
              {tr("累计", "Total")} {formatBytes(totalUp)}
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
                <span>{tr("下载速度", "Download")}</span>
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
              {tr("累计", "Total")} {formatBytes(totalDown)}
            </div>
          </div>
          <div className="sparkline-wrap">
            <Sparkline values={downSeries} strokeColor="#1677ff" height={52} />
          </div>
        </section>

        {/* ROW 2: Outbound Mode (5) + System Proxy (3) + Site Connectivity Doctor Entry (4) */}
        <section className="bento-card bento-card-compact col-5">
          <span
            className="bento-card-label"
            style={{ fontWeight: 600, color: "var(--text-primary)" }}
          >
            <SplitRouteIcon size={16} />
            <span>{tr("分流模式", "Routing mode")}</span>
          </span>
          <div
            className="mode-pills"
            role="group"
            aria-label={tr("分流模式", "Routing mode")}
          >
            <button
              id="mode-rule-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`mode-pill-btn ${
                (config?.mode ?? "rule") === "rule" ? "active" : ""
              }`}
              onClick={() => handleModeSwitch("rule")}
            >
              <RuleListIcon size={14} />
              <span>{tr("规则", "Rule")}</span>
            </button>
            <button
              id="mode-global-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`mode-pill-btn ${
                config?.mode === "global" ? "active" : ""
              }`}
              onClick={() => handleModeSwitch("global")}
            >
              <GlobeIcon size={14} />
              <span>{tr("全局", "Global")}</span>
            </button>
            <button
              id="mode-direct-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`mode-pill-btn ${
                config?.mode === "direct" ? "active" : ""
              }`}
              onClick={() => handleModeSwitch("direct")}
            >
              <DirectTargetIcon size={14} />
              <span>{tr("直连", "Direct")}</span>
            </button>
          </div>
        </section>

        <section className="bento-card bento-card-compact col-3">
          <span
            className="bento-card-label"
            style={{ fontWeight: 600, color: "var(--text-primary)" }}
          >
            <SysProxyIcon size={16} />
            <span>{tr("系统代理", "System proxy")}</span>
          </span>
          <button
            id="toggle-sysproxy-btn"
            type="button"
            role="switch"
            aria-checked={sysproxyEnabled}
            aria-label={tr("系统代理开关", "Toggle System proxy")}
            disabled={
              busyKey === "sysproxy" || config?.sysproxy?.supported === false
            }
            className={`pill-switch ${sysproxyEnabled ? "checked" : ""}`}
            onClick={handleSysProxySwitch}
          />
        </section>

        <section
          className="bento-card bento-card-compact col-4"
          style={{
            borderColor:
              threeLayer.connectivity.state === "unreachable"
                ? "var(--accent-rose)"
                : undefined,
          }}
        >
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 13, fontWeight: 650 }}>
              {tr("某个网站打不开？", "Website Won't Open?")}
            </div>
            <div
              style={{
                fontSize: 11.5,
                color: "var(--text-muted)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {tr(
                "按网址诊断分流路径、DNS 与 TLS 握手",
                "Check route, DNS & TLS for any site",
              )}
            </div>
          </div>
          <button
            id="open-site-doctor-btn"
            type="button"
            className="btn btn-primary btn-sm"
            style={{ flexShrink: 0 }}
            onClick={() => onOpenSiteDoctor("chatgpt.com")}
          >
            {tr("诊断连接问题", "Site Doctor")}
          </button>
        </section>

        {/* ROW 3: Active Profile (4) + Service Connectivity (3) + Proxy Groups Quick Switcher (5) */}
        <section
          className="bento-card col-4"
          style={{
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            gap: 10,
          }}
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
                {tr("策略组", "Groups")}
              </div>
            </div>
            <div>
              <div className="tabular" style={{ fontSize: 15.5, fontWeight: 700 }}>
                {proxyCount}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {tr("节点", "Nodes")}
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
          style={{
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            gap: 8,
          }}
        >
          <div className="bento-card-head" style={{ marginBottom: 2 }}>
            <span className="bento-card-label">
              <ShieldCheckIcon size={16} />
              <span>{tr("连通性检测", "Connectivity")}</span>
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
                      ? serviceLatency.google === null
                        ? "warn"
                        : "idle"
                      : serviceLatency.google < 400
                        ? ""
                        : "warn"
                  }`}
                />
              </span>
              <span className="tabular" style={{ fontSize: 12.5, fontWeight: 600 }}>
                {serviceLatency.probing && serviceLatency.google === undefined
                  ? tr("检测中…", "Testing...")
                  : serviceLatency.google != null
                    ? `${serviceLatency.google} ms`
                    : serviceLatency.google === null
                      ? tr("超时 / 失败", "Unreachable")
                      : tr("尚未检测", "Not Checked")}
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
                      ? serviceLatency.github === null
                        ? "warn"
                        : "idle"
                      : serviceLatency.github < 400
                        ? ""
                        : "warn"
                  }`}
                />
              </span>
              <span className="tabular" style={{ fontSize: 12.5, fontWeight: 600 }}>
                {serviceLatency.probing && serviceLatency.github === undefined
                  ? tr("检测中…", "Testing...")
                  : serviceLatency.github != null
                    ? `${serviceLatency.github} ms`
                    : serviceLatency.github === null
                      ? tr("超时 / 失败", "Unreachable")
                      : tr("尚未检测", "Not Checked")}
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

        <section className="bento-card col-5">
          <div className="bento-card-head" style={{ marginBottom: 10 }}>
            <span className="bento-card-label">
              <LayersGroupIcon size={16} />
              <span>{tr("当前节点与策略组", "Active Node & Groups")}</span>
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
                padding: "16px 14px",
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

        {/* ROW 4: Collapsible Advanced Network & System Section (TUN, Allow LAN, Memory, Live Activity) */}
        <section className="bento-card col-12" style={{ padding: "12px 18px" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              cursor: "pointer",
              userSelect: "none",
              flexWrap: "wrap",
            }}
            onClick={() => setAdvancedOpen((v) => !v)}
          >
            <div>
              <div style={{ fontSize: 14, fontWeight: 650 }}>
                {tr(
                  "高级网络接管与底层运行状态",
                  "Advanced Network Takeover & Runtime Telemetry",
                )}
              </div>
              <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                {tr(
                  "包含 TUN 虚拟网卡、局域网监听共享、真实进程内存占用及实时连接 / DNS 明细",
                  "TUN virtual interface, LAN sharing, verified memory RSS, and live connection / DNS tables",
                )}
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span
                className={`badge ${
                  tunEnabled ? "badge-emerald" : "badge-neutral"
                }`}
              >
                TUN: {tunEnabled ? tr("已启用", "On") : tr("关闭", "Off")}
              </span>
              <span
                className={`badge ${
                  config?.["allow-lan"] ? "badge-sky" : "badge-neutral"
                }`}
              >
                LAN: {config?.["allow-lan"] ? tr("已开启", "On") : tr("关闭", "Off")}
              </span>
              <span className="badge badge-neutral tabular">
                {tr("内存: ", "Mem: ")}
                {memModel.coreBytes != null
                  ? formatBytes(memModel.coreBytes)
                  : tr("暂无数据", "Unavailable")}
              </span>
              <span style={{ color: "var(--text-muted)", display: "inline-flex" }}>
                {advancedOpen ? (
                  <ChevronDownIcon size={16} />
                ) : (
                  <ChevronRightIcon size={16} />
                )}
              </span>
            </div>
          </div>

          {advancedOpen && (
            <div className="bento-grid" style={{ marginTop: 13 }}>
              <div className="sub-pill-box col-4" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                  <ScallopedShieldBadge size={30} active={tunEnabled} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 650 }}>
                      {tr("TUN 虚拟网卡", "TUN Interface")}
                    </div>
                    <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                      {tunEnabled
                        ? tr("已接管全局三层流量", "Layer-3 takeover active")
                        : tr("接管不走系统代理的应用流量", "Capture non-proxy-aware apps")}
                    </div>
                  </div>
                </div>
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
              </div>

              <div
                className="sub-pill-box col-4"
                style={{
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between",
                  gap: 8,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span className="bento-card-label" style={{ fontSize: 12 }}>
                    <MonitorIpIcon size={15} />
                    <span>{tr("本机局域网地址", "LAN / Intranet IP")}</span>
                  </span>
                  <button
                    type="button"
                    className="bento-icon-action"
                    disabled={!intranetIp}
                    onClick={() => void handleCopyIntranetIp()}
                    title={
                      !intranetIp
                        ? tr("暂无局域网地址", "No LAN IP reported")
                        : ipCopied
                          ? tr("已复制", "Copied")
                          : tr("复制地址", "Copy IP")
                    }
                  >
                    {ipCopied ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
                  </button>
                </div>

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <span
                    className="tabular"
                    style={{
                      fontSize: 15,
                      fontWeight: 700,
                      color: intranetIp ? "var(--text-primary)" : "var(--text-muted)",
                    }}
                  >
                    {intranetIp ?? tr("暂无数据", "Unavailable")}
                  </span>

                  <div style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
                    <WifiIcon size={14} />
                    <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                      {tr("局域网共享", "Allow LAN")}
                    </span>
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
                </div>
              </div>

              <div
                className="sub-pill-box col-4"
                style={{
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between",
                  gap: 6,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span className="bento-card-label" style={{ fontSize: 12 }}>
                    <ChipMemoryIcon size={15} />
                    <span>{tr("真实内存占用", "Process Memory")}</span>
                  </span>
                  <button
                    type="button"
                    className="bento-icon-action"
                    onClick={onOpenTools}
                    title={tr("打开工具与设置", "Open Tools")}
                  >
                    <ChevronRightIcon size={14} />
                  </button>
                </div>

                {totalMemParts ? (
                  <>
                    <div className="tabular" style={{ fontSize: 16, fontWeight: 700 }}>
                      {totalMemParts.value}{" "}
                      <span style={{ fontSize: 12, fontWeight: 500, color: "var(--text-muted)" }}>
                        {totalMemParts.unit}
                      </span>
                    </div>
                    <div className="mem-bar-track" style={{ margin: "2px 0" }}>
                      <div className="mem-bar-core" style={{ width: `${memModel.corePct}%` }} />
                      <div className="mem-bar-ui" style={{ width: `${memModel.uiPct}%` }} />
                    </div>
                  </>
                ) : (
                  <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-muted)" }}>
                    {tr("暂无数据", "Unavailable")}
                  </div>
                )}

                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--text-muted)" }}>
                  <span className="tabular">
                    {tr("核心 RSS: ", "Core RSS: ")}
                    <strong style={{ color: "var(--text-secondary)" }}>
                      {memModel.coreBytes != null
                        ? formatBytes(memModel.coreBytes)
                        : tr("暂无数据", "Unavailable")}
                    </strong>
                  </span>
                  <span className="tabular">
                    {tr("界面堆: ", "UI Heap: ")}
                    <strong style={{ color: "var(--text-secondary)" }}>
                      {memModel.uiBytes != null
                        ? formatBytes(memModel.uiBytes)
                        : tr("未暴露", "N/A")}
                    </strong>
                  </span>
                </div>
              </div>

              {/* Activity & DNS Table */}
              <div className="sub-pill-box col-12" style={{ padding: "12px 14px" }}>
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
                                padding: "22px 8px",
                                color: "var(--text-muted)",
                              }}
                            >
                              {tr(
                                "暂无 Fake-IP DNS 解析记录",
                                "No Fake-IP DNS entries yet",
                              )}
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
                                padding: "22px 8px",
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
              </div>
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
                  {tr(
                    "快速切换当前策略组出站节点",
                    "Quickly switch node for this group",
                  )}
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
