import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiHttpError,
  clashApi,
  fetchExitIp,
  isTauriDesktop,
  patchConfig,
  relaunchElevatedForTun,
  setSysProxy,
  testProxyDelay,
} from "../api";
import {
  ExitCountryLandmark,
  countryDisplayFor,
  landmarkCaptionFor,
} from "../components/ExitCountryLandmark";
import {
  CheckIcon,
  ChevronRightIcon,
  CloseIcon,
  CopyIcon,
  GithubMarkIcon,
  GoogleGIcon,
  LayersGroupIcon,
  RefreshIcon,
  ShieldCheckIcon,
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
  prettyProtocolLabel,
  splitSpeedParts,
} from "../utils/format";
import {
  decideMasterToggleProbeAction,
  decideModeSwitchProbeAction,
  decideSysProxyToggleProbeAction,
  decideTunToggleProbeAction,
  isCurrentProbe,
} from "../utils/dashboardProbes.mjs";
import {
  deriveExitIpDisplay,
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
  groupOrder?: string[];
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

function isTunPrivilegeFailure(
  err: unknown,
  msg: string,
  privilegeOk?: boolean,
): boolean {
  if (
    err instanceof ApiHttpError &&
    (err.status === 401 || err.status === 403)
  ) {
    return false;
  }
  if (/cannot reach rustclash controller|failed to fetch|networkerror/i.test(msg)) {
    return false;
  }
  if (
    /cap_net_admin|privilege|permission|operation not permitted|access is denied|administrator|root|elevat|wintun|utun|\/dev\/net\/tun|eacces|eperm/i.test(
      msg,
    )
  ) {
    return true;
  }
  return privilegeOk === false && err instanceof ApiHttpError;
}

function canAutoElevateDesktopTun(config: ConfigSnapshot | null): boolean {
  const h = config?.tun.health;
  return Boolean(
    isTauriDesktop() &&
      h &&
      (h.platform === "windows" ||
        h.platform === "macos" ||
        h.platform === "linux") &&
      h.driver_loaded &&
      !h.privilege_ok,
  );
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  online,
  config,
  profilesSnapshot,
  proxies,
  groupOrder = [],
  rules,
  connections,
  trafficHistory,
  latestTraffic,
  onRefreshAll,
  onOpenProfiles,
  onOpenProxies,
  onOpenSiteDoctor,
}) => {
  const { lang, tr } = useI18n();

  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);
  const [tunPrivilegeHint, setTunPrivilegeHint] = useState<string | null>(null);
  const [lanIpCopied, setLanIpCopied] = useState(false);
  const [exitIpCopied, setExitIpCopied] = useState(false);

  // Exit IP state (`GET /tools/ip`) — null means not yet checked
  const [exitIp, setExitIp] = useState<ExitIpInfo | null>(null);
  const [ipLoading, setIpLoading] = useState(false);

  // Service connectivity probe state (`undefined` = unchecked, `null` = failed)
  const [serviceLatency, setServiceLatency] = useState<{
    google?: number | null;
    github?: number | null;
    probing: boolean;
  }>({ probing: false });

  // Activity tab state (`live` | `recent` | `failed` | `dns`)
  const [activityTab, setActivityTab] = useState<
    "live" | "recent" | "failed" | "dns"
  >("live");
  const [recentDiagnostics, setRecentDiagnostics] = useState<ConnectionItem[]>(
    [],
  );
  const [failedDiagnostics, setFailedDiagnostics] = useState<ConnectionItem[]>(
    [],
  );
  const [fakeIpPool, setFakeIpPool] = useState<FakeIpPoolResponse | null>(null);

  // Quick group node picker modal
  const [quickPickerGroup, setQuickPickerGroup] = useState<string | null>(null);

  // Live 1s uptime ticker
  const bootMsRef = useRef<number>(Date.now());
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const mountedRef = useRef(true);
  const exitIpSeqRef = useRef(0);
  const probeSeqRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  const groups = useMemo(() => {
    const list = Object.values(proxies).filter(
      (p) => GROUP_TYPES.has(p.type) && p.all && p.all.length > 0,
    );
    const orderIndex = new Map<string, number>();
    groupOrder.forEach((name, idx) => orderIndex.set(name, idx));
    const configuredPrimary = config?.["effective-outbound"]?.primary_group ?? "";
    list.sort((a, b) => {
      if (a.name === "GLOBAL") return 1;
      if (b.name === "GLOBAL") return -1;
      const ia = orderIndex.get(a.name);
      const ib = orderIndex.get(b.name);
      if (ia !== undefined && ib !== undefined) return ia - ib;
      if (ia !== undefined) return -1;
      if (ib !== undefined) return 1;
      if (configuredPrimary) {
        if (a.name === configuredPrimary) return -1;
        if (b.name === configuredPrimary) return 1;
      }
      return a.name.localeCompare(b.name);
    });
    return list;
  }, [proxies, groupOrder, config]);

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

  const primaryGroup = useMemo(() => {
    const configuredPrimary = config?.["effective-outbound"]?.primary_group;
    if (configuredPrimary) {
      const exact = groups.find((g) => g.name === configuredPrimary);
      if (exact) return exact;
    }
    return (
      groups.find(
        (g) =>
          g.type === "Selector" &&
          (g.name === "PROXY" ||
            g.name === "🚀 Proxy" ||
            g.name === "🚀 节点选择" ||
            g.name === "节点选择"),
      ) ?? groups.find((g) => g.type === "Selector" && g.name !== "GLOBAL")
    );
  }, [groups, config]);

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

  const invalidateDashboardProbes = useCallback(() => {
    exitIpSeqRef.current += 1;
    probeSeqRef.current += 1;
    if (!mountedRef.current) return;
    setIpLoading(false);
    setServiceLatency((prev) =>
      prev.probing ? { ...prev, probing: false } : prev,
    );
  }, []);

  const loadExitIp = useCallback(async (forceRefresh = false) => {
    const seq = ++exitIpSeqRef.current;
    setIpLoading(true);
    try {
      const info = await fetchExitIp(forceRefresh);
      if (!isCurrentProbe(seq, exitIpSeqRef.current, mountedRef.current)) return;
      if (info && info.ip && info.ok !== false) {
        setExitIp(info);
      } else {
        setExitIp({ ip: "", country_code: "", country: "", ok: false });
      }
    } catch {
      if (!isCurrentProbe(seq, exitIpSeqRef.current, mountedRef.current)) return;
      setExitIp({ ip: "", country_code: "", country: "", ok: false });
    } finally {
      if (isCurrentProbe(seq, exitIpSeqRef.current, mountedRef.current)) {
        setIpLoading(false);
      }
    }
  }, []);

  const probeConnectivity = useCallback(async () => {
    if (!online) return;
    const seq = ++probeSeqRef.current;
    setServiceLatency((prev) => ({ ...prev, probing: true }));
    const demoOrigin =
      config?.demo.enabled && config.demo.http_benchmark_origin
        ? `${config.demo.http_benchmark_origin}/generate_204`
        : null;
    const googleUrl = demoOrigin ?? "https://www.gstatic.com/generate_204";
    const githubUrl = demoOrigin ?? "https://api.github.com/";

    try {
      const [gRes, ghRes] = await Promise.allSettled([
        testProxyDelay(probeTargetName, googleUrl, 4000),
        testProxyDelay(probeTargetName, githubUrl, 4000),
      ]);

      if (!isCurrentProbe(seq, probeSeqRef.current, mountedRef.current)) return;

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
    } finally {
      if (isCurrentProbe(seq, probeSeqRef.current, mountedRef.current)) {
        setServiceLatency((prev) =>
          prev.probing ? { ...prev, probing: false } : prev,
        );
      }
    }
  }, [online, config?.demo.enabled, config?.demo.http_benchmark_origin, probeTargetName]);

  const loadAuxActivity = useCallback(async () => {
    if (!online) return;
    const [diagRes, failedRes, fakeRes] = await Promise.allSettled([
      clashApi.getConnectionDiagnostics(80),
      clashApi.getConnectionDiagnostics(50, true),
      clashApi.getFakeIpPool(),
    ]);
    if (!mountedRef.current) return;
    if (diagRes.status === "fulfilled") {
      setRecentDiagnostics(diagRes.value.diagnostics);
    }
    if (failedRes.status === "fulfilled") {
      setFailedDiagnostics(
        failedRes.value.diagnostics.filter(
          (d) => d.status === "failed" || Boolean(d.error),
        ),
      );
    }
    if (fakeRes.status === "fulfilled") {
      setFakeIpPool(fakeRes.value);
    }
  }, [online]);

  const sysproxyEnabled = Boolean(config?.sysproxy?.enabled);
  const tunEnabled = Boolean(config?.tun.enable || config?.["tun-active"]);
  const proxyRunning = sysproxyEnabled || tunEnabled;

  useEffect(() => {
    if (!online || (!proxyRunning && !config?.demo.enabled)) {
      invalidateDashboardProbes();
      return;
    }
    void loadExitIp(false);
    void probeConnectivity();
  }, [
    online,
    proxyRunning,
    config?.demo.enabled,
    effectiveOutbound,
    config?.mode,
    loadExitIp,
    probeConnectivity,
    invalidateDashboardProbes,
  ]);

  useEffect(() => {
    if (!online) return;
    void loadAuxActivity();
  }, [activityTab, online, loadAuxActivity]);

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

  const tryAutoElevateDesktopTun = async (
    preserveSysproxy: boolean,
  ): Promise<"relaunching" | "cancelled" | "fallback" | "error"> => {
    try {
      const outcome = await relaunchElevatedForTun(preserveSysproxy);
      if (outcome.status === "relaunching") {
        saveTakeoverPref({ sysproxy: preserveSysproxy, tun: true });
        setTunPrivilegeHint(null);
        setToast({
          ok: true,
          text: tr(
            "已同意管理员授权，正在提权重启并自动开启 TUN...",
            "Administrator access granted — restarting elevated and enabling TUN...",
          ),
        });
        return "relaunching";
      }
      if (outcome.status === "cancelled") {
        setToast({
          ok: true,
          text: tr(
            "已取消管理员授权，TUN 未开启（日常上网可直接开启系统代理）",
            "Administrator prompt cancelled — TUN remains off (use System Proxy for non-admin browsing).",
          ),
        });
        return "cancelled";
      }
      return "fallback";
    } catch (elevErr) {
      const msg = elevErr instanceof Error ? elevErr.message : String(elevErr);
      setToast({
        ok: false,
        text: tr(
          `请求管理员提权失败：${msg}`,
          `Failed to request Administrator elevation: ${msg}`,
        ),
      });
      const hint = config?.tun.health?.privilege_hint;
      if (hint) {
        setTunPrivilegeHint(hint);
      }
      return "error";
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
          if (sysproxyDisabled) {
            await setSysProxy(true).catch(() => {});
          }
          throw stepErr;
        }
      } else {
        // On non-elevated Desktop (Windows UAC / macOS / Linux Polkit), trigger elevation BEFORE
        // toggling system proxy so cancelling the prompt leaves the current session untouched.
        if (
          plan.targetTun &&
          !tunEnabled &&
          canAutoElevateDesktopTun(config)
        ) {
          const elev = await tryAutoElevateDesktopTun(
            Boolean(plan.targetSysproxy),
          );
          if (elev !== "fallback") {
            return;
          }
        }

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
          if (sysproxyTurnedOn) {
            await setSysProxy(false).catch(() => {});
          }
          const stepMsg =
            stepErr instanceof Error ? stepErr.message : String(stepErr);
          const hint = config?.tun.health?.privilege_hint;
          if (
            plan.targetTun &&
            !tunEnabled &&
            hint &&
            isTunPrivilegeFailure(
              stepErr,
              stepMsg,
              config?.tun.health?.privilege_ok,
            )
          ) {
            setTunPrivilegeHint(hint);
          }
          throw stepErr;
        }
      }

      const masterProbeAction = decideMasterToggleProbeAction({
        action: plan.action,
        demoEnabled: Boolean(config?.demo.enabled),
      });
      if (masterProbeAction === "invalidate") {
        invalidateDashboardProbes();
      }
      await onRefreshAll();
      if (masterProbeAction === "probe") {
        void loadExitIp(true);
        void probeConnectivity();
      } else {
        invalidateDashboardProbes();
      }
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
      if (
        decideModeSwitchProbeAction({
          proxyRunning,
          demoEnabled: Boolean(config?.demo.enabled),
        }) === "probe"
      ) {
        void loadExitIp(true);
        void probeConnectivity();
      } else {
        invalidateDashboardProbes();
      }
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
      if (
        decideSysProxyToggleProbeAction({
          nextSysproxyEnabled: nextSys,
          tunEnabled,
          demoEnabled: Boolean(config?.demo.enabled),
        }) === "probe"
      ) {
        void loadExitIp(true);
      } else {
        invalidateDashboardProbes();
      }
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
        if (nextEnable && canAutoElevateDesktopTun(config)) {
          const elev = await tryAutoElevateDesktopTun(sysproxyEnabled);
          if (elev !== "fallback") {
            return;
          }
        }
        await patchConfig({ tun: { enable: nextEnable } });
        if (sysproxyEnabled || nextEnable) {
          saveTakeoverPref({ sysproxy: sysproxyEnabled, tun: nextEnable });
        }
        const tunProbeAction = decideTunToggleProbeAction({
          sysproxyEnabled,
          nextTunEnabled: nextEnable,
          demoEnabled: Boolean(config?.demo.enabled),
        });
        if (tunProbeAction === "invalidate") {
          invalidateDashboardProbes();
        }
        await onRefreshAll();
        if (tunProbeAction === "probe") {
          void loadExitIp(true);
        } else {
          invalidateDashboardProbes();
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setToast({ ok: false, text: msg });
        const hint = config.tun.health?.privilege_hint;
        if (
          nextEnable &&
          hint &&
          isTunPrivilegeFailure(err, msg, config.tun.health?.privilege_ok)
        ) {
          setTunPrivilegeHint(hint);
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
      setLanIpCopied(true);
      window.setTimeout(() => setLanIpCopied(false), 1600);
    } catch {
      // ignore clipboard restriction
    }
  };

  const handleCopyExitIp = async (ipStr: string) => {
    if (!ipStr) return;
    try {
      await navigator.clipboard?.writeText(ipStr);
      setExitIpCopied(true);
      window.setTimeout(() => setExitIpCopied(false), 1600);
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

  const proxyCount =
    config?.["proxy-count"] ?? activeProfile?.proxy_count ?? concreteNodeCount;
  const ruleCount =
    config?.["rule-count"] ?? activeProfile?.rule_count ?? rules.length;

  // Live speed & cumulative totals
  const upParts = splitSpeedParts(latestTraffic.up);
  const downParts = splitSpeedParts(latestTraffic.down);
  const totalUp = connections?.uploadTotal ?? latestTraffic.total_up;
  const totalDown = connections?.downloadTotal ?? latestTraffic.total_down;
  const combinedTotal = totalUp + totalDown;
  const downSeries = useMemo(
    () => trafficHistory.slice(-36).map((p) => p.down + p.up),
    [trafficHistory],
  );

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
    exitIpOk:
      exitIp === null ? undefined : exitIp.ok !== false && Boolean(exitIp.ip),
  });

  const exitDisplay = deriveExitIpDisplay({
    online,
    ipLoading,
    exitIp,
    demoEnabled: Boolean(config?.demo.enabled),
    effectiveOutbound,
    effectiveProto,
  });

  // Only show city landmark & verified IP prominently when takeover is active (or in demo) & verified
  const showActiveExit = Boolean(
    online && (proxyRunning || config?.demo.enabled) && exitDisplay.verified,
  );
  const exitCountryCode = showActiveExit ? (exitIp?.country_code ?? "") : "";
  const countryInfo = countryDisplayFor(
    exitCountryCode,
    exitIp?.country,
    lang,
  );
  const landmarkCaption = showActiveExit
    ? landmarkCaptionFor(exitCountryCode, lang)
    : "";
  const verifiedOrg = lang === "zh" ? exitDisplay.orgZh : exitDisplay.orgEn;
  const verifiedIpText = lang === "zh" ? exitDisplay.headlineZh : exitDisplay.headlineEn;
  const ipTypeLabel = showActiveExit ? (exitIp?.node_type || exitIp?.ip_type || "") : "";

  // Primary latency metric & sparkbars from real probe / proxy history
  const activeProxyObj = proxies[effectiveOutbound];
  const nodeHistoryDelays = useMemo(() => {
    const raw = (activeProxyObj?.history ?? [])
      .map((h) => h.delay)
      .filter((d) => typeof d === "number" && d > 0);
    return raw.slice(-11);
  }, [activeProxyObj]);

  const hasManualOrLiveProbe =
    proxyRunning ||
    Boolean(config?.demo.enabled) ||
    serviceLatency.google !== undefined ||
    serviceLatency.github !== undefined;

  const primaryLatencyMs = useMemo(() => {
    const candidates: number[] = [];
    if (typeof serviceLatency.google === "number" && serviceLatency.google > 0) {
      candidates.push(serviceLatency.google);
    }
    if (typeof serviceLatency.github === "number" && serviceLatency.github > 0) {
      candidates.push(serviceLatency.github);
    }
    if (
      showActiveExit &&
      typeof exitIp?.latency_ms === "number" &&
      exitIp.latency_ms > 0
    ) {
      candidates.push(exitIp.latency_ms);
    }
    if (nodeHistoryDelays.length > 0) {
      candidates.push(nodeHistoryDelays[nodeHistoryDelays.length - 1]);
    }
    return candidates.length > 0 ? Math.min(...candidates) : null;
  }, [
    serviceLatency.google,
    serviceLatency.github,
    showActiveExit,
    exitIp?.latency_ms,
    nodeHistoryDelays,
  ]);

  const latencyQuality = useMemo(() => {
    if (!online) return { text: tr("核心离线", "Core Offline"), tone: "muted" };
    if (!hasManualOrLiveProbe) {
      if (primaryLatencyMs != null) {
        return { text: tr("待机 · 上次测速", "Standby · Last Test"), tone: "muted" };
      }
      return { text: tr("待机中", "Standby"), tone: "muted" };
    }
    if (serviceLatency.probing && primaryLatencyMs == null) {
      return { text: tr("正在测速…", "Probing..."), tone: "muted" };
    }
    if (primaryLatencyMs == null) {
      if (serviceLatency.google === null && serviceLatency.github === null) {
        return { text: tr("连通异常", "Unreachable"), tone: "rose" };
      }
      return { text: tr("等待测速", "Not Probed"), tone: "muted" };
    }
    if (primaryLatencyMs < 80) {
      return { text: tr("质量极佳", "Excellent"), tone: "emerald" };
    }
    if (primaryLatencyMs < 180) {
      return { text: tr("线路良好", "Good"), tone: "emerald" };
    }
    if (primaryLatencyMs < 360) {
      return { text: tr("延迟偏高", "Moderate"), tone: "amber" };
    }
    return { text: tr("拥塞较慢", "High Latency"), tone: "rose" };
  }, [
    online,
    hasManualOrLiveProbe,
    serviceLatency.probing,
    serviceLatency.google,
    serviceLatency.github,
    primaryLatencyMs,
    tr,
  ]);

  const sparkbarRatios = useMemo(() => {
    if (!hasManualOrLiveProbe || primaryLatencyMs == null) {
      return new Array<number>(11).fill(0.2);
    }
    if (nodeHistoryDelays.length >= 2) {
      const maxD = Math.max(...nodeHistoryDelays, 60);
      const padded =
        nodeHistoryDelays.length >= 11
          ? nodeHistoryDelays
          : [
              ...new Array<number>(11 - nodeHistoryDelays.length).fill(
                nodeHistoryDelays[0],
              ),
              ...nodeHistoryDelays,
            ];
      return padded.map((d) => Math.max(0.32, Math.min(0.96, d / maxD)));
    }
    const level = Math.max(0.35, Math.min(0.88, primaryLatencyMs / 80));
    return new Array<number>(11).fill(level);
  }, [hasManualOrLiveProbe, nodeHistoryDelays, primaryLatencyMs]);

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

  const modeSummary =
    config?.mode === "global"
      ? tr("全局代理 · 全部流量经节点", "Global · All traffic via proxy")
      : config?.mode === "direct"
        ? tr("全局直连 · 绕过代理节点", "Direct · Bypass proxy nodes")
        : tr("规则分流 · 国内直连 / 国外代理", "Rule · Smart split routing");

  return (
    <div className="dashboard-layout">
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
          <div style={{ display: "flex", gap: "8px", flexShrink: 0 }}>
            {canAutoElevateDesktopTun(config) && (
              <button
                type="button"
                className="btn btn-sm btn-primary"
                disabled={Boolean(busyKey)}
                onClick={handleTunSwitch}
              >
                {tr("提权重启并开启 TUN", "Restart as Admin & Enable TUN")}
              </button>
            )}
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setTunPrivilegeHint(null)}
            >
              {tr("关闭", "Close")}
            </button>
          </div>
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

      {threeLayer.connectivity.state === "unreachable" && proxyRunning && (
        <div className="banner banner-err">
          <span>
            {tr(
              "当前已启用接管但外部连通性探测失败，可使用「网络诊断」定位 DNS、隧道或 TLS 阻塞阶段。",
              "Takeover is enabled but connectivity probes failed — open Site Doctor to isolate DNS, tunnel, or TLS issues.",
            )}
          </span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => onOpenSiteDoctor("chatgpt.com")}
          >
            <ShieldCheckIcon size={13} />
            <span>{tr("立即诊断", "Diagnose")}</span>
          </button>
        </div>
      )}

      {/* ROW 1: Dual Golden Hero Cards — Emerald Master Control (5) + Panoramic City Landmark (7) */}
      <div className="bento-grid dashboard-top-row">
        <section
          className={`hero-control-card col-5 ${proxyRunning ? "connected" : "standby"}`}
        >
          <div className="hero-control-top">
            <div className="hero-control-meta">
              <div className="hero-control-status">
                <span
                  className={`hero-status-dot ${
                    !online
                      ? "offline"
                      : proxyRunning
                        ? threeLayer.connectivity.state === "unreachable"
                          ? "error"
                          : "running"
                        : "idle"
                  }`}
                />
                <span>
                  {lang === "zh" ? threeLayer.hero.zh : threeLayer.hero.en}
                </span>
                {online && proxyRunning && (
                  <span className="hero-uptime tabular">
                    · {formatDurationHms(uptimeSecs)}
                  </span>
                )}
              </div>

              <button
                type="button"
                className="hero-node-title-btn"
                onClick={() => onOpenProxies(primaryGroup?.name)}
                title={tr("点击切换代理节点", "Click to switch proxy node")}
              >
                <span className="hero-node-title">{effectiveOutbound}</span>
                <ChevronRightIcon size={15} />
              </button>

              <div className="hero-node-sub">
                {effectiveProto !== "DIRECT"
                  ? `${prettyProtocolLabel(effectiveProto)} · ${modeSummary}`
                  : modeSummary}
              </div>
            </div>

            <button
              id="master-proxy-switch-btn"
              type="button"
              className={`hero-power-btn ${proxyRunning ? "on" : "off"} ${
                busyKey === "master" ? "busy" : ""
              }`}
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
              {busyKey === "master" ? (
                <RefreshIcon size={22} spinning />
              ) : (
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2.3"
                  strokeLinecap="round"
                  aria-hidden="true"
                >
                  <path d="M12 2.5v9.5" />
                  <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
                </svg>
              )}
            </button>
          </div>

          {/* 1-Tap Routing Mode Segmented Bar */}
          <div
            className="hero-mode-bar"
            role="group"
            aria-label={tr("分流模式", "Routing mode")}
          >
            <button
              id="mode-rule-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`hero-mode-btn ${
                (config?.mode ?? "rule") === "rule" ? "active" : ""
              }`}
              onClick={() => handleModeSwitch("rule")}
            >
              {tr("规则分流", "Rule")}
            </button>
            <button
              id="mode-global-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`hero-mode-btn ${
                config?.mode === "global" ? "active" : ""
              }`}
              onClick={() => handleModeSwitch("global")}
            >
              {tr("全局代理", "Global")}
            </button>
            <button
              id="mode-direct-btn"
              type="button"
              disabled={Boolean(busyKey)}
              className={`hero-mode-btn ${
                config?.mode === "direct" ? "active" : ""
              }`}
              onClick={() => handleModeSwitch("direct")}
            >
              {tr("全局直连", "Direct")}
            </button>
          </div>

          {/* Inline System Proxy + TUN Twin Toggles */}
          <div className="hero-takeover-row">
            <div className="hero-takeover-pill">
              <span className="hero-takeover-label">
                {tr("系统代理", "System Proxy")}
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
                className={`mini-switch ${sysproxyEnabled ? "checked" : ""}`}
                onClick={handleSysProxySwitch}
              />
            </div>

            <div
              className="hero-takeover-pill"
              title={
                canAutoElevateDesktopTun(config) && !tunEnabled
                  ? config?.tun.health?.platform === "windows"
                    ? tr(
                        "点击后将弹出 Windows 管理员授权（UAC），同意后自动重启并开启 TUN",
                        "Clicking will prompt Windows Administrator elevation (UAC) and automatically restart with TUN enabled",
                      )
                    : config?.tun.health?.platform === "macos"
                      ? tr(
                          "点击后将弹出 macOS 管理员授权窗口，同意后自动提权重启并开启 TUN",
                          "Clicking will prompt macOS Administrator elevation and automatically restart with TUN enabled",
                        )
                      : tr(
                          "点击后将弹出系统管理员授权（Polkit），同意后自动提权重启并开启 TUN",
                          "Clicking will prompt Polkit Administrator elevation and automatically restart with TUN enabled",
                        )
                  : undefined
              }
            >
              <span className="hero-takeover-label">
                {tr("TUN 网卡", "TUN Mode")}
              </span>
              <button
                id="toggle-tun-btn"
                type="button"
                role="switch"
                aria-checked={tunEnabled}
                aria-label={tr("TUN 虚拟网卡开关", "Toggle TUN")}
                disabled={busyKey === "tun" || !config}
                className={`mini-switch ${tunEnabled ? "checked" : ""}`}
                onClick={handleTunSwitch}
              />
            </div>
          </div>
        </section>

        {/* Panoramic Exit Country Landmark Card (7 cols) */}
        <section className="bento-card landmark-showcase-card col-7">
          <div className="landmark-head">
            <div className="landmark-title-col">
              <div className="landmark-kicker">
                <span>{tr("落地出口", "Exit Location")}</span>
                <span className="landmark-iso-pill">
                  {showActiveExit
                    ? exitDisplay.badgeCode
                    : config?.demo.enabled
                      ? "LAB"
                      : "LOCAL"}
                </span>
              </div>

              <div className="landmark-country-row">
                {showActiveExit ? (
                  <>
                    {countryInfo.flag && (
                      <span className="landmark-flag" aria-hidden="true">
                        {countryInfo.flag}
                      </span>
                    )}
                    <span className="landmark-country-name">
                      {countryInfo.name}
                    </span>
                  </>
                ) : config?.demo.enabled ? (
                  <span className="landmark-country-name">
                    {tr("演练沙盒", "Demo Sandbox")}
                  </span>
                ) : (
                  <span className="landmark-country-name">
                    {tr("本地网络", "Local Network")}
                  </span>
                )}
              </div>

              <div className="landmark-sub" title={verifiedOrg}>
                {showActiveExit
                  ? ipTypeLabel
                    ? `${verifiedOrg} · ${ipTypeLabel}`
                    : verifiedOrg
                  : !online
                    ? tr("等待连接本地代理核心", "Waiting for local proxy core")
                    : !proxyRunning
                      ? tr(
                          "待机 · 开启接管后自动识别落地出口",
                          "Standby · Exit region detected automatically once enabled",
                        )
                      : ipLoading
                        ? tr("正在探测真实落地出口…", "Probing verified exit IP...")
                        : verifiedOrg}
              </div>
            </div>

            <div className="landmark-right-col">
              <div className="landmark-ip-actions">
                {showActiveExit ? (
                  <button
                    type="button"
                    className="landmark-ip-pill mono tabular"
                    onClick={() => void handleCopyExitIp(verifiedIpText)}
                    title={
                      exitIpCopied
                        ? tr("已复制出口 IP", "Copied Exit IP")
                        : tr("点击复制出口 IP", "Click to copy exit IP")
                    }
                  >
                    <span>{verifiedIpText}</span>
                    {exitIpCopied ? (
                      <CheckIcon size={13} />
                    ) : (
                      <CopyIcon size={13} />
                    )}
                  </button>
                ) : (
                  <span className="landmark-standby-chip">
                    {!online
                      ? tr("离线", "Offline")
                      : ipLoading
                        ? tr("探测中…", "Probing...")
                        : !proxyRunning
                          ? tr("待机", "Standby")
                          : tr("未探测", "Unverified")}
                  </span>
                )}

                {(proxyRunning || config?.demo.enabled) && (
                  <button
                    type="button"
                    className="bento-icon-action"
                    disabled={!online || ipLoading}
                    onClick={() => {
                      void loadExitIp(true);
                      void probeConnectivity();
                    }}
                    title={tr("重新探测真实出口 IP", "Re-probe real exit IP")}
                    aria-label={tr("重新探测出口 IP", "Re-probe exit IP")}
                  >
                    <RefreshIcon size={14} spinning={ipLoading} />
                  </button>
                )}
              </div>

              {showActiveExit && landmarkCaption && (
                <div className="landmark-caption">{landmarkCaption}</div>
              )}
            </div>
          </div>

          <div className="landmark-canvas-wrap">
            <ExitCountryLandmark
              countryCode={exitCountryCode}
              connected={showActiveExit}
            />
          </div>
        </section>
      </div>

      {/* ROW 2: Refined 3-Column Bento Telemetry (Throughput 4 + Latency 4 + Quick Groups 4) */}
      <div className="bento-grid dashboard-mid-row">
        {/* Col 1: Unified Real-Time Throughput */}
        <section className="bento-card telemetry-card col-4">
          <div>
            <div className="bento-card-head" style={{ marginBottom: 6 }}>
              <span className="bento-card-label">
                <span>{tr("实时速率", "Live Throughput")}</span>
              </span>
              <span className="tabular" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                {tr("累计", "Total")} {formatBytes(combinedTotal)}
              </span>
            </div>

            <div className="throughput-primary-row">
              <div className="speed-big-row tabular">
                <span className="throughput-dir-dl">↓</span>
                <span className="speed-big-num">{downParts.value}</span>
                <span className="speed-big-unit">{downParts.unit}</span>
              </div>
              <span className="tabular throughput-sub-bytes">
                {formatBytes(totalDown)}
              </span>
            </div>

            <div className="throughput-secondary-row">
              <span className="tabular throughput-up-val">
                <span className="throughput-dir-ul">↑</span>
                {upParts.value} {upParts.unit}
              </span>
              <span className="tabular throughput-sub-bytes">
                {formatBytes(totalUp)}
              </span>
            </div>
          </div>

          <div className="sparkline-wrap-clean">
            <Sparkline
              values={downSeries}
              strokeColor="var(--accent-blue)"
              height={48}
              idle={!proxyRunning}
            />
          </div>
        </section>

        {/* Col 2: Node Latency & Service Connectivity */}
        <section className="bento-card telemetry-card col-4">
          <div>
            <div className="bento-card-head" style={{ marginBottom: 6 }}>
              <span className="bento-card-label">
                <span>{tr("节点延迟与连通性", "Latency & Reachability")}</span>
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

            <div className="latency-top-split">
              <div>
                <div className="speed-big-row tabular">
                  <span className="speed-big-num">
                    {primaryLatencyMs != null ? primaryLatencyMs : "—"}
                  </span>
                  {primaryLatencyMs != null && (
                    <span className="speed-big-unit">ms</span>
                  )}
                </div>
                <div className={`latency-quality-label ${latencyQuality.tone}`}>
                  {latencyQuality.text}
                </div>
              </div>

              <div className="service-compact-stack">
                <div className="service-mini-chip">
                  <GoogleGIcon size={13} />
                  <span className="service-mini-name">Google</span>
                  <span className="service-mini-ms tabular">
                    {serviceLatency.probing && serviceLatency.google === undefined
                      ? "…"
                      : serviceLatency.google != null
                        ? `${serviceLatency.google}ms`
                        : serviceLatency.google === null
                          ? tr("超时", "Fail")
                          : "—"}
                  </span>
                </div>
                <div className="service-mini-chip">
                  <GithubMarkIcon size={13} />
                  <span className="service-mini-name">GitHub</span>
                  <span className="service-mini-ms tabular">
                    {serviceLatency.probing && serviceLatency.github === undefined
                      ? "…"
                      : serviceLatency.github != null
                        ? `${serviceLatency.github}ms`
                        : serviceLatency.github === null
                          ? tr("超时", "Fail")
                          : "—"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="latency-sparkbars" aria-hidden="true">
            {sparkbarRatios.map((ratio, idx) => (
              <span
                key={idx}
                className={`latency-bar ${
                  !hasManualOrLiveProbe || primaryLatencyMs == null
                    ? "idle"
                    : idx === sparkbarRatios.length - 1
                      ? "latest"
                      : idx >= 7
                        ? "recent"
                        : "past"
                }`}
                style={{ height: `${Math.round(ratio * 100)}%` }}
              />
            ))}
          </div>
        </section>

        {/* Col 3: Proxy Groups Quick Switcher */}
        <section className="bento-card telemetry-card col-4">
          <div className="bento-card-head" style={{ marginBottom: 8 }}>
            <span className="bento-card-label">
              <LayersGroupIcon size={15} />
              <span>{tr("策略组快切", "Quick Groups")}</span>
              <span className="badge badge-neutral tabular">{groups.length}</span>
            </span>
            <button
              type="button"
              className="text-link-btn"
              onClick={() => onOpenProxies()}
            >
              <span>{tr("全部节点", "All")}</span>
              <ChevronRightIcon size={13} />
            </button>
          </div>

          {groups.length === 0 ? (
            <div className="groups-empty-box">
              <div style={{ color: "var(--text-muted)", fontSize: 12 }}>
                {tr("尚未配置代理策略组", "No proxy groups configured")}
              </div>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={onOpenProfiles}
              >
                {tr("去导入订阅", "Import Profile")}
              </button>
            </div>
          ) : (
            <div className="quick-group-list">
              {groups.slice(0, 6).map((grp) => {
                const selectedNode = grp.now || grp.effective_outbound || "DIRECT";
                const nodeObj = proxies[selectedNode];
                const lastDelay =
                  nodeObj && nodeObj.history.length > 0
                    ? nodeObj.history[nodeObj.history.length - 1]?.delay
                    : undefined;
                return (
                  <button
                    key={grp.name}
                    type="button"
                    className={`quick-group-row ${
                      quickPickerGroup === grp.name ? "active" : ""
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
                    <div className="quick-group-info">
                      <span className="quick-group-name">{grp.name}</span>
                      <span className="quick-group-now">{selectedNode}</span>
                    </div>
                    {lastDelay && lastDelay > 0 ? (
                      <span className="quick-group-delay tabular">
                        {lastDelay} ms
                      </span>
                    ) : (
                      <span style={{ color: "var(--text-muted)", display: "inline-flex" }}>
                        <ChevronRightIcon size={13} />
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </section>
      </div>

      {/* ROW 3 (Bottom A, flex: 1): Live Connections, Recent Routing, Failed & Fake-IP DNS Stream */}
      <section className="bento-card activity-stream-card">
        <div className="activity-stream-head">
          <div className="activity-tabs-compact">
            <button
              type="button"
              className={`activity-seg-btn ${activityTab === "live" ? "active" : ""}`}
              onClick={() => setActivityTab("live")}
            >
              <span>{tr("实时连接", "Live")}</span>
              <span className="activity-seg-count tabular">
                {formatCompactCount(liveConns.length)}
              </span>
            </button>
            <button
              type="button"
              className={`activity-seg-btn ${activityTab === "recent" ? "active" : ""}`}
              onClick={() => setActivityTab("recent")}
            >
              <span>{tr("最近分流", "Recent")}</span>
              <span className="activity-seg-count tabular">
                {formatCompactCount(totalReqCount)}
              </span>
            </button>
            <button
              type="button"
              className={`activity-seg-btn ${activityTab === "failed" ? "active" : ""}`}
              onClick={() => setActivityTab("failed")}
            >
              <span>{tr("异常", "Failed")}</span>
              <span
                className="activity-seg-count tabular"
                style={
                  failedDiagnostics.length > 0
                    ? { color: "var(--accent-rose)" }
                    : undefined
                }
              >
                {formatCompactCount(failedDiagnostics.length)}
              </span>
            </button>
            <button
              type="button"
              className={`activity-seg-btn ${activityTab === "dns" ? "active" : ""}`}
              onClick={() => setActivityTab("dns")}
            >
              <span>{tr("DNS / Fake-IP", "DNS / Fake-IP")}</span>
              <span className="activity-seg-count tabular">
                {formatCompactCount(dnsQueryCount)}
              </span>
            </button>
          </div>

          <div className="activity-meta-bar">
            <button
              type="button"
              className="activity-profile-chip"
              onClick={onOpenProfiles}
              title={tr("点击管理订阅与配置", "Click to manage profiles")}
            >
              <span className="activity-profile-label">
                {activeProfile?.name ?? tr("默认配置", "Default")}
              </span>
              <span className="activity-profile-stats tabular">
                {proxyCount} {tr("节点", "Nodes")} · {ruleCount.toLocaleString()}{" "}
                {tr("规则", "Rules")}
              </span>
            </button>

            {intranetIp && (
              <button
                type="button"
                className="activity-lan-ip mono tabular"
                onClick={() => void handleCopyIntranetIp()}
                title={
                  lanIpCopied
                    ? tr("已复制局域网 IP", "Copied LAN IP")
                    : tr("点击复制本机局域网 IP", "Copy LAN IP")
                }
              >
                <WifiIcon size={12} />
                <span>{intranetIp}</span>
                {lanIpCopied ? <CheckIcon size={12} /> : <CopyIcon size={11} />}
              </button>
            )}

            <div className="activity-lan-toggle">
              <span>{tr("局域网共享", "Allow LAN")}</span>
              <button
                type="button"
                role="switch"
                aria-checked={Boolean(config?.["allow-lan"])}
                aria-label={tr("允许局域网连接", "Allow LAN")}
                disabled={busyKey === "allow-lan" || !config}
                className={`mini-switch neutral ${
                  config?.["allow-lan"] ? "checked" : ""
                }`}
                onClick={handleAllowLanSwitch}
              />
            </div>
          </div>
        </div>

        <div className="activity-stream-body">
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
                    <td colSpan={4} className="activity-empty-cell">
                      {tr(
                        "暂无 Fake-IP DNS 解析记录 · 流量经过代理后将实时显示映射明细",
                        "No Fake-IP DNS entries yet — mappings appear here once traffic flows",
                      )}
                    </td>
                  </tr>
                ) : (
                  fakeIpPool.entries.slice(0, 30).map((entry) => (
                    <tr key={`${entry.ip}-${entry.domain}`}>
                      <td
                        className="mono"
                        style={{
                          maxWidth: 260,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          fontWeight: 550,
                        }}
                        title={entry.domain}
                      >
                        {entry.domain}
                      </td>
                      <td className="mono tabular" style={{ color: "var(--text-secondary)" }}>
                        {entry.ip}
                      </td>
                      <td className="mono tabular" style={{ color: "var(--text-muted)" }}>
                        {entry.real_ip || "—"}
                      </td>
                      <td
                        className="mono tabular"
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
                  <th>{tr("目标域名", "Target")}</th>
                  <th>{tr("命中规则", "Rule")}</th>
                  <th>{tr("出口链路", "Exit")}</th>
                  <th style={{ textAlign: "right" }}>
                    {activityTab === "failed"
                      ? tr("失败原因", "Error")
                      : tr("下载 / 上传", "DL / UL")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {(() => {
                  const activeRows =
                    activityTab === "live"
                      ? liveConns
                      : activityTab === "failed"
                        ? failedDiagnostics
                        : recentDiagnostics;
                  if (activeRows.length === 0) {
                    return (
                      <tr>
                        <td colSpan={5} className="activity-empty-cell">
                          {activityTab === "failed"
                            ? tr("暂无异常连接记录", "No failed connections recorded")
                            : !proxyRunning
                              ? tr(
                                  "待机中 · 开启系统代理或 TUN 接管后，这里将实时呈现连接分流与 DNS 命中轨迹",
                                  "Standby — enable System Proxy or TUN to watch live routing and connection trails here",
                                )
                              : activityTab === "live"
                                ? tr("当前没有活跃连接", "No active connections right now")
                                : tr("暂无最近请求记录", "No recent requests recorded")}
                        </td>
                      </tr>
                    );
                  }
                  return activeRows.slice(0, 30).map((conn) => {
                    const procLabel =
                      conn.metadata.process?.trim() ||
                      conn.metadata.type ||
                      conn.metadata.source;
                    const targetLabel = `${
                      conn.metadata.host || conn.metadata.destination_ip || "*"
                    }:${conn.metadata.destination_port}`;
                    const ruleLabel = conn.rule
                      ? conn.rule_payload
                        ? `${conn.rule},${conn.rule_payload}`
                        : conn.rule
                      : "MATCH";
                    const exitHop =
                      conn.effective_outbound ||
                      conn.chains[conn.chains.length - 1] ||
                      conn.chains[0] ||
                      "DIRECT";
                    const isDirect = exitHop.toUpperCase() === "DIRECT";
                    const isFailed =
                      conn.status === "failed" || Boolean(conn.error);
                    return (
                      <tr key={`${conn.id}-${conn.start_epoch_ms}`}>
                        <td>
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 7,
                              maxWidth: 140,
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
                          className="mono"
                          style={{
                            maxWidth: 230,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            color: "var(--text-primary)",
                          }}
                          title={
                            conn.error
                              ? `${targetLabel} — ${conn.error}`
                              : targetLabel
                          }
                        >
                          {targetLabel}
                        </td>
                        <td
                          className="mono"
                          style={{
                            maxWidth: 170,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            color: "var(--text-muted)",
                          }}
                          title={ruleLabel}
                        >
                          {ruleLabel}
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              isFailed
                                ? "badge-rose"
                                : isDirect
                                  ? "badge-neutral"
                                  : "badge-emerald"
                            }`}
                            title={exitHop}
                          >
                            {exitHop}
                          </span>
                        </td>
                        <td
                          className="mono tabular"
                          style={{
                            textAlign: "right",
                            maxWidth: activityTab === "failed" ? 260 : undefined,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            color:
                              activityTab === "failed" || isFailed
                                ? "var(--accent-rose)"
                                : "var(--text-secondary)",
                          }}
                          title={conn.error || undefined}
                        >
                          {activityTab === "failed"
                            ? conn.error || tr("连接失败", "Failed")
                            : isFailed && conn.error
                              ? conn.error
                              : `${formatBytes(conn.download)} / ${formatBytes(conn.upload)}`}
                        </td>
                      </tr>
                    );
                  });
                })()}
              </tbody>
            </table>
          )}
        </div>
      </section>

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
                                ? "var(--accent-emerald)"
                                : delay < 400
                                  ? "var(--accent-amber)"
                                  : "var(--accent-rose)",
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
    </div>
  );
};
