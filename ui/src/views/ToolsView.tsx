import React, { useCallback, useEffect, useState } from "react";
import {
  clashApi,
  exportDiagnosticsBundle,
  fetchDesktopPrefs,
  generateVlessKeypair,
  isTauriDesktop,
  loadControllerSettings,
  patchConfig,
  runBenchmark,
  runDiagnosticsWaterfall,
  saveControllerSettings,
  setSysProxy,
  toggleDemoMode,
  updateDesktopPrefs,
} from "../api";
import { ChevronDownIcon, ChevronRightIcon } from "../components/Icons";
import { useI18n } from "../i18n";
import type {
  BenchmarkResponse,
  ConfigAuditReport,
  ConfigSnapshot,
  EndpointMatrixReport,
  LogEntry,
  ProxyInfo,
  RoutingPresetChoice,
  RoutingPresetSnapshot,
  RuleItem,
  SiteDiagnosisReport,
  VersionInfo,
  VlessKeypairResponse,
  WaterfallProbeReport,
} from "../types";
import { formatBytes } from "../utils/format";
import { LogsView } from "./LogsView";
import { RulesDnsView } from "./RulesDnsView";

export type ToolsSubTab =
  | "settings"
  | "rules-dns"
  | "diagnostics"
  | "logs"
  | "developer";

interface ToolsViewProps {
  version: VersionInfo | null;
  config: ConfigSnapshot | null;
  proxies: Record<string, ProxyInfo>;
  rules: RuleItem[];
  logs: LogEntry[];
  theme: "light" | "dark";
  onChangeTheme: (next: "light" | "dark") => void;
  onRefreshCore: () => Promise<void>;
  onClearLogs: () => void;
  onControllerUpdated: () => void;
  initialSubTab?: ToolsSubTab;
  initialSiteTarget?: string;
  onOpenProxies?: () => void;
  onOpenProfiles?: () => void;
}

const SITE_PRESETS = [
  "chatgpt.com",
  "claude.ai",
  "github.com",
  "www.google.com",
  "www.bilibili.com",
];

export const ToolsView: React.FC<ToolsViewProps> = ({
  version,
  config,
  proxies,
  rules,
  logs,
  theme,
  onChangeTheme,
  onRefreshCore,
  onClearLogs,
  onControllerUpdated,
  initialSubTab = "settings",
  initialSiteTarget = "chatgpt.com",
  onOpenProxies,
  onOpenProfiles,
}) => {
  const { lang, setLang, tr } = useI18n();

  const [subTab, setSubTab] = useState<ToolsSubTab>(initialSubTab);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    setSubTab(initialSubTab);
  }, [initialSubTab]);

  // Settings tab state
  const desktopMode = isTauriDesktop();
  const [closeToTray, setCloseToTray] = useState(true);
  const [presetSnap, setPresetSnap] = useState<RoutingPresetSnapshot | null>(
    null,
  );
  const [mixedPortInput, setMixedPortInput] = useState<string>(
    String(config?.["mixed-port"] ?? 7890),
  );
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [ctrlUrl, setCtrlUrl] = useState(() => loadControllerSettings().baseUrl);
  const [ctrlSecret, setCtrlSecret] = useState(
    () => loadControllerSettings().secret,
  );

  // Site Connectivity Doctor state
  const [siteTarget, setSiteTarget] = useState<string>(initialSiteTarget);
  const [siteDiag, setSiteDiag] = useState<SiteDiagnosisReport | null>(null);
  const [siteRawOpen, setSiteRawOpen] = useState<boolean>(false);

  useEffect(() => {
    if (initialSiteTarget) {
      setSiteTarget(initialSiteTarget);
    }
  }, [initialSiteTarget]);

  // Node-level Diagnostics tab state
  const [probeProxy, setProbeProxy] = useState<string>("");
  const [probeUrl, setProbeUrl] = useState<string>("https://api.github.com/");
  const [waterfallRes, setWaterfallRes] = useState<WaterfallProbeReport | null>(
    null,
  );
  const [matrixRes, setMatrixRes] = useState<EndpointMatrixReport | null>(null);
  const [auditRes, setAuditRes] = useState<ConfigAuditReport | null>(null);

  // Developer tab state
  const [pqMode, setPqMode] = useState("xorpub");
  const [zeroRtt, setZeroRtt] = useState(true);
  const [includePq, setIncludePq] = useState(true);
  const [keypair, setKeypair] = useState<VlessKeypairResponse | null>(null);
  const [benchStreams, setBenchStreams] = useState(4);
  const [benchResult, setBenchResult] = useState<BenchmarkResponse | null>(
    null,
  );

  useEffect(() => {
    if (config?.["mixed-port"]) {
      setMixedPortInput(String(config["mixed-port"]));
    }
  }, [config]);

  const loadSettingsExtras = useCallback(async () => {
    if (desktopMode) {
      try {
        const prefs = await fetchDesktopPrefs();
        setCloseToTray(prefs.close_to_tray);
      } catch {
        // ignore if unavailable
      }
    }
    try {
      const p = await clashApi.getRoutingPreset();
      setPresetSnap(p);
    } catch {
      // ignore
    }
  }, [desktopMode]);

  useEffect(() => {
    void loadSettingsExtras();
  }, [loadSettingsExtras]);

  const runSettingAction = async (key: string, fn: () => Promise<void>) => {
    setBusyKey(key);
    setToast(null);
    try {
      await fn();
      await onRefreshCore();
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  const handleCloseToTrayChange = async (nextCloseToTray: boolean) => {
    setBusyKey("desktop-prefs");
    setToast(null);
    try {
      const updated = await updateDesktopPrefs(nextCloseToTray);
      setCloseToTray(updated.close_to_tray);
      setToast({
        ok: true,
        text: updated.close_to_tray
          ? tr(
              "已设置：点击关闭按钮时最小化到系统托盘",
              "Close button set to minimize to system tray",
            )
          : tr(
              "已设置：点击关闭按钮时直接退出程序",
              "Close button set to quit application",
            ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  const handleSaveMixedPort = async (e: React.FormEvent) => {
    e.preventDefault();
    const portNum = Number.parseInt(mixedPortInput.trim(), 10);
    if (!Number.isFinite(portNum) || portNum < 1024 || portNum > 65535) {
      setToast({
        ok: false,
        text: tr(
          "端口需在 1024 到 65535 之间",
          "Port must be between 1024 and 65535",
        ),
      });
      return;
    }
    await runSettingAction("mixed-port", async () => {
      await patchConfig({ "mixed-port": portNum });
      setToast({
        ok: true,
        text: tr(
          `混合代理端口已更新为 ${portNum}`,
          `Mixed port updated to ${portNum}`,
        ),
      });
    });
  };

  const handleSelectPreset = async (choice: RoutingPresetChoice) => {
    await runSettingAction(`preset-${choice}`, async () => {
      const snap = await clashApi.setRoutingPreset(choice);
      setPresetSnap(snap);
      setToast({
        ok: true,
        text: tr(
          `已切换分流策略预设（共 ${snap.rule_count} 条规则生效）`,
          `Applied routing preset (${snap.rule_count} rules active)`,
        ),
      });
    });
  };

  const handleSaveController = async (e: React.FormEvent) => {
    e.preventDefault();
    saveControllerSettings({ baseUrl: ctrlUrl.trim(), secret: ctrlSecret });
    onControllerUpdated();
    await onRefreshCore();
    setToast({
      ok: true,
      text: tr(
        "控制接口连接设置已保存",
        "Controller API settings saved",
      ),
    });
  };

  // Site Connectivity Doctor actions
  const runSiteDiagnosis = async (rawTarget?: string) => {
    const cleaned = (rawTarget ?? siteTarget).trim();
    if (!cleaned) {
      setToast({
        ok: false,
        text: tr(
          "请输入需要诊断的域名或网址，例如 chatgpt.com",
          "Please enter a domain or URL to diagnose, e.g. chatgpt.com",
        ),
      });
      return;
    }
    setBusyKey("site-doctor");
    setToast(null);
    try {
      const rep = await clashApi.diagnoseSite(cleaned, {
        checkUdp: true,
        timeoutMs: 5500,
      });
      setSiteDiag(rep);
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  const handleSiteDoctorSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runSiteDiagnosis();
  };

  const handleQuickSuggestedFix = async (kind: string) => {
    if (kind === "switch_node") {
      onOpenProxies?.();
      return;
    }
    if (kind === "import_profile") {
      onOpenProfiles?.();
      return;
    }
    if (kind === "edit_rules") {
      setSubTab("rules-dns");
      return;
    }
    if (kind === "enable_takeover") {
      setBusyKey("site-fix");
      setToast(null);
      try {
        if (config?.sysproxy?.supported !== false) {
          await setSysProxy(true);
        } else {
          await patchConfig({ tun: { enable: true } });
        }
        await onRefreshCore();
        await runSiteDiagnosis();
      } catch (err) {
        setToast({
          ok: false,
          text: err instanceof Error ? err.message : String(err),
        });
      } finally {
        setBusyKey(null);
      }
      return;
    }
    if (kind === "switch_mode_rule") {
      setBusyKey("site-fix");
      setToast(null);
      try {
        await patchConfig({ mode: "rule" });
        await onRefreshCore();
        await runSiteDiagnosis();
      } catch (err) {
        setToast({
          ok: false,
          text: err instanceof Error ? err.message : String(err),
        });
      } finally {
        setBusyKey(null);
      }
    }
  };

  // Diagnostics actions
  const defaultTargetProxy =
    config?.["effective-outbound"]?.primary_group ||
    config?.["effective-outbound"]?.effective_outbound ||
    Object.keys(proxies)[0] ||
    "DIRECT";
  const effectiveTargetProxy =
    probeProxy && proxies[probeProxy] ? probeProxy : defaultTargetProxy;

  const handleRunWaterfall = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusyKey("waterfall");
    setToast(null);
    try {
      const rep = await runDiagnosticsWaterfall(effectiveTargetProxy, {
        url: probeUrl.trim() || "https://api.github.com/",
        checkUdp: true,
        timeoutMs: 5000,
      });
      setWaterfallRes(rep);
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  const handleRunMatrix = async () => {
    setBusyKey("matrix");
    setToast(null);
    try {
      const rep = await clashApi.probeEndpointMatrix(effectiveTargetProxy, 4500);
      setMatrixRes(rep);
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  const handleRunSecurityAudit = async () => {
    setBusyKey("audit");
    setToast(null);
    try {
      const rep = await clashApi.getConfigAudit(false);
      setAuditRes(rep);
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  const handleExportDiag = async () => {
    setBusyKey("export-diag");
    setToast(null);
    try {
      const payload = await exportDiagnosticsBundle();
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `rust-clash-diagnostics-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setToast({
        ok: true,
        text: tr(
          "已导出脱敏诊断包（所有密码、UUID 与订阅密钥均已自动擦除）",
          "Exported redacted diagnostic bundle (all passwords, UUIDs, and URLs scrubbed)",
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  // Developer actions
  const handleToggleDemo = async (enable: boolean) => {
    await runSettingAction("demo", async () => {
      await toggleDemoMode(enable);
      setToast({
        ok: true,
        text: enable
          ? tr(
              "已开启本地多协议演练沙盒",
              "Enabled local Multi-Protocol Demo Sandbox",
            )
          : tr(
              "已退出演练沙盒，恢复真实用户配置",
              "Exited Demo Sandbox and restored user profile",
            ),
      });
    });
  };

  const handleGeneratePqKeys = async () => {
    setBusyKey("pq");
    setToast(null);
    try {
      const kp = await generateVlessKeypair({
        mode: pqMode,
        zero_rtt: zeroRtt,
        post_quantum: includePq,
      });
      setKeypair(kp);
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  const handleBenchmark = async () => {
    setBusyKey("bench");
    setToast(null);
    try {
      const res = await runBenchmark(benchStreams, 524_288);
      setBenchResult(res);
      await onRefreshCore();
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyKey(null);
    }
  };

  const renderSuggestedFixButton = (diag: SiteDiagnosisReport) => {
    const kind = diag.suggested_action_kind;
    if (!kind) return null;
    const labelMap: Record<string, { zh: string; en: string }> = {
      switch_node: { zh: "去切换代理节点", en: "Switch Proxy Node" },
      enable_takeover: {
        zh: "一键开启系统接管并复测",
        en: "Enable Takeover & Re-test",
      },
      switch_mode_rule: {
        zh: "切换为规则分流并复测",
        en: "Switch to Rule Mode & Re-test",
      },
      import_profile: { zh: "前往导入订阅", en: "Import Subscription" },
      edit_rules: { zh: "检查分流规则", en: "Inspect Rules" },
    };
    const lbl = labelMap[kind];
    if (!lbl) return null;
    return (
      <button
        type="button"
        className="btn btn-primary btn-sm"
        disabled={busyKey === "site-fix" || busyKey === "site-doctor"}
        onClick={() => void handleQuickSuggestedFix(kind)}
      >
        {busyKey === "site-fix"
          ? tr("处理中…", "Applying...")
          : lang === "zh"
            ? lbl.zh
            : lbl.en}
      </button>
    );
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {/* Top 5 Segmented Sub-Tabs */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 10,
          flexWrap: "wrap",
        }}
      >
        <div className="segmented" role="tablist">
          <button
            type="button"
            className={`seg-btn ${subTab === "settings" ? "active" : ""}`}
            onClick={() => setSubTab("settings")}
          >
            {tr("通用设置", "Settings")}
          </button>
          <button
            type="button"
            className={`seg-btn ${subTab === "rules-dns" ? "active" : ""}`}
            onClick={() => setSubTab("rules-dns")}
          >
            {tr("规则与 DNS", "Rules & DNS")}
          </button>
          <button
            type="button"
            className={`seg-btn ${subTab === "diagnostics" ? "active" : ""}`}
            onClick={() => setSubTab("diagnostics")}
          >
            {tr("网络诊断", "Diagnostics")}
          </button>
          <button
            type="button"
            className={`seg-btn ${subTab === "logs" ? "active" : ""}`}
            onClick={() => setSubTab("logs")}
          >
            {tr("运行日志", "Logs")}
          </button>
          <button
            type="button"
            className={`seg-btn ${subTab === "developer" ? "active" : ""}`}
            onClick={() => setSubTab("developer")}
          >
            {tr("高级工具", "Developer")}
          </button>
        </div>

        {version && (
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
            RustClash {version.version}
          </span>
        )}
      </div>

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

      {/* SUB-TAB 1: SETTINGS */}
      {subTab === "settings" && (
        <div className="bento-grid">
          <section
            className="bento-card col-6"
            style={{ display: "flex", flexDirection: "column", gap: 11 }}
          >
            <div style={{ fontSize: 15, fontWeight: 650 }}>
              {tr("界面外观与语言", "Appearance & Language")}
            </div>

            <div className="setting-row">
              <div>
                <div className="setting-title">
                  {tr("界面主题", "Theme")}
                </div>
                <div className="setting-desc">
                  {tr(
                    "推荐使用浅色清爽 Bento 卡片风格",
                    "Crisp light Bento cards or comfortable dark mode",
                  )}
                </div>
              </div>
              <div className="segmented">
                <button
                  type="button"
                  className={`seg-btn ${theme === "light" ? "active" : ""}`}
                  onClick={() => onChangeTheme("light")}
                >
                  {tr("浅色清爽", "Light")}
                </button>
                <button
                  type="button"
                  className={`seg-btn ${theme === "dark" ? "active" : ""}`}
                  onClick={() => onChangeTheme("dark")}
                >
                  {tr("深色夜间", "Dark")}
                </button>
              </div>
            </div>

            <div className="setting-row">
              <div>
                <div className="setting-title">
                  {tr("显示语言", "Language")}
                </div>
                <div className="setting-desc">
                  {tr(
                    "实时切换中英文界面文案",
                    "Switch interface language immediately",
                  )}
                </div>
              </div>
              <div className="segmented">
                <button
                  type="button"
                  className={`seg-btn ${lang === "zh" ? "active" : ""}`}
                  onClick={() => setLang("zh")}
                >
                  简体中文
                </button>
                <button
                  type="button"
                  className={`seg-btn ${lang === "en" ? "active" : ""}`}
                  onClick={() => setLang("en")}
                >
                  English
                </button>
              </div>
            </div>

            <div className="setting-row">
              <div>
                <div className="setting-title">
                  {tr("分流策略预设", "Routing Preset")}
                </div>
                <div className="setting-desc">
                  {tr(
                    "国内网站直连不减速，海外服务智能走代理",
                    "Smart mainland direct split-tunnel or global routing",
                  )}
                </div>
              </div>
              <div className="segmented">
                <button
                  type="button"
                  disabled={Boolean(busyKey)}
                  className={`seg-btn ${
                    presetSnap?.active_choice === "smart-cn" ? "active" : ""
                  }`}
                  onClick={() => void handleSelectPreset("smart-cn")}
                >
                  {tr("智能分流", "Smart CN")}
                </button>
                <button
                  type="button"
                  disabled={Boolean(busyKey)}
                  className={`seg-btn ${
                    presetSnap?.active_choice === "global" ? "active" : ""
                  }`}
                  onClick={() => void handleSelectPreset("global")}
                >
                  {tr("全局代理", "Global")}
                </button>
                <button
                  type="button"
                  disabled={Boolean(busyKey)}
                  className={`seg-btn ${
                    presetSnap?.active_choice === "direct" ? "active" : ""
                  }`}
                  onClick={() => void handleSelectPreset("direct")}
                >
                  {tr("全局直连", "Direct")}
                </button>
              </div>
            </div>
          </section>

          <section
            className="bento-card col-6"
            style={{ display: "flex", flexDirection: "column", gap: 11 }}
          >
            <div style={{ fontSize: 15, fontWeight: 650 }}>
              {tr("系统集成与网络监听", "System Integration & Network")}
            </div>

            <div className="setting-row">
              <div>
                <div className="setting-title">
                  {tr("开机自启", "Launch at Login")}
                </div>
                <div className="setting-desc">
                  {tr(
                    "登录系统时自动在后台启动 RustClash",
                    "Start RustClash automatically when you sign in",
                  )}
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={Boolean(config?.autostart?.enabled)}
                disabled={
                  busyKey === "autostart" ||
                  config?.autostart?.supported === false
                }
                className={`pill-switch ${
                  config?.autostart?.enabled ? "checked" : ""
                }`}
                onClick={() =>
                  void runSettingAction("autostart", async () => {
                    await clashApi.patchAutostart(
                      !Boolean(config?.autostart?.enabled),
                    );
                  })
                }
              />
            </div>

            {desktopMode && (
              <div className="setting-row">
                <div>
                  <div className="setting-title">
                    {tr("点击关闭按钮时", "Close Button Behavior")}
                  </div>
                  <div className="setting-desc">
                    {tr(
                      "最小化到托盘可保持代理不断开",
                      "Keep proxy running in background tray or quit",
                    )}
                  </div>
                </div>
                <div className="segmented">
                  <button
                    type="button"
                    disabled={busyKey === "desktop-prefs"}
                    className={`seg-btn ${closeToTray ? "active" : ""}`}
                    onClick={() => void handleCloseToTrayChange(true)}
                  >
                    {tr("最小化到托盘", "Minimize to Tray")}
                  </button>
                  <button
                    type="button"
                    disabled={busyKey === "desktop-prefs"}
                    className={`seg-btn ${!closeToTray ? "active" : ""}`}
                    onClick={() => void handleCloseToTrayChange(false)}
                  >
                    {tr("直接退出", "Quit App")}
                  </button>
                </div>
              </div>
            )}

            <div className="setting-row">
              <div>
                <div className="setting-title">
                  {tr("允许局域网设备连接", "Allow LAN")}
                </div>
                <div className="setting-desc">
                  {tr(
                    "允许同一 Wi-Fi 下的手机、平板共享此代理端口",
                    "Share proxy listener with other devices on your LAN",
                  )}
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={Boolean(config?.["allow-lan"])}
                disabled={busyKey === "allow-lan" || !config}
                className={`pill-switch ${
                  config?.["allow-lan"] ? "checked" : ""
                }`}
                onClick={() =>
                  void runSettingAction("allow-lan", async () => {
                    await patchConfig({
                      "allow-lan": !Boolean(config?.["allow-lan"]),
                    });
                  })
                }
              />
            </div>

            <div className="setting-row">
              <div>
                <div className="setting-title">{tr("IPv6 网络支持", "IPv6")}</div>
                <div className="setting-desc">
                  {tr(
                    "启用 IPv6 DNS 解析与 TUN 双栈路由",
                    "Enable IPv6 DNS resolution and dual-stack routing",
                  )}
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={Boolean(config?.ipv6 || config?.tun.ipv6)}
                disabled={busyKey === "ipv6" || !config}
                className={`pill-switch ${
                  config?.ipv6 || config?.tun.ipv6 ? "checked" : ""
                }`}
                onClick={() =>
                  void runSettingAction("ipv6", async () => {
                    const next = !Boolean(config?.ipv6 || config?.tun.ipv6);
                    await patchConfig({ ipv6: next, tun: { ipv6: next } });
                  })
                }
              />
            </div>

            <form className="setting-row" onSubmit={handleSaveMixedPort}>
              <div>
                <div className="setting-title">
                  {tr("混合代理端口 (HTTP + SOCKS5)", "Mixed Proxy Port")}
                </div>
                <div className="setting-desc tabular">
                  127.0.0.1:{config?.["mixed-port"] ?? 7890}
                </div>
              </div>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <input
                  className="input tabular"
                  style={{ width: 88, padding: "5px 10px" }}
                  value={mixedPortInput}
                  onChange={(e) => setMixedPortInput(e.target.value)}
                />
                <button
                  type="submit"
                  className="btn btn-sm"
                  disabled={busyKey === "mixed-port"}
                >
                  {tr("保存", "Save")}
                </button>
              </div>
            </form>
          </section>

          {/* Collapsible Advanced Controller Settings */}
          <section className="bento-card col-12" style={{ padding: "13px 18px" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                cursor: "pointer",
                userSelect: "none",
              }}
              onClick={() => setAdvancedOpen((v) => !v)}
            >
              <div>
                <div style={{ fontSize: 14, fontWeight: 650 }}>
                  {tr("高级控制接口设置", "Advanced Controller API Settings")}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {tr(
                    "连接远程或自定义端口的 External Controller API 与访问密钥",
                    "Configure custom External Controller URL and Bearer Secret",
                  )}
                </div>
              </div>
              <span style={{ color: "var(--text-muted)" }}>
                {advancedOpen ? (
                  <ChevronDownIcon size={16} />
                ) : (
                  <ChevronRightIcon size={16} />
                )}
              </span>
            </div>

            {advancedOpen && (
              <form
                onSubmit={handleSaveController}
                style={{
                  marginTop: 12,
                  display: "flex",
                  gap: 10,
                  flexWrap: "wrap",
                  alignItems: "flex-end",
                }}
              >
                <div className="form-field" style={{ flex: "1 1 240px" }}>
                  <label className="form-label">
                    {tr("API 地址（留空自动发现本地引擎）", "Controller Base URL")}
                  </label>
                  <input
                    className="input mono"
                    placeholder="http://127.0.0.1:9090"
                    value={ctrlUrl}
                    onChange={(e) => setCtrlUrl(e.target.value)}
                  />
                </div>
                <div className="form-field" style={{ flex: "1 1 200px" }}>
                  <label className="form-label">
                    {tr("访问密钥 (Bearer Secret)", "Bearer Secret")}
                  </label>
                  <input
                    type="password"
                    className="input mono"
                    placeholder={tr("未设置可留空", "Optional secret")}
                    value={ctrlSecret}
                    onChange={(e) => setCtrlSecret(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn btn-primary">
                  {tr("保存并重连", "Save & Reconnect")}
                </button>
              </form>
            )}
          </section>
        </div>
      )}

      {/* SUB-TAB 2: RULES & DNS */}
      {subTab === "rules-dns" && (
        <RulesDnsView rules={rules} onRefreshRules={onRefreshCore} />
      )}

      {/* SUB-TAB 3: DIAGNOSTICS */}
      {subTab === "diagnostics" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          {/* Flagship Plain-Language Site Connectivity Doctor */}
          <section
            className="bento-card"
            style={{ display: "flex", flexDirection: "column", gap: 12 }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "flex-start",
                justifyContent: "space-between",
                gap: 10,
                flexWrap: "wrap",
              }}
            >
              <div>
                <div style={{ fontSize: 15.5, fontWeight: 700 }}>
                  {tr(
                    "为什么这个网站打不开？（按网站诊断分流与连通性）",
                    "Why Won't This Website Open? (Site Route & Connectivity Doctor)",
                  )}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                  {tr(
                    "输入任意域名或网址，自动检查分流规则去向、系统代理接管、DNS 解析、TLS 握手与出口风控原因",
                    "Enter any domain or URL to inspect its rule path, system takeover, DNS, TLS handshake, and WAF/Geo blocks",
                  )}
                </div>
              </div>

              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={busyKey === "audit"}
                  onClick={() => void handleRunSecurityAudit()}
                >
                  {busyKey === "audit"
                    ? tr("体检中…", "Auditing...")
                    : tr("配置安全体检", "Security Audit")}
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={busyKey === "export-diag"}
                  onClick={() => void handleExportDiag()}
                >
                  {busyKey === "export-diag"
                    ? tr("导出中…", "Exporting...")
                    : tr("导出脱敏诊断包", "Export Diagnostics")}
                </button>
              </div>
            </div>

            <form
              onSubmit={handleSiteDoctorSubmit}
              style={{ display: "flex", gap: 8, flexWrap: "wrap" }}
            >
              <input
                id="site-doctor-input"
                className="input"
                style={{ flex: "1 1 260px" }}
                placeholder={tr(
                  "输入打不开的域名或网址，例如 chatgpt.com、claude.ai、github.com…",
                  "Enter domain or URL, e.g. chatgpt.com, claude.ai, github.com...",
                )}
                value={siteTarget}
                onChange={(e) => setSiteTarget(e.target.value)}
              />
              <button
                id="site-doctor-submit-btn"
                type="submit"
                className="btn btn-primary"
                disabled={busyKey === "site-doctor"}
              >
                {busyKey === "site-doctor"
                  ? tr("正在诊断…", "Diagnosing...")
                  : tr("开始诊断", "Diagnose Site")}
              </button>
            </form>

            <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
              <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                {tr("常见示例：", "Examples:")}
              </span>
              {SITE_PRESETS.map((sample) => (
                <button
                  key={sample}
                  type="button"
                  className="btn btn-sm"
                  style={{ padding: "3px 10px", fontSize: 11.5 }}
                  disabled={busyKey === "site-doctor"}
                  onClick={() => {
                    setSiteTarget(sample);
                    void runSiteDiagnosis(sample);
                  }}
                >
                  {sample}
                </button>
              ))}
            </div>

            {siteDiag && (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 10,
                  marginTop: 2,
                }}
              >
                {/* Part 1: Verdict Headline & Actionable Advice */}
                <div
                  className="sub-pill-box"
                  style={{
                    border: `1px solid ${
                      siteDiag.severity === "ok"
                        ? "var(--accent-emerald)"
                        : siteDiag.severity === "warning"
                          ? "var(--accent-amber)"
                          : "var(--accent-rose)"
                    }`,
                    background:
                      siteDiag.severity === "ok"
                        ? "var(--accent-emerald-soft)"
                        : siteDiag.severity === "warning"
                          ? "var(--accent-amber-soft)"
                          : "var(--accent-rose-soft)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                    padding: "12px 14px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 10,
                      flexWrap: "wrap",
                    }}
                  >
                    <div style={{ fontSize: 14.5, fontWeight: 700 }}>
                      {lang === "zh" ? siteDiag.headline_zh : siteDiag.headline_en}
                    </div>
                    {renderSuggestedFixButton(siteDiag)}
                  </div>

                  <div style={{ fontSize: 12.5, lineHeight: 1.5 }}>
                    {lang === "zh" ? siteDiag.summary_zh : siteDiag.summary_en}
                  </div>

                  {(lang === "zh" ? siteDiag.actions_zh : siteDiag.actions_en)
                    .length > 0 && (
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 3,
                        fontSize: 12,
                        paddingTop: 4,
                      }}
                    >
                      <strong>{tr("建议操作：", "Recommended actions:")}</strong>
                      {(lang === "zh"
                        ? siteDiag.actions_zh
                        : siteDiag.actions_en
                      ).map((act, idx) => (
                        <div key={idx}>• {act}</div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Part 2: Expected Routing Path */}
                <div
                  className="sub-pill-box"
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 6,
                    padding: "11px 14px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 8,
                      flexWrap: "wrap",
                    }}
                  >
                    <strong style={{ fontSize: 12.5 }}>
                      {tr("预计分流路径", "Expected Routing Path")}
                    </strong>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <span
                        className={`badge ${
                          siteDiag.exit_type === "PROXY"
                            ? "badge-sky"
                            : siteDiag.exit_type === "DIRECT"
                              ? "badge-emerald"
                              : "badge-rose"
                        }`}
                      >
                        {siteDiag.exit_type} · {siteDiag.effective_outbound} (
                        {siteDiag.effective_protocol})
                      </span>
                      <span
                        className={`badge ${
                          siteDiag.takeover.sysproxy_enabled ||
                          siteDiag.takeover.tun_enabled
                            ? "badge-emerald"
                            : "badge-amber"
                        }`}
                      >
                        {siteDiag.takeover.sysproxy_enabled &&
                        siteDiag.takeover.tun_enabled
                          ? tr("系统代理 + TUN 已启用", "SysProxy + TUN On")
                          : siteDiag.takeover.tun_enabled
                            ? tr("TUN 已启用", "TUN On")
                            : siteDiag.takeover.sysproxy_enabled
                              ? tr("系统代理已启用", "SysProxy On")
                              : tr("未开启系统接管", "Takeover Off")}
                      </span>
                    </div>
                  </div>
                  <div style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                    {lang === "zh"
                      ? siteDiag.route_summary_zh
                      : siteDiag.route_summary_en}
                  </div>
                </div>

                {/* Part 3: Stage-by-Stage Check Cards */}
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(175px, 1fr))",
                    gap: 8,
                  }}
                >
                  {siteDiag.stage_checks.map((st) => {
                    const badgeCls =
                      st.status === "ok"
                        ? "badge-emerald"
                        : st.status === "warning"
                          ? "badge-amber"
                          : st.status === "failed"
                            ? "badge-rose"
                            : "badge-neutral";
                    const statusText =
                      st.status === "ok"
                        ? st.latency_ms != null
                          ? `${st.latency_ms} ms`
                          : tr("正常", "OK")
                        : st.status === "warning"
                          ? tr("注意", "Warn")
                          : st.status === "failed"
                            ? tr("失败", "Failed")
                            : tr("跳过", "Skipped");
                    return (
                      <div
                        key={st.stage}
                        className="sub-pill-box"
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: 4,
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            gap: 6,
                          }}
                        >
                          <strong style={{ fontSize: 12 }}>
                            {lang === "zh" ? st.label_zh : st.label_en}
                          </strong>
                          <span className={`badge tabular ${badgeCls}`}>
                            {statusText}
                          </span>
                        </div>
                        <div
                          style={{
                            fontSize: 11.5,
                            color: "var(--text-secondary)",
                            lineHeight: 1.4,
                          }}
                        >
                          {lang === "zh" ? st.detail_zh : st.detail_en}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Part 4: Collapsible Technical Waterfall Details */}
                {siteDiag.waterfall && (
                  <div className="sub-pill-box" style={{ padding: "9px 13px" }}>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        cursor: "pointer",
                        fontSize: 12,
                        color: "var(--text-secondary)",
                        fontWeight: 600,
                      }}
                      onClick={() => setSiteRawOpen((v) => !v)}
                    >
                      <span>
                        {tr(
                          "展开底层协议与耗时瀑布详情（高级排障）",
                          "Technical Waterfall & TLS Details (Advanced)",
                        )}
                      </span>
                      {siteRawOpen ? (
                        <ChevronDownIcon size={15} />
                      ) : (
                        <ChevronRightIcon size={15} />
                      )}
                    </div>

                    {siteRawOpen && (
                      <div
                        className="tabular mono"
                        style={{
                          marginTop: 8,
                          fontSize: 11.5,
                          color: "var(--text-secondary)",
                          display: "flex",
                          flexDirection: "column",
                          gap: 4,
                        }}
                      >
                        <div>
                          URL: {siteDiag.normalized_url} · Rule:{" "}
                          {siteDiag.matched_rule} · Endpoint:{" "}
                          {siteDiag.remote_endpoint}
                        </div>
                        <div>
                          DNS ({siteDiag.waterfall.dns_mode}):{" "}
                          {siteDiag.waterfall.dns_resolve_ms ?? "—"} ms | Tunnel:{" "}
                          {siteDiag.waterfall.tunnel_connect_ms ?? "—"} ms | TLS (
                          {siteDiag.waterfall.tls_version ?? "—"} / ALPN{" "}
                          {siteDiag.waterfall.alpn ?? "—"}):{" "}
                          {siteDiag.waterfall.tls_handshake_ms ?? "—"} ms | TTFB:{" "}
                          {siteDiag.waterfall.http_ttfb_ms ?? "—"} ms | HTTP:{" "}
                          {siteDiag.waterfall.http_status ?? "—"}
                        </div>
                        {siteDiag.waterfall.error && (
                          <div style={{ color: "var(--accent-rose)" }}>
                            Raw Error: {siteDiag.waterfall.error}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {auditRes && (
              <div className="sub-pill-box" style={{ fontSize: 12.5 }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: auditRes.findings.length > 0 ? 6 : 0,
                  }}
                >
                  <strong>
                    {tr("配置安全体检得分：", "Security Audit Score: ")}
                    {auditRes.score}/100 ({auditRes.grade})
                  </strong>
                  <span className="badge badge-emerald">
                    {auditRes.findings.length === 0
                      ? tr("全部通过", "All Passed")
                      : tr(
                          `${auditRes.findings.length} 项提示`,
                          `${auditRes.findings.length} findings`,
                        )}
                  </span>
                </div>
                {auditRes.findings.slice(0, 5).map((f, idx) => (
                  <div
                    key={`${f.code}-${idx}`}
                    style={{
                      fontSize: 12,
                      color: "var(--text-secondary)",
                      marginTop: 3,
                    }}
                  >
                    • <strong>{f.title}:</strong> {f.detail}
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Secondary Engineering Card: Specific Node Waterfall & Endpoint Matrix */}
          <section
            className="bento-card"
            style={{ display: "flex", flexDirection: "column", gap: 12 }}
          >
            <div>
              <div style={{ fontSize: 14.5, fontWeight: 650 }}>
                {tr(
                  "指定节点耗时瀑布与全球服务连通矩阵（进阶）",
                  "Per-Node Waterfall Probe & Global Endpoint Matrix (Advanced)",
                )}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {tr(
                  "绕过分流规则直接指定任意节点或策略组，对比各阶段握手延迟与常见服务解锁状态",
                  "Test a specific proxy or group directly across DNS, TCP, TLS, TTFB, UDP, and global endpoints",
                )}
              </div>
            </div>

            <form
              onSubmit={handleRunWaterfall}
              style={{ display: "flex", gap: 8, flexWrap: "wrap" }}
            >
              <select
                className="select"
                value={effectiveTargetProxy}
                onChange={(e) => setProbeProxy(e.target.value)}
              >
                {Object.keys(proxies).map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>

              <input
                className="input"
                style={{ flex: "1 1 220px" }}
                placeholder="https://api.github.com/"
                value={probeUrl}
                onChange={(e) => setProbeUrl(e.target.value)}
              />

              <button
                type="submit"
                className="btn"
                disabled={busyKey === "waterfall"}
              >
                {busyKey === "waterfall"
                  ? tr("探测中…", "Probing...")
                  : tr("单节点瀑布探测", "Waterfall Probe")}
              </button>

              <button
                type="button"
                className="btn"
                disabled={busyKey === "matrix"}
                onClick={() => void handleRunMatrix()}
              >
                {busyKey === "matrix"
                  ? tr("检测中…", "Checking...")
                  : tr("常见网站连通矩阵", "Endpoint Matrix")}
              </button>
            </form>

            {waterfallRes && (
              <div
                className="sub-pill-box"
                style={{ display: "flex", flexDirection: "column", gap: 8 }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 8,
                    flexWrap: "wrap",
                  }}
                >
                  <div>
                    <strong>{waterfallRes.effective_outbound}</strong>{" "}
                    <span style={{ color: "var(--text-muted)", fontSize: 12 }}>
                      ({waterfallRes.protocol}) → {waterfallRes.target_host}
                    </span>
                  </div>
                  <span
                    className={`badge tabular ${
                      waterfallRes.verdict === "reachable" ||
                      waterfallRes.verdict === "auth_required"
                        ? "badge-emerald"
                        : "badge-rose"
                    }`}
                  >
                    {waterfallRes.verdict} · {waterfallRes.total_ms} ms
                  </span>
                </div>

                <div
                  className="tabular"
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
                    gap: 8,
                    fontSize: 12,
                  }}
                >
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>DNS: </span>
                    <strong>
                      {waterfallRes.dns_resolve_ms != null
                        ? `${waterfallRes.dns_resolve_ms} ms`
                        : "—"}
                    </strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>
                      {tr("隧道连接: ", "Tunnel: ")}
                    </span>
                    <strong>
                      {waterfallRes.tunnel_connect_ms != null
                        ? `${waterfallRes.tunnel_connect_ms} ms`
                        : "—"}
                    </strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>TLS: </span>
                    <strong>
                      {waterfallRes.tls_handshake_ms != null
                        ? `${waterfallRes.tls_handshake_ms} ms`
                        : "—"}
                    </strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>HTTP TTFB: </span>
                    <strong>
                      {waterfallRes.http_ttfb_ms != null
                        ? `${waterfallRes.http_ttfb_ms} ms`
                        : "—"}
                    </strong>
                  </div>
                  {waterfallRes.udp_probe && (
                    <div>
                      <span style={{ color: "var(--text-muted)" }}>UDP: </span>
                      <strong>{waterfallRes.udp_probe.status}</strong>
                    </div>
                  )}
                </div>

                {waterfallRes.error && (
                  <div style={{ fontSize: 12, color: "var(--accent-rose)" }}>
                    {waterfallRes.error}
                  </div>
                )}
              </div>
            )}

            {matrixRes && (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
                  gap: 8,
                }}
              >
                {matrixRes.items.map((item) => {
                  const ok =
                    item.report.verdict === "reachable" ||
                    item.report.verdict === "auth_required";
                  return (
                    <div
                      key={item.id}
                      className="sub-pill-box"
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        gap: 8,
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 600, fontSize: 12.5 }}>
                          {item.label}
                        </div>
                        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                          {item.category}
                        </div>
                      </div>
                      <span
                        className={`badge tabular ${
                          ok ? "badge-emerald" : "badge-rose"
                        }`}
                      >
                        {ok ? `${item.report.total_ms} ms` : item.report.verdict}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      )}

      {/* SUB-TAB 4: LOGS */}
      {subTab === "logs" && <LogsView logs={logs} onClear={onClearLogs} />}

      {/* SUB-TAB 5: DEVELOPER */}
      {subTab === "developer" && (
        <div className="bento-grid">
          <section
            className="bento-card col-6"
            style={{ display: "flex", flexDirection: "column", gap: 12 }}
          >
            <div>
              <div style={{ fontSize: 15, fontWeight: 650 }}>
                {tr("多协议本地演练沙盒", "Multi-Protocol Demo Sandbox")}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                {tr(
                  "在本地回环自动启动 SS-2022、抗量子 VLESS 与 AnyTLS v2 测试服务端，无需外部节点即可体验全部功能",
                  "Spin up local loopback SS-2022, Post-Quantum VLESS, and AnyTLS v2 test servers",
                )}
              </div>
            </div>

            <div className="setting-row">
              <div>
                <div className="setting-title">
                  {config?.demo.enabled
                    ? tr("演练沙盒运行中", "Demo Sandbox Active")
                    : tr("演练沙盒已关闭", "Demo Sandbox Inactive")}
                </div>
                <div className="setting-desc">
                  {tr(
                    "退出沙盒后会自动恢复您原有的真实订阅配置",
                    "Exiting restores your saved real user profile",
                  )}
                </div>
              </div>
              <button
                type="button"
                className={`btn btn-sm ${
                  config?.demo.enabled ? "btn-danger" : "btn-primary"
                }`}
                disabled={busyKey === "demo"}
                onClick={() => void handleToggleDemo(!Boolean(config?.demo.enabled))}
              >
                {config?.demo.enabled
                  ? tr("退出沙盒", "Exit Sandbox")
                  : tr("启动沙盒", "Launch Sandbox")}
              </button>
            </div>

            <div
              style={{
                borderTop: "1px solid var(--border-subtle)",
                paddingTop: 10,
                display: "flex",
                flexDirection: "column",
                gap: 10,
              }}
            >
              <div>
                <div style={{ fontSize: 14, fontWeight: 650 }}>
                  {tr("本地回环吞吐压测", "Loopback Throughput Benchmark")}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {tr(
                    "通过当前选中的策略组测试真实并发代理吞吐率",
                    "Measure concurrent proxy tunnel throughput through the active group",
                  )}
                </div>
              </div>

              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <select
                  className="select"
                  value={benchStreams}
                  onChange={(e) => setBenchStreams(Number(e.target.value))}
                >
                  <option value={2}>2 {tr("并发流", "Streams")}</option>
                  <option value={4}>4 {tr("并发流", "Streams")}</option>
                  <option value={8}>8 {tr("并发流", "Streams")}</option>
                </select>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busyKey === "bench"}
                  onClick={() => void handleBenchmark()}
                >
                  {busyKey === "bench"
                    ? tr("压测中...", "Running...")
                    : tr("开始吞吐压测", "Run Benchmark")}
                </button>
              </div>

              {benchResult && (
                <div className="sub-pill-box tabular" style={{ fontSize: 12.5 }}>
                  <strong>{benchResult.throughput_mbps.toFixed(1)} Mbps</strong> ·{" "}
                  {formatBytes(benchResult.total_bytes)} /{" "}
                  {benchResult.elapsed_ms.toFixed(1)} ms
                </div>
              )}
            </div>
          </section>

          <section
            className="bento-card col-6"
            style={{ display: "flex", flexDirection: "column", gap: 11 }}
          >
            <div>
              <div style={{ fontSize: 15, fontWeight: 650 }}>
                {tr(
                  "抗量子 VLESS 密钥生成器",
                  "Post-Quantum VLESS Keypair Generator",
                )}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                {tr(
                  "生成兼容 Xray-core 的 X25519 + ML-KEM-768 混合密钥对与节点配置片段",
                  "Generate Xray-compatible hybrid X25519 + ML-KEM-768 encryption/decryption keys",
                )}
              </div>
            </div>

            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <select
                className="select"
                value={pqMode}
                onChange={(e) => setPqMode(e.target.value)}
              >
                <option value="xorpub">xorpub</option>
                <option value="random">random</option>
                <option value="native">native</option>
              </select>

              <label style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 12.5 }}>
                <input
                  type="checkbox"
                  checked={zeroRtt}
                  onChange={(e) => setZeroRtt(e.target.checked)}
                />
                0-RTT
              </label>

              <label style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 12.5 }}>
                <input
                  type="checkbox"
                  checked={includePq}
                  onChange={(e) => setIncludePq(e.target.checked)}
                />
                ML-KEM-768
              </label>

              <button
                type="button"
                className="btn btn-primary"
                disabled={busyKey === "pq"}
                onClick={() => void handleGeneratePqKeys()}
              >
                {busyKey === "pq"
                  ? tr("生成中...", "Generating...")
                  : tr("生成密钥对", "Generate Keypair")}
              </button>
            </div>

            {keypair && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div className="sub-pill-box mono" style={{ fontSize: 11.5, wordBreak: "break-all" }}>
                  <div style={{ color: "var(--text-muted)", marginBottom: 2 }}>
                    encryption:
                  </div>
                  {keypair.encryption}
                </div>
                <pre
                  className="sub-pill-box mono"
                  style={{
                    margin: 0,
                    fontSize: 11.5,
                    whiteSpace: "pre-wrap",
                    maxHeight: 150,
                    overflowY: "auto",
                  }}
                >
                  {keypair.client_yaml_snippet}
                </pre>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
};
