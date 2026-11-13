import React, { useState } from "react";
import {
  clashApi,
  importProfile,
  readClipboardText,
  updateProfileSettings,
} from "../api";
import {
  CloseIcon,
  PlusIcon,
  RefreshIcon,
} from "../components/Icons";
import { useI18n } from "../i18n";
import type {
  ConfigAuditReport,
  ConfigDiffSummary,
  ProfileMetadata,
  ProfilesSnapshot,
} from "../types";
import { formatBytes, formatRelativeTime } from "../utils/format";

interface ProfilesViewProps {
  profilesSnapshot: ProfilesSnapshot | null;
  onReloaded: () => Promise<void>;
}

const INTERVAL_OPTIONS: Array<{
  value: number;
  zh: string;
  en: string;
}> = [
  { value: 86400, zh: "每 24 小时 (推荐)", en: "Every 24h (Recommended)" },
  { value: 43200, zh: "每 12 小时", en: "Every 12h" },
  { value: 21600, zh: "每 6 小时", en: "Every 6h" },
  { value: 3600, zh: "每 1 小时", en: "Every 1h" },
  { value: 0, zh: "关闭自动更新（仅手动）", en: "Off (Manual only)" },
];

function normalizeIntervalOption(secs?: number | null): number {
  if (!secs || secs <= 0) return 0;
  if (secs <= 3600) return 3600;
  if (secs <= 21600) return 21600;
  if (secs <= 43200) return 43200;
  return 86400;
}

export const ProfilesView: React.FC<ProfilesViewProps> = ({
  profilesSnapshot,
  onReloaded,
}) => {
  const { lang, tr } = useI18n();

  const [profileName, setProfileName] = useState("");
  const [importInput, setImportInput] = useState("");
  const [autoIntervalSecs, setAutoIntervalSecs] = useState<number>(86400);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);

  // YAML Editor Modal state
  const [yamlModalOpen, setYamlModalOpen] = useState(false);
  const [yamlTargetName, setYamlTargetName] = useState("");
  const [yamlText, setYamlText] = useState("");
  const [yamlBusy, setYamlBusy] = useState<"audit" | "save" | null>(null);
  const [yamlMsg, setYamlMsg] = useState<{ ok: boolean; text: string } | null>(
    null,
  );
  const [auditReport, setAuditReport] = useState<ConfigAuditReport | null>(
    null,
  );
  const [diffSummary, setDiffSummary] = useState<ConfigDiffSummary | null>(
    null,
  );

  const handlePasteClipboard = async () => {
    const clip = await readClipboardText();
    if (clip && clip.trim()) {
      setImportInput(clip.trim());
    } else {
      setToast({
        ok: false,
        text: tr(
          "剪贴板为空或需要授权，请直接在输入框中粘贴",
          "Clipboard is empty or blocked — paste directly into the input box",
        ),
      });
    }
  };

  const handleQuickImport = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = importInput.trim();
    if (!trimmed) {
      setToast({
        ok: false,
        text: tr(
          "请输入 https:// 订阅链接、节点分享链接或 Clash YAML",
          "Please enter an https:// subscription URL, share links, or Clash YAML",
        ),
      });
      return;
    }

    setBusyId("import");
    setToast(null);
    try {
      const intervalArg = autoIntervalSecs > 0 ? autoIntervalSecs : null;
      const res = await importProfile(
        trimmed,
        profileName.trim() || undefined,
        true,
        intervalArg,
      );
      setProfileName("");
      setImportInput("");
      await onReloaded();
      setToast({
        ok: true,
        text: tr(
          `成功导入并启用配置（共 ${res["total-nodes"] ?? res.count} 个节点）`,
          `Imported and enabled profile (${res["total-nodes"] ?? res.count} nodes)`,
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleCreateBlankProfile = async () => {
    setBusyId("blank");
    setToast(null);
    try {
      const idx = (profilesSnapshot?.profiles.length ?? 0) + 1;
      const defaultName =
        profileName.trim() ||
        (lang === "zh" ? `本地配置 ${idx}` : `Local Profile ${idx}`);
      const starterYaml = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "proxies: []",
        "rules:",
        "  - MATCH,DIRECT",
        "",
      ].join("\n");
      const res = await clashApi.createProfile({
        name: defaultName,
        yaml: starterYaml,
        activate: true,
      });
      setProfileName("");
      await onReloaded();
      setToast({
        ok: true,
        text: tr(
          `已新建并启用空白配置「${res.profile.name}」`,
          `Created and activated blank profile '${res.profile.name}'`,
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleActivate = async (p: ProfileMetadata) => {
    setBusyId(p.id);
    setToast(null);
    try {
      await clashApi.activateProfile(p.id);
      await onReloaded();
      setToast({
        ok: true,
        text: tr(
          `已切换至配置「${p.name}」`,
          `Activated profile '${p.name}'`,
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleRefresh = async (p: ProfileMetadata) => {
    setBusyId(`refresh:${p.id}`);
    setToast(null);
    try {
      const res = await clashApi.refreshProfile(p.id);
      await onReloaded();
      const manualCount = res.profile.manual_proxy_count ?? 0;
      const protectedNote =
        manualCount > 0
          ? tr(
              `，已自动保留 ${manualCount} 个手动节点`,
              `, ${manualCount} manual node(s) preserved`,
            )
          : "";
      setToast({
        ok: true,
        text: tr(
          `已更新订阅「${res.profile.name}」（${res.profile.proxy_count} 个节点${protectedNote}）`,
          `Updated '${res.profile.name}' (${res.profile.proxy_count} nodes${protectedNote})`,
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleUpdateAutoInterval = async (
    p: ProfileMetadata,
    nextSecs: number,
  ) => {
    setBusyId(`interval:${p.id}`);
    setToast(null);
    try {
      await updateProfileSettings(p.id, {
        auto_update_interval_secs: nextSecs > 0 ? nextSecs : null,
      });
      await onReloaded();
      const labelObj = INTERVAL_OPTIONS.find((o) => o.value === nextSecs);
      const label = labelObj
        ? lang === "zh"
          ? labelObj.zh
          : labelObj.en
        : String(nextSecs);
      setToast({
        ok: true,
        text: tr(
          `已将「${p.name}」更新频率设为：${label}`,
          `Updated '${p.name}' auto-refresh to: ${label}`,
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (p: ProfileMetadata) => {
    setBusyId(`del:${p.id}`);
    setToast(null);
    try {
      await clashApi.deleteProfile(p.id);
      await onReloaded();
      setToast({
        ok: true,
        text: tr(`已删除配置「${p.name}」`, `Deleted profile '${p.name}'`),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleOpenEditYaml = async (p: ProfileMetadata) => {
    setBusyId(`yaml:${p.id}`);
    setToast(null);
    setYamlMsg(null);
    setAuditReport(null);
    setDiffSummary(null);
    try {
      if (profilesSnapshot && p.id !== profilesSnapshot.active_profile_id) {
        await clashApi.activateProfile(p.id);
        await onReloaded();
      }
      const raw = await clashApi.getRawYaml(false);
      setYamlTargetName(p.name);
      setYamlText(raw.yaml);
      setYamlModalOpen(true);
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleAuditDraft = async () => {
    if (!yamlText.trim()) return;
    setYamlBusy("audit");
    setYamlMsg(null);
    try {
      const res = await clashApi.postConfigAudit(yamlText, true);
      setAuditReport(res.audit);
      setDiffSummary(res.diff ?? null);
      setYamlMsg({
        ok: true,
        text: tr(
          `配置体检完成：评分 ${res.audit.score}/100（等级 ${res.audit.grade}），共 ${res.audit.findings.length} 项提示`,
          `Audit complete: Score ${res.audit.score}/100 (Grade ${res.audit.grade}), ${res.audit.findings.length} finding(s)`,
        ),
      });
    } catch (err) {
      setYamlMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setYamlBusy(null);
    }
  };

  const handleSaveYaml = async () => {
    if (!yamlText.trim()) return;
    setYamlBusy("save");
    setYamlMsg(null);
    try {
      await clashApi.reloadYaml(yamlText);
      await onReloaded();
      setYamlModalOpen(false);
      setToast({
        ok: true,
        text: tr(
          "YAML 配置已验证并热重载生效",
          "YAML configuration validated and hot-reloaded",
        ),
      });
    } catch (err) {
      setYamlMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setYamlBusy(null);
    }
  };

  const profiles = profilesSnapshot?.profiles ?? [];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
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

      {/* Top Quick-Import Card */}
      <section className="bento-card" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 10,
            flexWrap: "wrap",
          }}
        >
          <div>
            <div style={{ fontSize: 15.5, fontWeight: 650 }}>
              {tr("快速导入订阅或节点配置", "Quick Import Subscription or Nodes")}
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
              {tr(
                "粘贴机场 https:// 订阅链接、节点分享链接或 YAML 即可一键导入启用",
                "Paste an https:// subscription URL, share links, or Clash YAML to import in one click",
              )}
            </div>
          </div>

          <button
            type="button"
            className="btn btn-sm"
            disabled={busyId === "blank"}
            onClick={() => void handleCreateBlankProfile()}
          >
            <PlusIcon size={13} />
            <span>{tr("新建空白配置", "New Blank Profile")}</span>
          </button>
        </div>

        <form
          onSubmit={handleQuickImport}
          style={{
            display: "flex",
            gap: 9,
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          <input
            className="input"
            style={{ width: 170, flex: "0 1 170px" }}
            placeholder={tr("配置名称（可选）", "Profile name (opt)")}
            value={profileName}
            onChange={(e) => setProfileName(e.target.value)}
          />

          <div
            style={{
              display: "flex",
              gap: 6,
              flex: "1 1 280px",
              minWidth: 0,
            }}
          >
            <input
              id="quick-import-profile-input"
              className="input"
              style={{ flex: 1 }}
              placeholder={tr(
                "粘贴 https:// 订阅地址 或 vless:// / ss:// / trojan:// 节点链接...",
                "Paste https:// subscription URL or share links...",
              )}
              value={importInput}
              onChange={(e) => setImportInput(e.target.value)}
            />
            <button
              type="button"
              className="btn"
              onClick={() => void handlePasteClipboard()}
            >
              {tr("粘贴", "Paste")}
            </button>
          </div>

          <select
            className="select"
            value={autoIntervalSecs}
            onChange={(e) => setAutoIntervalSecs(Number(e.target.value))}
            aria-label={tr("自动更新频率", "Auto-update interval")}
          >
            {INTERVAL_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {lang === "zh" ? opt.zh : opt.en}
              </option>
            ))}
          </select>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={busyId === "import"}
          >
            {busyId === "import"
              ? tr("导入中...", "Importing...")
              : tr("导入并启用", "Import & Enable")}
          </button>
        </form>

        <div className="banner banner-ok" style={{ fontSize: 12, padding: "8px 13px" }}>
          <span>
            🛡{" "}
            {tr(
              "已启用手动节点保护：在此配置中手动导入或新建的节点会独立保存，订阅自动更新时不会丢失。",
              "Manual Node Protection Enabled: Manually imported or created nodes are stored independently and never lost on subscription auto-update.",
            )}
          </span>
        </div>
      </section>

      {/* Saved Profile Cards Grid */}
      {profiles.length === 0 ? (
        <section
          className="bento-card"
          style={{ padding: "32px 20px", textAlign: "center", color: "var(--text-muted)" }}
        >
          {tr(
            "暂无已保存的配置，请在上方输入订阅地址导入。",
            "No saved profiles yet — import a subscription URL above.",
          )}
        </section>
      ) : (
        <div className="profile-grid">
          {profiles.map((p) => {
            const isActive = p.id === profilesSnapshot?.active_profile_id;
            const isSub = p.kind === "subscription";
            const manualCount = p.manual_proxy_count ?? 0;
            const usedBytes =
              (p.userinfo?.upload_bytes ?? 0) +
              (p.userinfo?.download_bytes ?? 0);
            const totalBytes = p.userinfo?.total_bytes ?? 0;
            const usedPct =
              totalBytes > 0
                ? Math.min(100, Math.round((usedBytes / totalBytes) * 100))
                : 0;

            return (
              <div
                key={p.id}
                className={`profile-card ${isActive ? "active" : ""}`}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: 15,
                        fontWeight: 650,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={p.name}
                    >
                      {p.name}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        marginTop: 4,
                        flexWrap: "wrap",
                      }}
                    >
                      <span className="badge badge-neutral">
                        {isSub
                          ? tr("订阅", "Subscription")
                          : tr("本地", "Local")}
                      </span>
                      <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                        {formatRelativeTime(p.last_updated_ms, lang)}
                      </span>
                    </div>
                  </div>

                  {isActive && (
                    <span className="badge badge-sky">
                      {tr("当前使用", "Active")}
                    </span>
                  )}
                </div>

                {/* Node counts & Manual Node Protection Badge */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    flexWrap: "wrap",
                  }}
                >
                  <span
                    className="tabular"
                    style={{ fontSize: 12, color: "var(--text-secondary)" }}
                  >
                    {p.proxy_count} {tr("个节点", "nodes")} · {p.rule_count}{" "}
                    {tr("条规则", "rules")}
                  </span>

                  {manualCount > 0 && (
                    <span className="badge badge-emerald tabular">
                      🛡 {tr(`已保护 ${manualCount} 个手动节点`, `${manualCount} manual protected`)}
                    </span>
                  )}
                </div>

                {/* Subscription Traffic Usage */}
                {p.userinfo && (
                  <div
                    className="sub-pill-box"
                    style={{ display: "flex", flexDirection: "column", gap: 6 }}
                  >
                    <div
                      className="tabular"
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        fontSize: 11.5,
                        color: "var(--text-secondary)",
                      }}
                    >
                      <span>
                        {formatBytes(usedBytes)}
                        {totalBytes > 0 ? ` / ${formatBytes(totalBytes)}` : ""}
                      </span>
                      {p.userinfo.expire_unix_secs && (
                        <span>
                          {tr("到期 ", "Exp ")}
                          {new Date(
                            p.userinfo.expire_unix_secs * 1000,
                          ).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                    {totalBytes > 0 && (
                      <div className="progress-track">
                        <div
                          className="progress-fill"
                          style={{ width: `${usedPct}%` }}
                        />
                      </div>
                    )}
                  </div>
                )}

                {/* Inline Auto-Update Selector for Subscription Profiles */}
                {isSub && (
                  <div
                    className="sub-pill-box"
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 8,
                    }}
                  >
                    <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                      {tr("自动更新频率", "Auto-update")}
                    </span>
                    <select
                      className="select"
                      style={{ padding: "4px 9px", fontSize: 12 }}
                      disabled={busyId === `interval:${p.id}`}
                      value={normalizeIntervalOption(p.auto_update_interval_secs)}
                      onChange={(e) =>
                        void handleUpdateAutoInterval(p, Number(e.target.value))
                      }
                    >
                      <option value={0}>
                        {tr("关闭自动更新", "Off (Manual)")}
                      </option>
                      <option value={3600}>{tr("每 1 小时", "Every 1h")}</option>
                      <option value={21600}>{tr("每 6 小时", "Every 6h")}</option>
                      <option value={43200}>
                        {tr("每 12 小时", "Every 12h")}
                      </option>
                      <option value={86400}>
                        {tr("每 24 小时", "Every 24h")}
                      </option>
                    </select>
                  </div>
                )}

                {p.last_error && (
                  <div style={{ fontSize: 11.5, color: "var(--accent-rose)" }}>
                    {tr("上次更新提示：", "Last update note: ")}
                    {p.last_error}
                  </div>
                )}

                {/* Action Buttons */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 7,
                    marginTop: "auto",
                    paddingTop: 4,
                    flexWrap: "wrap",
                  }}
                >
                  {!isActive && (
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      disabled={busyId === p.id}
                      onClick={() => void handleActivate(p)}
                    >
                      {tr("启用", "Activate")}
                    </button>
                  )}

                  {isSub && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={busyId === `refresh:${p.id}`}
                      onClick={() => void handleRefresh(p)}
                    >
                      <RefreshIcon
                        size={13}
                        spinning={busyId === `refresh:${p.id}`}
                      />
                      <span>
                        {busyId === `refresh:${p.id}`
                          ? tr("更新中...", "Refreshing...")
                          : tr("立即更新", "Refresh")}
                      </span>
                    </button>
                  )}

                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={busyId === `yaml:${p.id}`}
                    onClick={() => void handleOpenEditYaml(p)}
                  >
                    {tr("编辑 YAML", "Edit YAML")}
                  </button>

                  {!isActive && p.kind !== "starter" && (
                    <button
                      type="button"
                      className="btn btn-danger btn-sm"
                      style={{ marginLeft: "auto" }}
                      disabled={busyId === `del:${p.id}`}
                      onClick={() => void handleDelete(p)}
                    >
                      {tr("删除", "Delete")}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* YAML Editor Modal with Audit / Diff Support */}
      {yamlModalOpen && (
        <div
          className="modal-backdrop"
          onClick={() => {
            if (!yamlBusy) setYamlModalOpen(false);
          }}
        >
          <div
            className="modal-card"
            style={{ maxWidth: 740 }}
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
                <div style={{ fontSize: 16, fontWeight: 650 }}>
                  {tr(`编辑 YAML：${yamlTargetName}`, `Edit YAML: ${yamlTargetName}`)}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {tr(
                    "支持配置安全检查与差异对比，保存后零停机热重载",
                    "Supports static security audit & diff check with zero-downtime hot reload",
                  )}
                </div>
              </div>
              <button
                type="button"
                className="bento-icon-action"
                onClick={() => {
                  if (!yamlBusy) setYamlModalOpen(false);
                }}
              >
                <CloseIcon size={15} />
              </button>
            </div>

            {yamlMsg && (
              <div className={`banner ${yamlMsg.ok ? "banner-ok" : "banner-err"}`}>
                <span>{yamlMsg.text}</span>
              </div>
            )}

            {diffSummary && (
              <div className="sub-pill-box" style={{ fontSize: 12 }}>
                <strong>{tr("变更预览：", "Diff Preview: ")}</strong>
                {tr(
                  `安全评分 ${diffSummary.score_before} → ${diffSummary.score_after} · 新增节点 ${diffSummary.added_proxies.length} · 移除节点 ${diffSummary.removed_proxies.length} · 规则数 ${diffSummary.rules_prev_count} → ${diffSummary.rules_next_count}`,
                  `Score ${diffSummary.score_before} → ${diffSummary.score_after} · +${diffSummary.added_proxies.length} / -${diffSummary.removed_proxies.length} proxies · Rules ${diffSummary.rules_prev_count} → ${diffSummary.rules_next_count}`,
                )}
              </div>
            )}

            {auditReport && auditReport.findings.length > 0 && (
              <div
                className="sub-pill-box"
                style={{
                  maxHeight: 120,
                  overflowY: "auto",
                  fontSize: 12,
                  display: "flex",
                  flexDirection: "column",
                  gap: 4,
                }}
              >
                {auditReport.findings.slice(0, 6).map((f, i) => (
                  <div key={`${f.code}-${i}`}>
                    <span className="badge badge-amber" style={{ marginRight: 6 }}>
                      {f.severity.toUpperCase()}
                    </span>
                    <strong>{f.title}:</strong> {f.detail}
                  </div>
                ))}
              </div>
            )}

            <textarea
              className="code-editor mono"
              rows={15}
              value={yamlText}
              onChange={(e) => setYamlText(e.target.value)}
            />

            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              <button
                type="button"
                className="btn"
                disabled={Boolean(yamlBusy)}
                onClick={() => void handleAuditDraft()}
              >
                {yamlBusy === "audit"
                  ? tr("检查中...", "Auditing...")
                  : tr("语法与安全检查", "Audit & Diff")}
              </button>

              <div style={{ display: "flex", gap: 8 }}>
                <button
                  type="button"
                  className="btn"
                  disabled={Boolean(yamlBusy)}
                  onClick={() => setYamlModalOpen(false)}
                >
                  {tr("取消", "Cancel")}
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={Boolean(yamlBusy)}
                  onClick={() => void handleSaveYaml()}
                >
                  {yamlBusy === "save"
                    ? tr("保存中...", "Saving...")
                    : tr("保存并热重载", "Save & Reload")}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
