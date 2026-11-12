import React, { useEffect, useState } from "react";
import { clashApi } from "../api";
import type {
  ConfigAuditReport,
  ConfigDiffSummary,
  ProfileMetadata,
  ProfilesSnapshot,
  VlessKeypairResponse,
} from "../types";
import { formatBytes } from "../utils/format";
import { renderInlineCode } from "../utils/inlineCode";

interface StudioViewProps {
  profilesSnapshot: ProfilesSnapshot | null;
  onReloaded: () => Promise<void>;
}

type CreateSourceMode = "subscription" | "uris" | "yaml";

const MCP_SNIPPET = JSON.stringify(
  {
    mcpServers: {
      "rust-clash": {
        command: "rust-clash",
        args: ["mcp"],
      },
    },
  },
  null,
  2,
);

export const StudioView: React.FC<StudioViewProps> = ({
  profilesSnapshot,
  onReloaded,
}) => {
  const [yamlText, setYamlText] = useState("");
  const [exportedUris, setExportedUris] = useState<string[]>([]);
  const [uriInput, setUriInput] = useState("");
  const [statusMsg, setStatusMsg] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  // Persistent Profile & Subscription form state
  const [sourceMode, setSourceMode] =
    useState<CreateSourceMode>("subscription");
  const [profileName, setProfileName] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [autoIntervalHours, setAutoIntervalHours] = useState(6);
  const [profilePayload, setProfilePayload] = useState("");
  const [profileBusyId, setProfileBusyId] = useState<string | null>(null);

  // Subscription Refresh & Draft YAML Security Diff state
  const [latestDiff, setLatestDiff] = useState<ConfigDiffSummary | null>(null);
  const [draftAudit, setDraftAudit] = useState<ConfigAuditReport | null>(null);
  const [diffSourceLabel, setDiffSourceLabel] = useState<string>("");
  const [mcpCopied, setMcpCopied] = useState(false);

  // VLESS PQ Studio state
  const [pqMode, setPqMode] = useState("xorpub");
  const [zeroRtt, setZeroRtt] = useState(true);
  const [includePq, setIncludePq] = useState(true);
  const [keypair, setKeypair] = useState<VlessKeypairResponse | null>(null);
  const [keygenBusy, setKeygenBusy] = useState(false);

  // Section-local feedback so errors/confirmations are always visible right next to the editor
  const [importBusy, setImportBusy] = useState(false);
  const [importMsg, setImportMsg] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);
  const [yamlBusy, setYamlBusy] = useState<"audit" | "reload" | null>(null);
  const [yamlMsg, setYamlMsg] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  const loadYamlAndUris = async () => {
    try {
      const data = await clashApi.getRawYaml();
      setYamlText(data.yaml);
      setExportedUris(data.uris);
    } catch {
      // ignore initial load error
    }
  };

  useEffect(() => {
    void loadYamlAndUris();
  }, []);

  const handleCreateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!profileName.trim()) {
      setStatusMsg({ ok: false, text: "Profile name is required." });
      return;
    }
    if (sourceMode === "subscription" && !subUrl.trim()) {
      setStatusMsg({
        ok: false,
        text: "Subscription HTTPS URL is required.",
      });
      return;
    }
    if (sourceMode !== "subscription" && !profilePayload.trim()) {
      setStatusMsg({
        ok: false,
        text:
          sourceMode === "uris"
            ? "Please paste one or more share links (or Base64 subscription payload)."
            : "Please paste a Clash / Mihomo YAML configuration.",
      });
      return;
    }
    setProfileBusyId("create");
    setStatusMsg(null);
    try {
      const spec =
        sourceMode === "subscription"
          ? {
              name: profileName.trim(),
              subscription_url: subUrl.trim(),
              auto_update_interval_secs:
                autoIntervalHours > 0 ? autoIntervalHours * 3600 : undefined,
              activate: true,
            }
          : sourceMode === "uris"
            ? {
                name: profileName.trim(),
                uris: profilePayload.trim(),
                activate: true,
              }
            : {
                name: profileName.trim(),
                yaml: profilePayload,
                activate: true,
              };
      const res = await clashApi.createProfile(spec);
      setProfileName("");
      setSubUrl("");
      setProfilePayload("");
      await loadYamlAndUris();
      await onReloaded();
      const skipped = res["skipped-unsupported"] ?? [];
      const skippedProtos = Array.from(
        new Set(skipped.map((s) => s.protocol)),
      ).join(", ");
      const skippedCount = skipped.length || res.profile.last_skipped_count || 0;
      const skippedSuffix =
        skippedCount > 0
          ? ` [${skippedCount} unsupported skipped${skippedProtos ? `: ${skippedProtos}` : ""}]`
          : "";
      setStatusMsg({
        ok: true,
        text: `Saved & activated encrypted profile '${res.profile.name}' (${res.profile.proxy_count} proxy nodes)${skippedSuffix}.`,
      });
    } catch (err) {
      setStatusMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setProfileBusyId(null);
    }
  };

  const handleActivateProfile = async (p: ProfileMetadata) => {
    setProfileBusyId(p.id);
    setStatusMsg(null);
    try {
      await clashApi.activateProfile(p.id);
      await loadYamlAndUris();
      await onReloaded();
      setStatusMsg({
        ok: true,
        text: `Switched active profile to '${p.name}'.`,
      });
    } catch (err) {
      setStatusMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setProfileBusyId(null);
    }
  };

  const handleRefreshSubscription = async (p: ProfileMetadata) => {
    setProfileBusyId(p.id);
    setStatusMsg(null);
    try {
      const res = await clashApi.refreshProfile(p.id);
      if (res.diff) {
        setLatestDiff(res.diff);
        setDraftAudit(null);
        setDiffSourceLabel(`Subscription Refresh: ${res.profile.name}`);
      }
      await loadYamlAndUris();
      await onReloaded();
      const skipped = res.profile.last_skipped_count ?? 0;
      const gradeSuffix =
        res.audit_grade && res.audit_score != null
          ? ` · Audit Grade ${res.audit_grade} (${res.audit_score}/100)`
          : "";
      setStatusMsg({
        ok: true,
        text: `Updated subscription '${res.profile.name}' (${res.profile.proxy_count} nodes${skipped > 0 ? `, ${skipped} unsupported skipped` : ""})${gradeSuffix}.`,
      });
    } catch (err) {
      setStatusMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setProfileBusyId(null);
    }
  };

  const handleDeleteProfile = async (p: ProfileMetadata) => {
    setProfileBusyId(p.id);
    setStatusMsg(null);
    try {
      await clashApi.deleteProfile(p.id);
      await onReloaded();
      setStatusMsg({
        ok: true,
        text: `Deleted profile '${p.name}'.`,
      });
    } catch (err) {
      setStatusMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setProfileBusyId(null);
    }
  };

  const handleGenerateKeys = async () => {
    if (keygenBusy) return;
    setKeygenBusy(true);
    setStatusMsg(null);
    try {
      const generated = await clashApi.generateVlessKeys({
        mode: pqMode,
        zero_rtt: zeroRtt,
        post_quantum: includePq,
      });
      setKeypair(generated);
    } catch (e) {
      setStatusMsg({
        ok: false,
        text: e instanceof Error ? e.message : String(e),
      });
    } finally {
      setKeygenBusy(false);
    }
  };

  const handleImportUris = async () => {
    if (!uriInput.trim()) {
      setImportMsg({
        ok: false,
        text: "Please paste one or more share URIs, a Base64 bundle, Clash YAML, or an HTTPS subscription URL.",
      });
      return;
    }
    setImportBusy(true);
    setImportMsg(null);
    setStatusMsg(null);
    try {
      const res = await clashApi.importUris(uriInput, true);
      setUriInput("");
      await loadYamlAndUris();
      await onReloaded();
      const dupCount = res["skipped-duplicates"] ?? 0;
      const dupNote =
        dupCount > 0 ? ` (${dupCount} duplicate skipped)` : "";
      const skipped = res["skipped-unsupported"] ?? [];
      const skippedProtos = Array.from(
        new Set(skipped.map((s) => s.protocol)),
      ).join(", ");
      const skippedNote =
        skipped.length > 0
          ? ` [${skipped.length} unsupported skipped: ${skippedProtos}]`
          : "";
      const msg = `Imported and activated ${res.count} proxy node(s) into live router${dupNote}${skippedNote}.`;
      setImportMsg({ ok: true, text: msg });
      setStatusMsg({ ok: true, text: msg });
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e);
      setImportMsg({ ok: false, text });
    } finally {
      setImportBusy(false);
    }
  };

  const handleAuditDraftYaml = async () => {
    if (!yamlText.trim()) {
      setYamlMsg({ ok: false, text: "YAML editor cannot be empty." });
      return;
    }
    setYamlBusy("audit");
    setYamlMsg(null);
    setStatusMsg(null);
    try {
      const res = await clashApi.postConfigAudit(yamlText, true);
      setDraftAudit(res.audit);
      setLatestDiff(res.diff ?? null);
      setDiffSourceLabel("Draft YAML vs Active Engine");
      const text = `Draft YAML audited: Grade ${res.audit.grade} (${res.audit.score}/100) — ${res.audit.findings.length} finding(s).`;
      setYamlMsg({ ok: true, text });
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e);
      setYamlMsg({ ok: false, text });
    } finally {
      setYamlBusy(null);
    }
  };

  const handleCopyMcpSnippet = async () => {
    try {
      await navigator.clipboard?.writeText(MCP_SNIPPET);
      setMcpCopied(true);
      setTimeout(() => setMcpCopied(false), 2000);
    } catch {
      setMcpCopied(false);
    }
  };

  const handleSaveYaml = async () => {
    if (!yamlText.trim()) {
      setYamlMsg({ ok: false, text: "YAML configuration cannot be empty." });
      return;
    }
    setYamlBusy("reload");
    setYamlMsg(null);
    setStatusMsg(null);
    try {
      await clashApi.reloadYaml(yamlText);
      await loadYamlAndUris();
      await onReloaded();
      const text =
        "Validated and hot-reloaded Clash YAML configuration with zero downtime.";
      setYamlMsg({ ok: true, text });
      setStatusMsg({ ok: true, text });
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e);
      setYamlMsg({ ok: false, text });
    } finally {
      setYamlBusy(null);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {statusMsg && (
        <div className={`banner ${statusMsg.ok ? "banner-ok" : "banner-err"}`}>
          <span>{statusMsg.text}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setStatusMsg(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      <section className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">
              Persistent Profiles &amp; TLS 1.3 HTTPS Subscriptions
            </h2>
            <div className="card-subtitle">
              Subscription URLs &amp; secrets encrypted at rest via{" "}
              <code className="mono">
                {profilesSnapshot?.secret_backend ?? "os-vault"}
              </code>{" "}
              with atomic rollback on failed updates
            </div>
          </div>
          <span className="badge badge-emerald">
            {profilesSnapshot?.profiles.length ?? 0} Saved
          </span>
        </div>

        {profilesSnapshot && profilesSnapshot.profiles.length > 0 && (
          <div className="profile-grid" style={{ marginBottom: 16 }}>
            {profilesSnapshot.profiles.map((p) => {
              const isActive = p.id === profilesSnapshot.active_profile_id;
              const used =
                (p.userinfo?.upload_bytes ?? 0) +
                (p.userinfo?.download_bytes ?? 0);
              const total = p.userinfo?.total_bytes ?? 0;
              const pct =
                total > 0
                  ? Math.min(100, Math.round((used / total) * 100))
                  : 0;
              return (
                <div
                  key={p.id}
                  className={`profile-card ${isActive ? "active" : ""}`}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "flex-start",
                      gap: 8,
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 650, fontSize: 13.5 }}>
                        {p.name}
                      </div>
                      <div
                        className="mono"
                        style={{ fontSize: 11, color: "var(--text-muted)" }}
                      >
                        {p.kind} · {p.proxy_count} nodes · {p.rule_count} rules
                      </div>
                    </div>
                    {isActive && (
                      <span className="badge badge-emerald">Active</span>
                    )}
                  </div>

                  {p.subscription_url_redacted && (
                    <div
                      className="mono"
                      style={{
                        fontSize: 11,
                        color: "var(--text-secondary)",
                        wordBreak: "break-all",
                      }}
                    >
                      {p.subscription_url_redacted}
                    </div>
                  )}

                  {p.userinfo && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      <div
                        className="tabular"
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          fontSize: 11,
                          color: "var(--text-secondary)",
                        }}
                      >
                        <span>
                          Used {formatBytes(used)}
                          {total > 0 ? ` / ${formatBytes(total)}` : ""}
                        </span>
                        {p.userinfo.expire_unix_secs && (
                          <span>
                            Exp{" "}
                            {new Date(
                              p.userinfo.expire_unix_secs * 1000,
                            ).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                      {total > 0 && (
                        <div className="progress-track">
                          <div
                            className="progress-fill"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      )}
                    </div>
                  )}

                  {p.last_error && (
                    <div
                      style={{
                        fontSize: 11,
                        color: "var(--accent-rose)",
                      }}
                    >
                      Last update error: {p.last_error}
                    </div>
                  )}

                  <div
                    style={{
                      display: "flex",
                      gap: 6,
                      marginTop: "auto",
                      paddingTop: 4,
                      flexWrap: "wrap",
                    }}
                  >
                    {!isActive && (
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        disabled={profileBusyId === p.id}
                        onClick={() => void handleActivateProfile(p)}
                      >
                        Activate
                      </button>
                    )}
                    {p.kind === "subscription" && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        disabled={profileBusyId === p.id}
                        onClick={() => void handleRefreshSubscription(p)}
                      >
                        {profileBusyId === p.id ? "Refreshing..." : "Refresh"}
                      </button>
                    )}
                    {!isActive && p.kind !== "starter" && (
                      <button
                        type="button"
                        className="btn btn-danger btn-sm"
                        disabled={profileBusyId === p.id}
                        onClick={() => void handleDeleteProfile(p)}
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <form
          onSubmit={handleCreateProfile}
          style={{
            borderTop: "1px solid var(--border-subtle)",
            paddingTop: 14,
            display: "flex",
            flexDirection: "column",
            gap: 10,
          }}
        >
          <div
            style={{
              display: "flex",
              gap: 8,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <div className="segmented">
              <button
                type="button"
                className={`seg-btn ${sourceMode === "subscription" ? "active" : ""}`}
                onClick={() => {
                  setSourceMode("subscription");
                  setStatusMsg(null);
                }}
              >
                HTTPS Subscription
              </button>
              <button
                type="button"
                className={`seg-btn ${sourceMode === "uris" ? "active" : ""}`}
                onClick={() => {
                  setSourceMode("uris");
                  setStatusMsg(null);
                }}
              >
                Share URIs
              </button>
              <button
                type="button"
                className={`seg-btn ${sourceMode === "yaml" ? "active" : ""}`}
                onClick={() => {
                  setSourceMode("yaml");
                  setStatusMsg(null);
                }}
              >
                Local YAML
              </button>
            </div>

            <input
              id="new-profile-name-input"
              className="input"
              style={{ flex: "1 1 180px" }}
              placeholder="Profile name (e.g. Global Edge Sub)"
              value={profileName}
              onChange={(e) => setProfileName(e.target.value)}
            />

            {sourceMode === "subscription" && (
              <select
                className="select"
                value={autoIntervalHours}
                onChange={(e) => setAutoIntervalHours(Number(e.target.value))}
                aria-label="Auto update interval"
              >
                <option value={0}>Manual Refresh Only</option>
                <option value={1}>Auto-Update: Every 1h</option>
                <option value={6}>Auto-Update: Every 6h</option>
                <option value={24}>Auto-Update: Every 24h</option>
              </select>
            )}
          </div>

          {sourceMode === "subscription" ? (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input
                id="new-profile-sub-url-input"
                className="input mono"
                style={{ flex: "1 1 260px" }}
                placeholder="https://provider.example.com/sub?token=... (TLS 1.3 verified, stored in Keystore)"
                value={subUrl}
                onChange={(e) => setSubUrl(e.target.value)}
              />
              <button
                id="create-profile-submit-btn"
                type="submit"
                className="btn btn-primary"
                disabled={profileBusyId === "create"}
              >
                {profileBusyId === "create"
                  ? "Fetching..."
                  : "Fetch & Activate"}
              </button>
            </div>
          ) : (
            <>
              <textarea
                className="code-editor"
                rows={4}
                placeholder={
                  sourceMode === "uris"
                    ? "Paste ss://, vless://, trojan://, anytls://, socks5://, or http-proxy:// links (or Base64 bundle)..."
                    : "Paste full Clash / Mihomo YAML profile..."
                }
                value={profilePayload}
                onChange={(e) => setProfilePayload(e.target.value)}
              />
              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={profileBusyId === "create"}
                >
                  {profileBusyId === "create"
                    ? "Saving..."
                    : "Save & Activate Profile"}
                </button>
              </div>
            </>
          )}
        </form>
      </section>

      <div className="two-col">
        <section className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Post-Quantum VLESS Keypair Studio (
                <code className="mono">mlkem768x25519plus</code>)
              </h2>
              <div className="card-subtitle">
                100% wire-compatible with Xray-core{" "}
                <code className="mono">vlessenc</code> hybrid X25519 + FIPS-203
                ML-KEM-768
              </div>
            </div>
          </div>

          <div
            style={{
              display: "flex",
              gap: 10,
              alignItems: "center",
              flexWrap: "wrap",
              marginBottom: 12,
            }}
          >
            <select
              id="keygen-mode-select"
              className="select"
              value={pqMode}
              onChange={(e) => setPqMode(e.target.value)}
            >
              <option value="native">Mode: native (raw header)</option>
              <option value="xorpub">Mode: xorpub (X25519 pubkey mask)</option>
              <option value="random">
                Mode: random (AES-256-CTR record mask)
              </option>
            </select>

            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontSize: 12.5,
              }}
            >
              <input
                type="checkbox"
                checked={zeroRtt}
                onChange={(e) => setZeroRtt(e.target.checked)}
              />
              0-RTT Ticket Resumption
            </label>

            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontSize: 12.5,
              }}
            >
              <input
                type="checkbox"
                checked={includePq}
                onChange={(e) => setIncludePq(e.target.checked)}
              />
              ML-KEM-768 Hybrid
            </label>

            <button
              id="keygen-generate-btn"
              type="button"
              className="btn btn-primary"
              disabled={keygenBusy}
              onClick={handleGenerateKeys}
            >
              {keygenBusy ? "Generating..." : "Generate PQ Keypair"}
            </button>
          </div>

          {keypair ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <div>
                <div
                  style={{
                    fontSize: 11.5,
                    color: "var(--text-muted)",
                    marginBottom: 3,
                  }}
                >
                  Client <code className="mono">encryption</code> (
                  {keypair.mlkem768_encapsulation_key_bytes} B ML-KEM-768 EK)
                </div>
                <div className="kv-box mono">{keypair.encryption}</div>
              </div>
              <div>
                <div
                  style={{
                    fontSize: 11.5,
                    color: "var(--text-muted)",
                    marginBottom: 3,
                  }}
                >
                  Server <code className="mono">decryption</code> (64 B
                  deterministic seed + X25519 clamped key)
                </div>
                <div className="kv-box mono">{keypair.decryption}</div>
              </div>
              <div>
                <div
                  style={{
                    fontSize: 11.5,
                    color: "var(--text-muted)",
                    marginBottom: 3,
                  }}
                >
                  Ready-to-Paste Clash Node YAML
                </div>
                <pre
                  className="kv-box mono"
                  style={{ margin: 0, whiteSpace: "pre-wrap" }}
                >
                  {keypair.client_yaml_snippet}
                </pre>
              </div>
            </div>
          ) : (
            <div className="kv-box" style={{ color: "var(--text-muted)" }}>
              Click <strong>Generate PQ Keypair</strong> to synthesize fresh
              X25519 + ML-KEM-768 keys via the Rust crypto engine.
            </div>
          )}
        </section>

        <section className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Quick Live Node Importer &amp; URI Exporter
              </h2>
              <div className="card-subtitle">
                Supports <code className="mono">ss://</code> (SIP002/2022),{" "}
                <code className="mono">vless://</code>,{" "}
                <code className="mono">trojan://</code>,{" "}
                <code className="mono">anytls://</code>,{" "}
                <code className="mono">socks5://</code>,{" "}
                <code className="mono">http-proxy://</code>, and Base64 bundles
              </div>
            </div>
          </div>

          {importMsg && (
            <div
              className={`banner ${importMsg.ok ? "banner-ok" : "banner-err"}`}
              style={{ marginBottom: 10 }}
            >
              <span>{importMsg.text}</span>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setImportMsg(null)}
              >
                Dismiss
              </button>
            </div>
          )}

          <textarea
            id="uri-import-textarea"
            className="code-editor"
            rows={4}
            placeholder="Paste ss://, vless://, trojan://, anytls://, socks5://, or http-proxy:// share links (one per line or Base64)..."
            value={uriInput}
            onChange={(e) => {
              setUriInput(e.target.value);
              if (importMsg && !importMsg.ok) setImportMsg(null);
            }}
          />
          <div
            style={{
              marginTop: 8,
              marginBottom: 14,
              display: "flex",
              justifyContent: "flex-end",
            }}
          >
            <button
              id="uri-import-btn"
              type="button"
              className="btn btn-primary"
              disabled={importBusy}
              onClick={handleImportUris}
            >
              {importBusy ? "Importing..." : "Import & Activate Nodes"}
            </button>
          </div>

          <div
            style={{
              fontSize: 11.5,
              color: "var(--text-muted)",
              marginBottom: 4,
            }}
          >
            Active Engine Node Share URIs ({exportedUris.length})
          </div>
          <div
            id="exported-uris-box"
            className="kv-box mono"
            style={{ maxHeight: 150, overflowY: "auto", fontSize: 11.5 }}
          >
            {exportedUris.length === 0 ? (
              <div style={{ color: "var(--text-muted)" }}>
                No shareable proxy nodes in active profile yet — import share
                URIs or a subscription above.
              </div>
            ) : (
              exportedUris.map((u, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: "3px 0",
                    borderBottom: "1px solid var(--border-subtle)",
                  }}
                >
                  {u}
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      {(latestDiff || draftAudit) && (
        <section className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Config Security Diff &amp; Pre-Flight Audit
              </h2>
              <div className="card-subtitle">
                {diffSourceLabel || "Redacted security & topology delta"} (100%
                credential-scrubbed)
              </div>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {latestDiff && (
                <span
                  className={`badge tabular ${
                    latestDiff.score_after >= latestDiff.score_before
                      ? "badge-emerald"
                      : "badge-amber"
                  }`}
                >
                  Grade {latestDiff.grade_before} ({latestDiff.score_before}) →{" "}
                  {latestDiff.grade_after} ({latestDiff.score_after})
                </span>
              )}
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  setLatestDiff(null);
                  setDraftAudit(null);
                }}
              >
                Dismiss
              </button>
            </div>
          </div>

          {latestDiff && (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 10,
                marginBottom: draftAudit ? 12 : 0,
              }}
            >
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <span className="badge badge-emerald tabular">
                  +{latestDiff.added_proxies.length} Added Nodes
                </span>
                <span className="badge badge-neutral tabular">
                  -{latestDiff.removed_proxies.length} Removed Nodes
                </span>
                <span className="badge badge-sky tabular">
                  ~{latestDiff.changed_proxies.length} Changed Nodes
                </span>
                <span className="badge badge-neutral tabular">
                  Rules: {latestDiff.rules_prev_count} →{" "}
                  {latestDiff.rules_next_count} (+{latestDiff.rules_added_count}{" "}
                  / -{latestDiff.rules_removed_count})
                </span>
              </div>

              {latestDiff.newly_insecure_nodes.length > 0 && (
                <div className="banner banner-err">
                  <span>
                    <strong>MITM / Downgrade Warning:</strong> Subscription or
                    draft introduced insecure TLS (
                    <code className="mono">skip-cert-verify: true</code> or
                    plaintext transport) on:{" "}
                    <code className="mono">
                      {latestDiff.newly_insecure_nodes.join(", ")}
                    </code>
                  </span>
                </div>
              )}

              {latestDiff.dns_changed && latestDiff.dns_changes.length > 0 && (
                <div className="kv-box" style={{ fontSize: 12 }}>
                  <strong>DNS Changes:</strong>{" "}
                  {latestDiff.dns_changes.join(" · ")}
                </div>
              )}

              {latestDiff.changed_proxies.length > 0 && (
                <div className="kv-box" style={{ fontSize: 12 }}>
                  <strong>Modified Nodes:</strong>{" "}
                  {latestDiff.changed_proxies
                    .map((c) => `${c.name} [${c.changes.join(", ")}]`)
                    .join("; ")}
                </div>
              )}
            </div>
          )}

          {draftAudit && draftAudit.findings.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {draftAudit.findings.slice(0, 6).map((f, i) => (
                <div
                  key={`${f.code}-${i}`}
                  className="kv-box"
                  style={{ fontSize: 12 }}
                >
                  <strong className="mono">[{f.code}]</strong> ({f.location}) —{" "}
                  {renderInlineCode(f.title)} ·{" "}
                  <span style={{ color: "var(--accent-emerald)" }}>
                    Fix: {renderInlineCode(f.remediation)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      <section className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">
              Live Clash Meta (Mihomo) YAML Configuration
            </h2>
            <div className="card-subtitle">
              Credentials &amp; UUIDs are redacted (
              <code className="mono">***REDACTED***</code> / nil UUID) for API
              safety and preserved automatically on hot-reload
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              className="btn btn-sm"
              disabled={yamlBusy !== null}
              onClick={() => {
                setYamlMsg(null);
                void loadYamlAndUris();
              }}
            >
              Reset from Engine
            </button>
            <button
              id="yaml-audit-diff-btn"
              type="button"
              className="btn btn-sm"
              disabled={yamlBusy !== null}
              onClick={() => void handleAuditDraftYaml()}
            >
              {yamlBusy === "audit" ? "Auditing..." : "Audit & Diff Draft"}
            </button>
            <button
              id="yaml-reload-btn"
              type="button"
              className="btn btn-primary"
              disabled={yamlBusy !== null}
              onClick={handleSaveYaml}
            >
              {yamlBusy === "reload"
                ? "Validating..."
                : "Validate & Hot-Reload YAML"}
            </button>
          </div>
        </div>

        {yamlMsg && (
          <div
            id="yaml-editor-status-banner"
            className={`banner ${yamlMsg.ok ? "banner-ok" : "banner-err"}`}
            style={{ marginBottom: 12 }}
          >
            <span>{renderInlineCode(yamlMsg.text)}</span>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setYamlMsg(null)}
            >
              Dismiss
            </button>
          </div>
        )}

        <textarea
          id="yaml-editor-textarea"
          className="code-editor"
          rows={18}
          value={yamlText}
          onChange={(e) => {
            setYamlText(e.target.value);
            if (yamlMsg && !yamlMsg.ok) setYamlMsg(null);
          }}
        />
      </section>

      <section className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">
              AI-Native Credential-Redacted MCP Server (
              <code className="mono">rust-clash mcp</code>)
            </h2>
            <div className="card-subtitle">
              Let Claude Code, Gemini CLI, or Cursor diagnose routing rules,
              Split-DNS risks, TLS/WAF <code className="mono">403</code> vs{" "}
              <code className="mono">429</code> status, and UDP readiness over
              JSON-RPC 2.0 <code className="mono">stdio</code> — credentials
              &amp; server endpoints redacted by default (
              <code className="mono">--include-network-metadata</code> /{" "}
              <code className="mono">--allow-mutations</code> opt-in)
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className="badge badge-emerald">
              Read-Only &amp; Metadata-Private Default
            </span>
            <button
              id="copy-mcp-snippet-btn"
              type="button"
              className="btn btn-sm"
              onClick={() => void handleCopyMcpSnippet()}
            >
              {mcpCopied ? "Copied!" : "Copy mcpServers JSON"}
            </button>
          </div>
        </div>

        <div
          style={{
            display: "flex",
            gap: 8,
            flexWrap: "wrap",
            marginBottom: 10,
          }}
        >
          <span className="badge badge-sky mono">
            audit_config_security (config_path)
          </span>
          <span className="badge badge-sky mono">explain_route</span>
          <span className="badge badge-sky mono">probe_waterfall</span>
          <span className="badge badge-sky mono">probe_ai_matrix</span>
          <span className="badge badge-sky mono">get_proxy_status</span>
          <span className="badge badge-neutral mono">
            switch_proxy_selector (--allow-mutations)
          </span>
        </div>

        <pre
          className="kv-box mono"
          style={{ margin: 0, fontSize: 12, overflowX: "auto" }}
        >
          {MCP_SNIPPET}
        </pre>
      </section>
    </div>
  );
};
