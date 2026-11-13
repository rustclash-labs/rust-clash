import React, { useCallback, useEffect, useMemo, useState } from "react";
import { clashApi } from "../api";
import type {
  ConfigAuditReport,
  DnsQueryResponse,
  FakeIpPoolResponse,
  GeoDataStatus,
  RoutingPresetChoice,
  RoutingPresetSnapshot,
  RuleExplainResponse,
  RuleItem,
} from "../types";
import { renderInlineCode } from "../utils/inlineCode";

interface RulesDnsViewProps {
  rules: RuleItem[];
  onRefreshRules: () => Promise<void>;
}

const PRESET_META: Array<{
  id: RoutingPresetChoice;
  label: string;
  desc: string;
}> = [
  {
    id: "smart-cn",
    label: "Smart-CN 分流",
    desc: "Private LAN & mainland CN domains/IPs go DIRECT; global traffic uses primary proxy group.",
  },
  {
    id: "global",
    label: "Global Proxy",
    desc: "Route all TCP/UDP traffic through the GLOBAL / primary proxy selector.",
  },
  {
    id: "direct",
    label: "Global Direct",
    desc: "Bypass all proxy nodes and connect directly to destination endpoints.",
  },
  {
    id: "custom",
    label: "Custom Rules",
    desc: "Evaluate your custom Mihomo/Clash rule list with automatic backup & restore.",
  },
];

export const RulesDnsView: React.FC<RulesDnsViewProps> = ({
  rules,
  onRefreshRules,
}) => {
  const [ruleSearch, setRuleSearch] = useState("");
  const [explainTarget, setExplainTarget] = useState("api.github.com:443");
  const [explainSrcIp, setExplainSrcIp] = useState("");
  const [explainRes, setExplainRes] = useState<RuleExplainResponse | null>(
    null,
  );
  const [explainErr, setExplainErr] = useState<string | null>(null);
  const [explainBusy, setExplainBusy] = useState(false);

  // Config Firewall & Rule Clippy Audit state
  const [auditReport, setAuditReport] = useState<ConfigAuditReport | null>(
    null,
  );
  const [auditBusy, setAuditBusy] = useState(false);
  const [auditErr, setAuditErr] = useState<string | null>(null);

  // Routing preset & custom rules state
  const [presetSnap, setPresetSnap] = useState<RoutingPresetSnapshot | null>(
    null,
  );
  const [customEditorOpen, setCustomEditorOpen] = useState(false);
  const [customRulesText, setCustomRulesText] = useState("");
  const [customRulesError, setCustomRulesError] = useState<string | null>(null);
  const [routingBusy, setRoutingBusy] = useState(false);
  const [routingMsg, setRoutingMsg] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  // GeoData state
  const [geoStatus, setGeoStatus] = useState<GeoDataStatus | null>(null);
  const [geoUpdating, setGeoUpdating] = useState(false);

  // DNS & Fake-IP state
  const [dnsDomain, setDnsDomain] = useState("api.anthropic.com");
  const [dnsType, setDnsType] = useState<"A" | "AAAA">("A");
  const [dnsResult, setDnsResult] = useState<DnsQueryResponse | null>(null);
  const [fakePool, setFakePool] = useState<FakeIpPoolResponse | null>(null);
  const [dnsError, setDnsError] = useState<string | null>(null);
  const [flushNotice, setFlushNotice] = useState<string | null>(null);
  const [dnsBusy, setDnsBusy] = useState(false);
  const [flushBusy, setFlushBusy] = useState(false);

  const runAudit = useCallback(async (resolveDns = false) => {
    setAuditBusy(true);
    setAuditErr(null);
    try {
      const rep = await clashApi.getConfigAudit(resolveDns);
      setAuditReport(rep);
    } catch (err) {
      setAuditErr(err instanceof Error ? err.message : String(err));
    } finally {
      setAuditBusy(false);
    }
  }, []);

  const loadAuxSnapshots = useCallback(async () => {
    try {
      const [p, g, f, a] = await Promise.allSettled([
        clashApi.getRoutingPreset(),
        clashApi.getGeoDataStatus(),
        clashApi.getFakeIpPool(),
        clashApi.getConfigAudit(),
      ]);
      if (p.status === "fulfilled") setPresetSnap(p.value);
      if (g.status === "fulfilled") setGeoStatus(g.value);
      if (f.status === "fulfilled") setFakePool(f.value);
      if (a.status === "fulfilled") setAuditReport(a.value);
    } catch {
      // ignore initial error
    }
  }, []);

  useEffect(() => {
    void loadAuxSnapshots();
  }, [loadAuxSnapshots]);

  const filteredRules = useMemo(() => {
    const q = ruleSearch.trim().toLowerCase();
    if (!q) return rules;
    return rules.filter(
      (r) =>
        r.type.toLowerCase().includes(q) ||
        r.payload.toLowerCase().includes(q) ||
        r.proxy.toLowerCase().includes(q),
    );
  }, [rules, ruleSearch]);

  const handleSelectPreset = async (choice: RoutingPresetChoice) => {
    setRoutingBusy(true);
    setRoutingMsg(null);
    try {
      const snap = await clashApi.setRoutingPreset(choice);
      setPresetSnap(snap);
      await onRefreshRules();
      await runAudit();
      setRoutingMsg({
        ok: true,
        text: `Applied routing preset '${snap.active_choice}' (${snap.rule_count} active rules).`,
      });
    } catch (err) {
      setRoutingMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setRoutingBusy(false);
    }
  };

  const handleOpenCustomRulesEditor = async () => {
    setRoutingMsg(null);
    setCustomRulesError(null);
    try {
      const res = await clashApi.getCustomRules();
      setCustomRulesText(res.rules.join("\n"));
    } catch {
      setCustomRulesText(
        rules
          .map((r) =>
            r.type.toUpperCase() === "MATCH"
              ? `MATCH,${r.proxy}`
              : `${r.type.toUpperCase()},${r.payload},${r.proxy}`,
          )
          .join("\n"),
      );
    }
    setCustomEditorOpen(true);
  };

  const handleSaveCustomRules = async () => {
    const lines = customRulesText
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));
    if (lines.length === 0) {
      setCustomRulesError(
        "Please enter at least one non-comment routing rule (for example: MATCH,PROXY).",
      );
      return;
    }
    setRoutingBusy(true);
    setRoutingMsg(null);
    setCustomRulesError(null);
    try {
      const snap = await clashApi.saveCustomRules(lines);
      setPresetSnap(snap);
      setCustomEditorOpen(false);
      await onRefreshRules();
      await runAudit();
      setRoutingMsg({
        ok: true,
        text: `Saved & activated ${lines.length} custom rule(s) under 'custom' preset.`,
      });
    } catch (err) {
      const text = err instanceof Error ? err.message : String(err);
      setCustomRulesError(text);
    } finally {
      setRoutingBusy(false);
    }
  };

  const handleUpdateGeoData = async () => {
    setGeoUpdating(true);
    setRoutingMsg(null);
    try {
      const updated = await clashApi.updateGeoData();
      setGeoStatus(updated);
      await onRefreshRules();
      await runAudit();
      setRoutingMsg({
        ok: true,
        text: `Updated GeoSite/GeoIP datasets (${updated.geosite_cn_entries} CN domains, ${updated.geoip_cn_ranges} CN CIDRs) from ${updated.source_label}.`,
      });
    } catch (err) {
      setRoutingMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setGeoUpdating(false);
    }
  };

  const handleExplainRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!explainTarget.trim() || explainBusy) return;
    setExplainBusy(true);
    setExplainErr(null);
    try {
      const res = await clashApi.explainRule(
        explainTarget.trim(),
        explainSrcIp.trim() || undefined,
      );
      setExplainRes(res);
    } catch (err) {
      setExplainErr(err instanceof Error ? err.message : String(err));
    } finally {
      setExplainBusy(false);
    }
  };

  const handleDnsLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!dnsDomain.trim() || dnsBusy) return;
    setDnsBusy(true);
    setDnsError(null);
    setFlushNotice(null);
    try {
      const res = await clashApi.queryDns(dnsDomain.trim(), dnsType);
      setDnsResult(res);
      const p = await clashApi.getFakeIpPool();
      setFakePool(p);
    } catch (err) {
      setDnsError(err instanceof Error ? err.message : String(err));
    } finally {
      setDnsBusy(false);
    }
  };

  const handleFlushDns = async () => {
    if (flushBusy) return;
    setFlushBusy(true);
    setDnsError(null);
    try {
      const res = await clashApi.flushDnsCache();
      const p = await clashApi.getFakeIpPool();
      setFakePool(p);
      setFlushNotice(
        `Flushed positive & negative DNS caches (${res.cached_records} cached records remaining; active Fake-IP bindings preserved).`,
      );
    } catch (err) {
      setDnsError(err instanceof Error ? err.message : String(err));
    } finally {
      setFlushBusy(false);
    }
  };

  const gradeBadgeVariant = (grade?: string) => {
    if (!grade) return "badge-neutral";
    if (grade === "A") return "badge-emerald";
    if (grade === "B") return "badge-sky";
    if (grade === "C") return "badge-amber";
    return "badge-rose";
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Static Config Audit, Rule Clippy & Split-DNS Route Simulator */}
      <section className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">
              Static Config Audit, Rule Clippy &amp; Route Simulator
            </h2>
            <div className="card-subtitle">
              Static linter for MITM{" "}
              <code className="mono">skip-cert-verify</code> risks, rule
              shadowing / dead rules after <code className="mono">MATCH</code>,
              and pre-route <code className="mono">no-resolve</code> DNS
              behavior (DoH/DoT vs plaintext <code className="mono">:53</code>)
            </div>
          </div>
          <div
            style={{
              display: "flex",
              gap: 8,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            {auditReport && (
              <>
                <span
                  id="config-audit-grade-badge"
                  className={`badge tabular ${gradeBadgeVariant(auditReport.grade)}`}
                  style={{ fontSize: 12.5, padding: "4px 10px" }}
                >
                  Grade {auditReport.grade} · {auditReport.score}/100
                </span>
                {auditReport.simulation_basis && (
                  <span className="badge badge-neutral mono">
                    {auditReport.simulation_basis}
                  </span>
                )}
                {auditReport.counts.high > 0 && (
                  <span className="badge badge-rose tabular">
                    {auditReport.counts.high} HIGH
                  </span>
                )}
                {auditReport.counts.medium > 0 && (
                  <span className="badge badge-amber tabular">
                    {auditReport.counts.medium} MEDIUM
                  </span>
                )}
                {auditReport.counts.low > 0 && (
                  <span className="badge badge-sky tabular">
                    {auditReport.counts.low} LOW
                  </span>
                )}
              </>
            )}
            <button
              id="rerun-config-audit-btn"
              type="button"
              className="btn btn-sm"
              disabled={auditBusy}
              onClick={() => void runAudit(false)}
            >
              {auditBusy ? "Auditing..." : "Re-run Audit"}
            </button>
            <button
              id="verify-live-dns-audit-btn"
              type="button"
              className="btn btn-sm"
              disabled={auditBusy}
              onClick={() => void runAudit(true)}
              title="Resolve simulation domains via the configured DNS engine to evaluate IP-CIDR and GEOIP rules"
            >
              Verify with Live DNS
            </button>
          </div>
        </div>

        {auditErr && (
          <div className="banner banner-err" style={{ marginBottom: 12 }}>
            <span>{auditErr}</span>
          </div>
        )}

        {auditReport && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {auditReport.findings.length === 0 ? (
              <div className="banner banner-ok">
                <span>
                  <strong>No static config issues detected:</strong> All
                  configured nodes verify TLS certificates, no rules are
                  statically shadowed or unreachable after{" "}
                  <code className="mono">MATCH</code>, and IP/GeoIP rules
                  include <code className="mono">no-resolve</code>.
                </span>
              </div>
            ) : (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 8,
                  maxHeight: 240,
                  overflowY: "auto",
                }}
              >
                {auditReport.findings.map((f, idx) => (
                  <div
                    key={`${f.code}-${f.location}-${idx}`}
                    className="kv-box"
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 4,
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: 8,
                        flexWrap: "wrap",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          flexWrap: "wrap",
                        }}
                      >
                        <span
                          className={`badge ${
                            f.severity === "high"
                              ? "badge-rose"
                              : f.severity === "medium"
                                ? "badge-amber"
                                : f.severity === "low"
                                  ? "badge-sky"
                                  : "badge-neutral"
                          }`}
                        >
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="mono" style={{ fontSize: 11.5 }}>
                          {f.code}
                        </span>
                        <strong style={{ fontSize: 12.5 }}>
                          {renderInlineCode(f.title)}
                        </strong>
                      </div>
                      <span
                        className="badge badge-neutral mono"
                        style={{ fontSize: 11 }}
                      >
                        {f.location}
                      </span>
                    </div>
                    <div
                      style={{ fontSize: 12, color: "var(--text-secondary)" }}
                    >
                      {renderInlineCode(f.detail)}
                    </div>
                    <div
                      style={{
                        fontSize: 11.5,
                        color: "var(--accent-emerald)",
                      }}
                    >
                      <strong>Fix:</strong> {renderInlineCode(f.remediation)}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div>
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: "var(--text-secondary)",
                  marginBottom: 6,
                }}
              >
                Split-Tunnel &amp; DNS Route Simulation (
                {auditReport.simulation_basis ?? "live_router_selection"} —
                click any row to inspect in Route Debugger)
              </div>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Scenario</th>
                      <th>Target</th>
                      <th>Matched Rule</th>
                      <th>Effective Exit</th>
                      <th>DNS Strategy</th>
                      <th>Risk Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditReport.leak_matrix.map((row) => (
                      <tr
                        key={row.target}
                        style={{ cursor: "pointer" }}
                        title={row.note}
                        onClick={() => setExplainTarget(row.target)}
                      >
                        <td style={{ fontWeight: 600 }}>{row.label}</td>
                        <td className="mono" style={{ fontSize: 11.5 }}>
                          {row.target}
                        </td>
                        <td className="mono" style={{ fontSize: 11.5 }}>
                          {row.matched_rule}
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              row.exit_type === "REJECT"
                                ? "badge-rose"
                                : row.exit_type === "DIRECT"
                                  ? "badge-neutral"
                                  : "badge-emerald"
                            }`}
                          >
                            {row.effective_outbound}
                          </span>
                        </td>
                        <td style={{ fontSize: 11.5 }}>
                          {renderInlineCode(row.dns_strategy)}
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              row.risk_level === "ok" ||
                              row.risk_level === "pass"
                                ? "badge-emerald"
                                : row.risk_level === "warning" ||
                                    row.risk_level === "warn"
                                  ? "badge-amber"
                                  : "badge-rose"
                            }`}
                          >
                            {row.risk_level.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </section>

      {routingMsg && (
        <div
          className={`banner ${routingMsg.ok ? "banner-ok" : "banner-err"}`}
        >
          <span>{renderInlineCode(routingMsg.text)}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setRoutingMsg(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Routing Presets, Custom Rules & GeoData Updater */}
      <div className="two-col">
        <section className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Routing Presets &amp; Custom Rule Manager
              </h2>
              <div className="card-subtitle">
                Switch between Smart-CN split tunneling, Global, Direct, or
                validated Custom Rules
              </div>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() =>
                customEditorOpen
                  ? setCustomEditorOpen(false)
                  : void handleOpenCustomRulesEditor()
              }
            >
              {customEditorOpen ? "Hide Editor" : "Edit Custom Rules"}
            </button>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: 8,
            }}
          >
            {PRESET_META.map((item) => {
              const active = presetSnap?.active_choice === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  disabled={routingBusy}
                  onClick={() => void handleSelectPreset(item.id)}
                  className={`node-tile ${active ? "selected" : ""}`}
                  style={{ textAlign: "left", cursor: "pointer" }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 6,
                    }}
                  >
                    <span style={{ fontWeight: 650, fontSize: 13 }}>
                      {item.label}
                    </span>
                    {active && (
                      <span className="badge badge-emerald">Active</span>
                    )}
                  </div>
                  <div
                    style={{
                      fontSize: 11.5,
                      color: "var(--text-muted)",
                      marginTop: 4,
                      lineHeight: 1.4,
                    }}
                  >
                    {item.desc}
                  </div>
                </button>
              );
            })}
          </div>

          {customEditorOpen && (
            <div style={{ marginTop: 12 }}>
              <div
                style={{
                  fontSize: 11.5,
                  color: "var(--text-secondary)",
                  marginBottom: 6,
                }}
              >
                One rule per line (e.g.{" "}
                <code className="mono">DOMAIN-SUFFIX,openai.com,PROXY</code>,{" "}
                <code className="mono">GEOSITE,cn,DIRECT</code>,{" "}
                <code className="mono">IP-CIDR,10.0.0.0/8,DIRECT,no-resolve</code>
                , <code className="mono">MATCH,PROXY</code>):
              </div>
              {customRulesError && (
                <div className="banner banner-err" style={{ marginBottom: 8 }}>
                  <span>{renderInlineCode(customRulesError)}</span>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => setCustomRulesError(null)}
                  >
                    Dismiss
                  </button>
                </div>
              )}
              <textarea
                id="custom-rules-textarea"
                className="code-editor"
                rows={7}
                value={customRulesText}
                onChange={(e) => {
                  setCustomRulesText(e.target.value);
                  if (customRulesError) setCustomRulesError(null);
                }}
              />
              <div
                style={{
                  marginTop: 8,
                  display: "flex",
                  justifyContent: "flex-end",
                  gap: 8,
                }}
              >
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={routingBusy}
                  onClick={() => {
                    setCustomRulesError(null);
                    setCustomEditorOpen(false);
                  }}
                >
                  Cancel
                </button>
                <button
                  id="save-custom-rules-btn"
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={routingBusy}
                  onClick={() => void handleSaveCustomRules()}
                >
                  {routingBusy ? "Saving..." : "Validate & Save Custom Rules"}
                </button>
              </div>
            </div>
          )}
        </section>

        <section className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">GeoSite &amp; GeoIP Rule Datasets</h2>
              <div className="card-subtitle">
                Hot-swappable CN / Non-CN domain trie &amp; sorted IP-CIDR
                binary-search overlays
              </div>
            </div>
            <button
              id="geodata-update-btn"
              type="button"
              className="btn btn-primary btn-sm"
              disabled={geoUpdating}
              onClick={() => void handleUpdateGeoData()}
            >
              {geoUpdating ? "Updating..." : "Update GeoData"}
            </button>
          </div>

          <div className="kv-box mono" style={{ lineHeight: 1.7 }}>
            <div>
              <strong>Source:</strong>{" "}
              {geoStatus?.source_label || "Built-in Embedded Baseline"}
            </div>
            <div>
              <strong>GeoSite CN / !CN:</strong>{" "}
              <span className="tabular">
                {geoStatus?.geosite_cn_entries ?? 0} /{" "}
                {geoStatus?.geosite_non_cn_entries ?? 0} rules
              </span>
            </div>
            <div>
              <strong>GeoIP CN Ranges:</strong>{" "}
              <span className="tabular">
                {geoStatus?.geoip_cn_ranges ?? 0} CIDRs
              </span>{" "}
              {geoStatus?.mmdb_present && (
                <span className="badge badge-emerald">MMDB Active</span>
              )}
            </div>
            <div>
              <strong>Last Updated:</strong>{" "}
              {geoStatus && geoStatus.last_updated_ms > 0
                ? new Date(geoStatus.last_updated_ms).toLocaleString()
                : "Using embedded offline dataset"}
              {geoStatus?.is_expired && (
                <span
                  className="badge badge-amber"
                  style={{ marginLeft: 8 }}
                >
                  Stale (&gt;7d)
                </span>
              )}
            </div>
            {geoStatus?.last_error && (
              <div style={{ color: "var(--accent-rose)" }}>
                <strong>Last Error:</strong> {geoStatus.last_error}
              </div>
            )}
          </div>
        </section>
      </div>

      <section className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">
              Interactive Rule Match &amp; Outbound Chain Explainer
            </h2>
            <div className="card-subtitle">
              Trace any domain, <code className="mono">host:port</code>, IP
              CIDR, or Fake-IP (<code className="mono">198.18.x.x</code>)
              through FastRuleIndex, GeoIP/GeoSite, and policy groups
            </div>
          </div>
          <span className="badge badge-emerald">
            O(1) Trie + O(log N) CIDR
          </span>
        </div>

        <form
          onSubmit={handleExplainRule}
          style={{
            display: "flex",
            gap: 8,
            flexWrap: "wrap",
            marginBottom: explainRes || explainErr ? 12 : 0,
          }}
        >
          <input
            id="rule-explain-target-input"
            className="input mono"
            style={{ flex: "2 1 220px" }}
            value={explainTarget}
            onChange={(e) => setExplainTarget(e.target.value)}
            placeholder="Target domain, IP, or host:port (e.g. 198.18.0.2:443)"
          />
          <input
            id="rule-explain-src-input"
            className="input mono"
            style={{ flex: "1 1 150px" }}
            value={explainSrcIp}
            onChange={(e) => setExplainSrcIp(e.target.value)}
            placeholder="Optional SRC-IP (e.g. 192.168.1.10)"
          />
          <button
            id="rule-explain-submit"
            type="submit"
            className="btn btn-primary"
            disabled={explainBusy}
          >
            {explainBusy ? "Tracing..." : "Explain Route"}
          </button>
        </form>

        {explainErr && (
          <div className="banner banner-err">
            <span>{explainErr}</span>
          </div>
        )}

        {explainRes && (
          <div className="kv-box mono" style={{ lineHeight: 1.65 }}>
            <div>
              <strong>Target:</strong> {explainRes.normalized_target}
              {explainRes.restored_from_fake_ip && (
                <span style={{ color: "var(--accent-sky)" }}>
                  {" "}
                  (restored from Fake-IP {explainRes.restored_from_fake_ip})
                </span>
              )}
            </div>
            <div>
              <strong>Matched Rule:</strong>{" "}
              <span className="badge badge-neutral">
                {explainRes.rule_type}
              </span>{" "}
              {explainRes.rule_payload || "*"} (mode: {explainRes.mode})
            </div>
            <div>
              <strong>Resolved Chain:</strong>{" "}
              <span style={{ color: "var(--accent-emerald)" }}>
                {explainRes.chains.join(" → ")}
              </span>{" "}
              → <strong>{explainRes.outbound}</strong> ({explainRes.protocol})
            </div>
          </div>
        )}
      </section>

      <div className="two-col">
        <section className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Mihomo Routing Rules &amp; Hit Telemetry
              </h2>
              <div className="card-subtitle">
                Evaluated after automatic Fake-IP (
                <code className="mono">198.18.0.0/15</code>) domain restoration
              </div>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => void onRefreshRules()}
            >
              Refresh Hits
            </button>
          </div>

          <div style={{ marginBottom: 12 }}>
            <input
              id="rule-search-input"
              className="input"
              style={{ width: "100%" }}
              placeholder="Search DOMAIN-SUFFIX, GEOSITE, RULE-SET, GEOIP, IP-CIDR, PROCESS-NAME..."
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
            />
          </div>

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Type</th>
                  <th>Payload</th>
                  <th>Target Policy</th>
                  <th>Hits</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.length === 0 ? (
                  <tr>
                    <td
                      colSpan={5}
                      style={{
                        textAlign: "center",
                        padding: 18,
                        color: "var(--text-muted)",
                      }}
                    >
                      {ruleSearch.trim() ? (
                        <div
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 10,
                            flexWrap: "wrap",
                          }}
                        >
                          <span>
                            No routing rules match &ldquo;{ruleSearch.trim()}
                            &rdquo;.
                          </span>
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={() => setRuleSearch("")}
                          >
                            Clear Filter
                          </button>
                        </div>
                      ) : (
                        "No routing rules configured."
                      )}
                    </td>
                  </tr>
                ) : (
                  filteredRules.map((r, idx) => (
                    <tr key={`${r.type}-${r.payload}-${idx}`}>
                      <td
                        className="tabular"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {idx + 1}
                      </td>
                      <td>
                        <span className="badge badge-neutral mono">
                          {r.type}
                        </span>
                      </td>
                      <td className="mono">{r.payload || "*"}</td>
                      <td>
                        <span
                          className={`badge ${
                            r.proxy === "REJECT"
                              ? "badge-rose"
                              : r.proxy === "DIRECT"
                                ? "badge-neutral"
                                : "badge-emerald"
                          }`}
                        >
                          {r.proxy}
                        </span>
                      </td>
                      <td className="tabular" style={{ fontWeight: 600 }}>
                        {r.hits}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Fake-IP DNS Probe &amp; Cache Control
              </h2>
              <div className="card-subtitle">
                CIDR {fakePool?.cidr ?? "198.18.0.0/15"} · Mode{" "}
                {fakePool?.enhanced_mode ?? "fake-ip"} · Cached:{" "}
                {fakePool?.cached_records ?? 0}
              </div>
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <span className="badge badge-sky tabular">
                {fakePool?.count ?? 0} Fake-IPs
              </span>
              <button
                id="dns-flush-btn"
                type="button"
                className="btn btn-sm"
                disabled={flushBusy}
                onClick={() => void handleFlushDns()}
              >
                {flushBusy ? "Flushing..." : "Flush DNS"}
              </button>
            </div>
          </div>

          <form
            onSubmit={handleDnsLookup}
            style={{
              display: "flex",
              gap: 8,
              marginBottom: 12,
              flexWrap: "wrap",
            }}
          >
            <input
              id="dns-query-input"
              className="input mono"
              style={{ flex: "1 1 160px" }}
              value={dnsDomain}
              onChange={(e) => setDnsDomain(e.target.value)}
              placeholder="Domain to resolve (e.g. api.github.com)"
            />
            <select
              id="dns-qtype-select"
              className="select"
              value={dnsType}
              onChange={(e) => setDnsType(e.target.value as "A" | "AAAA")}
            >
              <option value="A">A (IPv4)</option>
              <option value="AAAA">AAAA (IPv6)</option>
            </select>
            <button
              id="dns-query-submit"
              type="submit"
              className="btn btn-primary"
              disabled={dnsBusy}
            >
              {dnsBusy ? "Resolving..." : "Resolve"}
            </button>
          </form>

          {flushNotice && (
            <div className="banner banner-ok" style={{ marginBottom: 12 }}>
              <span>{flushNotice}</span>
            </div>
          )}

          {dnsError && (
            <div className="banner banner-err" style={{ marginBottom: 12 }}>
              <span>{dnsError}</span>
            </div>
          )}

          {dnsResult && (
            <div className="kv-box" style={{ marginBottom: 14 }}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: 6,
                }}
              >
                <strong className="mono">
                  {dnsResult.Question.name} ({dnsResult.Question.type})
                </strong>
                <span
                  className={`badge ${
                    dnsResult.bypass_fake_ip ? "badge-amber" : "badge-emerald"
                  }`}
                >
                  {dnsResult.bypass_fake_ip
                    ? "Filter Bypassed"
                    : "Fake-IP Assigned"}
                </span>
              </div>
              {dnsResult.Answer.length === 0 ? (
                <div style={{ color: "var(--text-muted)" }}>
                  Empty NOERROR response (Happy-Eyeballs IPv4 Fake-IP
                  preference)
                </div>
              ) : (
                dnsResult.Answer.map((ans, i) => (
                  <div key={i} className="mono tabular">
                    {ans.type} → <strong>{ans.data}</strong>{" "}
                    {ans.restored_domain
                      ? `(Reverse restores: ${ans.restored_domain})`
                      : ""}
                  </div>
                ))
              )}
            </div>
          )}

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Fake-IPv4</th>
                  <th>Original Domain (LRU Cache)</th>
                </tr>
              </thead>
              <tbody>
                {!fakePool || fakePool.entries.length === 0 ? (
                  <tr>
                    <td
                      colSpan={2}
                      style={{
                        textAlign: "center",
                        color: "var(--text-muted)",
                        padding: 18,
                      }}
                    >
                      Click Resolve above to allocate a deterministic{" "}
                      <code className="mono">198.18.x.x</code> Fake-IP.
                    </td>
                  </tr>
                ) : (
                  fakePool.entries.map((entry) => (
                    <tr key={entry.ip}>
                      <td
                        className="mono tabular"
                        style={{ color: "var(--accent-sky)" }}
                      >
                        {entry.ip}
                      </td>
                      <td className="mono">{entry.domain}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
};
