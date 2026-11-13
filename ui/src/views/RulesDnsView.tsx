import React, { useCallback, useEffect, useMemo, useState } from "react";
import { clashApi } from "../api";
import { RefreshIcon, SearchIcon } from "../components/Icons";
import { useI18n } from "../i18n";
import type {
  DnsQueryResponse,
  FakeIpPoolResponse,
  GeoDataStatus,
  RuleExplainResponse,
  RuleItem,
} from "../types";

interface RulesDnsViewProps {
  rules: RuleItem[];
  onRefreshRules: () => Promise<void>;
}

export const RulesDnsView: React.FC<RulesDnsViewProps> = ({
  rules,
  onRefreshRules,
}) => {
  const { tr } = useI18n();

  // Route simulator (`Explain Host/IP`)
  const [explainTarget, setExplainTarget] = useState("www.google.com:443");
  const [explainRes, setExplainRes] = useState<RuleExplainResponse | null>(
    null,
  );
  const [explainBusy, setExplainBusy] = useState(false);

  // DNS resolver & Fake-IP cache
  const [dnsDomain, setDnsDomain] = useState("github.com");
  const [dnsType, setDnsType] = useState<"A" | "AAAA">("A");
  const [dnsResult, setDnsResult] = useState<DnsQueryResponse | null>(null);
  const [fakePool, setFakePool] = useState<FakeIpPoolResponse | null>(null);
  const [dnsBusy, setDnsBusy] = useState(false);
  const [flushBusy, setFlushBusy] = useState(false);

  // GeoIP / GeoSite status
  const [geoStatus, setGeoStatus] = useState<GeoDataStatus | null>(null);
  const [geoUpdating, setGeoUpdating] = useState(false);

  // Rules search & Custom rules editor
  const [ruleSearch, setRuleSearch] = useState("");
  const [customEditorOpen, setCustomEditorOpen] = useState(false);
  const [customRulesText, setCustomRulesText] = useState("");
  const [savingCustom, setSavingCustom] = useState(false);

  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);

  const loadAux = useCallback(async () => {
    const [gRes, fRes] = await Promise.allSettled([
      clashApi.getGeoDataStatus(),
      clashApi.getFakeIpPool(),
    ]);
    if (gRes.status === "fulfilled") setGeoStatus(gRes.value);
    if (fRes.status === "fulfilled") setFakePool(fRes.value);
  }, []);

  useEffect(() => {
    void loadAux();
  }, [loadAux]);

  const handleExplain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!explainTarget.trim() || explainBusy) return;
    setExplainBusy(true);
    setToast(null);
    try {
      const res = await clashApi.explainRule(explainTarget.trim());
      setExplainRes(res);
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setExplainBusy(false);
    }
  };

  const handleDnsLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!dnsDomain.trim() || dnsBusy) return;
    setDnsBusy(true);
    setToast(null);
    try {
      const res = await clashApi.queryDns(dnsDomain.trim(), dnsType);
      setDnsResult(res);
      const pool = await clashApi.getFakeIpPool();
      setFakePool(pool);
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setDnsBusy(false);
    }
  };

  const handleFlushDns = async () => {
    setFlushBusy(true);
    setToast(null);
    try {
      const res = await clashApi.flushDnsCache();
      const pool = await clashApi.getFakeIpPool();
      setFakePool(pool);
      setToast({
        ok: true,
        text: tr(
          `已清空 DNS 缓存（剩余 ${res.cached_records} 条记录）`,
          `Flushed DNS cache (${res.cached_records} cached records remaining)`,
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setFlushBusy(false);
    }
  };

  const handleUpdateGeo = async () => {
    setGeoUpdating(true);
    setToast(null);
    try {
      const next = await clashApi.updateGeoData();
      setGeoStatus(next);
      await onRefreshRules();
      setToast({
        ok: true,
        text: tr(
          `GeoIP / GeoSite 更新完成（${next.geosite_cn_entries} 条国内域名，${next.geoip_cn_ranges} 段国内 IP）`,
          `Updated GeoIP / GeoSite (${next.geosite_cn_entries} CN domains, ${next.geoip_cn_ranges} CN CIDRs)`,
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setGeoUpdating(false);
    }
  };

  const handleOpenCustomEditor = async () => {
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
      setToast({
        ok: false,
        text: tr(
          "请至少输入一条有效分流规则（如 MATCH,PROXY）",
          "Please enter at least one valid rule (e.g. MATCH,PROXY)",
        ),
      });
      return;
    }
    setSavingCustom(true);
    setToast(null);
    try {
      await clashApi.saveCustomRules(lines);
      setCustomEditorOpen(false);
      await onRefreshRules();
      setToast({
        ok: true,
        text: tr(
          `已保存并启用 ${lines.length} 条自定义分流规则`,
          `Saved and activated ${lines.length} custom rules`,
        ),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setSavingCustom(false);
    }
  };

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

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
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

      <div className="bento-grid">
        {/* Route Simulator Card */}
        <section className="bento-card col-6" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 650 }}>
              {tr("分流规则模拟测试", "Routing Rule Simulator")}
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              {tr(
                "输入任意域名或 IP:端口，查看会命中哪条规则并走哪个节点",
                "Enter any domain or IP:port to inspect the matched rule and outbound chain",
              )}
            </div>
          </div>

          <form
            onSubmit={handleExplain}
            style={{ display: "flex", gap: 8, flexWrap: "wrap" }}
          >
            <input
              className="input"
              style={{ flex: "1 1 200px" }}
              placeholder="www.google.com:443"
              value={explainTarget}
              onChange={(e) => setExplainTarget(e.target.value)}
            />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={explainBusy}
            >
              {explainBusy
                ? tr("匹配中...", "Matching...")
                : tr("测试匹配", "Explain")}
            </button>
          </form>

          {explainRes && (
            <div
              className="sub-pill-box"
              style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12.5 }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
                <span>
                  <span style={{ color: "var(--text-muted)" }}>
                    {tr("命中规则：", "Rule: ")}
                  </span>
                  <strong>
                    {explainRes.rule_type}
                    {explainRes.rule_payload ? `, ${explainRes.rule_payload}` : ""}
                  </strong>
                </span>
                <span className="badge badge-sky">{explainRes.outbound}</span>
              </div>
              <div style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                {tr("出站链路：", "Chain: ")}
                {explainRes.chains.length > 0
                  ? explainRes.chains.slice().reverse().join(" → ")
                  : explainRes.outbound}
              </div>
            </div>
          )}
        </section>

        {/* DNS Resolver + Fake-IP Cache Card */}
        <section className="bento-card col-6" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 8,
            }}
          >
            <div>
              <div style={{ fontSize: 15, fontWeight: 650 }}>
                {tr("DNS 解析测试与 Fake-IP 缓存", "DNS Tester & Fake-IP Cache")}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {tr(
                  `当前 Fake-IP 池：${fakePool?.count ?? 0} 条映射`,
                  `Active Fake-IP pool: ${fakePool?.count ?? 0} bindings`,
                )}
              </div>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              disabled={flushBusy}
              onClick={() => void handleFlushDns()}
            >
              {flushBusy
                ? tr("清空中...", "Flushing...")
                : tr("清空 DNS 缓存", "Flush DNS")}
            </button>
          </div>

          <form
            onSubmit={handleDnsLookup}
            style={{ display: "flex", gap: 8, flexWrap: "wrap" }}
          >
            <input
              className="input"
              style={{ flex: "1 1 170px" }}
              placeholder="github.com"
              value={dnsDomain}
              onChange={(e) => setDnsDomain(e.target.value)}
            />
            <select
              className="select"
              value={dnsType}
              onChange={(e) => setDnsType(e.target.value as "A" | "AAAA")}
            >
              <option value="A">A (IPv4)</option>
              <option value="AAAA">AAAA (IPv6)</option>
            </select>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={dnsBusy}
            >
              {dnsBusy
                ? tr("解析中...", "Resolving...")
                : tr("解析", "Query")}
            </button>
          </form>

          {dnsResult && (
            <div
              className="sub-pill-box"
              style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12 }}
            >
              {dnsResult.Answer.length === 0 ? (
                <span style={{ color: "var(--text-muted)" }}>
                  {tr("无应答记录", "No DNS records returned")}
                </span>
              ) : (
                dnsResult.Answer.map((ans, idx) => (
                  <div
                    key={`${ans.data}-${idx}`}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 8,
                    }}
                  >
                    <span className="tabular" style={{ fontWeight: 600 }}>
                      {ans.data}
                    </span>
                    <span
                      className={`badge ${
                        ans.is_fake_ip ? "badge-sky" : "badge-emerald"
                      }`}
                    >
                      {ans.is_fake_ip ? "Fake-IP" : ans.type}
                    </span>
                  </div>
                ))
              )}
            </div>
          )}
        </section>

        {/* GeoIP / GeoSite Status Card */}
        <section className="bento-card col-12">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              flexWrap: "wrap",
            }}
          >
            <div>
              <div style={{ fontSize: 15, fontWeight: 650 }}>
                {tr("GeoIP 与 GeoSite 分流数据库", "GeoIP & GeoSite Databases")}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                {geoStatus
                  ? tr(
                      `数据来源：${geoStatus.source_label} · 国内域名 ${geoStatus.geosite_cn_entries.toLocaleString()} 条 · 国内 IP 段 ${geoStatus.geoip_cn_ranges.toLocaleString()} 个`,
                      `Source: ${geoStatus.source_label} · ${geoStatus.geosite_cn_entries.toLocaleString()} CN domains · ${geoStatus.geoip_cn_ranges.toLocaleString()} CN CIDRs`,
                    )
                  : tr("内置离线国内外分流数据库已就绪", "Built-in GeoIP / GeoSite datasets ready")}
              </div>
            </div>

            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() =>
                  customEditorOpen
                    ? setCustomEditorOpen(false)
                    : void handleOpenCustomEditor()
                }
              >
                {customEditorOpen
                  ? tr("收起规则编辑", "Hide Custom Rules")
                  : tr("编辑自定义规则", "Edit Custom Rules")}
              </button>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                disabled={geoUpdating}
                onClick={() => void handleUpdateGeo()}
              >
                <RefreshIcon size={13} spinning={geoUpdating} />
                <span>
                  {geoUpdating
                    ? tr("更新中...", "Updating...")
                    : tr("更新数据库", "Update GeoData")}
                </span>
              </button>
            </div>
          </div>

          {customEditorOpen && (
            <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 8 }}>
              <textarea
                className="code-editor mono"
                rows={7}
                placeholder="DOMAIN-SUFFIX,openai.com,PROXY&#10;GEOSITE,cn,DIRECT&#10;MATCH,PROXY"
                value={customRulesText}
                onChange={(e) => setCustomRulesText(e.target.value)}
              />
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => setCustomEditorOpen(false)}
                >
                  {tr("取消", "Cancel")}
                </button>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={savingCustom}
                  onClick={() => void handleSaveCustomRules()}
                >
                  {savingCustom
                    ? tr("保存中...", "Saving...")
                    : tr("保存自定义规则", "Save Custom Rules")}
                </button>
              </div>
            </div>
          )}
        </section>
      </div>

      {/* Active Rules Table */}
      <section className="bento-card" style={{ padding: "14px 18px" }}>
        <div className="toolbar" style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 15, fontWeight: 650 }}>
            {tr("当前生效分流规则", "Active Routing Rules")}{" "}
            <span className="badge badge-neutral tabular">
              {filteredRules.length.toLocaleString()}
            </span>
          </div>

          <div style={{ position: "relative", width: 260, maxWidth: "100%" }}>
            <span
              style={{
                position: "absolute",
                left: 11,
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--text-muted)",
                display: "inline-flex",
              }}
            >
              <SearchIcon size={14} />
            </span>
            <input
              className="input"
              style={{ width: "100%", paddingLeft: 32 }}
              placeholder={tr("搜索规则内容或目标组...", "Search rules...")}
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
            />
          </div>
        </div>

        <div style={{ maxHeight: 360, overflowY: "auto" }}>
          <table className="bento-table">
            <thead>
              <tr>
                <th>{tr("类型", "Type")}</th>
                <th>{tr("匹配内容", "Payload")}</th>
                <th>{tr("目标策略", "Target")}</th>
                <th style={{ textAlign: "right" }}>{tr("命中次数", "Hits")}</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.slice(0, 300).map((r, idx) => (
                <tr key={`${r.type}-${r.payload}-${idx}`}>
                  <td>
                    <span className="badge badge-neutral">{r.type}</span>
                  </td>
                  <td style={{ fontWeight: 550 }}>{r.payload || "*"}</td>
                  <td>
                    <span className="badge badge-sky">{r.proxy}</span>
                  </td>
                  <td
                    className="tabular"
                    style={{ textAlign: "right", color: "var(--text-muted)" }}
                  >
                    {r.hits.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
