import React, { useState } from "react";
import { clashApi } from "../api";
import { ThroughputChart } from "../components/ThroughputChart";
import type {
  BenchmarkResponse,
  ConfigSnapshot,
  ConnectionsResponse,
  ProfilesSnapshot,
  TrafficPoint,
  VersionInfo,
} from "../types";
import { formatBytes, formatSpeed } from "../utils/format";

interface OverviewViewProps {
  version: VersionInfo | null;
  config: ConfigSnapshot | null;
  profilesSnapshot: ProfilesSnapshot | null;
  connections: ConnectionsResponse | null;
  trafficHistory: TrafficPoint[];
  latestTraffic: TrafficPoint;
  onRefreshAll: () => Promise<void>;
  onOpenProfiles: () => void;
  onOpenAddNode: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  version,
  config,
  profilesSnapshot,
  connections,
  trafficHistory,
  latestTraffic,
  onRefreshAll,
  onOpenProfiles,
  onOpenAddNode,
}) => {
  const [benchLoading, setBenchLoading] = useState(false);
  const [benchResult, setBenchResult] = useState<BenchmarkResponse | null>(
    null,
  );
  const [benchError, setBenchError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [streams, setStreams] = useState(4);

  const runAction = async (key: string, fn: () => Promise<void>) => {
    setBusyKey(key);
    setActionError(null);
    setActionSuccess(null);
    try {
      await fn();
      await onRefreshAll();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
      await onRefreshAll();
    } finally {
      setBusyKey(null);
    }
  };

  const handleToggleTun = () => {
    if (!config) return;
    void runAction("tun", async () => {
      await clashApi.patchConfigs({ tun: { enable: !config.tun.enable } });
    });
  };

  const handleToggleTunStrictRoute = () => {
    if (!config) return;
    void runAction("strict-route", async () => {
      await clashApi.patchConfigs({
        tun: { "strict-route": !config.tun["strict-route"] },
      });
    });
  };

  const handleToggleTunIpv6 = () => {
    if (!config) return;
    void runAction("tun-ipv6", async () => {
      await clashApi.patchConfigs({
        tun: { ipv6: !config.tun.ipv6 },
      });
    });
  };

  const handleToggleSysProxy = () => {
    const enabled = Boolean(config?.sysproxy?.enabled);
    void runAction("sysproxy", async () => {
      await clashApi.patchSysProxy(!enabled);
    });
  };

  const handleToggleAutostart = () => {
    const enabled = Boolean(config?.autostart?.enabled);
    void runAction("autostart", async () => {
      await clashApi.patchAutostart(!enabled);
    });
  };

  const handleToggleDemo = (enable: boolean) => {
    void runAction("demo", async () => {
      await clashApi.toggleDemoSandbox(enable);
      setActionSuccess(
        enable
          ? "Activated local Multi-Protocol Demo Sandbox cluster."
          : "Exited Demo Sandbox and restored Real User Mode profile.",
      );
    });
  };

  const handleExportDiagnostics = async () => {
    setBusyKey("diag");
    setActionError(null);
    try {
      const payload = await clashApi.exportDiagnostics();
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
      setActionSuccess(
        "Exported redacted diagnostic bundle (all passwords, UUIDs, secrets, and subscription URLs scrubbed).",
      );
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusyKey(null);
    }
  };

  const handleRunBenchmark = async () => {
    setBenchLoading(true);
    setBenchError(null);
    try {
      const res = await clashApi.runBenchmark(streams, 524_288);
      setBenchResult(res);
      await onRefreshAll();
    } catch (e) {
      setBenchError(e instanceof Error ? e.message : String(e));
    } finally {
      setBenchLoading(false);
    }
  };

  const totalDown = connections?.downloadTotal ?? latestTraffic.total_down;
  const totalUp = connections?.uploadTotal ?? latestTraffic.total_up;
  const activeCount = connections?.connections.length ?? 0;
  const rssBytes = connections?.memory ?? 0;
  const tunHealth = config?.tun.health;
  const tunModeLabel = config?.tun.enable
    ? "OS TUN ON"
    : config?.tun["virtual-enable"]
      ? "VIRTUAL"
      : "OFF";
  const effectiveOutbound =
    config?.["effective-outbound"]?.effective_outbound ?? "DIRECT";
  const effectiveProto =
    config?.["effective-outbound"]?.effective_protocol ?? "DIRECT";

  const showOnboarding =
    Boolean(profilesSnapshot) &&
    !profilesSnapshot?.onboarding_completed &&
    !config?.demo.enabled;

  return (
    <>
      {actionError && (
        <div className="banner banner-err">
          <span>{actionError}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setActionError(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {actionSuccess && (
        <div className="banner banner-ok">
          <span>{actionSuccess}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setActionSuccess(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {showOnboarding && (
        <section className="onboarding-card">
          <div style={{ maxWidth: 680 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                marginBottom: 4,
                flexWrap: "wrap",
              }}
            >
              <span className="badge badge-emerald">Real User Mode</span>
              <span className="badge badge-sky">
                Vault: {profilesSnapshot?.secret_backend}
              </span>
              <span className="badge badge-amber">
                Outbound: {effectiveOutbound} ({effectiveProto})
              </span>
            </div>
            <div style={{ fontSize: 14.5, fontWeight: 700, marginBottom: 3 }}>
              Welcome to RustClash — Paste a Share Link to Connect Immediately
            </div>
            <div style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
              Copy any `ss://`, `vless://`, or `anytls://` link and click{" "}
              <strong>+ Add Node</strong>, or import an HTTPS subscription /
              Clash YAML profile. Nodes and selections persist across restarts.
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              id="onboarding-add-node-btn"
              type="button"
              className="btn btn-primary"
              onClick={onOpenAddNode}
            >
              + Add Node / 添加节点
            </button>
            <button
              id="onboarding-import-btn"
              type="button"
              className="btn"
              onClick={onOpenProfiles}
            >
              Subscriptions &amp; Profiles
            </button>
            <button
              id="onboarding-demo-btn"
              type="button"
              className="btn"
              disabled={busyKey === "demo"}
              onClick={() => handleToggleDemo(true)}
            >
              Try Demo Sandbox
            </button>
          </div>
        </section>
      )}

      {config?.demo.enabled && (
        <div className="banner banner-ok">
          <span>
            <strong>Demo Sandbox Active:</strong> Running local loopback
            SS-2022, VLESS (`mlkem768x25519plus`), and AnyTLS v2 servers for
            safe offline testing.
          </span>
          <button
            id="exit-demo-btn"
            type="button"
            className="btn btn-sm"
            disabled={busyKey === "demo"}
            onClick={() => handleToggleDemo(false)}
          >
            Exit to Real User Mode
          </button>
        </div>
      )}

      <section className="kpi-strip">
        <div className="card">
          <div className="kpi-label">Live Throughput</div>
          <div
            className="kpi-value"
            style={{ color: "var(--accent-emerald)" }}
          >
            ↓ {formatSpeed(latestTraffic.down)}
          </div>
          <div className="kpi-foot tabular">
            <span style={{ color: "var(--accent-sky)" }}>
              ↑ {formatSpeed(latestTraffic.up)}
            </span>
            <span>1 Hz stream</span>
          </div>
        </div>

        <div className="card">
          <div className="kpi-label">Cumulative Session Data</div>
          <div className="kpi-value">{formatBytes(totalDown + totalUp)}</div>
          <div className="kpi-foot tabular">
            <span>DL {formatBytes(totalDown)}</span>
            <span>UL {formatBytes(totalUp)}</span>
          </div>
        </div>

        <div className="card">
          <div className="kpi-label">Active Streams &amp; Fake-IP</div>
          <div className="kpi-value">{activeCount}</div>
          <div className="kpi-foot tabular">
            <span>Fake-IP: {config?.dns["fake-ip-entries"] ?? 0}</span>
            <span>{config?.dns["fake-ip-range"] ?? "198.18.0.0/15"}</span>
          </div>
        </div>

        <div className="card">
          <div className="kpi-label">Process RSS &amp; Listeners</div>
          <div className="kpi-value">
            {rssBytes > 0 ? formatBytes(rssBytes) : "Pure Rust"}
          </div>
          <div className="kpi-foot tabular">
            <span>Mixed :{config?.["mixed-port"] ?? 7890}</span>
            <span>
              TUN:{" "}
              <strong
                style={{
                  color: config?.tun.enable
                    ? "var(--accent-emerald)"
                    : config?.tun["virtual-enable"]
                      ? "var(--accent-sky)"
                      : "var(--text-muted)",
                }}
              >
                {tunModeLabel}
              </strong>
            </span>
          </div>
        </div>
      </section>

      <section className="two-col">
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Real-Time Encrypted Tunnel Throughput
              </h2>
              <div className="card-subtitle">
                60-second rolling telemetry window across Mixed Inbound &amp;
                event-driven smoltcp TUN
              </div>
            </div>
            <button
              id="toggle-tun-btn"
              type="button"
              className={`btn btn-sm ${config?.tun.enable ? "btn-danger" : "btn-primary"}`}
              disabled={busyKey === "tun"}
              onClick={handleToggleTun}
            >
              {config?.tun.enable ? "Disable OS TUN" : "Enable OS TUN"}
            </button>
          </div>
          <ThroughputChart points={trafficHistory} />

          {config?.demo.enabled && (
            <div
              style={{
                marginTop: 14,
                paddingTop: 12,
                borderTop: "1px solid var(--border-subtle)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
              <div>
                <div style={{ fontSize: 12.5, fontWeight: 600 }}>
                  Live Loopback Stress Benchmark
                </div>
                <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                  Pushes real SOCKS5 + Fake-IP (`198.18.0.x`) traffic through
                  the active proxy group
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <select
                  id="bench-streams-select"
                  className="select"
                  value={streams}
                  onChange={(e) => setStreams(Number(e.target.value))}
                  aria-label="Concurrent benchmark streams"
                >
                  <option value={2}>2 Streams (1 MB)</option>
                  <option value={4}>4 Streams (2 MB)</option>
                  <option value={8}>8 Streams (4 MB)</option>
                </select>
                <button
                  id="run-benchmark-btn"
                  type="button"
                  className="btn btn-primary"
                  disabled={benchLoading}
                  onClick={handleRunBenchmark}
                >
                  {benchLoading ? "Running..." : "Run Live Benchmark"}
                </button>
              </div>
            </div>
          )}

          {benchResult && (
            <div
              className="banner banner-ok tabular"
              style={{ marginTop: 10 }}
            >
              <span>
                Transferred{" "}
                <strong>{formatBytes(benchResult.total_bytes)}</strong> across{" "}
                <strong>{benchResult.streams}</strong> streams via{" "}
                <code className="mono">
                  {benchResult.active_proxy_group_selection ??
                    "Active Outbound"}
                </code>{" "}
                in <strong>{benchResult.elapsed_ms.toFixed(1)} ms</strong>
              </span>
              <strong>{benchResult.throughput_mbps.toFixed(1)} Mbps</strong>
            </div>
          )}

          {benchError && (
            <div className="banner banner-err" style={{ marginTop: 10 }}>
              <span>{benchError}</span>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                OS Network Integration &amp; TUN Health
              </h2>
              <div className="card-subtitle">
                {tunHealth?.backend ?? "cross-platform"} · Protector:{" "}
                <code className="mono">
                  {tunHealth?.socket_protector ?? "auto"}
                </code>
              </div>
            </div>
            <button
              id="export-diagnostics-btn"
              type="button"
              className="btn btn-sm"
              disabled={busyKey === "diag"}
              onClick={() => void handleExportDiagnostics()}
            >
              Export Diagnostics
            </button>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div className="switch-row">
              <div>
                <div style={{ fontSize: 12.5, fontWeight: 600 }}>
                  OS System Proxy (HTTP + SOCKS5)
                </div>
                <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                  {config?.sysproxy?.enabled
                    ? `Active → ${config.sysproxy.host}:${config.sysproxy.port} (${config.sysproxy.backend})`
                    : `Points OS apps to 127.0.0.1:${config?.["mixed-port"] ?? 7890} (${config?.sysproxy?.backend ?? "native"})`}
                </div>
              </div>
              <button
                id="toggle-sysproxy-btn"
                type="button"
                className={`btn btn-sm ${config?.sysproxy?.enabled ? "btn-primary" : ""}`}
                disabled={
                  busyKey === "sysproxy" || config?.sysproxy?.supported === false
                }
                onClick={handleToggleSysProxy}
              >
                {config?.sysproxy?.enabled ? "Enabled" : "Enable"}
              </button>
            </div>

            <div className="switch-row">
              <div>
                <div style={{ fontSize: 12.5, fontWeight: 600 }}>
                  Start at Login (Non-Admin)
                </div>
                <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                  Mechanism:{" "}
                  <code className="mono">
                    {config?.autostart?.mechanism ?? "os-autostart"}
                  </code>
                </div>
              </div>
              <button
                id="toggle-autostart-btn"
                type="button"
                className={`btn btn-sm ${config?.autostart?.enabled ? "btn-primary" : ""}`}
                disabled={
                  busyKey === "autostart" ||
                  config?.autostart?.supported === false
                }
                onClick={handleToggleAutostart}
              >
                {config?.autostart?.enabled ? "Enabled" : "Enable"}
              </button>
            </div>

            <div className="switch-row">
              <div>
                <div style={{ fontSize: 12.5, fontWeight: 600 }}>
                  TUN Options (`strict-route` &amp; `IPv6`)
                </div>
                <div
                  className="tabular"
                  style={{ fontSize: 11.5, color: "var(--text-muted)" }}
                >
                  RX {tunHealth?.rx_packets ?? 0} pkts · TX{" "}
                  {tunHealth?.tx_packets ?? 0} pkts · Egress:{" "}
                  {tunHealth?.default_egress_iface ?? "auto"}
                </div>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  type="button"
                  className={`btn btn-sm ${config?.tun["strict-route"] ? "btn-primary" : ""}`}
                  disabled={busyKey === "strict-route"}
                  onClick={handleToggleTunStrictRoute}
                >
                  Strict
                </button>
                <button
                  type="button"
                  className={`btn btn-sm ${config?.tun.ipv6 ? "btn-primary" : ""}`}
                  disabled={busyKey === "tun-ipv6"}
                  onClick={handleToggleTunIpv6}
                >
                  IPv6
                </button>
              </div>
            </div>

            {tunHealth && !tunHealth.privilege_ok && tunHealth.privilege_hint && (
              <div
                className="kv-box"
                style={{ fontSize: 11.5, color: "var(--text-secondary)" }}
              >
                <strong>TUN Privilege / Driver Hint:</strong>{" "}
                {tunHealth.privilege_hint}
              </div>
            )}

            {!config?.demo.enabled && (
              <div className="switch-row">
                <div>
                  <div style={{ fontSize: 12.5, fontWeight: 600 }}>
                    Multi-Protocol Demo Sandbox
                  </div>
                  <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                    Temporarily spin up local SS-2022, VLESS+PQ &amp; AnyTLS v2
                    servers
                  </div>
                </div>
                <button
                  id="launch-demo-btn"
                  type="button"
                  className="btn btn-sm"
                  disabled={busyKey === "demo"}
                  onClick={() => handleToggleDemo(true)}
                >
                  Launch Sandbox
                </button>
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Protocol &amp; Crypto Stack</h2>
            <div className="card-subtitle">
              {version?.version ?? "rust-clash"} — Zero C/Go proxy dependencies
              (`aws-lc-rs` + `rustls` + `smoltcp`)
            </div>
          </div>
          <span className="badge badge-emerald">Pure Rust</span>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))",
            gap: 10,
          }}
        >
          <div className="proto-row">
            <div>
              <div className="proto-title">VLESS + PQ Encryption</div>
              <div className="proto-desc">
                Xray `mlkem768x25519plus` (`native`/`xorpub`/`random`, 0/1-RTT)
              </div>
            </div>
            <span className="badge badge-emerald">ML-KEM-768</span>
          </div>

          <div className="proto-row">
            <div>
              <div className="proto-title">AnyTLS v2 Multiplexing</div>
              <div className="proto-desc">
                SHA-256 + `padding0`, dynamic MD5 `PaddingScheme`, LIFO pool
              </div>
            </div>
            <span className="badge badge-sky">TLS 1.3 Mux</span>
          </div>

          <div className="proto-row">
            <div>
              <div className="proto-title">Shadowsocks 2022 &amp; AEAD</div>
              <div className="proto-desc">
                SIP022 BLAKE3-AES256/ChaCha20 TCP+UDP + 60s replay filter
              </div>
            </div>
            <span className="badge badge-amber">SIP022</span>
          </div>

          <div className="proto-row">
            <div>
              <div className="proto-title">DoH / DoT + Fake-IP TUN</div>
              <div className="proto-desc">
                `198.18.0.0/15` LRU domain restoration + `198.19.255.254:53`
              </div>
            </div>
            <span className="badge badge-neutral">L3/L4 Stack</span>
          </div>
        </div>
      </section>
    </>
  );
};
