import React, { useCallback, useEffect, useMemo, useState } from "react";
import { clashApi } from "../api";
import type { ConnectionItem } from "../types";
import { formatAge, formatBytes } from "../utils/format";

interface ConnectionsViewProps {
  items: ConnectionItem[];
  onRefresh: () => Promise<void>;
}

type ViewMode = "active" | "diagnostics";
type DiagFilter = "ALL" | "PROXY" | "DIRECT" | "FAILED";

export const ConnectionsView: React.FC<ConnectionsViewProps> = ({
  items,
  onRefresh,
}) => {
  const [viewMode, setViewMode] = useState<ViewMode>("active");
  const [query, setQuery] = useState("");
  const [inboundFilter, setInboundFilter] = useState("ALL");
  const [diagFilter, setDiagFilter] = useState<DiagFilter>("ALL");
  const [diagnostics, setDiagnostics] = useState<ConnectionItem[]>([]);

  const loadDiagnostics = useCallback(async () => {
    try {
      const res = await clashApi.getConnectionDiagnostics(150);
      setDiagnostics(res.diagnostics);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    if (viewMode !== "diagnostics") return;
    void loadDiagnostics();
    const timer = window.setInterval(() => {
      if (!document.hidden) {
        void loadDiagnostics();
      }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [viewMode, loadDiagnostics]);

  const filteredActive = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter((c) => {
      if (inboundFilter !== "ALL" && !c.metadata.type.includes(inboundFilter)) {
        return false;
      }
      if (!q) return true;
      const hay = [
        c.metadata.host,
        c.metadata.source,
        c.metadata.type,
        c.metadata.fake_ip ?? "",
        c.rule,
        c.rule_payload,
        c.chains.join(" "),
        c.effective_outbound ?? "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [items, query, inboundFilter]);

  const filteredDiagnostics = useMemo(() => {
    const q = query.trim().toLowerCase();
    return diagnostics.filter((d) => {
      if (diagFilter === "DIRECT" && d.exit_type !== "DIRECT") return false;
      if (diagFilter === "PROXY" && d.exit_type !== "PROXY") return false;
      if (
        diagFilter === "FAILED" &&
        d.status !== "failed" &&
        d.exit_type !== "ERROR" &&
        !d.error
      ) {
        return false;
      }
      if (!q) return true;
      const hay = [
        d.metadata.host,
        d.metadata.destination_ip ?? "",
        d.metadata.fake_ip ?? "",
        d.rule,
        d.rule_payload,
        d.effective_outbound ?? "",
        d.effective_protocol ?? "",
        d.remote_endpoint ?? "",
        d.error ?? "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [diagnostics, diagFilter, query]);

  const handleCloseOne = async (id: string) => {
    await clashApi.closeConnection(id);
    await onRefresh();
  };

  const handleCloseAll = async () => {
    await clashApi.closeAllConnections();
    await onRefresh();
  };

  const handleClearDiagnostics = async () => {
    await clashApi.clearConnectionDiagnostics();
    await loadDiagnostics();
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div className="toolbar">
        <div
          style={{
            display: "flex",
            gap: 10,
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          <div className="segmented">
            <button
              type="button"
              className={`seg-btn ${viewMode === "active" ? "active" : ""}`}
              onClick={() => setViewMode("active")}
            >
              Active Streams ({items.length})
            </button>
            <button
              type="button"
              className={`seg-btn ${viewMode === "diagnostics" ? "active" : ""}`}
              onClick={() => setViewMode("diagnostics")}
            >
              Route Diagnostics
            </button>
          </div>

          <input
            id="conn-search-input"
            className="input"
            style={{ width: 260 }}
            placeholder="Filter host, Fake-IP, rule, outbound..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />

          {viewMode === "active" ? (
            <>
              <select
                id="conn-inbound-filter"
                className="select"
                value={inboundFilter}
                onChange={(e) => setInboundFilter(e.target.value)}
              >
                <option value="ALL">All Inbounds</option>
                <option value="SOCKS5">SOCKS5</option>
                <option value="HTTP">HTTP / CONNECT</option>
                <option value="TUN">TUN (smoltcp)</option>
              </select>
              <span className="badge badge-neutral tabular">
                Showing {filteredActive.length} / {items.length} active
              </span>
            </>
          ) : (
            <div className="segmented">
              {(["ALL", "PROXY", "DIRECT", "FAILED"] as DiagFilter[]).map(
                (f) => (
                  <button
                    key={f}
                    type="button"
                    className={`seg-btn ${diagFilter === f ? "active" : ""}`}
                    onClick={() => setDiagFilter(f)}
                  >
                    {f}
                  </button>
                ),
              )}
            </div>
          )}
        </div>

        {viewMode === "active" ? (
          <button
            id="close-all-conns-btn"
            type="button"
            className="btn btn-danger"
            disabled={items.length === 0}
            onClick={() => void handleCloseAll()}
          >
            Close All ({items.length})
          </button>
        ) : (
          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => void loadDiagnostics()}
            >
              Refresh
            </button>
            <button
              type="button"
              className="btn btn-danger btn-sm"
              disabled={diagnostics.length === 0}
              onClick={() => void handleClearDiagnostics()}
            >
              Clear Ring Buffer
            </button>
          </div>
        )}
      </div>

      {viewMode === "active" ? (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Inbound</th>
                <th>Target Host &amp; Fake-IP Restoration</th>
                <th>Matched Rule</th>
                <th>Outbound Chain</th>
                <th>Download</th>
                <th>Upload</th>
                <th>Age</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredActive.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    style={{
                      textAlign: "center",
                      padding: "28px 12px",
                      color: "var(--text-muted)",
                    }}
                  >
                    No active connections right now. Run the Live Benchmark on
                    Overview or send traffic to Mixed Inbound.
                  </td>
                </tr>
              ) : (
                filteredActive.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <span className="badge badge-neutral mono">
                        {c.metadata.type}
                      </span>
                    </td>
                    <td>
                      <div className="mono" style={{ fontWeight: 600 }}>
                        {(c.metadata.host || c.metadata.destination_ip) ?? "*"}:
                        {c.metadata.destination_port}
                      </div>
                      {c.metadata.fake_ip && (
                        <div style={{ marginTop: 3 }}>
                          <span className="badge badge-sky mono">
                            Fake-IP {c.metadata.fake_ip} → {c.metadata.host}
                          </span>
                        </div>
                      )}
                    </td>
                    <td>
                      <span className="badge badge-amber">{c.rule}</span>
                      {c.rule_payload && (
                        <span
                          className="mono"
                          style={{
                            marginLeft: 6,
                            fontSize: 11.5,
                            color: "var(--text-secondary)",
                          }}
                        >
                          {c.rule_payload}
                        </span>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {c.chains.join(" ← ")}
                    </td>
                    <td className="tabular">{formatBytes(c.download)}</td>
                    <td className="tabular">{formatBytes(c.upload)}</td>
                    <td
                      className="tabular"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {formatAge(c.start_epoch_ms)}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-sm btn-danger"
                        onClick={() => void handleCloseOne(c.id)}
                      >
                        Close
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Target &amp; Fake-IP</th>
                <th>Rule Match</th>
                <th>Exit &amp; Protocol</th>
                <th>Traffic</th>
                <th>Remote / Error</th>
              </tr>
            </thead>
            <tbody>
              {filteredDiagnostics.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    style={{
                      textAlign: "center",
                      padding: "28px 12px",
                      color: "var(--text-muted)",
                    }}
                  >
                    No diagnostic records match the current filter.
                  </td>
                </tr>
              ) : (
                filteredDiagnostics.map((d) => {
                  const statusBadge =
                    d.status === "failed" || d.error
                      ? "badge-rose"
                      : d.status === "active"
                        ? "badge-emerald"
                        : "badge-neutral";
                  const exitBadge =
                    d.exit_type === "PROXY"
                      ? "badge-emerald"
                      : d.exit_type === "REJECT" || d.exit_type === "ERROR"
                        ? "badge-rose"
                        : "badge-neutral";
                  return (
                    <tr key={`${d.id}-${d.start_epoch_ms}`}>
                      <td>
                        <span className={`badge ${statusBadge} mono`}>
                          {d.status ?? "closed"}
                        </span>
                      </td>
                      <td>
                        <div className="mono" style={{ fontWeight: 600 }}>
                          {d.metadata.host || d.metadata.destination_ip || "*"}:
                          {d.metadata.destination_port} (
                          {d.metadata.network.toUpperCase()})
                        </div>
                        {d.metadata.fake_ip && (
                          <span className="badge badge-sky mono">
                            Fake-IP {d.metadata.fake_ip}
                          </span>
                        )}
                      </td>
                      <td>
                        <span className="badge badge-amber">{d.rule}</span>{" "}
                        <span
                          className="mono"
                          style={{
                            fontSize: 11.5,
                            color: "var(--text-secondary)",
                          }}
                        >
                          {d.rule_payload || "*"}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${exitBadge}`}>
                          {d.exit_type || "DIRECT"}
                        </span>{" "}
                        <span className="mono" style={{ fontSize: 12 }}>
                          {d.effective_outbound || d.chains[0] || "DIRECT"}
                          {d.effective_protocol
                            ? ` (${d.effective_protocol})`
                            : ""}
                        </span>
                      </td>
                      <td className="tabular">
                        ↓ {formatBytes(d.download)} · ↑ {formatBytes(d.upload)}
                      </td>
                      <td
                        className="mono"
                        style={{
                          fontSize: 11.5,
                          color: d.error
                            ? "var(--accent-rose)"
                            : "var(--text-muted)",
                          maxWidth: 280,
                          wordBreak: "break-word",
                        }}
                      >
                        {d.error ? d.error : d.remote_endpoint || "-"}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
