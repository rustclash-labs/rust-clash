import React, { useEffect, useMemo, useState } from "react";
import { clashApi } from "../api";
import { CloseIcon, SearchIcon } from "../components/Icons";
import { useI18n } from "../i18n";
import type { ConnectionItem, ConnectionsResponse, TrafficPoint } from "../types";
import {
  extractBadgeInitial,
  formatAge,
  formatBytes,
  formatSpeed,
} from "../utils/format";

interface ConnectionsViewProps {
  connections: ConnectionsResponse | null;
  latestTraffic: TrafficPoint;
  onRefresh: () => Promise<void>;
}

export const ConnectionsView: React.FC<ConnectionsViewProps> = ({
  connections,
  latestTraffic,
  onRefresh,
}) => {
  const { tr } = useI18n();

  const [query, setQuery] = useState("");
  const [paused, setPaused] = useState(false);
  const [frozenItems, setFrozenItems] = useState<ConnectionItem[]>([]);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const liveItems = connections?.connections ?? [];

  useEffect(() => {
    if (!paused) {
      setFrozenItems(liveItems);
    }
  }, [paused, liveItems]);

  const sourceItems = paused ? frozenItems : liveItems;

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return sourceItems;
    return sourceItems.filter((c) => {
      const hay = [
        c.metadata.process ?? "",
        c.metadata.source,
        c.metadata.type,
        c.metadata.host,
        c.metadata.destination_ip ?? "",
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
  }, [sourceItems, query]);

  const handleCloseOne = async (id: string) => {
    setActionBusy(`close:${id}`);
    setErrorMsg(null);
    try {
      await clashApi.closeConnection(id);
      await onRefresh();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setActionBusy(null);
    }
  };

  const handleCloseAll = async () => {
    setActionBusy("close-all");
    setErrorMsg(null);
    try {
      await clashApi.closeAllConnections();
      await onRefresh();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setActionBusy(null);
    }
  };

  const totalReqs =
    connections?.totalConnections ?? Math.max(liveItems.length, 0);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
      {errorMsg && (
        <div className="banner banner-err">
          <span>{errorMsg}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setErrorMsg(null)}
          >
            {tr("关闭", "Dismiss")}
          </button>
        </div>
      )}

      {/* Summary Metric Strip + Controls */}
      <section className="bento-card" style={{ padding: "14px 18px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            flexWrap: "wrap",
            marginBottom: 12,
          }}
        >
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <div className="sub-pill-box" style={{ padding: "7px 14px" }}>
              <span style={{ fontSize: 11.5, color: "var(--text-muted)", marginRight: 8 }}>
                {tr("活跃连接", "Active")}
              </span>
              <strong className="tabular" style={{ fontSize: 14.5 }}>
                {liveItems.length}
              </strong>
            </div>

            <div className="sub-pill-box" style={{ padding: "7px 14px" }}>
              <span style={{ fontSize: 11.5, color: "var(--text-muted)", marginRight: 8 }}>
                {tr("累计请求", "Total Requests")}
              </span>
              <strong className="tabular" style={{ fontSize: 14.5 }}>
                {totalReqs.toLocaleString()}
              </strong>
            </div>

            <div className="sub-pill-box tabular" style={{ padding: "7px 14px" }}>
              <span style={{ fontSize: 11.5, color: "var(--text-muted)", marginRight: 8 }}>
                {tr("实时速率", "Live Speed")}
              </span>
              <strong style={{ fontSize: 13.5, color: "var(--accent-blue)" }}>
                ↓ {formatSpeed(latestTraffic.down)}
              </strong>
              <span style={{ margin: "0 6px", color: "var(--text-muted)" }}>·</span>
              <strong style={{ fontSize: 13.5 }}>
                ↑ {formatSpeed(latestTraffic.up)}
              </strong>
            </div>
          </div>

          <button
            type="button"
            className="btn btn-danger"
            disabled={liveItems.length === 0 || actionBusy === "close-all"}
            onClick={() => void handleCloseAll()}
          >
            {actionBusy === "close-all"
              ? tr("断开中...", "Closing...")
              : tr(
                  `一键断开全部连接 (${liveItems.length})`,
                  `Close All (${liveItems.length})`,
                )}
          </button>
        </div>

        <div className="toolbar">
          <div
            style={{
              position: "relative",
              flex: "1 1 280px",
              maxWidth: 420,
            }}
          >
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
              type="text"
              className="input"
              style={{ width: "100%", paddingLeft: 32 }}
              placeholder={tr(
                "搜索域名、IP、进程名、出站节点或规则...",
                "Filter by domain, IP, process, outbound, or rule...",
              )}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span
              className="tabular"
              style={{ fontSize: 12, color: "var(--text-muted)" }}
            >
              {tr(
                `显示 ${filtered.length} / ${sourceItems.length}`,
                `Showing ${filtered.length} / ${sourceItems.length}`,
              )}
            </span>

            <button
              type="button"
              className={`btn btn-sm ${paused ? "btn-primary" : ""}`}
              onClick={() => setPaused((v) => !v)}
            >
              {paused ? tr("恢复刷新", "Resume") : tr("暂停列表", "Pause")}
            </button>
          </div>
        </div>
      </section>

      {/* Full-Width Bento Connections Table */}
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>{tr("进程 / 来源", "Source / Process")}</th>
              <th>{tr("目标地址", "Target")}</th>
              <th>{tr("匹配规则", "Rule")}</th>
              <th>{tr("出站链路", "Outbound Chain")}</th>
              <th>{tr("下载 / 上传", "Traffic")}</th>
              <th>{tr("耗时", "Age")}</th>
              <th style={{ width: 46, textAlign: "center" }} />
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={7}
                  style={{
                    textAlign: "center",
                    padding: "36px 14px",
                    color: "var(--text-muted)",
                  }}
                >
                  {query.trim()
                    ? tr("没有匹配的连接记录", "No connections match your filter")
                    : tr("当前暂无活跃连接", "No active connections right now")}
                </td>
              </tr>
            ) : (
              filtered.map((c) => {
                const procName =
                  c.metadata.process?.trim() ||
                  c.metadata.type ||
                  c.metadata.source;
                const targetStr = `${
                  c.metadata.host || c.metadata.destination_ip || "*"
                }:${c.metadata.destination_port}`;
                const chainDisplay =
                  c.chains.length > 0
                    ? c.chains.slice().reverse().join(" → ")
                    : c.effective_outbound || "DIRECT";

                return (
                  <tr key={c.id}>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span className="source-avatar">
                          {extractBadgeInitial(procName)}
                        </span>
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontWeight: 600 }}>{procName}</div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                            {c.metadata.network.toUpperCase()} · {c.metadata.source}
                          </div>
                        </div>
                      </div>
                    </td>

                    <td>
                      <div style={{ fontWeight: 550 }}>{targetStr}</div>
                      {c.metadata.fake_ip && (
                        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                          Fake-IP: {c.metadata.fake_ip}
                        </div>
                      )}
                    </td>

                    <td>
                      <span className="badge badge-neutral">{c.rule}</span>
                      {c.rule_payload && (
                        <span
                          style={{
                            marginLeft: 6,
                            fontSize: 12,
                            color: "var(--text-secondary)",
                          }}
                        >
                          {c.rule_payload}
                        </span>
                      )}
                    </td>

                    <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                      {chainDisplay}
                    </td>

                    <td className="tabular">
                      <div>↓ {formatBytes(c.download)}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        ↑ {formatBytes(c.upload)}
                      </div>
                    </td>

                    <td className="tabular" style={{ color: "var(--text-muted)" }}>
                      {formatAge(c.start_epoch_ms)}
                    </td>

                    <td style={{ textAlign: "center" }}>
                      <button
                        type="button"
                        className="bento-icon-action"
                        disabled={actionBusy === `close:${c.id}`}
                        onClick={() => void handleCloseOne(c.id)}
                        title={tr("断开此连接", "Close connection")}
                      >
                        <CloseIcon size={14} />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
