import React, { useEffect, useMemo, useState } from "react";
import { SearchIcon } from "../components/Icons";
import { useI18n } from "../i18n";
import type { LogEntry } from "../types";
import { formatClockTime } from "../utils/format";

interface LogsViewProps {
  logs: LogEntry[];
  onClear: () => void;
}

const LEVELS = ["ALL", "INFO", "WARN", "ERROR", "DEBUG"] as const;

export const LogsView: React.FC<LogsViewProps> = ({ logs, onClear }) => {
  const { tr } = useI18n();

  const [levelFilter, setLevelFilter] = useState<string>("ALL");
  const [search, setSearch] = useState("");
  const [paused, setPaused] = useState(false);
  const [frozenLogs, setFrozenLogs] = useState<LogEntry[]>([]);

  useEffect(() => {
    if (!paused) {
      setFrozenLogs(logs);
    }
  }, [paused, logs]);

  const activeLogs = paused ? frozenLogs : logs;

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return activeLogs.filter((entry) => {
      const upper = entry.type.toUpperCase();
      if (levelFilter !== "ALL") {
        if (levelFilter === "WARN" && upper !== "WARN" && upper !== "WARNING") {
          return false;
        }
        if (levelFilter !== "WARN" && upper !== levelFilter) {
          return false;
        }
      }
      if (q && !entry.payload.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
  }, [activeLogs, levelFilter, search]);

  const levelBadge = (lvl: string) => {
    const u = lvl.toUpperCase();
    if (u === "ERROR") return "badge-rose";
    if (u === "WARN" || u === "WARNING") return "badge-amber";
    if (u === "INFO") return "badge-emerald";
    return "badge-neutral";
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
      <section className="bento-card" style={{ padding: "12px 16px" }}>
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
              {LEVELS.map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  className={`seg-btn ${levelFilter === lvl ? "active" : ""}`}
                  onClick={() => setLevelFilter(lvl)}
                >
                  {lvl === "ALL" ? tr("全部", "All") : lvl.toLowerCase()}
                </button>
              ))}
            </div>

            <div style={{ position: "relative", width: 250, maxWidth: "100%" }}>
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
                placeholder={tr("搜索日志内容...", "Search logs...")}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="button"
              className={`btn btn-sm ${paused ? "btn-primary" : ""}`}
              onClick={() => setPaused((v) => !v)}
            >
              {paused ? tr("恢复滚动", "Resume") : tr("暂停", "Pause")}
            </button>
            <button type="button" className="btn btn-sm" onClick={onClear}>
              {tr("清空日志", "Clear")} ({logs.length})
            </button>
          </div>
        </div>
      </section>

      <div className="log-stream">
        {filtered.length === 0 ? (
          <div
            style={{
              padding: "32px 16px",
              textAlign: "center",
              color: "var(--text-muted)",
            }}
          >
            {tr("暂无符合筛选条件的运行日志", "No log entries match your filter")}
          </div>
        ) : (
          filtered
            .slice()
            .reverse()
            .map((entry, idx) => (
              <div key={`${entry.timestamp_ms}-${idx}`} className="log-line">
                <span className="tabular mono" style={{ color: "var(--text-muted)" }}>
                  {formatClockTime(entry.timestamp_ms)}
                </span>
                <span>
                  <span className={`badge ${levelBadge(entry.type)}`}>
                    {entry.type.toLowerCase()}
                  </span>
                </span>
                <span className="mono" style={{ wordBreak: "break-word" }}>
                  {entry.payload}
                </span>
              </div>
            ))
        )}
      </div>
    </div>
  );
};
