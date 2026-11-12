import React, { useMemo, useState } from "react";
import type { LogEntry } from "../types";
import { formatClockTime } from "../utils/format";

interface LogsViewProps {
  logs: LogEntry[];
  onClear: () => void;
}

export const LogsView: React.FC<LogsViewProps> = ({ logs, onClear }) => {
  const [levelFilter, setLevelFilter] = useState("ALL");
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return logs.filter((entry) => {
      if (
        levelFilter !== "ALL" &&
        entry.type.toUpperCase() !== levelFilter
      ) {
        return false;
      }
      if (q && !entry.payload.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
  }, [logs, levelFilter, search]);

  const levelBadge = (lvl: string) => {
    const u = lvl.toUpperCase();
    if (u === "ERROR") return "badge-rose";
    if (u === "WARN" || u === "WARNING") return "badge-amber";
    if (u === "INFO") return "badge-emerald";
    return "badge-neutral";
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div className="toolbar">
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <div className="segmented">
            {["ALL", "INFO", "WARN", "ERROR"].map((lvl) => (
              <button
                key={lvl}
                type="button"
                className={`seg-btn ${levelFilter === lvl ? "active" : ""}`}
                onClick={() => setLevelFilter(lvl)}
              >
                {lvl}
              </button>
            ))}
          </div>
          <input
            id="log-search-input"
            className="input"
            style={{ width: 260, maxWidth: "100%" }}
            placeholder="Filter log payload..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <button type="button" className="btn btn-sm" onClick={onClear}>
          Clear Buffer ({logs.length})
        </button>
      </div>

      <div className="log-stream mono">
        {filtered.length === 0 ? (
          <div
            style={{
              padding: 24,
              textAlign: "center",
              color: "var(--text-muted)",
            }}
          >
            No log events match current filter.
          </div>
        ) : (
          filtered
            .slice()
            .reverse()
            .map((entry, idx) => (
              <div key={`${entry.timestamp_ms}-${idx}`} className="log-line">
                <span className="tabular" style={{ color: "var(--text-muted)" }}>
                  {formatClockTime(entry.timestamp_ms)}
                </span>
                <span>
                  <span className={`badge ${levelBadge(entry.type)}`}>
                    {entry.type.toUpperCase()}
                  </span>
                </span>
                <span style={{ wordBreak: "break-word" }}>{entry.payload}</span>
              </div>
            ))
        )}
      </div>
    </div>
  );
};
