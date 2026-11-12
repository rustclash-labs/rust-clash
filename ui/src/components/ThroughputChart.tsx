import React from "react";
import type { TrafficPoint } from "../types";
import { formatSpeed } from "../utils/format";

interface ThroughputChartProps {
  points: TrafficPoint[];
}

const MAX_POINTS = 60;

export const ThroughputChart: React.FC<ThroughputChartProps> = ({ points }) => {
  const padded: TrafficPoint[] = React.useMemo(() => {
    const recent = points.slice(-MAX_POINTS);
    if (recent.length >= MAX_POINTS) return recent;
    const padCount = MAX_POINTS - recent.length;
    const zeros: TrafficPoint[] = Array.from({ length: padCount }, () => ({
      timestamp_ms: 0,
      up: 0,
      down: 0,
      total_up: 0,
      total_down: 0,
    }));
    return [...zeros, ...recent];
  }, [points]);

  const width = 680;
  const height = 185;
  const padLeft = 8;
  const padRight = 8;
  const padTop = 14;
  const padBottom = 18;
  const innerW = width - padLeft - padRight;
  const innerH = height - padTop - padBottom;

  const peak = React.useMemo(() => {
    let m = 4096;
    for (const p of padded) {
      if (p.down > m) m = p.down;
      if (p.up > m) m = p.up;
    }
    return m * 1.15;
  }, [padded]);

  const toCoords = (selector: (p: TrafficPoint) => number) =>
    padded.map((p, i) => {
      const x = padLeft + (i / (MAX_POINTS - 1)) * innerW;
      const ratio = Math.min(1, selector(p) / peak);
      const y = padTop + innerH - ratio * innerH;
      return { x, y };
    });

  const downPts = toCoords((p) => p.down);
  const upPts = toCoords((p) => p.up);

  const buildPath = (pts: { x: number; y: number }[]) =>
    pts.map((pt, idx) => `${idx === 0 ? "M" : "L"}${pt.x.toFixed(1)},${pt.y.toFixed(1)}`).join(" ");

  const buildArea = (pts: { x: number; y: number }[]) => {
    if (pts.length === 0) return "";
    const baseline = padTop + innerH;
    return `${buildPath(pts)} L${pts[pts.length - 1].x.toFixed(1)},${baseline} L${pts[0].x.toFixed(1)},${baseline} Z`;
  };

  return (
    <div style={{ width: "100%" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: 11.5,
          color: "var(--text-muted)",
          marginBottom: 6,
        }}
        className="tabular"
      >
        <span>Peak Scale: {formatSpeed(peak)}</span>
        <span style={{ display: "flex", gap: 14 }}>
          <span style={{ color: "var(--accent-emerald)", fontWeight: 600 }}>
            ● Download
          </span>
          <span style={{ color: "var(--accent-sky)", fontWeight: 600 }}>
            ● Upload
          </span>
        </span>
      </div>

      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: "100%", height: 185, display: "block" }}
        role="img"
        aria-label="Live network upload and download throughput"
      >
        <defs>
          <linearGradient id="dlAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10b981" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
          </linearGradient>
          <linearGradient id="ulAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.22" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
          </linearGradient>
        </defs>

        {[0.25, 0.5, 0.75, 1].map((frac) => {
          const y = padTop + innerH * frac;
          return (
            <line
              key={frac}
              x1={padLeft}
              x2={width - padRight}
              y1={y}
              y2={y}
              stroke="var(--border-subtle)"
              strokeDasharray="3 4"
              strokeWidth="1"
            />
          );
        })}

        <path d={buildArea(downPts)} fill="url(#dlAreaGrad)" />
        <path d={buildArea(upPts)} fill="url(#ulAreaGrad)" />
        <path
          d={buildPath(downPts)}
          fill="none"
          stroke="#10b981"
          strokeWidth="2"
          strokeLinejoin="round"
        />
        <path
          d={buildPath(upPts)}
          fill="none"
          stroke="#38bdf8"
          strokeWidth="1.75"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
};
