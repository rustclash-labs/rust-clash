import React, { useId } from "react";

interface SparklineProps {
  values: number[];
  strokeColor?: string;
  height?: number;
  idle?: boolean;
}

function buildSmoothSparkline(
  values: number[],
  width: number,
  height: number,
): {
  strokePath: string;
  areaPath: string;
  lastPt: { x: number; y: number };
  hasSignal: boolean;
} {
  const padded =
    values.length >= 2
      ? values
      : values.length === 1
        ? [values[0], values[0]]
        : new Array<number>(24).fill(0);

  const rawMax = Math.max(...padded, 0);
  const hasSignal = rawMax > 0;
  const maxVal = Math.max(rawMax, 1024);
  const padX = 6;
  const topPad = 8;
  const bottomY = height - 6;
  const usableW = Math.max(16, width - padX * 2);
  const usableH = Math.max(8, bottomY - topPad);

  const coords = padded.map((v, idx) => {
    const x = padX + (idx / (padded.length - 1)) * usableW;
    const ratio = Math.min(1, Math.max(0, v / (maxVal * 1.12)));
    const y = bottomY - ratio * usableH;
    return { x, y };
  });

  let d = `M ${coords[0].x.toFixed(1)},${coords[0].y.toFixed(1)}`;
  for (let i = 0; i < coords.length - 1; i += 1) {
    const p0 = coords[i];
    const p1 = coords[i + 1];
    const midX = ((p0.x + p1.x) / 2).toFixed(1);
    d += ` C ${midX},${p0.y.toFixed(1)} ${midX},${p1.y.toFixed(1)} ${p1.x.toFixed(1)},${p1.y.toFixed(1)}`;
  }

  const lastPt = coords[coords.length - 1];
  const area = `${d} L ${lastPt.x.toFixed(1)},${height.toFixed(1)} L ${coords[0].x.toFixed(1)},${height.toFixed(1)} Z`;
  return { strokePath: d, areaPath: area, lastPt, hasSignal };
}

export const Sparkline: React.FC<SparklineProps> = ({
  values,
  strokeColor = "var(--accent-blue)",
  height = 54,
  idle = false,
}) => {
  const gradId = useId().replace(/:/g, "");
  const width = 280;
  const { strokePath, areaPath, lastPt, hasSignal } = buildSmoothSparkline(
    values,
    width,
    height,
  );

  if (idle && !hasSignal) {
    return (
      <svg
        className="sparkline-svg"
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <line
          x1="6"
          y1={height - 8}
          x2={width - 6}
          y2={height - 8}
          stroke="var(--border-strong)"
          strokeWidth="1.6"
          strokeDasharray="4 4"
        />
      </svg>
    );
  }

  return (
    <svg
      className="sparkline-svg"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="xMidYMid meet"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={`spark-${gradId}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={strokeColor} stopOpacity="0.24" />
          <stop offset="100%" stopColor={strokeColor} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#spark-${gradId})`} />
      <path
        d={strokePath}
        fill="none"
        stroke={strokeColor}
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {hasSignal && (
        <>
          <circle
            cx={lastPt.x}
            cy={lastPt.y}
            r="5.5"
            fill={strokeColor}
            fillOpacity="0.22"
          />
          <circle cx={lastPt.x} cy={lastPt.y} r="2.8" fill={strokeColor} />
        </>
      )}
    </svg>
  );
};
