import React, { useId } from "react";

interface SparklineProps {
  values: number[];
  strokeColor?: string;
  height?: number;
}

function buildSmoothSparkline(
  values: number[],
  width: number,
  height: number,
): { strokePath: string; areaPath: string } {
  const count = Math.max(values.length, 2);
  const padded =
    values.length >= 2
      ? values
      : values.length === 1
        ? [values[0], values[0]]
        : new Array<number>(24).fill(0);

  const maxVal = Math.max(...padded, 1024);
  const topPad = 6;
  const bottomY = height - 1;
  const usableH = Math.max(8, bottomY - topPad);

  const coords = padded.map((v, idx) => {
    const x = (idx / (count - 1)) * width;
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

  const area = `${d} L ${width.toFixed(1)},${height.toFixed(1)} L 0,${height.toFixed(1)} Z`;
  return { strokePath: d, areaPath: area };
}

export const Sparkline: React.FC<SparklineProps> = ({
  values,
  strokeColor = "#1677ff",
  height = 54,
}) => {
  const gradId = useId().replace(/:/g, "");
  const width = 260;
  const { strokePath, areaPath } = buildSmoothSparkline(values, width, height);

  return (
    <svg
      className="sparkline-svg"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={`spark-${gradId}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={strokeColor} stopOpacity="0.22" />
          <stop offset="100%" stopColor={strokeColor} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#spark-${gradId})`} />
      <path
        d={strokePath}
        fill="none"
        stroke={strokeColor}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
};
