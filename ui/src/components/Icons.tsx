import React from "react";

function buildScallopPath(
  cx: number,
  cy: number,
  baseR: number,
  amp: number,
  lobes = 12,
): string {
  const steps = lobes * 12;
  const pts: string[] = [];
  for (let i = 0; i < steps; i += 1) {
    const theta = (i / steps) * Math.PI * 2;
    const r = baseR + amp * Math.cos(lobes * theta);
    const x = cx + r * Math.cos(theta);
    const y = cy + r * Math.sin(theta);
    pts.push(`${i === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`);
  }
  pts.push("Z");
  return pts.join(" ");
}

const SCALLOP_100 = buildScallopPath(50, 50, 44.5, 3.3, 12);

export const SidebarToggleIcon: React.FC<{ size?: number }> = ({
  size = 18,
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect
      x="3.5"
      y="4.5"
      width="17"
      height="15"
      rx="3"
      stroke="currentColor"
      strokeWidth="1.75"
    />
    <path d="M9.2 4.8V19.2" stroke="currentColor" strokeWidth="1.75" />
  </svg>
);

export const DashboardGridIcon: React.FC<{ size?: number; active?: boolean }> = ({
  size = 18,
  active = false,
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect
      x="3.5"
      y="3.5"
      width="7.2"
      height="7.2"
      rx="2"
      fill={active ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <circle
      cx="17.1"
      cy="7.1"
      r="3.6"
      fill={active ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <circle
      cx="7.1"
      cy="16.9"
      r="3.6"
      fill={active ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <rect
      x="13.5"
      y="13.3"
      width="7.2"
      height="7.2"
      rx="2"
      fill={active ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="1.7"
    />
  </svg>
);

export const GlobeIcon: React.FC<{ size?: number }> = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="12" cy="12" r="8.5" stroke="currentColor" strokeWidth="1.7" />
    <ellipse cx="12" cy="12" rx="3.8" ry="8.5" stroke="currentColor" strokeWidth="1.6" />
    <path d="M3.8 12H20.2" stroke="currentColor" strokeWidth="1.6" />
  </svg>
);

export const ProfileDocIcon: React.FC<{ size?: number }> = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M6.5 3.8H13.8L18.2 8.2V19.2C18.2 20.03 17.53 20.7 16.7 20.7H6.5C5.67 20.7 5 20.03 5 19.2V5.3C5 4.47 5.67 3.8 6.5 3.8Z"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinejoin="round"
    />
    <path
      d="M13.5 3.9V8.4H18"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinejoin="round"
    />
    <path
      d="M8.5 12.5H14.8M8.5 16H13.2"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
    />
  </svg>
);

export const NetworkNodesIcon: React.FC<{ size?: number }> = ({
  size = 18,
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="12" cy="5.5" r="2.3" stroke="currentColor" strokeWidth="1.7" />
    <circle cx="6" cy="17.5" r="2.3" stroke="currentColor" strokeWidth="1.7" />
    <circle cx="18" cy="17.5" r="2.3" stroke="currentColor" strokeWidth="1.7" />
    <path
      d="M10.9 7.6L7.2 15.4M13.1 7.6L16.8 15.4M8.3 17.5H15.7"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
    />
  </svg>
);

export const ToolboxIcon: React.FC<{ size?: number }> = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect
      x="3.5"
      y="7.5"
      width="17"
      height="12.5"
      rx="2.6"
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <path
      d="M9 7.5V5.8C9 4.97 9.67 4.3 10.5 4.3H13.5C14.33 4.3 15 4.97 15 5.8V7.5"
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <path d="M3.8 12.6H20.2" stroke="currentColor" strokeWidth="1.6" />
    <circle cx="12" cy="12.6" r="1.3" fill="currentColor" />
  </svg>
);

export const ActivityPulseIcon: React.FC<{ size?: number }> = ({
  size = 16,
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect
      x="3"
      y="4.5"
      width="18"
      height="15"
      rx="3.5"
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <path
      d="M6.8 12.2H9.3L10.9 8.8L13.1 15.2L14.7 12.2H17.2"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ArrowUpIcon: React.FC<{ size?: number; color?: string }> = ({
  size = 15,
  color = "currentColor",
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M12 19V5M12 5L6.8 10.2M12 5L17.2 10.2"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ArrowDownIcon: React.FC<{ size?: number; color?: string }> = ({
  size = 15,
  color = "currentColor",
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M12 5V19M12 19L6.8 13.8M12 19L17.2 13.8"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const SplitRouteIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M12 20V12.5M12 12.5L6.5 7M12 12.5L17.5 7M6.5 11V7H10.5M17.5 11V7H13.5"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const RuleListIcon: React.FC<{ size?: number }> = ({ size = 15 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect
      x="3.5"
      y="4.5"
      width="17"
      height="15"
      rx="2.6"
      stroke="currentColor"
      strokeWidth="1.75"
    />
    <path
      d="M7.5 9.2H16.5M7.5 12.5H16.5M7.5 15.8H13"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
    />
  </svg>
);

export const DirectTargetIcon: React.FC<{ size?: number }> = ({
  size = 15,
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="1.75" />
    <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.75" />
    <path
      d="M15.5 8.5L19.5 4.5"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
    />
  </svg>
);

export const SysProxyIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M4 8H11L15 16H20M17.5 13.5L20 16L17.5 18.5M4 16H9.5M14.5 8H20M17.5 5.5L20 8L17.5 10.5"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ScallopedShieldBadge: React.FC<{
  size?: number;
  active?: boolean;
}> = ({ size = 28, active = true }) => (
  <svg width={size} height={size} viewBox="0 0 100 100" fill="none" aria-hidden="true">
    <path
      d={SCALLOP_100}
      fill={active ? "var(--accent-blue)" : "var(--text-muted)"}
    />
    <path
      d="M50 28L66 34.5V48.5C66 59.5 59.2 68.4 50 72.5C40.8 68.4 34 59.5 34 48.5V34.5L50 28Z"
      stroke="#ffffff"
      strokeWidth="5.5"
      strokeLinejoin="round"
    />
    <path
      d="M44 50.5L48.5 55L57 45.5"
      stroke="#ffffff"
      strokeWidth="5.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ScallopedMasterShape: React.FC<{
  running: boolean;
  busy?: boolean;
  size?: number;
}> = ({ running, busy = false, size = 68 }) => (
  <svg width={size} height={size} viewBox="0 0 100 100" fill="none" aria-hidden="true">
    <path d={SCALLOP_100} fill="currentColor" />
    {busy ? (
      <circle
        cx="50"
        cy="50"
        r="14"
        stroke="#ffffff"
        strokeWidth="5.5"
        strokeDasharray="56 28"
        strokeLinecap="round"
      >
        <animateTransform
          attributeName="transform"
          type="rotate"
          from="0 50 50"
          to="360 50 50"
          dur="0.85s"
          repeatCount="indefinite"
        />
      </circle>
    ) : running ? (
      <>
        <rect x="40.5" y="37" width="6.2" height="26" rx="3.1" fill="#ffffff" />
        <rect x="53.3" y="37" width="6.2" height="26" rx="3.1" fill="#ffffff" />
      </>
    ) : (
      <path
        d="M43 36.5C43 34.9 44.75 33.92 46.12 34.75L64.2 45.75C65.52 46.55 65.52 48.45 64.2 49.25L46.12 60.25C44.75 61.08 43 60.1 43 58.5V36.5Z"
        fill="#ffffff"
      />
    )}
  </svg>
);

export const MonitorIpIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect
      x="3"
      y="4.5"
      width="14.5"
      height="11"
      rx="2"
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <rect
      x="14"
      y="9.5"
      width="7"
      height="10"
      rx="1.6"
      fill="var(--bg-card)"
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <path
      d="M7.5 19.5H11.5"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
    />
  </svg>
);

export const WifiIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M4.2 9.5C8.6 5.8 15.4 5.8 19.8 9.5M7.3 13C10.1 10.6 13.9 10.6 16.7 13"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
    />
    <circle cx="12" cy="16.8" r="1.5" fill="currentColor" />
  </svg>
);

export const CopyIcon: React.FC<{ size?: number }> = ({ size = 15 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect
      x="8.5"
      y="8.5"
      width="11"
      height="11"
      rx="2.2"
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <path
      d="M15.5 8.5V6.2C15.5 5.26 14.74 4.5 13.8 4.5H6.2C5.26 4.5 4.5 5.26 4.5 6.2V13.8C4.5 14.74 5.26 15.5 6.2 15.5H8.5"
      stroke="currentColor"
      strokeWidth="1.7"
    />
  </svg>
);

export const CheckIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M5.5 12.5L10 17L18.5 7.8"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ShieldCheckIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M12 3.5L19 6.3V11.8C19 16.3 15.95 19.85 12 21.3C8.05 19.85 5 16.3 5 11.8V6.3L12 3.5Z"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinejoin="round"
    />
    <path
      d="M9.2 12.2L11.2 14.2L15.2 9.8"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const GoogleGIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M20.4 12.2C20.4 11.55 20.34 10.95 20.22 10.4H12V13.95H16.74C16.54 15.08 15.88 16.04 14.91 16.69V18.95H17.74C19.42 17.4 20.4 15.05 20.4 12.2Z"
      fill="currentColor"
    />
    <path
      d="M12 20.75C14.37 20.75 16.36 19.97 17.74 18.95L14.91 16.69C14.13 17.22 13.15 17.55 12 17.55C9.75 17.55 7.85 16.03 7.16 13.98H4.24V16.31C5.66 19.12 8.6 20.75 12 20.75Z"
      fill="currentColor"
    />
    <path
      d="M7.16 13.98C6.98 13.45 6.88 12.88 6.88 12.28C6.88 11.68 6.98 11.11 7.16 10.58V8.25H4.24C3.63 9.46 3.28 10.83 3.28 12.28C3.28 13.73 3.63 15.1 4.24 16.31L7.16 13.98Z"
      fill="currentColor"
    />
    <path
      d="M12 7.01C13.29 7.01 14.44 7.45 15.35 8.32L17.83 5.84C16.35 4.46 14.37 3.8 12 3.8C8.6 3.8 5.66 5.44 4.24 8.25L7.16 10.58C7.85 8.53 9.75 7.01 12 7.01Z"
      fill="currentColor"
    />
  </svg>
);

export const GithubMarkIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M12 2.2C6.47 2.2 2 6.68 2 12.22C2 16.65 4.87 20.4 8.84 21.73C9.34 21.82 9.52 21.52 9.52 21.25C9.52 21.01 9.51 20.22 9.51 19.38C6.73 19.99 6.14 18.2 6.14 18.2C5.69 17.04 5.03 16.73 5.03 16.73C4.12 16.11 5.1 16.12 5.1 16.12C6.1 16.19 6.63 17.15 6.63 17.15C7.52 18.68 8.97 18.24 9.54 17.98C9.63 17.33 9.89 16.89 10.17 16.64C7.95 16.39 5.62 15.53 5.62 11.68C5.62 10.58 6.01 9.69 6.65 8.99C6.55 8.74 6.2 7.72 6.75 6.34C6.75 6.34 7.59 6.07 9.5 7.37C10.3 7.15 11.15 7.04 12 7.04C12.85 7.04 13.7 7.15 14.5 7.37C16.41 6.07 17.25 6.34 17.25 6.34C17.8 7.72 17.45 8.74 17.35 8.99C17.99 9.69 18.38 10.58 18.38 11.68C18.38 15.54 16.04 16.38 13.81 16.63C14.17 16.94 14.49 17.55 14.49 18.5C14.49 19.85 14.48 20.93 14.48 21.25C14.48 21.52 14.66 21.83 15.17 21.73C19.13 20.4 22 16.65 22 12.22C22 6.68 17.52 2.2 12 2.2Z"
    />
  </svg>
);

export const ChipMemoryIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect
      x="6.5"
      y="6.5"
      width="11"
      height="11"
      rx="2.2"
      stroke="currentColor"
      strokeWidth="1.7"
    />
    <rect
      x="9.5"
      y="9.5"
      width="5"
      height="5"
      rx="1"
      stroke="currentColor"
      strokeWidth="1.5"
    />
    <path
      d="M9.5 3.5V6.5M14.5 3.5V6.5M9.5 17.5V20.5M14.5 17.5V20.5M3.5 9.5H6.5M3.5 14.5H6.5M17.5 9.5H20.5M17.5 14.5H20.5"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
    />
  </svg>
);

export const LayersGroupIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M12 4L20 8.2L12 12.4L4 8.2L12 4Z"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinejoin="round"
    />
    <path
      d="M4 12.3L12 16.5L20 12.3M4 16.3L12 20.5L20 16.3"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ChevronRightIcon: React.FC<{ size?: number }> = ({
  size = 15,
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M9 6L15 12L9 18"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const ChevronDownIcon: React.FC<{ size?: number }> = ({ size = 15 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M6 9L12 15L18 9"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const SunIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="12" cy="12" r="4.2" stroke="currentColor" strokeWidth="1.75" />
    <path
      d="M12 3V5.2M12 18.8V21M3 12H5.2M18.8 12H21M5.6 5.6L7.2 7.2M16.8 16.8L18.4 18.4M18.4 5.6L16.8 7.2M7.2 16.8L5.6 18.4"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
    />
  </svg>
);

export const MoonIcon: React.FC<{ size?: number }> = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M19.5 14.5C18.3 15.05 16.95 15.35 15.5 15.35C10.34 15.35 6.15 11.16 6.15 6C6.15 4.95 6.33 3.94 6.65 3C4.15 4.46 2.5 7.18 2.5 10.3C2.5 15.93 7.07 20.5 12.7 20.5C16.22 20.5 19.32 18.71 21 16C20.52 15.53 20.01 15.03 19.5 14.5Z"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinejoin="round"
    />
  </svg>
);

export const BoltIcon: React.FC<{ size?: number }> = ({ size = 15 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M13 3L5.5 13.5H12L11 21L18.5 10.5H12L13 3Z"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinejoin="round"
    />
  </svg>
);

export const PlusIcon: React.FC<{ size?: number }> = ({ size = 15 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M12 5V19M5 12H19"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
    />
  </svg>
);

export const SearchIcon: React.FC<{ size?: number }> = ({ size = 15 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="11" cy="11" r="6.8" stroke="currentColor" strokeWidth="1.8" />
    <path
      d="M16.2 16.2L20 20"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
    />
  </svg>
);

export const RefreshIcon: React.FC<{ size?: number; spinning?: boolean }> = ({
  size = 15,
  spinning = false,
}) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    aria-hidden="true"
    className={spinning ? "rc-spin" : undefined}
  >
    <path
      d="M20 11A8 8 0 1 0 18.3 16.2M20 11V6M20 11H15"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const CloseIcon: React.FC<{ size?: number }> = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M6.5 6.5L17.5 17.5M17.5 6.5L6.5 17.5"
      stroke="currentColor"
      strokeWidth="1.9"
      strokeLinecap="round"
    />
  </svg>
);
