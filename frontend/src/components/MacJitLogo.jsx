import React from "react";

/**
 * MacJitLogo
 * Circular badge SVG matching MacJit brand (orange + dark navy).
 * Elements: outer ring, gear, crossed wrench + tire, lightning spark.
 *
 * Props:
 *  - size: number | px  (default 40)
 *  - withWordmark: boolean -> renders "MACJIT" + tagline beside the mark
 *  - variant: "dark" (default, on dark bg) | "light" (on light bg)
 */
export default function MacJitLogo({ size = 40, withWordmark = false, tagline = true, variant = "dark", className = "" }) {
  const navy = "#1E2A44";
  const orange = "#F26A21";
  const cream = "#F5F3EF";
  const steel = "#C7CAD1";

  const bg = variant === "light" ? cream : navy;
  const ringFill = variant === "light" ? navy : cream;

  return (
    <div className={`inline-flex items-center gap-3 ${className}`} data-testid="macjit-logo">
      <svg
        width={size}
        height={size}
        viewBox="0 0 128 128"
        xmlns="http://www.w3.org/2000/svg"
        className="shrink-0"
        aria-label="MacJit"
      >
        {/* Outer badge */}
        <circle cx="64" cy="64" r="62" fill={bg} stroke={orange} strokeWidth="3" />
        <circle cx="64" cy="64" r="54" fill="none" stroke={ringFill} strokeOpacity="0.15" strokeWidth="1" />

        {/* Gear teeth ring */}
        <g fill={orange}>
          {Array.from({ length: 12 }).map((_, i) => {
            const a = (i * 30 * Math.PI) / 180;
            const cx = 64 + Math.cos(a) * 48;
            const cy = 64 + Math.sin(a) * 48;
            return <rect key={i} x={cx - 3} y={cy - 5} width="6" height="10" rx="1.5" transform={`rotate(${i * 30} ${cx} ${cy})`} />;
          })}
        </g>

        {/* Inner gear disc */}
        <circle cx="64" cy="64" r="38" fill={variant === "light" ? "#FFFFFF" : "#0F1628"} stroke={orange} strokeWidth="2" />

        {/* Tire tread */}
        <g stroke={steel} strokeWidth="2.2" strokeLinecap="round">
          <circle cx="64" cy="64" r="26" fill="none" />
          <circle cx="64" cy="64" r="14" fill="none" stroke={ringFill} strokeOpacity="0.5" strokeWidth="1.5" />
          {Array.from({ length: 16 }).map((_, i) => {
            const a = (i * 22.5 * Math.PI) / 180;
            return (
              <line
                key={i}
                x1={64 + Math.cos(a) * 22}
                y1={64 + Math.sin(a) * 22}
                x2={64 + Math.cos(a) * 30}
                y2={64 + Math.sin(a) * 30}
              />
            );
          })}
        </g>

        {/* Wrench (rotated) */}
        <g transform="translate(64 64) rotate(45)" fill={steel} stroke={navy} strokeWidth="1.2">
          <rect x="-4" y="-30" width="8" height="44" rx="2" />
          <path d="M -7 -32 a 8 8 0 1 1 14 0 l -3 4 l -3 -2 l -2 2 l -3 -2 z" />
          <rect x="-4" y="10" width="8" height="8" rx="1.5" />
        </g>

        {/* Lightning bolt accent */}
        <path
          d="M 72 46 L 58 68 L 66 68 L 60 84 L 78 60 L 70 60 L 76 46 Z"
          fill={orange}
          stroke={navy}
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
      </svg>

      {withWordmark && (
        <div className="leading-none flex flex-col gap-1">
          <span className="font-display font-black tracking-tighter text-inherit" style={{ fontSize: `${size * 0.5}px` }}>
            <span style={{ color: variant === "light" ? navy : "inherit" }}>MAC</span>
            <span style={{ color: orange }}>JIT</span>
          </span>
          {tagline && (
            <span
              className="font-mono uppercase tracking-[0.22em] text-orange-500"
              style={{ fontSize: `${Math.max(8, size * 0.16)}px` }}
            >
              Mechanic Just In Time
            </span>
          )}
        </div>
      )}
    </div>
  );
}
