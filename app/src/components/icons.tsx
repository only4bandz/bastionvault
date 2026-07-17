// Minimal inline icon set (stroke-based, 1.6px) — no external icon dependency.
import type { JSX } from "react";

type P = { size?: number };
const S = (size = 18) => ({
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
});

export const IcVault = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="12" cy="12" r="3" /><path d="M12 9v-1M12 16v-1M15 12h1M8 12h1" /></svg>
);
export const IcShared = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><circle cx="9" cy="8" r="3" /><path d="M3 20a6 6 0 0 1 12 0" /><path d="M16 6a3 3 0 0 1 0 6M18 20a6 6 0 0 0-3-5" /></svg>
);
export const IcTrash = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13" /></svg>
);
export const IcFolder = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></svg>
);
export const IcGen = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1" /><circle cx="12" cy="12" r="3" /></svg>
);
export const IcHealth = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M4 12h3l2 5 4-10 2 5h5" /></svg>
);
export const IcMask = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M3 8c4-2 14-2 18 0 0 6-3 9-9 9S3 14 3 8z" /><circle cx="8.5" cy="11" r="1" /><circle cx="15.5" cy="11" r="1" /></svg>
);
export const IcBreach = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M12 3l8 4v5c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V7z" /><path d="M12 8v4M12 15v.5" /></svg>
);
export const IcSearch = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><circle cx="11" cy="11" r="7" /><path d="m20 20-3-3" /></svg>
);
export const IcMenu = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M4 6h16M4 12h16M4 18h16" /></svg>
);
export const IcPlus = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M12 5v14M5 12h14" /></svg>
);
export const IcCopy = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h8" /></svg>
);
export const IcEdit = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M4 20h4L19 9l-4-4L4 16z" /><path d="M14 6l4 4" /></svg>
);
export const IcDownload = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M12 3v12M6 11l6 6 6-6" /><path d="M4 21h16" /></svg>
);
export const IcStar = ({ size, filled = false }: P & { filled?: boolean }): JSX.Element => (
  <svg {...S(size)} fill={filled ? "currentColor" : "none"}>
    <path d="M12 3l2.8 5.7 6.2.9-4.5 4.4 1.1 6.2L12 17.3 6.4 20.2l1.1-6.2L3 9.6l6.2-.9z" />
  </svg>
);
export const IcEye = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>
);
export const IcLock = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></svg>
);
export const IcKey = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><circle cx="8" cy="8" r="4" /><path d="m11 11 9 9M17 17l2-2M14 14l2-2" /></svg>
);
export const IcNote = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><rect x="5" y="3" width="14" height="18" rx="2" /><path d="M9 8h6M9 12h6M9 16h4" /></svg>
);
export const IcCard = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 10h18" /></svg>
);
export const IcX = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M6 6l12 12M18 6 6 18" /></svg>
);
export const IcRefresh = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M20 11a8 8 0 1 0-1.5 5" /><path d="M20 5v6h-6" /></svg>
);
export const IcUpload = ({ size }: P): JSX.Element => (
  <svg {...S(size)}><path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" /><path d="M12 16V4M7 9l5-5 5 5" /></svg>
);
