import type { JSX } from "react";

export function ShieldLogo({ size = 34 }: { size?: number }): JSX.Element {
  return (
    <svg className="logo" width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <defs>
        <linearGradient id="bastion-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#9a8cff" />
          <stop offset="1" stopColor="#5a47e6" />
        </linearGradient>
      </defs>
      <path fill="url(#bastion-g)" d="M16 2l11 4v8.5c0 7-4.7 12.9-11 15.5C9.7 27.4 5 21.5 5 14.5V6l11-4z" />
      <path fill="#0a0c12" d="M16 10.5a3 3 0 00-1.5 5.6l-1.1 4.9h5.2l-1.1-4.9A3 3 0 0016 10.5z" />
    </svg>
  );
}

export function Brand({ size = 34 }: { size?: number }): JSX.Element {
  return (
    <div className="brand">
      <ShieldLogo size={size} />
      <span className="name">
        <b>BASTION</b>
      </span>
    </div>
  );
}
