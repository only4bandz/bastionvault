import type { JSX } from "react";
import { itemColor, type VaultItem } from "../lib/types";
import { detectScheme, type Scheme } from "../lib/bin";
import { IcCard } from "./icons";

type IconItem = Pick<
  VaultItem,
  "type" | "url" | "title" | "cardNumber" | "cardBrand" | "cardBankDomain"
>;

/**
 * Item icon rendered entirely from local data. No saved domain or card prefix
 * is disclosed to a favicon or issuer lookup service.
 */
export function Favicon({ item, size = 36 }: { item: IconItem; size?: number }): JSX.Element {
  if (item.type === "card") {
    const scheme = (item.cardBrand as Scheme) || detectScheme(item.cardNumber || "");
    return <SchemeBadge scheme={scheme} title={item.title} size={size} />;
  }
  return <LetterTile title={item.title} size={size} />;
}

export function SchemeBadge({
  scheme,
  title,
  size,
}: {
  scheme: Scheme;
  title: string;
  size: number;
}): JSX.Element {
  if (scheme === "mastercard") {
    return (
      <span className="fav-ico" style={{ width: size, height: size, background: "#16191f" }}>
        <svg width={size * 0.66} height={size * 0.42} viewBox="0 0 32 20" aria-hidden>
          <circle cx="12" cy="10" r="9" fill="#EB001B" />
          <circle cx="20" cy="10" r="9" fill="#F79E1B" />
          <path d="M16 3.2a9 9 0 000 13.6 9 9 0 000-13.6z" fill="#FF5F00" />
        </svg>
      </span>
    );
  }
  if (scheme === "visa") {
    return (
      <span className="fav-ico" style={{ width: size, height: size, background: "#1434CB" }}>
        <span style={{ color: "#fff", fontWeight: 800, fontStyle: "italic", fontSize: size * 0.3 }}>
          VISA
        </span>
      </span>
    );
  }
  if (scheme === "amex") {
    return (
      <span className="fav-ico" style={{ width: size, height: size, background: "#1f72cd" }}>
        <span style={{ color: "#fff", fontWeight: 800, fontSize: size * 0.27 }}>AMEX</span>
      </span>
    );
  }
  if (scheme === "discover") {
    return (
      <span className="fav-ico" style={{ width: size, height: size, background: "#16191f" }}>
        <span style={{ color: "#ff6000", fontWeight: 800, fontSize: size * 0.27 }}>DISC</span>
      </span>
    );
  }
  return (
    <span className="fav-ico" style={{ width: size, height: size, background: itemColor(title) }}>
      <IcCard size={size * 0.5} />
    </span>
  );
}

function LetterTile({ title, size }: { title: string; size: number }): JSX.Element {
  return (
    <span
      className="fav-ico"
      style={{ width: size, height: size, background: itemColor(title), fontSize: size * 0.42 }}
    >
      {(title[0] || "?").toUpperCase()}
    </span>
  );
}
