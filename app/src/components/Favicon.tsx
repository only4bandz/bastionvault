import { useEffect, useMemo, useState, type JSX } from "react";
import { itemColor, type VaultItem } from "../lib/types";
import { detectScheme, lookupBin, type Scheme } from "../lib/bin";
import { IcCard } from "./icons";

type IconItem = Pick<
  VaultItem,
  "type" | "url" | "title" | "cardNumber" | "cardBrand" | "cardBankDomain"
>;

function ddg(domain: string): string {
  return `https://icons.duckduckgo.com/ip3/${domain}.ico`;
}

/** Best-effort domain for a login item, from its URL or its title. */
function domainFor(item: IconItem): string | null {
  if (item.type !== "login") return null;
  const candidate = (item.url || item.title || "").trim();
  if (!candidate.includes(".")) return null;
  let host = candidate;
  try {
    host = /^https?:\/\//i.test(candidate) ? new URL(candidate).hostname : candidate.split("/")[0];
  } catch {
    host = candidate.split("/")[0];
  }
  host = host.toLowerCase().replace(/^www\./, "");
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(host) ? host : null;
}

/**
 * Item icon: real site favicon for logins, issuer-bank logo for cards (detected
 * from the BIN), with a graceful fallback to a network badge or letter tile.
 * The Bastion server never sees the domain or card — only the browser resolves.
 */
export function Favicon({ item, size = 36 }: { item: IconItem; size?: number }): JSX.Element {
  if (item.type === "card") return <CardIcon item={item} size={size} />;
  if (item.type === "login") return <LoginIcon item={item} size={size} />;
  return <LetterTile title={item.title} size={size} />;
}

function LoginIcon({ item, size }: { item: IconItem; size: number }): JSX.Element {
  const domain = useMemo(() => domainFor(item), [item]);
  const [failed, setFailed] = useState(false);
  if (domain && !failed) {
    return (
      <img
        className="fav-ico fav-img"
        style={{ width: size, height: size }}
        src={ddg(domain)}
        onError={() => setFailed(true)}
        alt=""
        loading="lazy"
      />
    );
  }
  return <LetterTile title={item.title} size={size} />;
}

function CardIcon({ item, size }: { item: IconItem; size: number }): JSX.Element {
  const bin = (item.cardNumber || "").replace(/\D/g, "").slice(0, 8);
  const [domain, setDomain] = useState<string | null>(item.cardBankDomain ?? null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (item.cardBankDomain) {
      setDomain(item.cardBankDomain);
      return;
    }
    if (bin.length < 6) return;
    let active = true;
    lookupBin(bin).then((r) => active && setDomain(r?.bankDomain ?? null));
    return () => {
      active = false;
    };
  }, [bin, item.cardBankDomain]);

  if (domain && !failed) {
    return (
      <img
        className="fav-ico fav-img"
        style={{ width: size, height: size }}
        src={ddg(domain)}
        onError={() => setFailed(true)}
        alt=""
        loading="lazy"
      />
    );
  }
  const scheme = (item.cardBrand as Scheme) || detectScheme(item.cardNumber || "");
  return <SchemeBadge scheme={scheme} title={item.title} size={size} />;
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
      <div className="fav-ico" style={{ width: size, height: size, background: "#16191f" }}>
        <svg width={size * 0.66} height={size * 0.42} viewBox="0 0 32 20" aria-hidden>
          <circle cx="12" cy="10" r="9" fill="#EB001B" />
          <circle cx="20" cy="10" r="9" fill="#F79E1B" />
          <path d="M16 3.2a9 9 0 000 13.6 9 9 0 000-13.6z" fill="#FF5F00" />
        </svg>
      </div>
    );
  }
  if (scheme === "visa") {
    return (
      <div className="fav-ico" style={{ width: size, height: size, background: "#1434CB" }}>
        <span style={{ color: "#fff", fontWeight: 800, fontStyle: "italic", fontSize: size * 0.3 }}>
          VISA
        </span>
      </div>
    );
  }
  if (scheme === "amex") {
    return (
      <div className="fav-ico" style={{ width: size, height: size, background: "#1f72cd" }}>
        <span style={{ color: "#fff", fontWeight: 800, fontSize: size * 0.27 }}>AMEX</span>
      </div>
    );
  }
  if (scheme === "discover") {
    return (
      <div className="fav-ico" style={{ width: size, height: size, background: "#16191f" }}>
        <span style={{ color: "#ff6000", fontWeight: 800, fontSize: size * 0.27 }}>DISC</span>
      </div>
    );
  }
  return (
    <div className="fav-ico" style={{ width: size, height: size, background: itemColor(title) }}>
      <IcCard size={size * 0.5} />
    </div>
  );
}

function LetterTile({ title, size }: { title: string; size: number }): JSX.Element {
  return (
    <div
      className="fav-ico"
      style={{ width: size, height: size, background: itemColor(title), fontSize: size * 0.42 }}
    >
      {(title[0] || "?").toUpperCase()}
    </div>
  );
}
