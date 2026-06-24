import { useMemo, useState, type JSX } from "react";
import { itemColor, type VaultItem } from "../lib/types";

type IconItem = Pick<VaultItem, "type" | "url" | "title">;

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
 * Real site favicon (via DuckDuckGo's privacy-respecting icon service), with a
 * graceful fallback to a coloured letter tile. The Bastion server never sees
 * the domain — items are encrypted; only the browser resolves the icon.
 */
export function Favicon({ item, size = 36 }: { item: IconItem; size?: number }): JSX.Element {
  const domain = useMemo(() => domainFor(item), [item]);
  const [failed, setFailed] = useState(false);

  if (domain && !failed) {
    return (
      <img
        className="fav-ico fav-img"
        style={{ width: size, height: size }}
        src={`https://icons.duckduckgo.com/ip3/${domain}.ico`}
        onError={() => setFailed(true)}
        alt=""
        loading="lazy"
      />
    );
  }
  return (
    <div
      className="fav-ico"
      style={{ width: size, height: size, background: itemColor(item.title), fontSize: size * 0.42 }}
    >
      {(item.title[0] || "?").toUpperCase()}
    </div>
  );
}
