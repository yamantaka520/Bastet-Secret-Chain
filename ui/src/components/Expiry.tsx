import { useEffect, useState } from "react";
import { api } from "../api";
import type { Key } from "../i18n";
import type { Item, Token } from "../types";
import { emoji, fmtTime, secondsUntil } from "../util";

type T = (k: Key, v?: Record<string, string | number>) => string;

function left(t: T, iso: string | null) {
  const s = secondsUntil(iso);
  if (s === null) return "—";
  if (s <= 0) return `⛔ ${t("expired")}`;
  if (s > 86400) return `⏰ ${t("days_left", { d: Math.floor(s / 86400) })}`;
  return `⏰ ${t("hours_left", { h: Math.max(1, Math.floor(s / 3600)) })}`;
}

export default function Expiry({ t, refreshKey }: { t: T; refreshKey: number }) {
  const [items, setItems] = useState<Item[]>([]);
  const [tokens, setTokens] = useState<Token[]>([]);
  useEffect(() => {
    api.items().then((r) => setItems(r.items.filter((i) => i.expires_at).sort((a, b) => (secondsUntil(a.expires_at) ?? 0) - (secondsUntil(b.expires_at) ?? 0)))).catch(() => {});
    api.tokens().then((r) => setTokens(r.tokens.filter((k) => !k.revoked_at).sort((a, b) => (secondsUntil(a.expires_at) ?? 0) - (secondsUntil(b.expires_at) ?? 0)))).catch(() => {});
  }, [refreshKey]);
  const cls = (iso: string | null) => { const s = secondsUntil(iso); return s !== null && s <= 0 ? "bad" : s !== null && s < 30 * 86400 ? "warn" : "ok"; };
  return (
    <div className="grid2">
      <div className="card">
        <h3 style={{ marginTop: 0 }}>🗝️ {t("expiry_items")}</h3>
        {items.length === 0 && <div className="muted small">{t("nothing_expiring")}</div>}
        <table><tbody>
          {items.map((i) => (
            <tr key={i.sref}><td>{emoji(i.type)} <a href={`#/items?open=${i.sref}`}>{i.name ?? i.sref}</a><div className="mono small muted">{i.path}</div></td>
              <td><span className={`badge ${cls(i.expires_at)}`}>{left(t, i.expires_at)}</span><div className="small muted">{fmtTime(i.expires_at)}</div></td></tr>
          ))}
        </tbody></table>
      </div>
      <div className="card">
        <h3 style={{ marginTop: 0 }}>🎫 {t("expiry_tokens")}</h3>
        <table><tbody>
          {tokens.map((k) => (
            <tr key={k.id}><td><strong>{k.label ?? k.id}</strong><div className="mono small muted">{k.id}</div></td>
              <td><span className={`badge ${cls(k.expires_at)}`}>{left(t, k.expires_at)}</span><div className="small muted">{fmtTime(k.expires_at)}</div></td></tr>
          ))}
        </tbody></table>
      </div>
    </div>
  );
}
