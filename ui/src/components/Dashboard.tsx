import { useEffect, useState } from "react";
import { useToast } from "./Toast";
import { api } from "../api";
import type { Key } from "../i18n";
import type { Item, Status } from "../types";
import { isExpiringSoon } from "../util";

export default function Dashboard({ t, status }: { t: (k: Key, v?: Record<string, string | number>) => string; status: Status | null }) {
  const [items, setItems] = useState<Item[]>([]);
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const toast = useToast();
  useEffect(() => { api.items().then((r) => setItems(r.items)).catch(() => {}); }, [status?.items]);
  const expiring = items.filter((i) => isExpiringSoon(i.expires_at)).length;
  const chain = status?.chain;
  return (
    <>
      <div className="tiles">
        <Tile k={t("tile_items")} v={status?.items ?? "—"} e="🗝️" />
        <Tile k={t("tile_expiring")} v={expiring} e="⏰" warn={expiring > 0} />
        <Tile k={t("tile_pending")} v={status?.pending_approvals ?? 0} e="✋" warn={(status?.pending_approvals ?? 0) > 0} href="#/approvals" />
        <Tile k={t("tile_sessions")} v={status?.active_sessions ?? 0} e="▶️" />
        <Tile k={t("tile_tokens")} v={status?.live_tokens ?? 0} e="🎫" href="#/tokens" />
        <Tile k={t("tile_chain")} v={chain ? (chain.intact ? `✅ ${t("chain_intact")}` : `⚠️ ${t("chain_broken", { n: chain.broken_at ?? 0 })}`) : "—"} e="🧾" href="#/audit" small />
      </div>
      <div className="card" style={{ marginBottom: 14 }}>
        <h3 style={{ marginTop: 0 }}>🔑 {t("change_pw")}</h3>
        <p className="muted small">{t("change_pw_hint")}</p>
        <div className="grid2">
          <div className="field"><label>{t("current_pw")}</label><input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" /></div>
          <div className="field"><label>{t("new_pw")}</label><input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" /></div>
        </div>
        <button className="btn primary" disabled={!cur || next.length < 12} onClick={async () => {
          try { await api.changePassphrase(cur, next); setCur(""); setNext(""); toast({ title: `🔑 ${t("pw_changed")}` }); setTimeout(() => location.reload(), 1200); }
          catch (e) { toast({ title: t("error_generic"), body: String(e), bad: true }); }
        }}>🔑 {t("change_pw")}</button>
      </div>
      <div className="card">
        <div className="kv">
          <dt>version</dt><dd className="mono">{status?.version}</dd>
          <dt>uptime</dt><dd>{status?.uptime}s</dd>
          <dt>KDF</dt><dd className="mono">{status?.kdf ? `Argon2id ${status.kdf.m_cost_kib / 1024} MiB · t=${status.kdf.t_cost} · p=${status.kdf.p_cost}` : "—"}</dd>
          <dt>{t("head")}</dt><dd className="mono small" style={{ wordBreak: "break-all" }}>{chain?.head ?? "—"}</dd>
        </div>
      </div>
    </>
  );
}

function Tile({ k, v, e, warn, href, small }: { k: string; v: string | number; e: string; warn?: boolean; href?: string; small?: boolean }) {
  const inner = (
    <div className="tile" style={warn ? { borderColor: "var(--warn)" } : undefined}>
      <div className="k">{e} {k}</div>
      <div className="v" style={small ? { fontSize: 18 } : undefined}>{v}</div>
    </div>
  );
  return href ? <a href={href} style={{ textDecoration: "none", color: "inherit" }}>{inner}</a> : inner;
}
