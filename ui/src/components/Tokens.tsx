import { useEffect, useState } from "react";
import { api } from "../api";
import type { Key } from "../i18n";
import type { Grant, Item, Token } from "../types";
import { copyText, fmtTime, parseList, secondsUntil, fmtDuration } from "../util";
import { useToast } from "./Toast";

type T = (k: Key, v?: Record<string, string | number>) => string;

export default function Tokens({ t, refreshKey, refresh, presetPath }: { t: T; refreshKey: number; refresh: () => void; presetPath?: string }) {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [items, setItems] = useState<Item[]>([]);
  const [gTok, setGTok] = useState("");
  const [gItem, setGItem] = useState("");
  const [gTtl, setGTtl] = useState(1800);
  const [minting, setMinting] = useState(!!presetPath);
  const [minted, setMinted] = useState<Token | null>(null);
  const [label, setLabel] = useState("");
  const [paths, setPaths] = useState(presetPath ?? "");
  const [tags, setTags] = useState("");
  const [lifetime, setLifetime] = useState(86400);
  const [maxReads, setMaxReads] = useState("");
  const [rate, setRate] = useState(60);
  const toast = useToast();

  async function load() { try { setTokens((await api.tokens()).tokens); setGrants((await api.grants()).grants); setItems((await api.items()).items.filter((i) => i.approval_required)); } catch { /* */ } }
  useEffect(() => { load(); const i = setInterval(load, 10_000); return () => clearInterval(i); }, [refreshKey]);

  async function mint() {
    try {
      const tok = await api.mint({ label: label.trim(), scope: { paths: parseList(paths), tags: parseList(tags) }, lifetime, max_reads: maxReads ? Number(maxReads) : null, rate_limit_per_min: rate });
      setMinted(tok); setMinting(false); setLabel(""); setPaths(""); setTags(""); setMaxReads("");
      load(); refresh();
    } catch (e) { toast({ title: t("error_generic"), body: String(e), bad: true }); }
  }
  async function revoke(id: string) { await api.revoke(id); load(); refresh(); }

  return (
    <>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14 }}>
        <button className="btn primary" onClick={() => setMinting(true)}>🎫 {t("mint")}</button>
      </div>
      <table>
        <thead><tr><th>{t("label")}</th><th>scope</th><th>{t("expires")}</th><th>{t("reads")}</th><th>{t("rate")}</th><th></th></tr></thead>
        <tbody>
          {tokens.map((k) => {
            const left = secondsUntil(k.expires_at) ?? 0;
            return (
              <tr key={k.id} style={{ opacity: k.live ? 1 : 0.55 }}>
                <td><strong>{k.label ?? "•••"}</strong><div className="mono small muted">{k.id}</div></td>
                <td>{(k.scope?.paths ?? []).map((p) => <span key={p} className="chip" style={{ marginRight: 4 }}>{p}</span>)}{(k.scope?.tags ?? []).map((p) => <span key={p} className="chip" style={{ marginRight: 4 }}>#{p}</span>)}</td>
                <td>{k.revoked_at ? <span className="badge bad">{t("revoked")}</span> : k.live ? <><span className="badge ok">{t("live")}</span> <span className="small muted">{fmtDuration(left)}</span></> : <span className="badge">{t("expired_t")}</span>}<div className="small muted">{fmtTime(k.expires_at)}</div></td>
                <td>{k.reads_used}{k.max_reads !== null ? ` / ${k.max_reads}` : ""}</td>
                <td>{k.rate_limit_per_min}/min</td>
                <td>{!k.revoked_at && <button className="btn sm danger" onClick={() => revoke(k.id)}>{t("revoke")}</button>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <h3 style={{ marginTop: 28 }}>🎟️ {t("grants_title")}</h3>
      <p className="muted small">{t("grant_hint")}</p>
      <div className="card" style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 12 }}>
        <div className="field" style={{ margin: 0, flex: 1 }}><label>{t("grant_token")}</label>
          <select value={gTok} onChange={(e) => setGTok(e.target.value)}><option value="">—</option>{tokens.filter((k) => k.live).map((k) => <option key={k.id} value={k.id}>{k.label ?? k.id}</option>)}</select></div>
        <div className="field" style={{ margin: 0, flex: 1 }}><label>{t("grant_item")}</label>
          <select value={gItem} onChange={(e) => setGItem(e.target.value)}><option value="">—</option>{items.map((i) => <option key={i.sref} value={i.sref}>{i.name ?? i.sref} · {i.path}</option>)}</select></div>
        <div className="field" style={{ margin: 0 }}><label>{t("grant_ttl")}</label>
          <select value={gTtl} onChange={(e) => setGTtl(Number(e.target.value))}><option value={900}>15 min</option><option value={1800}>30 min</option><option value={3600}>1 h</option><option value={7200}>2 h</option><option value={28800}>8 h</option></select></div>
        <button className="btn primary" disabled={!gTok || !gItem} onClick={async () => { try { await api.grant(gTok, gItem, gTtl); setGTok(""); setGItem(""); load(); refresh(); } catch (e) { toast({ title: t("error_generic"), body: String(e), bad: true }); } }}>🎟️ {t("grant_new")}</button>
      </div>
      {grants.length === 0 ? <div className="muted small">{t("no_grants")}</div> : (
        <table><thead><tr><th>{t("grant_token")}</th><th>{t("grant_item")}</th><th>source</th><th>{t("grant_until")}</th><th></th></tr></thead><tbody>
          {grants.map((g) => (
            <tr key={g.token_id + g.sref}><td><strong>{g.token_label ?? g.token_id}</strong></td><td>{g.item_name ?? g.sref}</td>
              <td><span className={`badge ${g.source === "pre-authorized" ? "info" : "ok"}`}>{g.source === "pre-authorized" ? t("grant_source_pre") : t("grant_source_approval")}</span></td>
              <td className="small">{fmtTime(g.until)} <span className="muted">({fmtDuration(Math.max(0, secondsUntil(g.until) ?? 0))})</span></td>
              <td><button className="btn sm danger" onClick={async () => { await api.revokeGrant(g.token_id, g.sref); load(); refresh(); }}>{t("grant_revoke")}</button></td></tr>
          ))}
        </tbody></table>
      )}

      {minting && (
        <div className="overlay center" onClick={() => setMinting(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <h2>🎫 {t("mint")}</h2>
            <div className="field"><label>{t("label")}</label><input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="deploy-bot" autoFocus /></div>
            <div className="grid2">
              <div className="field"><label>{t("scope_paths")}</label><input value={paths} onChange={(e) => setPaths(e.target.value)} placeholder="prod/gcp" /></div>
              <div className="field"><label>{t("scope_tags")}</label><input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="mobile" /></div>
              <div className="field"><label>{t("lifetime")}</label>
                <select value={lifetime} onChange={(e) => setLifetime(Number(e.target.value))}>
                  <option value={1800}>30 min</option><option value={3600}>1 h</option><option value={8 * 3600}>8 h</option>
                  <option value={86400}>24 h</option><option value={7 * 86400}>7 d</option><option value={30 * 86400}>30 d</option>
                </select>
              </div>
              <div className="field"><label>{t("max_reads")}</label><input type="number" min={1} value={maxReads} onChange={(e) => setMaxReads(e.target.value)} /></div>
              <div className="field"><label>{t("rate")}</label><input type="number" min={1} value={rate} onChange={(e) => setRate(Number(e.target.value))} /></div>
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button className="btn" onClick={() => setMinting(false)}>{t("cancel")}</button>
              <button className="btn primary" onClick={mint} disabled={!label.trim() || (!paths.trim() && !tags.trim())}>🎫 {t("mint")}</button>
            </div>
          </div>
        </div>
      )}

      {minted && (
        <div className="overlay center" onClick={() => setMinted(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <h2>🎫 {t("minted_title")}</h2>
            <p className="muted small">{t("minted_body")}</p>
            <div className="value-box">{minted.value}</div>
            <div className="value-box small" style={{ marginTop: 8 }}>{`{ "mcpServers": { "bsc": { "command": "bsc", "args": ["mcp"], "env": { "BSC_TOKEN": "${minted.value}" } } } }`}</div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
              <button className="btn" onClick={() => copyText(minted.value ?? "").then(() => toast({ title: `📋 ${t("copy_token")}` }))}>📋 {t("copy_token")}</button>
              <button className="btn primary" onClick={() => setMinted(null)}>{t("close")}</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
