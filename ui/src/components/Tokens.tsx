import { useEffect, useState } from "react";
import { api } from "../api";
import type { Key } from "../i18n";
import type { Token } from "../types";
import { copyText, fmtTime, parseList, secondsUntil, fmtDuration } from "../util";
import { useToast } from "./Toast";

type T = (k: Key, v?: Record<string, string | number>) => string;

export default function Tokens({ t, refreshKey, refresh, presetPath }: { t: T; refreshKey: number; refresh: () => void; presetPath?: string }) {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [minting, setMinting] = useState(!!presetPath);
  const [minted, setMinted] = useState<Token | null>(null);
  const [label, setLabel] = useState("");
  const [paths, setPaths] = useState(presetPath ?? "");
  const [tags, setTags] = useState("");
  const [lifetime, setLifetime] = useState(86400);
  const [maxReads, setMaxReads] = useState("");
  const [rate, setRate] = useState(60);
  const toast = useToast();

  async function load() { try { setTokens((await api.tokens()).tokens); } catch { /* */ } }
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
