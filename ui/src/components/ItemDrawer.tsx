import { useEffect, useState } from "react";
import { api, ApiFailure } from "../api";
import type { Key } from "../i18n";
import type { AuditRecord, Item } from "../types";
import { bytes, copyText, emoji, fileToBase64, fmtTime, fmtWhen } from "../util";
import { useToast } from "./Toast";
import { Badges } from "./Items";

type T = (k: Key, v?: Record<string, string | number>) => string;

export default function ItemDrawer({ t, sref, onClose, onChanged }: { t: T; sref: string; onClose: () => void; onChanged: () => void }) {
  const [item, setItem] = useState<Item | null>(null);
  const [tab, setTab] = useState<"detail" | "audit" | "versions">("detail");
  const [audit, setAudit] = useState<AuditRecord[]>([]);
  const [reveal, setReveal] = useState<{ value: string; hideAt: number } | null>(null);
  const [needPw, setNeedPw] = useState(false);
  const [pw, setPw] = useState("");
  const [newVal, setNewVal] = useState("");
  const [newB64, setNewB64] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [, tick] = useState(0);
  const toast = useToast();

  useEffect(() => { api.item(sref).then(setItem).catch(() => onClose()); }, [sref]);
  useEffect(() => { if (tab === "audit") api.audit(1, 200, sref).then((r) => setAudit(r.records.reverse())).catch(() => {}); }, [tab, sref]);
  useEffect(() => { const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); }; window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h); }, [onClose]);
  useEffect(() => {
    if (!reveal) return;
    const i = setInterval(() => { tick((x) => x + 1); if (Date.now() >= reveal.hideAt) setReveal(null); }, 500);
    return () => clearInterval(i);
  }, [reveal]);

  async function doReveal(passphrase?: string) {
    try {
      const r = await api.reveal(sref, passphrase);
      setReveal({ value: r.value ?? `(base64) ${r.value_base64}`, hideAt: Date.now() + 30_000 });
      setNeedPw(false); setPw("");
    } catch (e) {
      if (e instanceof ApiFailure && (e.body.error === "invalid_request" || e.body.error === "bad_passphrase")) {
        setNeedPw(true);
        if (e.body.error === "bad_passphrase") toast({ title: t("bad_passphrase"), bad: true });
      } else toast({ title: t("error_generic"), body: String(e), bad: true });
    }
  }
  async function patch(b: Record<string, unknown>) {
    try { setItem(await api.patchItem(sref, b)); onChanged(); } catch (e) { toast({ title: t("error_generic"), body: String(e), bad: true }); }
  }
  async function addVersion() {
    try {
      await api.addVersion(sref, newB64 ? { value_base64: newB64, note: note || undefined } : { value: newVal, note: note || undefined });
      setNewVal(""); setNewB64(null); setNote("");
      setItem(await api.item(sref)); onChanged();
      toast({ title: `✅ ${t("add_version")}` });
    } catch (e) { toast({ title: t("error_generic"), body: String(e), bad: true }); }
  }

  if (!item) return null;
  return (
    <div className="overlay" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <h2>{emoji(item.type)} {item.name ?? item.sref} <Badges i={item} t={t} /></h2>
        <div className="mono small muted" style={{ wordBreak: "break-all" }}>{item.path} · {item.sref}</div>
        <div className="tabs">
          {(["detail", "versions", "audit"] as const).map((k) => (
            <button key={k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>{t(k === "detail" ? "detail" : k === "audit" ? "audit_tab" : "versions")}</button>
          ))}
        </div>

        {tab === "detail" && (
          <>
            <dl className="kv">
              <dt>{t("type")}</dt><dd>{emoji(item.type)} {t(`type_${item.type}` as Key)}</dd>
              <dt>{t("env")}</dt><dd>{item.env ?? "—"}</dd>
              <dt>{t("tags")}</dt><dd>{(item.tags ?? []).map((x) => <span key={x} className="chip" style={{ marginRight: 4 }}>#{x}</span>)}</dd>
              <dt>{t("version")}</dt><dd>v{item.version} · {bytes(item.size)}</dd>
              <dt>{t("created")}</dt><dd>{fmtTime(item.created)}</dd>
              <dt>{t("updated")}</dt><dd>{fmtTime(item.updated)}</dd>
              <dt>{t("expires")}</dt><dd>{item.expires_at ? fmtTime(item.expires_at) : t("never")}</dd>
            </dl>
            <div style={{ display: "flex", gap: 14, margin: "14px 0", flexWrap: "wrap" }}>
              <label style={{ display: "flex", gap: 6, alignItems: "center", color: "inherit" }}>
                <input type="checkbox" style={{ width: "auto" }} checked={item.approval_required} onChange={(e) => patch({ approval_required: e.target.checked })} /> 🔴 {t("approval_required")}
              </label>
              <label style={{ display: "flex", gap: 6, alignItems: "center", color: "inherit" }}>
                <input type="checkbox" style={{ width: "auto" }} checked={item.local_approval_only} onChange={(e) => patch({ local_approval_only: e.target.checked })} /> 🏠 {t("local_only")}
              </label>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn" onClick={() => copyText(`${location.origin}/v1/secrets/${item.sref}`).then(() => toast({ title: `📋 ${t("copied_title")}`, body: t("copied_body") }))}>📋 {t("copy_ref")}</button>
              <button className="btn primary" onClick={() => doReveal()}>👁 {t("reveal")}</button>
            </div>
            {needPw && (
              <div className="card" style={{ marginTop: 14 }}>
                <p className="small muted" style={{ marginTop: 0 }}>{t("reveal_needs_pw")}</p>
                <div style={{ display: "flex", gap: 8 }}>
                  <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder={t("passphrase")} autoFocus onKeyDown={(e) => { if (e.key === "Enter") doReveal(pw); }} />
                  <button className="btn primary" onClick={() => doReveal(pw)} disabled={!pw}>{t("reveal")}</button>
                </div>
              </div>
            )}
            {reveal && (
              <div className="card" style={{ marginTop: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <strong>{t("reveal_title")}</strong>
                  <span className="countdown">{t("reveal_hide_in", { s: Math.max(0, Math.ceil((reveal.hideAt - Date.now()) / 1000)) })}</span>
                </div>
                <div className="value-box" style={{ marginTop: 8 }}>{reveal.value}</div>
                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <button className="btn sm" onClick={() => copyText(reveal.value).then(() => toast({ title: t("value_copied") }))}>📋 {t("copy_value")}</button>
                  <button className="btn sm" onClick={() => setReveal(null)}>{t("close")}</button>
                </div>
              </div>
            )}
          </>
        )}

        {tab === "versions" && (
          <>
            <p className="small muted">v{item.version} · {t("updated")} {fmtTime(item.updated)}</p>
            <div className="field"><label>{t("value")}</label>
              <textarea value={newVal} onChange={(e) => { setNewVal(e.target.value); setNewB64(null); }} placeholder={t("value_hint")} />
              <input type="file" style={{ marginTop: 6 }} onChange={async (e) => { const f = e.target.files?.[0]; if (f) { setNewB64(await fileToBase64(f)); setNewVal(`📎 ${f.name} (${bytes(f.size)})`); } }} />
            </div>
            <div className="field"><label>{t("note")}</label><input value={note} onChange={(e) => setNote(e.target.value)} /></div>
            <button className="btn primary" onClick={addVersion} disabled={!newVal && !newB64}>➕ {t("add_version")}</button>
          </>
        )}

        {tab === "audit" && (
          <table>
            <thead><tr><th>{t("when")}</th><th>{t("actor")}</th><th>{t("action")}</th><th>{t("outcome")}</th></tr></thead>
            <tbody>
              {audit.map((r) => (
                <tr key={r.n}>
                  <td className="small" style={{ whiteSpace: "nowrap" }}>{fmtWhen(r.ts)}</td>
                  <td className="mono small" title={r.actor}>{r.actor.replace(/^human:hs_([0-9a-f]{6}).*/, "human:$1…")}</td>
                  <td>{r.action}{typeof r.meta.reason === "string" && r.meta.reason ? <div className="small muted">“{r.meta.reason}”</div> : null}</td>
                  <td><span className={`badge ${r.outcome === "ok" ? "ok" : r.outcome === "denied" ? "bad" : ""}`}>{r.outcome}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </aside>
    </div>
  );
}
