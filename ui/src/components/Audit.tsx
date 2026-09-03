import { useEffect, useState } from "react";
import { api } from "../api";
import type { Key } from "../i18n";
import type { AuditRecord } from "../types";
import { fmtWhen } from "../util";

type T = (k: Key, v?: Record<string, string | number>) => string;
const PAGE = 50;

export default function Audit({ t, refreshKey }: { t: T; refreshKey: number }) {
  const [recs, setRecs] = useState<AuditRecord[]>([]);
  const [from, setFrom] = useState(1);
  const [verify, setVerify] = useState<{ intact: boolean; len?: number; head?: string; broken_at?: number } | null>(null);
  async function load() {
    try {
      const v = await api.auditVerify(); setVerify(v);
      const start = from === 1 && v.len ? Math.max(1, v.len - PAGE + 1) : from;
      if (from === 1 && v.len) setFrom(start);
      setRecs((await api.audit(start, PAGE)).records.reverse());
    } catch { /* */ }
  }
  useEffect(() => { load(); }, [refreshKey, from]);
  return (
    <>
      <div className="card" style={{ display: "flex", gap: 14, alignItems: "center", marginBottom: 14 }}>
        <span style={{ fontSize: 22 }}>{verify?.intact ? "✅" : verify ? "⚠️" : "…"}</span>
        <div style={{ flex: 1 }}>
          <strong>{verify?.intact ? t("chain_intact") : verify ? t("chain_broken", { n: verify.broken_at ?? 0 }) : "—"}</strong>
          <div className="small muted">{verify?.len ?? 0} {t("records")} · {t("head")} <span className="mono">{verify?.head?.slice(0, 16)}…</span></div>
        </div>
        <button className="btn" onClick={load}>🔁 {t("verify")}</button>
        <button className="btn sm" onClick={() => setFrom((f) => Math.max(1, f - PAGE))} disabled={from <= 1}>← {t("prev")}</button>
        <button className="btn sm" onClick={() => setFrom((f) => f + PAGE)} disabled={!verify?.len || from + PAGE > verify.len}>{t("next")} →</button>
      </div>
      <table>
        <thead><tr><th>#</th><th>{t("when")}</th><th>{t("actor")}</th><th>{t("action")}</th><th>{t("subject")}</th><th>{t("outcome")}</th></tr></thead>
        <tbody>
          {recs.map((r) => (
            <tr key={r.n}>
              <td className="mono small">{r.n}</td>
              <td className="small" style={{ whiteSpace: "nowrap" }}>{fmtWhen(r.ts)}</td>
              <td className="mono small">{r.actor}</td>
              <td>{r.action}{typeof r.meta.reason === "string" && r.meta.reason ? <div className="small muted">“{r.meta.reason}”</div> : null}</td>
              <td className="mono small">{r.subject ? <a href={r.subject.startsWith("sref_") ? `#/items?open=${r.subject}` : "#/tokens"}>{r.subject}</a> : "—"}</td>
              <td><span className={`badge ${r.outcome === "ok" ? "ok" : r.outcome === "denied" || r.outcome === "error" ? "bad" : r.outcome === "timeout" ? "warn" : ""}`}>{r.outcome}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
