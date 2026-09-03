import { useEffect, useState } from "react";
import { api } from "../api";
import type { Key } from "../i18n";
import type { Session } from "../types";
import { fmtDuration, fmtTime, secondsUntil } from "../util";

type T = (k: Key, v?: Record<string, string | number>) => string;

export default function Sessions({ t, refreshKey, refresh }: { t: T; refreshKey: number; refresh: () => void }) {
  const [list, setList] = useState<Session[]>([]);
  const [, tick] = useState(0);
  async function load() { try { setList((await api.sessions()).sessions); } catch { /* */ } }
  useEffect(() => { load(); const i = setInterval(() => { load(); tick((x) => x + 1); }, 2000); return () => clearInterval(i); }, [refreshKey]);
  return (
    <>
      <p className="muted small">{t("session_hint")}</p>
      {list.length === 0 && <div className="empty">{t("no_sessions")}</div>}
      <div className="list">
        {list.map((s) => (
          <div key={s.id} className="card" style={{ display: "flex", gap: 14, alignItems: "center" }}>
            <span style={{ fontSize: 24 }}>▶️</span>
            <div style={{ flex: 1 }}>
              <div>{(s.scope?.paths ?? []).map((p) => <span key={p} className="chip" style={{ marginRight: 4 }}>{p}</span>)}{(s.scope?.tags ?? []).map((p) => <span key={p} className="chip" style={{ marginRight: 4 }}>#{p}</span>)}</div>
              <div className="small muted">{fmtTime(s.opened)} → {fmtTime(s.expires_at)} · <span className="mono">{s.id}</span></div>
            </div>
            <span className="countdown">{fmtDuration(Math.max(0, secondsUntil(s.expires_at) ?? 0))}</span>
            <button className="btn sm danger" onClick={async () => { await api.closeSession(s.id); load(); refresh(); }}>{t("end_session")}</button>
          </div>
        ))}
      </div>
    </>
  );
}
