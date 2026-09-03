import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { Key } from "../i18n";
import type { Approval } from "../types";
import { emoji, fmtDuration, secondsUntil } from "../util";
import { useToast } from "./Toast";

type T = (k: Key, v?: Record<string, string | number>) => string;

export default function Approvals({ t, refresh }: { t: T; refresh: () => void }) {
  const [list, setList] = useState<Approval[]>([]);
  const [focus, setFocus] = useState(0);
  const [, tick] = useState(0);
  const toast = useToast();
  const listRef = useRef(list);
  listRef.current = list;

  async function load() { try { setList((await api.approvals()).approvals); } catch { /* */ } }
  useEffect(() => { load(); const i = setInterval(load, 3000); const k = setInterval(() => tick((x) => x + 1), 1000); return () => { clearInterval(i); clearInterval(k); }; }, []);
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      const cur = listRef.current[focus];
      if (e.key === "a" && cur) decide(cur.id, true);
      if (e.key === "d" && cur) decide(cur.id, false);
      if (e.key === "ArrowDown") setFocus((f) => Math.min(f + 1, listRef.current.length - 1));
      if (e.key === "ArrowUp") setFocus((f) => Math.max(f - 1, 0));
    };
    window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h);
  }, [focus]);

  async function decide(id: string, ok: boolean) {
    try {
      await (ok ? api.approve(id) : api.deny(id));
      toast({ title: ok ? "✅ approved" : "⛔ denied" });
      await load(); refresh();
    } catch (e) { toast({ title: t("error_generic"), body: String(e), bad: true }); }
  }

  if (list.length === 0) return <div className="empty">{t("no_pending")}</div>;
  return (
    <div className="list">
      {list.map((a, i) => {
        const left = Math.max(0, secondsUntil(a.expires_at) ?? 0);
        return (
          <div key={a.id} className="card approval" style={i === focus ? { outline: "2px solid var(--accent)" } : undefined} onClick={() => setFocus(i)}>
            <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
              <strong>🤖 {a.token_label ?? a.token_id}</strong>
              <span className="muted">{t("wants")}</span>
              <strong>{a.item_type ? emoji(a.item_type) : "🗂️"} {a.item_name ?? a.sref}</strong>
              <span className="mono small muted">{a.item_path}</span>
              <span style={{ marginLeft: "auto" }} className="countdown">⏳ {t("auto_deny_in", { s: fmtDuration(left) })}</span>
            </div>
            <div className="small muted" style={{ marginTop: 6 }}>{t("reason_label")}</div>
            <div className="reason">“{a.reason}”</div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <button className="btn primary" onClick={() => decide(a.id, true)}>✅ {t("approve")}</button>
              <button className="btn danger" onClick={() => decide(a.id, false)}>⛔ {t("deny")}</button>
              {a.escalation > 1 && <span className="badge warn">📣 {t("escalated", { n: a.escalation })}</span>}
              <span className="mono small muted" style={{ marginLeft: "auto" }}>{a.id}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
