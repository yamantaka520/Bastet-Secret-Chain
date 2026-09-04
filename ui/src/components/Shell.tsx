import { useEffect, useState, type ReactNode } from "react";
import { LOCALES, type Key, type Locale } from "../i18n";
import type { Session, Status } from "../types";
import { api } from "../api";
import { fmtDuration, parseList, secondsUntil } from "../util";
import { useToast } from "./Toast";

type T = (k: Key, v?: Record<string, string | number>) => string;

const NAV: { route: string; key: Key; emoji: string }[] = [
  { route: "dashboard", key: "nav_dashboard", emoji: "🏠" },
  { route: "items", key: "nav_items", emoji: "🗝️" },
  { route: "approvals", key: "nav_approvals", emoji: "✋" },
  { route: "tokens", key: "nav_tokens", emoji: "🎫" },
  { route: "sessions", key: "nav_sessions", emoji: "▶️" },
  { route: "expiry", key: "nav_expiry", emoji: "⏰" },
  { route: "audit", key: "nav_audit", emoji: "🧾" },
];

export default function Shell(props: {
  t: T; route: string; status: Status | null; pending: number; children: ReactNode;
  theme: string; onTheme: () => void; locale: Locale; onLang: (l: Locale) => void; onLock: () => void;
  notifState: "default" | "granted" | "denied" | "unsupported"; onNotif: () => void; title: string; refresh: () => void;
}) {
  const { t, route, pending } = props;
  return (
    <div className="shell">
      <nav className="nav" aria-label="main">
        <div className="brand">🔐⛓️ <span>{t("app")}</span></div>
        {NAV.map((n) => (
          <a key={n.route} href={`#/${n.route}`} className={route === n.route ? "active" : ""}>
            <span>{n.emoji}</span><span>{t(n.key)}</span>
            {n.route === "approvals" && pending > 0 && <span className="pill-count">{pending}</span>}
          </a>
        ))}
        <div className="spacer" />
        <div className="foot">
          <button className="btn sm ghost" onClick={props.onTheme} title={t("theme")}>{props.theme === "dark" ? "🌙" : "☀️"}</button>
          <select className="btn sm ghost lang" value={props.locale} aria-label={t("lang")} title={t("lang")}
            onChange={(e) => props.onLang(e.target.value as Locale)}>
            {LOCALES.map((l) => <option key={l.code} value={l.code}>{l.native}</option>)}
          </select>
          {props.notifState !== "unsupported" && props.notifState !== "denied" && (
            <button className="btn sm ghost" onClick={props.onNotif} disabled={props.notifState === "granted"}>
              {props.notifState === "granted" ? t("notif_on") : t("notif_perm")}
            </button>
          )}
          <span className="small">{t("keyboard_hint")}</span>
        </div>
      </nav>
      <div className="main">
        <header className="topbar">
          <h1>{props.title}</h1>
          <SessionControl t={t} refresh={props.refresh} />
          <button className="btn" onClick={props.onLock}>🔒 {t("lock")}</button>
        </header>
        <div className="content">{props.children}</div>
      </div>
    </div>
  );
}

function SessionControl({ t, refresh }: { t: T; refresh: () => void }) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [open, setOpen] = useState(false);
  const [paths, setPaths] = useState("");
  const [tags, setTags] = useState("");
  const [dur, setDur] = useState(1800);
  const [, tick] = useState(0);
  const toast = useToast();

  async function load() {
    try { setSessions((await api.sessions()).sessions); } catch { /* not logged in yet */ }
  }
  useEffect(() => { load(); const i = setInterval(() => { load(); tick((x) => x + 1); }, 5000); return () => clearInterval(i); }, []);
  useEffect(() => { const i = setInterval(() => tick((x) => x + 1), 1000); return () => clearInterval(i); }, []);

  const active = sessions.filter((s) => s.active);
  async function start() {
    try {
      await api.openSession({ paths: parseList(paths), tags: parseList(tags) }, dur);
      setOpen(false); setPaths(""); setTags("");
      await load(); refresh();
    } catch (e) { toast({ title: t("error_generic"), body: String(e), bad: true }); }
  }
  async function end(id: string) {
    await api.closeSession(id); await load(); refresh();
  }
  return (
    <div style={{ position: "relative", display: "flex", gap: 8, alignItems: "center" }}>
      {active.map((s) => {
        const left = secondsUntil(s.expires_at) ?? 0;
        return (
          <span key={s.id} className="session-pill" title={(s.scope?.paths ?? []).concat(s.scope?.tags ?? []).join(", ")}>
            {t("session_active", { t: fmtDuration(left) })}
            <span className="chip">{(s.scope?.paths ?? []).join(", ") || (s.scope?.tags ?? []).join(", ")}</span>
            <button className="btn sm ghost" onClick={() => end(s.id)}>{t("end_session")}</button>
          </span>
        );
      })}
      <button className="btn" onClick={() => setOpen((o) => !o)} aria-expanded={open}>{t("start_session")}</button>
      {open && (
        <div className="card" style={{ position: "absolute", right: 0, top: "110%", width: 360, zIndex: 20 }}>
          <p className="muted small" style={{ marginTop: 0 }}>{t("session_hint")}</p>
          <div className="field"><label>{t("scope_paths")}</label><input value={paths} onChange={(e) => setPaths(e.target.value)} placeholder="prod/aws, prod/gcp" autoFocus /></div>
          <div className="field"><label>{t("scope_tags")}</label><input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="finance" /></div>
          <div className="field"><label>{t("duration")}</label>
            <select value={dur} onChange={(e) => setDur(Number(e.target.value))}>
              <option value={900}>{t("min15")}</option><option value={1800}>{t("min30")}</option>
              <option value={3600}>{t("min60")}</option><option value={7200}>{t("min120")}</option>
            </select>
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button className="btn" onClick={() => setOpen(false)}>{t("cancel")}</button>
            <button className="btn primary" onClick={start} disabled={!paths.trim() && !tags.trim()}>{t("start_session")}</button>
          </div>
        </div>
      )}
    </div>
  );
}
