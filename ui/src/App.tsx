import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { isLocale, makeT, resolveLocale, type Key, type Locale } from "./i18n";
import type { Status } from "./types";
import { ToastProvider } from "./components/Toast";
import Login from "./components/Login";
import Shell from "./components/Shell";
import Dashboard from "./components/Dashboard";
import Items from "./components/Items";
import Tokens from "./components/Tokens";
import Approvals from "./components/Approvals";
import Sessions from "./components/Sessions";
import Expiry from "./components/Expiry";
import Audit from "./components/Audit";

function useHash() {
  const [h, setH] = useState(location.hash);
  useEffect(() => { const f = () => setH(location.hash); window.addEventListener("hashchange", f); return () => window.removeEventListener("hashchange", f); }, []);
  const [pathPart, query = ""] = h.replace(/^#\/?/, "").split("?");
  return { route: pathPart || "dashboard", params: new URLSearchParams(query) };
}

export default function App() {
  const [locale, setLocale] = useState<Locale>(() => {
    const saved = localStorage.getItem("bsc.locale");
    // A stored choice wins; otherwise start in the browser's language, which
    // is right more often than any fixed default.
    return isLocale(saved) ? saved : resolveLocale(navigator.languages ?? [navigator.language]);
  });
  const [theme, setTheme] = useState(() => localStorage.getItem("bsc.theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  const [status, setStatus] = useState<Status | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [notifState, setNotifState] = useState<"default" | "granted" | "denied" | "unsupported">(() => ("Notification" in window ? Notification.permission : "unsupported"));
  const seenApprovals = useRef<Set<string>>(new Set());
  const t = makeT(locale);
  const { route, params } = useHash();

  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem("bsc.theme", theme); }, [theme]);
  useEffect(() => { localStorage.setItem("bsc.locale", locale); document.documentElement.lang = locale; }, [locale]);

  const loadStatus = useCallback(async () => {
    try { setStatus(await api.status()); } catch { setStatus(null); }
  }, []);
  useEffect(() => { loadStatus(); const i = setInterval(loadStatus, 5000); return () => clearInterval(i); }, [loadStatus, refreshKey]);

  const loggedIn = status !== null && status.items !== undefined;
  const pending = status?.pending_approvals ?? 0;

  // Title badge + browser notification when a new approval appears.
  useEffect(() => {
    document.title = pending > 0 ? `(${pending}) ✋ Bastet Secret Chain` : "Bastet Secret Chain";
    if (!loggedIn || pending === 0) return;
    api.approvals().then((r) => {
      for (const a of r.approvals) {
        if (seenApprovals.current.has(a.id)) continue;
        seenApprovals.current.add(a.id);
        if (notifState === "granted") {
          const n = new Notification("✋ Bastet Secret Chain", { body: `${a.token_label ?? a.token_id} → ${a.item_name ?? a.sref}: “${a.reason}”`, tag: a.id });
          n.onclick = () => { location.hash = "#/approvals"; window.focus(); };
        }
      }
    }).catch(() => {});
  }, [pending, loggedIn, notifState]);

  const refresh = () => setRefreshKey((k) => k + 1);
  const titles: Record<string, Key> = { dashboard: "nav_dashboard", items: "nav_items", tokens: "nav_tokens", approvals: "nav_approvals", sessions: "nav_sessions", expiry: "nav_expiry", audit: "nav_audit" };

  if (status === null) return <div className="login"><div className="card">…</div></div>;
  if (!loggedIn) return <ToastProvider><Login t={t} locale={locale} onLang={setLocale} onDone={() => { refresh(); loadStatus(); }} /></ToastProvider>;

  return (
    <ToastProvider>
      <Shell t={t} route={route} status={status} pending={pending} theme={theme} refresh={refresh}
        onTheme={() => setTheme((x) => (x === "dark" ? "light" : "dark"))}
        locale={locale} onLang={setLocale}
        onLock={async () => { await api.seal(); seenApprovals.current.clear(); loadStatus(); }}
        notifState={notifState}
        onNotif={() => Notification.requestPermission().then((p) => setNotifState(p))}
        title={t(titles[route] ?? "nav_dashboard")}>
        {route === "dashboard" && <Dashboard t={t} status={status} />}
        {route === "items" && <Items t={t} sealed={status.sealed} refreshKey={refreshKey} refresh={refresh} />}
        {route === "tokens" && <Tokens t={t} refreshKey={refreshKey} refresh={refresh} presetPath={params.get("path") ?? undefined} />}
        {route === "approvals" && <Approvals t={t} refresh={refresh} />}
        {route === "sessions" && <Sessions t={t} refreshKey={refreshKey} refresh={refresh} />}
        {route === "expiry" && <Expiry t={t} refreshKey={refreshKey} />}
        {route === "audit" && <Audit t={t} refreshKey={refreshKey} />}
      </Shell>
    </ToastProvider>
  );
}
