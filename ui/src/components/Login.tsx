import { useState, type FormEvent } from "react";
import { api, ApiFailure } from "../api";
import { LOCALES, type Key, type Locale } from "../i18n";

export default function Login({ t, onDone, locale, onLang }: { t: (k: Key, v?: Record<string, string | number>) => string; onDone: () => void; locale: Locale; onLang: (l: Locale) => void }) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      await api.unseal(pw);
      setPw("");
      onDone();
    } catch (e) {
      setErr(e instanceof ApiFailure && e.body.error === "bad_passphrase" ? t("bad_passphrase") : String(e));
    } finally { setBusy(false); }
  }
  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <h1>🔐⛓️ {t("unseal_title")}</h1>
        <p className="muted small">{t("unseal_hint")}</p>
        <div className="field">
          <label htmlFor="pw">{t("passphrase")}</label>
          <input id="pw" type="password" autoFocus autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
        </div>
        {err && <div className="badge bad" role="alert">{err}</div>}
        <div className="login-actions">
          <button className="btn primary" disabled={busy || !pw}>{busy ? t("unsealing") : t("unseal")}</button>
          {/* Before unsealing there is no sidebar, so this is the only chance
              someone has to switch to a language they can actually read. */}
          <select className="btn sm ghost lang" value={locale} aria-label={t("lang")} title={t("lang")}
            onChange={(e) => onLang(e.target.value as Locale)}>
            {LOCALES.map((l) => <option key={l.code} value={l.code}>{l.native}</option>)}
          </select>
        </div>
      </form>
    </div>
  );
}
