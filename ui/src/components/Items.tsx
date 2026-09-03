import { useEffect, useMemo, useRef, useState } from "react";
import { api, referenceUrl } from "../api";
import type { Key } from "../i18n";
import { ITEM_TYPES, type Item, type ItemType } from "../types";
import { buildTree, copyText, emoji, isExpiringSoon, secondsUntil, type TreeNode } from "../util";
import { useToast } from "./Toast";
import ItemDrawer from "./ItemDrawer";
import NewItem from "./NewItem";

type T = (k: Key, v?: Record<string, string | number>) => string;

export default function Items({ t, sealed, refreshKey, refresh }: { t: T; sealed: boolean; refreshKey: number; refresh: () => void }) {
  const [items, setItems] = useState<Item[]>([]);
  const [q, setQ] = useState("");
  const [type, setType] = useState<ItemType | "">("");
  const [env, setEnv] = useState("");
  const [path, setPath] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const search = useRef<HTMLInputElement>(null);
  const toast = useToast();

  async function load() { try { setItems((await api.items()).items); } catch { /* sealed or logged out */ } }
  useEffect(() => { load(); const i = setInterval(load, 10_000); const f = () => load(); window.addEventListener("focus", f); return () => { clearInterval(i); window.removeEventListener("focus", f); }; }, [refreshKey]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.key === "/" && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement)) { e.preventDefault(); search.current?.focus(); }
    };
    window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h);
  }, []);

  const envs = useMemo(() => Array.from(new Set(items.map((i) => i.env).filter(Boolean) as string[])).sort(), [items]);
  const tree = useMemo(() => buildTree(items.map((i) => i.path ?? "")), [items]);
  const shown = items.filter((i) => {
    if (type && i.type !== type) return false;
    if (env && i.env !== env) return false;
    if (path && !(i.path === path || (i.path ?? "").startsWith(path + "/"))) return false;
    if (q) {
      const hay = `${i.name ?? ""} ${i.path ?? ""} ${(i.tags ?? []).join(" ")} ${i.sref}`.toLowerCase();
      if (!q.toLowerCase().split(/\s+/).every((w) => hay.includes(w))) return false;
    }
    return true;
  });

  async function copyRef(i: Item) {
    const ok = await copyText(referenceUrl(i.sref));
    toast({ title: `📋 ${t("copied_title")}`, body: ok ? t("copied_body") : referenceUrl(i.sref), action: { label: t("mint_for_this"), href: `#/tokens?path=${encodeURIComponent(i.path ?? "")}` } });
  }

  return (
    <>
      {sealed && <div className="banner">🔒 {t("sealed_banner")}</div>}
      <div className="items-layout">
        <aside className="tree" aria-label="paths">
          <button className={path === "" ? "active" : ""} onClick={() => setPath("")}>📂 {t("tree_all")}<span className="count">{items.length}</span></button>
          {tree.map((n) => <TreeRow key={n.full} n={n} depth={0} sel={path} onSel={setPath} />)}
        </aside>
        <section>
          <div className="filterbar">
            <input ref={search} placeholder={t("search")} value={q} onChange={(e) => setQ(e.target.value)} aria-label={t("search")} />
            <select value={type} onChange={(e) => setType(e.target.value as ItemType | "")} aria-label={t("type")}>
              <option value="">{t("all_types")}</option>
              {ITEM_TYPES.map((ty) => <option key={ty} value={ty}>{emoji(ty)} {t(`type_${ty}` as Key)}</option>)}
            </select>
            <select value={env} onChange={(e) => setEnv(e.target.value)} aria-label={t("env")}>
              <option value="">{t("all_env")}</option>
              {envs.map((e) => <option key={e} value={e}>{e}</option>)}
            </select>
            <button className="btn primary" onClick={() => setCreating(true)} disabled={sealed}>＋ {t("new_item")}</button>
          </div>
          <div className="list">
            {shown.length === 0 && <div className="empty">🐈‍⬛ —</div>}
            {shown.map((i) => (
              <div key={i.sref} className="row" tabIndex={0} onClick={() => setOpen(i.sref)}
                onKeyDown={(e) => { if (e.key === "Enter") setOpen(i.sref); if (e.key === "c") { e.preventDefault(); copyRef(i); } }}>
                <div className="em" aria-label={i.type}>{emoji(i.type)}</div>
                <div>
                  <div className="title">
                    <span>{i.name ?? <span className="mono muted">{i.sref}</span>}</span>
                    <Badges i={i} t={t} />
                  </div>
                  <div className="sub">
                    <span className="mono">{i.path ?? "•••"}</span>
                    {i.env && <span className="chip">{i.env}</span>}
                    {(i.tags ?? []).map((tg) => <span key={tg} className="chip">#{tg}</span>)}
                    <span>v{i.version}</span>
                  </div>
                </div>
                <div className="actions" onClick={(e) => e.stopPropagation()}>
                  <button className="btn sm" onClick={() => copyRef(i)} title="c">📋 {t("copy_ref")}</button>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
      {open && <ItemDrawer t={t} sref={open} onClose={() => setOpen(null)} onChanged={() => { load(); refresh(); }} />}
      {creating && <NewItem t={t} onClose={() => setCreating(false)} onCreated={(i) => { setCreating(false); load(); refresh(); setOpen(i.sref); }} />}
    </>
  );
}

function TreeRow({ n, depth, sel, onSel }: { n: TreeNode; depth: number; sel: string; onSel: (p: string) => void }) {
  return (
    <>
      <button className={sel === n.full ? "active" : ""} style={{ paddingLeft: 8 + depth * 14 }} onClick={() => onSel(n.full)}>
        {n.children.length ? "📂" : "📁"} {n.name}<span className="count">{n.count}</span>
      </button>
      {n.children.map((c) => <TreeRow key={c.full} n={c} depth={depth + 1} sel={sel} onSel={onSel} />)}
    </>
  );
}

export function Badges({ i, t }: { i: Item; t: T }) {
  const s = secondsUntil(i.expires_at);
  return (
    <>
      {i.approval_required && <span className="badge bad">🔴 {t("approval_required")}</span>}
      {i.local_approval_only && <span className="badge info">🏠 {t("local_only")}</span>}
      {s !== null && s <= 0 && <span className="badge bad">⛔ {t("expired")}</span>}
      {s !== null && s > 0 && isExpiringSoon(i.expires_at) && <span className="badge warn">⏰ {t("expiring")}</span>}
    </>
  );
}
