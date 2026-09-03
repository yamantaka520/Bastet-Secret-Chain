import { useEffect, useState, type DragEvent } from "react";
import { api } from "../api";
import type { Key } from "../i18n";
import { ITEM_TYPES, type Item, type ItemType } from "../types";
import { bytes, emoji, fileToBase64, isProbablyText, parseList } from "../util";
import { useToast } from "./Toast";

type T = (k: Key, v?: Record<string, string | number>) => string;
const DEFAULT_APPROVAL: Record<ItemType, boolean> = {
  login: false, api_key: false, cloud_key: true, service_account: true, oauth: false, ssh_key: false, certificate: true, file: false,
};
function guessType(name: string): ItemType | null {
  const n = name.toLowerCase();
  if (/firebase|service.?account|adminsdk|gcp-.*\.json/.test(n)) return "service_account";
  if (/client_secret|oauth/.test(n)) return "oauth";
  if (/id_rsa|id_ed25519|\.pub$|ssh/.test(n)) return "ssh_key";
  if (/\.(pem|crt|cer|p12|pfx|jks|key)$/.test(n)) return "certificate";
  return null;
}

export default function NewItem({ t, onClose, onCreated }: { t: T; onClose: () => void; onCreated: (i: Item) => void }) {
  const [type, setType] = useState<ItemType>("api_key");
  const [path, setPath] = useState("");
  const [name, setName] = useState("");
  const [tags, setTags] = useState("");
  const [env, setEnv] = useState("prod");
  const [value, setValue] = useState("");
  const [b64, setB64] = useState<string | null>(null);
  const [fileInfo, setFileInfo] = useState<string | null>(null);
  const [approval, setApproval] = useState(DEFAULT_APPROVAL[type]);
  const [approvalTouched, setApprovalTouched] = useState(false);
  const [expires, setExpires] = useState("");
  const [rotation, setRotation] = useState("");
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  useEffect(() => { if (!approvalTouched) setApproval(DEFAULT_APPROVAL[type]); }, [type, approvalTouched]);
  useEffect(() => { const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); }; window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h); }, [onClose]);

  async function takeFile(f: File) {
    const buf = new Uint8Array(await f.arrayBuffer());
    if (isProbablyText(buf)) { setValue(new TextDecoder().decode(buf)); setB64(null); }
    else { setB64(await fileToBase64(f)); setValue(""); }
    setFileInfo(t("file_loaded", { name: f.name, size: bytes(f.size) }));
    if (!name) setName(f.name.replace(/\.[^.]+$/, ""));
    const g = guessType(f.name); if (g) setType(g);
  }
  function onDrop(e: DragEvent) { e.preventDefault(); setOver(false); const f = e.dataTransfer.files?.[0]; if (f) takeFile(f); }

  async function submit() {
    setBusy(true);
    try {
      const item = await api.createItem({
        path: path.trim(), name: name.trim(), type, tags: parseList(tags), env: env.trim() || null,
        approval_required: approval,
        expires_at: expires ? Math.floor(new Date(expires).getTime() / 1000) : null,
        rotation_days: rotation ? Number(rotation) : null,
        ...(b64 ? { value_base64: b64 } : { value }),
      });
      toast({ title: `✅ ${emoji(type)} ${item.name}`, body: `${item.path}/${item.name}` });
      onCreated(item);
    } catch (e) { toast({ title: t("error_generic"), body: String(e), bad: true }); }
    finally { setBusy(false); }
  }

  const ready = path.trim() && name.trim() && (value || b64);
  return (
    <div className="overlay center" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <h2>＋ {t("new_item")}</h2>
        <div className="field"><label>{t("type")}</label>
          <div className="typegrid">
            {ITEM_TYPES.map((ty) => (
              <button key={ty} type="button" className={type === ty ? "active" : ""} onClick={() => setType(ty)}>
                <span className="e">{emoji(ty)}</span>{t(`type_${ty}` as Key)}
              </button>
            ))}
          </div>
        </div>
        <div className="grid2">
          <div className="field"><label>{t("path")}</label><input value={path} onChange={(e) => setPath(e.target.value)} placeholder="prod/gcp" autoFocus /></div>
          <div className="field"><label>{t("name")}</label><input value={name} onChange={(e) => setName(e.target.value)} placeholder="firebase-admin" /></div>
          <div className="field"><label>{t("tags")}</label><input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="mobile, finance" /></div>
          <div className="field"><label>{t("env")}</label>
            <select value={env} onChange={(e) => setEnv(e.target.value)}>
              {["prod", "staging", "dev", "personal"].map((e) => <option key={e} value={e}>{t(`env_${e}` as Key)}</option>)}
            </select>
          </div>
        </div>
        <div className="field"><label>{t("value")}</label>
          <div className={`dropzone${over ? " over" : ""}`} onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={onDrop}>
            {over ? <div className="empty">📥 {t("drop_here")}</div> : (
              <>
                <textarea value={value} onChange={(e) => { setValue(e.target.value); setB64(null); setFileInfo(null); }} placeholder={t("value_hint")} disabled={!!b64} />
                <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 6 }}>
                  <input type="file" style={{ width: "auto" }} onChange={(e) => { const f = e.target.files?.[0]; if (f) takeFile(f); }} />
                  {fileInfo && <span className="badge ok">📎 {fileInfo}</span>}
                </div>
              </>
            )}
          </div>
        </div>
        <div className="grid2">
          <label style={{ display: "flex", gap: 8, alignItems: "center", color: "inherit" }}>
            <input type="checkbox" style={{ width: "auto" }} checked={approval} onChange={(e) => { setApproval(e.target.checked); setApprovalTouched(true); }} /> 🔴 {t("require_approval")}
          </label>
          <div className="field"><label>{t("expires_at")}</label><input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} /></div>
          <div className="field"><label>{t("rotation_days")}</label><input type="number" min={1} value={rotation} onChange={(e) => setRotation(e.target.value)} placeholder="90" /></div>
        </div>
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button className="btn" onClick={onClose}>{t("cancel")}</button>
          <button className="btn primary" onClick={submit} disabled={!ready || busy}>🔐 {busy ? t("creating") : t("create")}</button>
        </div>
      </div>
    </div>
  );
}
