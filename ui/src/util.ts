import type { ItemType } from "./types";
import { TYPE_EMOJI } from "./types";

export const emoji = (t: ItemType) => TYPE_EMOJI[t] ?? "🗂️";

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Compact: time only when today, otherwise short date + time. */
export function fmtWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  return sameDay
    ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function secondsUntil(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (isNaN(t)) return null;
  return Math.floor((t - Date.now()) / 1000);
}

export function fmtDuration(s: number): string {
  if (s <= 0) return "0s";
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec.toString().padStart(2, "0")}s`;
  return `${sec}s`;
}

export function parseList(s: string): string[] {
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

export function isExpiringSoon(iso: string | null | undefined, days = 30): boolean {
  const s = secondsUntil(iso);
  return s !== null && s < days * 86400;
}

export function fileToBase64(f: File): Promise<string> {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res((r.result as string).split(",")[1] ?? "");
    r.onerror = () => rej(r.error);
    r.readAsDataURL(f);
  });
}

export function isProbablyText(bytesArr: Uint8Array): boolean {
  const n = Math.min(bytesArr.length, 4096);
  for (let i = 0; i < n; i++) {
    const b = bytesArr[i];
    if (b === 0) return false;
    if (b < 7 || (b > 13 && b < 32)) return false;
  }
  return true;
}

export async function copyText(s: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(s);
    return true;
  } catch {
    return false;
  }
}

/** Build a nested tree from item paths. */
export interface TreeNode { name: string; full: string; count: number; children: TreeNode[] }
export function buildTree(paths: string[]): TreeNode[] {
  const root: TreeNode = { name: "", full: "", count: 0, children: [] };
  for (const p of paths) {
    let node = root;
    let acc = "";
    for (const seg of p.split("/").filter(Boolean)) {
      acc = acc ? `${acc}/${seg}` : seg;
      let child = node.children.find((c) => c.name === seg);
      if (!child) { child = { name: seg, full: acc, count: 0, children: [] }; node.children.push(child); }
      child.count++;
      node = child;
    }
  }
  const sort = (n: TreeNode) => { n.children.sort((a, b) => a.name.localeCompare(b.name)); n.children.forEach(sort); };
  sort(root);
  return root.children;
}
