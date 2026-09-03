import type { ApiError, Approval, AuditRecord, Item, Scope, Session, Status, Token } from "./types";

export class ApiFailure extends Error {
  constructor(public status: number, public body: ApiError) {
    super(body.message || body.error);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-BSC-Client": "web" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const resp = await fetch(path, {
    method, headers, credentials: "same-origin", cache: "no-store",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await resp.text();
  const json = text ? JSON.parse(text) : {};
  if (!resp.ok) throw new ApiFailure(resp.status, json as ApiError);
  return json as T;
}

export const api = {
  status: () => call<Status>("GET", "/v1/vault/status"),
  unseal: (passphrase: string) => call<{ sealed: boolean }>("POST", "/v1/vault/unseal", { passphrase }),
  seal: () => call<{ sealed: boolean }>("POST", "/v1/vault/seal"),

  items: () => call<{ items: Item[]; sealed: boolean }>("GET", "/v1/items"),
  item: (sref: string) => call<Item>("GET", `/v1/items/${sref}`),
  createItem: (b: {
    path: string; name: string; type: string; tags: string[]; env: string | null;
    approval_required?: boolean; expires_at?: number | null; value?: string; value_base64?: string;
  }) => call<Item>("POST", "/v1/items", b),
  patchItem: (sref: string, b: Record<string, unknown>) => call<Item>("PATCH", `/v1/items/${sref}`, b),
  addVersion: (sref: string, b: { value?: string; value_base64?: string; note?: string }) =>
    call<{ sref: string; version: number }>("POST", `/v1/items/${sref}/versions`, b),
  reveal: (sref: string, passphrase?: string) =>
    call<{ sref: string; version: number; value: string | null; value_base64: string | null }>(
      "POST", `/v1/items/${sref}/reveal`, passphrase ? { passphrase } : {}),

  tokens: () => call<{ tokens: Token[] }>("GET", "/v1/tokens"),
  mint: (b: { label: string; scope: Scope; lifetime?: number; max_reads?: number | null; rate_limit_per_min?: number }) =>
    call<Token>("POST", "/v1/tokens", b),
  revoke: (id: string) => call<Token>("DELETE", `/v1/tokens/${id}`),

  sessions: () => call<{ sessions: Session[] }>("GET", "/v1/sessions"),
  openSession: (scope: Scope, duration_seconds: number) => call<Session>("POST", "/v1/sessions", { scope, duration_seconds }),
  closeSession: (id: string) => call<Session>("DELETE", `/v1/sessions/${id}`),

  approvals: () => call<{ approvals: Approval[] }>("GET", "/v1/approvals"),
  approve: (id: string) => call<Approval>("POST", `/v1/approvals/${id}/approve`),
  deny: (id: string) => call<Approval>("POST", `/v1/approvals/${id}/deny`),

  audit: (from = 1, limit = 100, subject?: string) =>
    call<{ records: AuditRecord[] }>("GET", `/v1/audit?from=${from}&limit=${limit}${subject ? `&subject=${encodeURIComponent(subject)}` : ""}`),
  auditVerify: () => call<{ intact: boolean; len?: number; head?: string; broken_at?: number }>("GET", "/v1/audit/verify"),
};

/** The reference URL the copy button yields. Identifies; grants nothing. */
export function referenceUrl(sref: string): string {
  return `${location.origin}/v1/secrets/${sref}`;
}
