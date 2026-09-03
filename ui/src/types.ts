export type ItemType =
  | "login" | "api_key" | "cloud_key" | "service_account"
  | "oauth" | "ssh_key" | "certificate" | "file";

export const ITEM_TYPES: ItemType[] = [
  "login", "api_key", "cloud_key", "service_account", "oauth", "ssh_key", "certificate", "file",
];

export const TYPE_EMOJI: Record<ItemType, string> = {
  login: "🔐", api_key: "🔑", cloud_key: "☁️", service_account: "🔥",
  oauth: "🎫", ssh_key: "🖥️", certificate: "📜", file: "🗂️",
};

export interface UseBinding { urls: string[]; header: string; methods: string[] }

export interface Item {
  sref: string; type: ItemType; env: string | null;
  has_use_binding?: boolean; use_binding?: UseBinding | null;
  created: string; updated: string; expires_at: string | null;
  approval_required: boolean; local_approval_only: boolean;
  version: number; size: number;
  name?: string; path?: string; tags?: string[];
}

export interface Scope { paths: string[]; tags: string[] }

export interface Token {
  id: string; label: string | null; scope: Scope | null; created: string; expires_at: string;
  max_lifetime_until: string; max_reads: number | null; reads_used: number;
  rate_limit_per_min: number; created_by: string; revoked_at: string | null; live: boolean;
  value?: string; shown_once?: boolean;
}

export interface Session {
  id: string; scope: Scope | null; opened: string; expires_at: string;
  closed_at: string | null; active: boolean; seconds_left: number;
}

export interface Approval {
  id: string; token_id: string; sref: string; reason: string; requested_at: string;
  expires_at: string; seconds_left: number; status: string; escalation: number;
  token_label?: string | null; item_name?: string; item_path?: string; item_type?: ItemType;
}

export interface AuditRecord {
  n: number; ts: string; actor: string; action: string; subject: string | null;
  outcome: string; meta: Record<string, unknown>; hash: string;
}

export interface Status {
  sealed: boolean; version: string; uptime: number;
  items?: number; pending_approvals?: number; active_sessions?: number; live_tokens?: number;
  chain?: { intact: boolean; len?: number; head?: string; broken_at?: number };
  kdf?: { m_cost_kib: number; t_cost: number; p_cost: number };
}

export interface ApiError {
  error: string; message: string; next_action: string; do_not: string; request_id?: string;
  [k: string]: unknown;
}
