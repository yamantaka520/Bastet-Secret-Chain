//! Shared daemon state: the vault behind a mutex, human sessions, rate
//! limiter, clock, and the approval ticker.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use bsc_store::{Actor, Vault};

use crate::notify::{Escalation, LogNotifier, Notifier};

/// Tunables. Defaults are ADR 0005 §6 — chosen, not measured.
#[derive(Clone, Debug)]
pub struct Config {
    /// Seconds a pending approval waits before auto-deny.
    pub approval_wait: i64,
    /// Escalation offsets from the request time, seconds.
    pub ladder: Vec<i64>,
    /// Seconds an approval grant lasts (capped at token expiry).
    pub grant_ttl: i64,
    /// Human session idle timeout, seconds.
    pub human_idle: i64,
    /// Whether handoff links may be minted. Off by default.
    pub handoff_enabled: bool,
    /// Ticker interval for timeouts and escalations.
    pub tick: Duration,
    /// Default token lifetime when the mint request omits it, seconds.
    pub default_token_lifetime: i64,
    /// Hard cap on token lifetime through renewals, seconds.
    pub default_max_lifetime: i64,
    /// Default per-minute rate limit for new tokens.
    pub default_rate_limit: u32,
    /// Default task-session duration, seconds.
    pub default_session_duration: i64,
    /// Seconds an agent should wait between approval polls.
    pub poll_interval: u64,
    /// The one external origin (scheme + host[:port]) a reverse proxy in front
    /// of this daemon presents to browsers, e.g. `https://sec.example`. When
    /// set: that Origin is accepted on the human surface, the session cookie is
    /// `Secure` if the scheme is https, `X-Forwarded-For` from the loopback
    /// proxy is used as the client address for rate limiting, and an
    /// `exposure_acknowledged` record is written to the ledger at startup.
    /// `None` keeps the loopback-only posture (master plan §4.4).
    pub public_origin: Option<String>,
    /// Failed unseal/login attempts allowed per client address per 10 minutes
    /// before further attempts are refused for the rest of the window.
    pub login_attempts_per_10m: u32,
    /// Where the passphrase came from at startup, when the operator opted into
    /// unattended unseal (`"systemd-credential"`, `"macos-keychain"`). `None`
    /// means the vault waits for a human. Shown in `/v1/vault/status`.
    pub unattended_unseal: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            approval_wait: 5 * 60,
            ladder: vec![0, 20, 60],
            grant_ttl: 30 * 60,
            human_idle: 15 * 60,
            handoff_enabled: false,
            tick: Duration::from_secs(5),
            default_token_lifetime: 24 * 3600,
            default_max_lifetime: 30 * 86_400,
            default_rate_limit: 60,
            default_session_duration: 30 * 60,
            poll_interval: 5,
            public_origin: None,
            login_attempts_per_10m: 5,
            unattended_unseal: None,
        }
    }
}

/// Shared time source.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

struct HumanSession {
    created: i64,
    last_seen: i64,
}

/// Everything handlers share.
pub struct AppState {
    vault: Mutex<Vault>,
    human: Mutex<HashMap<String, HumanSession>>,
    rate: Mutex<HashMap<String, (i64, u32)>>,
    login_failures: Mutex<HashMap<String, (i64, u32)>>,
    /// Tunables.
    pub config: Config,
    clock: Clock,
    notifier: Arc<dyn Notifier>,
    started: i64,
}

fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

impl AppState {
    /// Production state: system clock, log notifier.
    pub fn new(vault: Vault, config: Config) -> Arc<AppState> {
        Self::with(vault, config, system_clock(), Arc::new(LogNotifier))
    }

    /// Production state with a chosen notifier (desktop notifications for
    /// `bsc serve`).
    pub fn new_with_notifier(
        vault: Vault,
        config: Config,
        notifier: Arc<dyn Notifier>,
    ) -> Arc<AppState> {
        Self::with(vault, config, system_clock(), notifier)
    }

    /// Fully injected state. Sets the vault's clock to the same source so
    /// ledger timestamps and expiry decisions agree.
    pub fn with(
        mut vault: Vault,
        config: Config,
        clock: Clock,
        notifier: Arc<dyn Notifier>,
    ) -> Arc<AppState> {
        let c = clock.clone();
        vault.set_clock(Box::new(move || c()));
        let started = clock();
        Arc::new(AppState {
            vault: Mutex::new(vault),
            human: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
            login_failures: Mutex::new(HashMap::new()),
            config,
            clock,
            notifier,
            started,
        })
    }

    /// Unix seconds from the shared clock.
    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Seconds since the daemon started.
    pub fn uptime(&self) -> i64 {
        self.now() - self.started
    }

    /// Lock the vault. A poisoned mutex means a handler panicked mid-
    /// transaction; SQLite has already rolled back, so continuing is safe.
    pub fn vault(&self) -> MutexGuard<'_, Vault> {
        self.vault.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ------------------------------------------------------ human sessions

    /// Open a human session and return its cookie value.
    pub fn open_human_session(&self) -> String {
        let mut b = [0u8; 16];
        let _ = getrandom::getrandom(&mut b);
        let id = format!("hs_{}", hex::encode(b));
        let now = self.now();
        if let Ok(mut m) = self.human.lock() {
            m.retain(|_, s| now - s.last_seen < self.config.human_idle);
            m.insert(
                id.clone(),
                HumanSession {
                    created: now,
                    last_seen: now,
                },
            );
        }
        id
    }

    /// Validate and touch a human session. Returns the actor on success.
    pub fn touch_human_session(&self, id: &str) -> Option<Actor> {
        let now = self.now();
        let mut m = self.human.lock().ok()?;
        let s = m.get_mut(id)?;
        if now - s.last_seen >= self.config.human_idle {
            m.remove(id);
            return None;
        }
        s.last_seen = now;
        let _ = s.created;
        Some(Actor::Human {
            session: id.to_string(),
        })
    }

    /// Drop every human session (on seal).
    pub fn clear_human_sessions(&self) {
        if let Ok(mut m) = self.human.lock() {
            m.clear();
        }
    }

    // ---------------------------------------------------------- rate limit

    /// Fixed one-minute window per token. `Err(retry_after)` when over.
    pub fn rate_check(&self, token_id: &str, per_min: u32) -> Result<(), u64> {
        let now = self.now();
        let window = now - now.rem_euclid(60);
        let mut m = self.rate.lock().map_err(|_| 60u64)?;
        let e = m.entry(token_id.to_string()).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        if e.1 >= per_min {
            return Err((window + 60 - now).max(1) as u64);
        }
        e.1 += 1;
        Ok(())
    }

    // ----------------------------------------------------- login throttle

    /// Whether this client may attempt an unseal/login right now.
    pub fn login_allowed(&self, client: &str) -> bool {
        let now = self.now();
        let window = now - now.rem_euclid(600);
        let m = match self.login_failures.lock() {
            Ok(m) => m,
            Err(_) => return false,
        };
        match m.get(client) {
            Some((w, n)) if *w == window => *n < self.config.login_attempts_per_10m,
            _ => true,
        }
    }

    /// Count one failed attempt.
    pub fn login_failed(&self, client: &str) {
        let now = self.now();
        let window = now - now.rem_euclid(600);
        if let Ok(mut m) = self.login_failures.lock() {
            let e = m.entry(client.to_string()).or_insert((window, 0));
            if e.0 != window {
                *e = (window, 0);
            }
            e.1 += 1;
        }
    }

    /// Whether the daemon has been told it sits behind a reverse proxy.
    pub fn is_exposed(&self) -> bool {
        self.config.public_origin.is_some()
    }

    /// Write the §4.4 acknowledgement record. Called once at serve start when
    /// `public_origin` is set, so the ledger shows when exposure began.
    pub fn record_exposure(&self) {
        if let Some(origin) = &self.config.public_origin {
            let v = self.vault();
            if let Err(e) = v.audit_event(
                &Actor::System,
                "exposure_acknowledged",
                None,
                "ok",
                serde_json::json!({ "public_origin": origin, "login_attempts_per_10m": self.config.login_attempts_per_10m }),
            ) {
                tracing::error!(error = %e, "could not record exposure acknowledgement");
            }
        }
    }

    // -------------------------------------------------------------- ticker

    /// One pass: time out overdue approvals, record due escalation steps,
    /// hand each new step to the notifier. Safe to call from tests directly.
    pub fn tick(&self) {
        let mut v = self.vault();
        if let Err(e) = v.timeout_approvals() {
            tracing::error!(error = %e, "timeout pass failed");
        }
        match v.escalate_approvals(&self.config.ladder) {
            Ok(steps) => {
                for (id, step) in steps {
                    if let Ok(a) = v.approval(&id) {
                        let item_name = v.detail(&a.item_id).ok().map(|d| d.name);
                        let token_label = v.token(&a.token_id).ok().and_then(|t| t.label);
                        self.notifier.notify(&Escalation {
                            approval_id: a.id,
                            step,
                            item_id: a.item_id,
                            token_id: a.token_id,
                            reason: a.reason,
                            expires_at: a.expires_at,
                            item_name,
                            token_label,
                        });
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "escalation pass failed"),
        }
    }

    /// Run [`Self::tick`] forever on the configured interval.
    pub fn spawn_ticker(self: &Arc<Self>) {
        let s = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(s.config.tick);
            loop {
                iv.tick().await;
                s.tick();
            }
        });
    }
}
