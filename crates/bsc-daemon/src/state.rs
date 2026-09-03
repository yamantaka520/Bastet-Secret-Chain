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
                        self.notifier.notify(&Escalation {
                            approval_id: a.id,
                            step,
                            item_id: a.item_id,
                            token_id: a.token_id,
                            reason: a.reason,
                            expires_at: a.expires_at,
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
