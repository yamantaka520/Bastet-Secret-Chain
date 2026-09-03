//! Where escalations go. M2 ships a log sink; OS notifications arrive in M3
//! and external channels in M6 (ADR 0005 §3–4). Whatever the sink, the event
//! never carries secret material — only ids, labels, and the agent's reason.

/// One escalation step becoming due.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escalation {
    /// `apr_…`
    pub approval_id: String,
    /// 1-based ladder step.
    pub step: u32,
    /// Item asked for.
    pub item_id: String,
    /// Requesting token id (never the value).
    pub token_id: String,
    /// Agent's stated reason, verbatim.
    pub reason: String,
    /// Auto-deny deadline, Unix seconds.
    pub expires_at: i64,
}

/// A notification sink.
pub trait Notifier: Send + Sync {
    /// Deliver one escalation. Must not block for long and must not fail loudly;
    /// the ledger already has the record.
    fn notify(&self, event: &Escalation);
}

/// Logs via `tracing`. The M2 default.
pub struct LogNotifier;

impl Notifier for LogNotifier {
    fn notify(&self, e: &Escalation) {
        tracing::warn!(
            approval = %e.approval_id,
            step = e.step,
            item = %e.item_id,
            token = %e.token_id,
            reason = %e.reason,
            "approval waiting for a human"
        );
    }
}

/// Collects events in memory. For tests.
#[derive(Default)]
pub struct RecordingNotifier {
    events: std::sync::Mutex<Vec<Escalation>>,
}

impl RecordingNotifier {
    /// Snapshot of everything delivered so far.
    pub fn events(&self) -> Vec<Escalation> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

impl Notifier for RecordingNotifier {
    fn notify(&self, e: &Escalation) {
        if let Ok(mut v) = self.events.lock() {
            v.push(e.clone());
        }
    }
}
