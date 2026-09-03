//! Where escalations go. M2 ships a log sink; OS notifications arrive in M3
//! and external channels in M6 (ADR 0005 §3–4). Whatever the sink, the event
//! never carries secret material — only ids, labels, and the agent's reason.

use std::sync::Arc;

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
    /// Decrypted item name, when the vault was unsealed at tick time.
    pub item_name: Option<String>,
    /// Token label, when available.
    pub token_label: Option<String>,
    /// The item may only be approved from the local UI; external channels may
    /// notify but must not offer approve/deny (ADR 0005 §4).
    pub local_only: bool,
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

/// Desktop notification through the platform's own tool, best effort:
/// `osascript` on macOS, `notify-send` on Linux, PowerShell on Windows. No
/// secret material is ever in the text — ids, labels, the agent's reason, and
/// the deadline. Approve/deny actions in the notification itself are not
/// available through these tools; the notification points at the inbox.
///
/// M3 default for `bsc serve`. Replace with a proper native integration when
/// there is a tray process to own it (M4).
#[derive(Default)]
pub struct OsNotifier {
    /// Base URL of the UI, for the notification body.
    pub ui_url: String,
}

impl OsNotifier {
    /// Title and body for one escalation, shared by every platform.
    pub fn text(&self, e: &Escalation) -> (String, String) {
        let title = match e.step {
            1 => "🔐 Bastet Secret Chain — approval needed".to_string(),
            2 => "🔐 Still waiting — approval needed".to_string(),
            _ => "🔐 Approval about to time out".to_string(),
        };
        let item = e.item_name.clone().unwrap_or_else(|| e.item_id.clone());
        let who = e.token_label.clone().unwrap_or_else(|| e.token_id.clone());
        let body = format!(
            "{who} wants {item}: \"{}\" — {}",
            one_line(&e.reason, 120),
            self.ui_url
        );
        (title, body)
    }

    fn command(&self, e: &Escalation) -> Option<std::process::Command> {
        let (title, body) = self.text(e);
        let mut cmd;
        if cfg!(target_os = "macos") {
            cmd = std::process::Command::new("osascript");
            cmd.arg("-e").arg(format!(
                "display notification \"{}\" with title \"{}\" sound name \"Ping\"",
                applescript_escape(&body),
                applescript_escape(&title)
            ));
        } else if cfg!(target_os = "linux") {
            cmd = std::process::Command::new("notify-send");
            cmd.arg("--urgency=critical")
                .arg("--app-name=Bastet Secret Chain")
                .arg(&title)
                .arg(&body);
        } else if cfg!(target_os = "windows") {
            cmd = std::process::Command::new("powershell");
            cmd.arg("-NoProfile").arg("-Command").arg(format!(
                "Add-Type -AssemblyName System.Windows.Forms; $n = New-Object System.Windows.Forms.NotifyIcon; \
$n.Icon = [System.Drawing.SystemIcons]::Shield; $n.Visible = $true; \
$n.ShowBalloonTip(10000, '{}', '{}', [System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep -s 10; $n.Dispose()",
                title.replace('\'', "''"),
                body.replace('\'', "''")
            ));
        } else {
            return None;
        }
        Some(cmd)
    }
}

fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > max {
        let cut: String = flat.chars().take(max - 1).collect();
        format!("{cut}…")
    } else {
        flat
    }
}

fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

impl Notifier for OsNotifier {
    fn notify(&self, e: &Escalation) {
        LogNotifier.notify(e);
        if let Some(mut cmd) = self.command(e) {
            cmd.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if let Err(err) = cmd.spawn() {
                tracing::debug!(error = %err, "desktop notification tool unavailable");
            }
        }
    }
}

/// Forwards escalations into an async channel so an outbound integration
/// (Telegram, …) can deliver them without blocking the ticker.
pub struct ChannelNotifier {
    inner: Arc<dyn Notifier>,
    tx: tokio::sync::mpsc::UnboundedSender<Escalation>,
}

impl ChannelNotifier {
    /// Wrap `inner` (which still runs, e.g. the desktop notifier) and also
    /// send every escalation to the returned receiver.
    pub fn new(
        inner: Arc<dyn Notifier>,
    ) -> (
        Arc<ChannelNotifier>,
        tokio::sync::mpsc::UnboundedReceiver<Escalation>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Arc::new(ChannelNotifier { inner, tx }), rx)
    }
}

impl Notifier for ChannelNotifier {
    fn notify(&self, e: &Escalation) {
        self.inner.notify(e);
        let _ = self.tx.send(e.clone());
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
