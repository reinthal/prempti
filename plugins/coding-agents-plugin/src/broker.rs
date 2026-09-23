use std::io::Write;
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Cross-platform stream type for interceptor connections.
/// Uses Unix domain sockets on all platforms (Windows 10+ supports AF_UNIX).
#[cfg(unix)]
pub type BrokerStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type BrokerStream = uds_windows::UnixStream;

use dashmap::DashMap;

use crate::audit::{AuditDraft, AuditSink, FalcoHit, LlmOutcome};
use crate::verdict::Verdict;

/// Default TTL for pending requests. Entries older than this are reaped.
/// Set well above the interceptor's timeout (default 5s) to avoid false
/// reaping during normal operation. This catches entries whose seen alert
/// was lost. Raised at init when the LLM monitor is enabled (see
/// `set_pending_ttl_secs`).
pub const DEFAULT_PENDING_TTL_SECS: u64 = 30;

/// How often the reaper thread scans for stale entries.
const REAPER_INTERVAL_SECS: u64 = 10;

/// How often the reaper thread wakes to check the shutdown flag. Keeping this
/// much smaller than `REAPER_INTERVAL_SECS` ensures `Drop` (which joins the
/// reaper) returns quickly on `ctl stop` — otherwise the whole plugin
/// teardown would stall up to `REAPER_INTERVAL_SECS`. 100ms is a good balance:
/// negligible CPU overhead, sub-second shutdown latency.
const REAPER_SHUTDOWN_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// Where a verdict signal came from. Recorded in the audit trail and used
/// to label the wire verdict's origin.
#[derive(Clone, Debug)]
pub enum Source {
    /// A Falco rule alert delivered over `http_output`.
    Falco { rule: String },
    /// The LLM monitor (second verdict source).
    Llm,
    /// The broker itself (queue full, parse failure, ...).
    Internal,
}

impl Source {
    fn label(&self) -> &'static str {
        match self {
            Source::Falco { .. } => "falco",
            Source::Llm => "llm",
            Source::Internal => "broker",
        }
    }
}

/// Tracks pending requests from interceptors, waiting for verdict resolution.
pub struct Broker {
    /// Maps correlation ID → pending request.
    pending: DashMap<u64, PendingRequest>,
    /// When true, all verdicts resolve as defer (monitor mode).
    monitor_mode: AtomicBool,
    /// When true, resolve all requests as defer immediately on register.
    passthrough: AtomicBool,
    /// The no-rule-match floor: when true, events matching no deny/ask rule
    /// resolve as `defer` (Prempti steps aside); when false, as `allow`
    /// (Prempti approves). Consulted in guardrails mode only — monitor and
    /// passthrough always resolve as defer regardless of this flag.
    default_defer: AtomicBool,
    /// Shutdown signal for background threads.
    shutdown: AtomicBool,
    /// Pending-request TTL in seconds, read by the reaper on every pass.
    pending_ttl_secs: AtomicU64,
    /// Audit trail sink. `None` when auditing is disabled (or in unit tests
    /// that don't care about the trail).
    audit: Mutex<Option<Arc<AuditSink>>>,
}

/// A pending request from an interceptor, awaiting a verdict.
///
/// Two lifecycles are tracked separately:
/// - **responded**: the wire verdict has been written to the interceptor
///   (`stream` taken). Happens at most once, possibly before every signal
///   has arrived (deny short-circuit, reaper).
/// - **complete**: every expected signal (Falco seen alerts + the LLM
///   monitor when enabled) has landed. Only then is the entry removed and
///   the audit record sealed, so late signals still reach the record.
struct PendingRequest {
    /// The connection back to the interceptor. `None` once responded.
    stream: Mutex<Option<BrokerStream>>,
    /// The wire protocol request ID (to include in the response).
    wire_id: String,
    /// The current best verdict (escalated as signals arrive) and the label
    /// of the source that staged it.
    current_verdict: Mutex<Option<(Verdict, &'static str)>>,
    /// When this request was registered.
    created_at: Instant,
    /// Number of completion signals still expected: one Falco seen alert per
    /// synthetic event (1 for ordinary hooks, N for codex apply_patch
    /// multiplex) plus one for the LLM monitor when it is enabled for this
    /// request. `signal_complete` decrements; the last signal seals.
    remaining_signals: AtomicU64,
    /// Audit record under construction.
    audit: Mutex<AuditDraft>,
}

impl Broker {
    pub fn new() -> Self {
        Broker {
            pending: DashMap::new(),
            monitor_mode: AtomicBool::new(false),
            passthrough: AtomicBool::new(false),
            default_defer: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            pending_ttl_secs: AtomicU64::new(DEFAULT_PENDING_TTL_SECS),
            audit: Mutex::new(None),
        }
    }

    /// Attach the audit sink. Records are appended for every request that
    /// completes, is reaped, or is short-circuited by passthrough.
    pub fn set_audit_sink(&self, sink: Arc<AuditSink>) {
        *self.audit.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
    }

    fn audit_append(&self, draft: &AuditDraft) {
        let guard = self.audit.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sink) = guard.as_ref() {
            sink.append(draft);
        }
    }

    /// Signal all background threads to stop.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Returns true if shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Generate an unguessable correlation nonce for an event.
    ///
    /// The loopback HTTP receiver is intentionally unauthenticated. Random IDs
    /// mitigate blind guessing by another local process, but are not a security
    /// boundary if a live ID is disclosed. Reject zero because Falco rules use
    /// `correlation.id > 0` as their catch-all, and reject any (extremely
    /// unlikely) collision with a pending request.
    pub fn next_correlation_id(&self) -> Result<u64, getrandom::Error> {
        loop {
            let id = getrandom::u64()?;
            if id != 0 && !self.pending.contains_key(&id) {
                return Ok(id);
            }
        }
    }

    /// Set monitor mode. When enabled, all verdicts resolve as defer after
    /// the synchronous rule-eval wait — Prempti steps aside but still logs
    /// would-deny / would-ask. Independent of passthrough mode.
    pub fn set_monitor_mode(&self, enabled: bool) {
        self.monitor_mode.store(enabled, Ordering::Relaxed);
        log::info!(
            "broker monitor: {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Set passthrough mode. When enabled, all interceptor requests are resolved
    /// as "defer" immediately upon registration, without waiting for rule evaluation.
    /// Events are still enqueued for the Falco engine to process.
    pub fn set_passthrough(&self, enabled: bool) {
        self.passthrough.store(enabled, Ordering::Relaxed);
        log::info!(
            "broker passthrough: {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Returns true if passthrough mode is active.
    pub fn is_passthrough(&self) -> bool {
        self.passthrough.load(Ordering::Relaxed)
    }

    /// Set the no-rule-match floor (`default_action`). When `defer` is true,
    /// events matching no deny/ask rule resolve as `defer` (Prempti steps
    /// aside, the agent's own permission system decides); when false, as
    /// `allow` (Prempti approves, skipping the agent prompt). Applies in
    /// guardrails mode only — monitor and passthrough always resolve as defer.
    pub fn set_default_action(&self, defer: bool) {
        self.default_defer.store(defer, Ordering::Relaxed);
        log::info!(
            "broker default_action: {}",
            if defer { "defer" } else { "allow" }
        );
    }

    /// Override the pending-request TTL (seconds). Clamped to at least the
    /// default so a misconfiguration cannot reap live requests early.
    pub fn set_pending_ttl_secs(&self, secs: u64) {
        let secs = secs.max(DEFAULT_PENDING_TTL_SECS);
        self.pending_ttl_secs.store(secs, Ordering::Relaxed);
        log::info!("broker pending TTL: {secs}s");
    }

    pub fn pending_ttl_secs(&self) -> u64 {
        self.pending_ttl_secs.load(Ordering::Relaxed)
    }

    /// The guardrails no-rule-match floor verdict, per `default_action`.
    fn default_verdict(&self) -> Verdict {
        if self.default_defer.load(Ordering::Relaxed) {
            Verdict::Defer
        } else {
            Verdict::Allow
        }
    }

    /// Returns true if monitor mode is active.
    fn is_monitor(&self) -> bool {
        self.monitor_mode.load(Ordering::Relaxed)
    }

    fn mode_label(&self) -> &'static str {
        if self.is_passthrough() {
            "passthrough"
        } else if self.is_monitor() {
            "monitor"
        } else {
            "guardrails"
        }
    }

    /// Write the wire response and close the connection.
    fn write_wire(stream: &mut BrokerStream, response: &str) {
        let _ = writeln!(stream, "{}", response);
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    }

    /// Respond once on a pending entry: take the stream, write the verdict,
    /// record it as the final verdict in the audit draft. Returns false if
    /// the entry had already responded.
    fn respond(pending: &PendingRequest, verdict: Verdict, source: &'static str) -> bool {
        let taken = pending
            .stream
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(mut stream) = taken else {
            return false;
        };
        let response = verdict.to_response_json(&pending.wire_id);
        Self::write_wire(&mut stream, &response);
        pending
            .audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_final(&verdict, source);
        true
    }

    /// Register a new pending request. `correlation_id` is the broker-assigned ID
    /// used for Falco alert correlation. `wire_id` is the interceptor's request ID
    /// used in the verdict response. `expected_signals` is the number of
    /// completion signals the broker should wait for before sealing — one
    /// Falco seen alert per event (1 for ordinary hooks, N for codex
    /// apply_patch multi-file multiplex), plus 1 when the LLM monitor will
    /// report on this request. Values below 1 are clamped to 1 so misuse
    /// can't deadlock the interceptor.
    ///
    /// In passthrough mode, the request is resolved as "defer" immediately
    /// without being added to the pending map; the audit record is written
    /// right away.
    pub fn register(
        &self,
        correlation_id: u64,
        wire_id: String,
        stream: BrokerStream,
        expected_signals: u64,
        mut draft: AuditDraft,
    ) {
        draft.mode = self.mode_label();
        if self.is_passthrough() {
            let verdict = Verdict::Defer;
            let response = verdict.to_response_json(&wire_id);
            let mut s = stream;
            Self::write_wire(&mut s, &response);
            draft.set_final(&verdict, "passthrough");
            self.audit_append(&draft);
            return;
        }
        self.pending.insert(
            correlation_id,
            PendingRequest {
                stream: Mutex::new(Some(stream)),
                wire_id,
                current_verdict: Mutex::new(None),
                created_at: Instant::now(),
                remaining_signals: AtomicU64::new(expected_signals.max(1)),
                audit: Mutex::new(draft),
            },
        );
    }

    /// Record a deny/ask signal in the entry's audit draft.
    fn record_hit(pending: &PendingRequest, source: &Source, kind: &'static str, reason: &str) {
        let mut draft = pending.audit.lock().unwrap_or_else(|e| e.into_inner());
        match source {
            Source::Falco { rule } => draft.falco.push(FalcoHit {
                rule: rule.clone(),
                kind,
                message: reason.to_string(),
            }),
            Source::Llm => {
                // `apply_llm_outcome` stores the full outcome first; keep the
                // model's own reason if it is already there.
                draft.llm.verdict = kind.to_string();
                if draft.llm.reason.is_empty() {
                    draft.llm.reason = reason.to_string();
                }
            }
            Source::Internal => draft.falco.push(FalcoHit {
                rule: "broker".to_string(),
                kind,
                message: reason.to_string(),
            }),
        }
    }

    /// Apply a deny verdict. Deny wins immediately — respond now. The entry
    /// stays until every expected signal has arrived so the audit record
    /// captures them all.
    pub fn apply_deny(&self, correlation_id: u64, reason: String, source: Source) {
        let Some(pending) = self.pending.get(&correlation_id) else {
            return;
        };
        Self::record_hit(&pending, &source, "deny", &reason);
        if self.is_monitor() {
            // In monitor mode, log the deny but don't respond yet — wait for completion.
            log::info!("monitor: would deny {} ({})", correlation_id, reason);
            return;
        }
        Self::respond(&pending, Verdict::Deny(reason), source.label());
    }

    /// Apply an ask verdict. Escalate: only upgrade if not already deny.
    pub fn apply_ask(&self, correlation_id: u64, reason: String, source: Source) {
        let Some(pending) = self.pending.get(&correlation_id) else {
            return;
        };
        Self::record_hit(&pending, &source, "ask", &reason);
        if self.is_monitor() {
            // In monitor mode, log the ask but don't stage it — wait for completion.
            log::info!("monitor: would ask {} ({})", correlation_id, reason);
            return;
        }
        let mut current = pending
            .current_verdict
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let new_verdict = Verdict::Ask(reason);
        // `Verdict::escalate` keeps `existing` whenever it is already deny
        // or ask (first ask wins on a tie); the source label follows the
        // verdict that survived.
        *current = Some(match current.take() {
            Some((existing, existing_src)) => {
                let existing_wins = matches!(existing, Verdict::Deny(_) | Verdict::Ask(_));
                let merged = existing.escalate(new_verdict);
                (
                    merged,
                    if existing_wins {
                        existing_src
                    } else {
                        source.label()
                    },
                )
            }
            None => (new_verdict, source.label()),
        });
        // Don't respond yet — wait for the completion signal.
    }

    /// Signal that rule evaluation is complete for one Falco event with this
    /// correlation ID (the catch-all seen alert). See `signal_complete`.
    pub fn apply_seen(&self, correlation_id: u64) {
        self.signal_complete(correlation_id);
    }

    /// The LLM monitor finished for this request: store its outcome in the
    /// audit draft, escalate `deny` / `ask` like a Falco alert (with
    /// `wire_reason` as the reason the agent sees), and count one completion
    /// signal. `allow`, skipped and empty outcomes only complete the count.
    pub fn apply_llm_outcome(&self, correlation_id: u64, outcome: LlmOutcome, wire_reason: String) {
        let verdict = outcome.verdict.clone();
        if let Some(pending) = self.pending.get(&correlation_id) {
            pending.audit.lock().unwrap_or_else(|e| e.into_inner()).llm = outcome;
        }
        match verdict.as_str() {
            "deny" => self.apply_deny(correlation_id, wire_reason, Source::Llm),
            "ask" => self.apply_ask(correlation_id, wire_reason, Source::Llm),
            _ => {}
        }
        self.signal_complete(correlation_id);
    }

    /// One completion signal has arrived (a Falco seen alert, or the LLM
    /// monitor finishing). When the last expected signal lands the broker
    /// responds — with the staged verdict (deny > ask > floor) if it has not
    /// responded yet — removes the entry, and seals the audit record. The
    /// no-rule-match floor is `allow` or `defer` per the configured
    /// `default_action`; in monitor mode the verdict is always defer.
    pub fn signal_complete(&self, correlation_id: u64) {
        // Decrement under the DashMap shard lock. `Some(true)` if we just
        // brought the counter to 0 (= ready to seal), `Some(false)` if more
        // signals are still expected, `None` if the entry is already gone.
        let should_seal = self
            .pending
            .get(&correlation_id)
            .map(|p| p.remaining_signals.fetch_sub(1, Ordering::AcqRel) == 1);
        match should_seal {
            Some(true) => {}
            Some(false) | None => return,
        }

        let Some((_, pending)) = self.pending.remove(&correlation_id) else {
            return;
        };
        if self.is_monitor() {
            Self::respond(&pending, Verdict::Defer, "monitor");
        } else {
            let staged = pending
                .current_verdict
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            let (verdict, source) = staged.unwrap_or_else(|| (self.default_verdict(), "floor"));
            Self::respond(&pending, verdict, source);
        }
        let draft = pending.audit.lock().unwrap_or_else(|e| e.into_inner());
        self.audit_append(&draft);
    }

    /// True when the wire verdict for this request has already been written
    /// (or the entry no longer exists). Lets a slow verdict source skip work
    /// whose outcome can no longer change the response.
    pub fn has_responded(&self, correlation_id: u64) -> bool {
        self.pending
            .get(&correlation_id)
            .map(|p| p.stream.lock().unwrap_or_else(|e| e.into_inner()).is_none())
            .unwrap_or(true)
    }

    /// Remove pending requests older than `ttl`.
    /// Returns the number of reaped entries.
    pub fn reap_stale(&self, ttl: std::time::Duration) -> usize {
        let now = Instant::now();
        let mut reaped = 0;

        // Collect stale IDs first to avoid holding DashMap iterators during removal.
        let stale_ids: Vec<u64> = self
            .pending
            .iter()
            .filter(|entry| now.duration_since(entry.value().created_at) > ttl)
            .map(|entry| *entry.key())
            .collect();

        for id in stale_ids {
            if let Some((_, pending)) = self.pending.remove(&id) {
                log::warn!(
                    "reaping stale pending request {} (age {:?})",
                    id,
                    now.duration_since(pending.created_at)
                );
                // Send deny to unblock the interceptor if it's somehow still waiting.
                Self::respond(
                    &pending,
                    Verdict::Deny("request expired".to_string()),
                    "reaper",
                );
                let draft = pending.audit.lock().unwrap_or_else(|e| e.into_inner());
                self.audit_append(&draft);
                reaped += 1;
            }
        }

        reaped
    }

    /// Number of currently pending requests.
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Start a background thread that periodically reaps stale pending requests.
    ///
    /// The thread polls the shutdown flag every `REAPER_SHUTDOWN_POLL` so it
    /// can exit quickly on `Drop`, and performs a reap pass whenever
    /// `REAPER_INTERVAL_SECS` has elapsed since the last one.
    pub fn start_reaper(broker: Arc<Broker>) -> std::thread::JoinHandle<()> {
        let reap_interval = std::time::Duration::from_secs(REAPER_INTERVAL_SECS);
        std::thread::Builder::new()
            .name("prempti-reaper".to_string())
            .spawn(move || {
                let mut last_reap = Instant::now();
                while !broker.is_shutdown() {
                    std::thread::sleep(REAPER_SHUTDOWN_POLL);
                    if last_reap.elapsed() >= reap_interval {
                        let ttl = std::time::Duration::from_secs(broker.pending_ttl_secs());
                        let reaped = broker.reap_stale(ttl);
                        if reaped > 0 {
                            log::info!("reaper: removed {} stale pending request(s)", reaped);
                        }
                        last_reap = Instant::now();
                    }
                }
                log::info!("reaper thread exiting");
            })
            .expect("failed to spawn reaper thread")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn read_response_json(peer: &UnixStream) -> serde_json::Value {
        let mut reader = BufReader::new(peer);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("read_line on peer stream");
        serde_json::from_str(line.trim()).expect("parse response JSON")
    }

    fn expect_no_response(peer: &UnixStream) {
        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 1];
        let err = (&mut &*peer)
            .read(&mut buf)
            .expect_err("peer should not have received data");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        peer.set_read_timeout(None).unwrap();
    }

    /// After a response the broker shuts the stream down; the peer must see
    /// EOF (or nothing) — never a second line.
    fn expect_no_extra_data(peer: &UnixStream) {
        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 1];
        match (&mut &*peer).read(&mut buf) {
            Ok(0) => {}
            Ok(n) => panic!("peer received {n} unexpected byte(s)"),
            Err(e) => assert!(matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )),
        }
        peer.set_read_timeout(None).unwrap();
    }

    fn register_with(broker: &Broker, id: u64, wire_id: &str) -> UnixStream {
        register_with_count(broker, id, wire_id, 1)
    }

    fn register_with_count(
        broker: &Broker,
        id: u64,
        wire_id: &str,
        expected_events: u64,
    ) -> UnixStream {
        let (broker_side, peer) = UnixStream::pair().expect("UnixStream::pair");
        broker.register(
            id,
            wire_id.to_string(),
            broker_side,
            expected_events,
            AuditDraft::default(),
        );
        peer
    }

    fn falco(rule: &str) -> Source {
        Source::Falco {
            rule: rule.to_string(),
        }
    }

    fn temp_audit_path(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "prempti-broker-audit-{}-{}",
            std::process::id(),
            label
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("audit.jsonl")
    }

    fn broker_with_audit(label: &str) -> (Broker, std::path::PathBuf) {
        let path = temp_audit_path(label);
        let broker = Broker::new();
        broker.set_audit_sink(Arc::new(AuditSink::open(&path).expect("open audit")));
        (broker, path)
    }

    fn audit_records(path: &std::path::Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        text.lines()
            .map(|l| serde_json::from_str(l).expect("audit line JSON"))
            .collect()
    }

    #[test]
    fn seen_with_no_verdict_resolves_as_allow() {
        // Default floor (default_action unset) is allow.
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
        assert_eq!(resp["id"], "wire-1");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn default_action_defer_resolves_no_match_as_defer() {
        // Guardrails no-rule-match floor follows default_action = defer.
        let broker = Broker::new();
        broker.set_default_action(true);
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "defer");
        assert_eq!(resp["id"], "wire-1");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn default_action_defer_does_not_affect_deny() {
        // default_action only governs the no-match floor — deny still wins.
        let broker = Broker::new();
        broker.set_default_action(true);
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_deny(1, "blocked".to_string(), falco("r"));
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["reason"], "blocked");
    }

    #[test]
    fn default_action_defer_does_not_affect_ask() {
        let broker = Broker::new();
        broker.set_default_action(true);
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_ask(1, "confirm".to_string(), falco("r"));
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "ask");
        assert_eq!(resp["reason"], "confirm");
    }

    #[test]
    fn deny_resolves_immediately_and_clears_pending() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_deny(1, "blocked".to_string(), falco("r"));
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["reason"], "blocked");
        // Responded, but the entry stays until the seen signal completes it
        // so the audit record can capture every signal.
        assert_eq!(broker.pending_count(), 1);
        assert!(broker.has_responded(1));
        broker.apply_seen(1);
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn ask_defers_until_seen() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_ask(1, "needs confirm".to_string(), falco("r"));
        expect_no_response(&peer);
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "ask");
        assert_eq!(resp["reason"], "needs confirm");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn deny_beats_ask_when_ask_arrives_first() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_ask(1, "confirm".to_string(), falco("r"));
        broker.apply_deny(1, "blocked".to_string(), falco("r"));
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["reason"], "blocked");
        // Seen after deny is a no-op.
        broker.apply_seen(1);
    }

    #[test]
    fn deny_beats_ask_when_ask_arrives_after() {
        // apply_ask after deny only lands in the audit draft; the wire
        // response was already written.
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_deny(1, "blocked".to_string(), falco("r"));
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        // The ask after deny must not produce a second wire write.
        broker.apply_ask(1, "confirm".to_string(), falco("r"));
        broker.apply_seen(1);
        expect_no_extra_data(&peer);
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn monitor_mode_suppresses_deny() {
        let broker = Broker::new();
        broker.set_monitor_mode(true);
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_deny(1, "would-block".to_string(), falco("r"));
        expect_no_response(&peer);
        // Seen then drives the defer verdict (monitor steps aside).
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "defer");
    }

    #[test]
    fn monitor_mode_suppresses_ask() {
        let broker = Broker::new();
        broker.set_monitor_mode(true);
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_ask(1, "would-ask".to_string(), falco("r"));
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "defer");
    }

    #[test]
    fn monitor_mode_defers_even_with_default_action_allow() {
        // default_action is a guardrails-only floor; monitor always defers.
        let broker = Broker::new();
        broker.set_monitor_mode(true);
        broker.set_default_action(false); // allow floor — must be ignored
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "defer");
    }

    #[test]
    fn unknown_correlation_id_is_noop() {
        let broker = Broker::new();
        // None of these should panic.
        broker.apply_deny(42, "r".to_string(), falco("r"));
        broker.apply_ask(42, "r".to_string(), falco("r"));
        broker.apply_seen(42);
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn correlation_ids_are_random_positive_nonces() {
        let broker = Broker::new();
        let ids: Vec<u64> = (0..32)
            .map(|_| broker.next_correlation_id().expect("OS randomness"))
            .collect();

        assert!(ids.iter().all(|id| *id > 0));
        assert!(ids
            .windows(2)
            .all(|pair| pair[1] != pair[0].wrapping_add(1)));
    }

    #[test]
    fn concurrent_requests_resolved_independently() {
        let broker = Broker::new();
        let peer1 = register_with(&broker, 1, "wire-1");
        let peer2 = register_with(&broker, 2, "wire-2");
        // Mix: peer1 gets deny, peer2 gets allow.
        broker.apply_deny(1, "one".to_string(), falco("r"));
        broker.apply_seen(2);
        let r1 = read_response_json(&peer1);
        let r2 = read_response_json(&peer2);
        assert_eq!(r1["id"], "wire-1");
        assert_eq!(r1["decision"], "deny");
        assert_eq!(r2["id"], "wire-2");
        assert_eq!(r2["decision"], "allow");
    }

    #[test]
    fn reap_stale_removes_and_denies() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        assert_eq!(broker.pending_count(), 1);
        std::thread::sleep(Duration::from_millis(20));
        let n = broker.reap_stale(Duration::from_millis(10));
        assert_eq!(n, 1);
        assert_eq!(broker.pending_count(), 0);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert!(resp["reason"].as_str().unwrap().contains("expired"));
    }

    #[test]
    fn reap_stale_preserves_fresh_entries() {
        let broker = Broker::new();
        let _peer = register_with(&broker, 1, "wire-1");
        let n = broker.reap_stale(Duration::from_secs(60));
        assert_eq!(n, 0);
        assert_eq!(broker.pending_count(), 1);
    }

    #[test]
    fn passthrough_defers_immediately_and_skips_pending() {
        let broker = Broker::new();
        broker.set_passthrough(true);
        broker.set_default_action(false); // allow floor — must be ignored
        let peer = register_with(&broker, 1, "wire-1");
        // Defer JSON is on the wire right away — no apply_* call needed.
        // Passthrough always steps aside, regardless of default_action.
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "defer");
        assert_eq!(resp["id"], "wire-1");
        // Pending map must stay empty: passthrough short-circuits before insert.
        assert_eq!(broker.pending_count(), 0);
    }

    // ------------------------------------------------------------------
    // Multi-event seen counting (apply_patch multiplex)
    //
    // These tests pin the broker's expected_events behavior: a single wire
    // request can correspond to N Falco events sharing the same correlation
    // id, and the broker must wait for N seen alerts before resolving.
    // Deny still short-circuits.
    // ------------------------------------------------------------------

    #[test]
    fn multi_event_seen_counts_down_before_resolving_allow() {
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 3);

        // First two seens do nothing on the wire — broker waits for all three.
        broker.apply_seen(1);
        expect_no_response(&peer);
        broker.apply_seen(1);
        expect_no_response(&peer);

        // Third seen resolves as allow (no deny/ask was applied).
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
        assert_eq!(resp["id"], "wire-1");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn multi_event_deny_short_circuits_pending_seens() {
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 5);

        // Deny responds immediately regardless of how many seens remain.
        broker.apply_deny(1, "blocked on path 2 of 5".to_string(), falco("r"));
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["reason"], "blocked on path 2 of 5");
        assert!(broker.has_responded(1));

        // Remaining seen alerts only count down; no double-write to the stream.
        broker.apply_seen(1);
        broker.apply_seen(1);
        broker.apply_seen(1);
        broker.apply_seen(1);
        assert_eq!(broker.pending_count(), 1);
        broker.apply_seen(1);
        assert_eq!(broker.pending_count(), 0);
        expect_no_extra_data(&peer);
    }

    #[test]
    fn multi_event_ask_resolves_only_at_last_seen() {
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 2);

        // Ask alert lands first; broker stages the verdict and waits.
        broker.apply_ask(1, "needs confirm".to_string(), falco("r"));
        expect_no_response(&peer);

        // First of two seens still doesn't resolve.
        broker.apply_seen(1);
        expect_no_response(&peer);

        // Second seen resolves with the staged ask.
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "ask");
        assert_eq!(resp["reason"], "needs confirm");
    }

    #[test]
    fn multi_event_monitor_mode_resolves_at_last_seen_as_defer() {
        let broker = Broker::new();
        broker.set_monitor_mode(true);
        let peer = register_with_count(&broker, 1, "wire-1", 2);

        // Monitor mode also has to wait for the full seen count — otherwise
        // a single-event observer would race ahead and resolve before the
        // rest of a multi-file apply_patch finishes evaluating.
        broker.apply_deny(1, "would-deny on first path".to_string(), falco("r"));
        expect_no_response(&peer);
        broker.apply_seen(1);
        expect_no_response(&peer);
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "defer");
    }

    #[test]
    fn register_with_zero_expected_events_clamps_to_one() {
        // Defensive: a caller bug passing 0 must not deadlock the broker by
        // requiring an impossible-to-reach seen count. Clamp to 1.
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 0);
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn passthrough_disabled_keeps_default_register_behavior() {
        // Default (passthrough=false): entry inserted, stream stays open until
        // a verdict is applied.
        let broker = Broker::new();
        assert!(!broker.is_passthrough());
        let peer = register_with(&broker, 1, "wire-1");
        assert_eq!(broker.pending_count(), 1);
        expect_no_response(&peer);
        // Resolve so the stream/peer drop cleanly.
        broker.apply_deny(1, "cleanup".to_string(), falco("r"));
        let _ = read_response_json(&peer);
        broker.apply_seen(1);
        assert_eq!(broker.pending_count(), 0);
    }

    // ------------------------------------------------------------------
    // Audit trail + two-source completion (LLM monitor as a second signal)
    // ------------------------------------------------------------------

    #[test]
    fn audit_record_written_on_completion_with_all_signals() {
        let (broker, path) = broker_with_audit("complete");
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_ask(1, "Rule A: confirm".to_string(), falco("Rule A"));
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "ask");
        let recs = audit_records(&path);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["mode"], "guardrails");
        assert_eq!(recs[0]["falco"]["verdict"], "ask");
        assert_eq!(recs[0]["falco"]["rules"][0]["rule"], "Rule A");
        assert_eq!(recs[0]["final"]["verdict"], "ask");
        assert_eq!(recs[0]["final"]["source"], "falco");
    }

    #[test]
    fn audit_record_captures_signals_after_deny_short_circuit() {
        let (broker, path) = broker_with_audit("late");
        let peer = register_with_count(&broker, 1, "wire-1", 2);
        broker.apply_deny(1, "Rule D: blocked".to_string(), falco("Rule D"));
        let _ = read_response_json(&peer);
        // Late ask + both seens still reach the record.
        broker.apply_ask(1, "Rule A: confirm".to_string(), falco("Rule A"));
        broker.apply_seen(1);
        assert!(audit_records(&path).is_empty());
        broker.apply_seen(1);
        let recs = audit_records(&path);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["falco"]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(recs[0]["final"]["verdict"], "deny");
        assert_eq!(recs[0]["final"]["source"], "falco");
    }

    #[test]
    fn llm_signal_counts_toward_completion() {
        // expected_signals = 1 seen + 1 LLM. Falco seen alone must not respond.
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 2);
        broker.apply_seen(1);
        expect_no_response(&peer);
        broker.apply_ask(1, "LLM monitor: sign-off".to_string(), Source::Llm);
        broker.signal_complete(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "ask");
        assert_eq!(resp["reason"], "LLM monitor: sign-off");
    }

    #[test]
    fn llm_deny_before_seen_responds_immediately() {
        let (broker, path) = broker_with_audit("llmdeny");
        let peer = register_with_count(&broker, 1, "wire-1", 2);
        broker.apply_deny(1, "LLM monitor: out of scope".to_string(), Source::Llm);
        broker.signal_complete(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        broker.apply_seen(1);
        let recs = audit_records(&path);
        assert_eq!(recs[0]["llm"]["verdict"], "deny");
        assert_eq!(recs[0]["final"]["source"], "llm");
    }

    #[test]
    fn llm_allow_never_downgrades_falco_ask() {
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 2);
        broker.apply_ask(1, "Rule A: confirm".to_string(), falco("Rule A"));
        broker.apply_seen(1);
        // LLM said allow: it contributes no verdict, only a completion signal.
        broker.signal_complete(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "ask");
        assert_eq!(resp["reason"], "Rule A: confirm");
    }

    #[test]
    fn monitor_mode_records_would_deny_from_llm() {
        let (broker, path) = broker_with_audit("monllm");
        broker.set_monitor_mode(true);
        let peer = register_with_count(&broker, 1, "wire-1", 2);
        broker.apply_deny(1, "LLM monitor: nope".to_string(), Source::Llm);
        broker.signal_complete(1);
        expect_no_response(&peer);
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "defer");
        let recs = audit_records(&path);
        assert_eq!(recs[0]["mode"], "monitor");
        assert_eq!(recs[0]["llm"]["verdict"], "deny");
        assert_eq!(recs[0]["final"]["verdict"], "defer");
        assert_eq!(recs[0]["final"]["source"], "monitor");
    }

    #[test]
    fn reaper_seals_audit_record() {
        let (broker, path) = broker_with_audit("reaper");
        let peer = register_with(&broker, 1, "wire-1");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(broker.reap_stale(Duration::from_millis(10)), 1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        let recs = audit_records(&path);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["final"]["source"], "reaper");
    }

    #[test]
    fn passthrough_writes_audit_record_immediately() {
        let (broker, path) = broker_with_audit("pass");
        broker.set_passthrough(true);
        let peer = register_with(&broker, 1, "wire-1");
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "defer");
        let recs = audit_records(&path);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["mode"], "passthrough");
        assert_eq!(recs[0]["final"]["source"], "passthrough");
    }

    #[test]
    fn has_responded_reports_wire_state() {
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 2);
        assert!(!broker.has_responded(1));
        broker.apply_deny(1, "x".to_string(), falco("r"));
        let _ = read_response_json(&peer);
        assert!(broker.has_responded(1));
        // Unknown id counts as responded (nothing left to influence).
        assert!(broker.has_responded(99));
    }

    #[test]
    fn pending_ttl_never_drops_below_default() {
        let broker = Broker::new();
        broker.set_pending_ttl_secs(1);
        assert_eq!(broker.pending_ttl_secs(), DEFAULT_PENDING_TTL_SECS);
        broker.set_pending_ttl_secs(120);
        assert_eq!(broker.pending_ttl_secs(), 120);
    }
}
