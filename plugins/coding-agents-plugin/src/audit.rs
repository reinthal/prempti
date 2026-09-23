//! Tamper-evident audit trail.
//!
//! One JSON line per interceptor request, appended to `audit.jsonl`. Every
//! record carries the verdict signals that reached the broker (Falco rule
//! hits, the LLM monitor outcome, the final wire verdict and its source) and
//! is hash-chained: `hash = sha256(prev_hash || canonical_body)`, where the
//! canonical body is the record without its `hash` field serialized with
//! sorted keys. Editing, deleting or reordering any line breaks the chain
//! from that point on; `premptictl audit verify` walks it.
//!
//! The file is deliberately NOT rotated by the supervisor — rotation would
//! split the chain. Sealing / rotation is a later `premptictl audit` job.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::verdict::Verdict;

/// `prev_hash` of the first record in a file.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Record format version.
const RECORD_VERSION: u64 = 1;

/// How much of the file tail to scan when recovering `seq` / `prev_hash`
/// from an existing audit file. Records are ~1–3 KB; 256 KiB is generous.
const RECOVERY_TAIL_BYTES: u64 = 256 * 1024;

#[derive(Default, Clone, Debug)]
pub struct AgentMeta {
    pub name: String,
    pub pid: u64,
    pub session_id: String,
    pub agent_id: String,
    pub agent_type: String,
    pub permission_mode: String,
    pub transcript_path: String,
    pub hook_event_name: String,
}

#[derive(Default, Clone, Debug)]
pub struct ToolMeta {
    pub name: String,
    pub use_id: String,
    /// `tool_input` serialized as JSON, truncated to the configured cap.
    pub input: String,
    /// sha256 over the full (untruncated) serialized `tool_input`.
    pub input_sha256: String,
    pub input_truncated: bool,
}

#[derive(Clone, Debug)]
pub struct FalcoHit {
    pub rule: String,
    /// `deny` or `ask`.
    pub kind: &'static str,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct LlmOutcome {
    /// `disabled` | `skipped:<reason>` | `ok` | `error:<reason>`.
    pub status: String,
    /// `allow` | `ask` | `deny` (empty unless status is `ok`).
    pub verdict: String,
    pub reason: String,
    pub roe_clause: String,
    pub model: String,
    pub roe_sha256: String,
    pub latency_ms: u64,
    pub attempts: u32,
}

impl Default for LlmOutcome {
    fn default() -> Self {
        LlmOutcome {
            status: "disabled".to_string(),
            verdict: String::new(),
            reason: String::new(),
            roe_clause: String::new(),
            model: String::new(),
            roe_sha256: String::new(),
            latency_ms: 0,
            attempts: 0,
        }
    }
}

/// Everything the broker accumulates about one wire request before the
/// record is sealed and appended.
#[derive(Clone, Debug)]
pub struct AuditDraft {
    pub correlation_id: u64,
    pub agent: AgentMeta,
    pub tool: ToolMeta,
    pub cwd: String,
    /// `guardrails` | `monitor` | `passthrough`.
    pub mode: &'static str,
    pub falco: Vec<FalcoHit>,
    pub llm: LlmOutcome,
    /// The verdict written to the wire and which signal produced it:
    /// `falco` | `llm` | `floor` | `monitor` | `passthrough` | `reaper` | `broker`.
    pub final_verdict: Option<(Verdict, &'static str)>,
    /// `none` | `pending` (held for hardware-key sign-off when sealed).
    pub signoff_status: &'static str,
    pub started: Instant,
}

impl Default for AuditDraft {
    fn default() -> Self {
        AuditDraft {
            correlation_id: 0,
            agent: AgentMeta::default(),
            tool: ToolMeta::default(),
            cwd: String::new(),
            mode: "",
            falco: Vec::new(),
            llm: LlmOutcome::default(),
            final_verdict: None,
            signoff_status: "none",
            started: Instant::now(),
        }
    }
}

fn str_field(event: &serde_json::Value, key: &str) -> String {
    event
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Truncate `s` to at most `max` bytes on a char boundary.
fn truncate_utf8(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    (s[..cut].to_string(), true)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

impl AuditDraft {
    /// Build the request-time part of the record from the raw hook JSON.
    pub fn from_event(
        correlation_id: u64,
        agent_name: &str,
        agent_pid: u64,
        event: &serde_json::Value,
        input_max_bytes: usize,
    ) -> Self {
        let input_full = event
            .get("tool_input")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let (input, input_truncated) = truncate_utf8(&input_full, input_max_bytes);
        AuditDraft {
            correlation_id,
            agent: AgentMeta {
                name: agent_name.to_string(),
                pid: agent_pid,
                session_id: str_field(event, "session_id"),
                agent_id: str_field(event, "agent_id"),
                agent_type: str_field(event, "agent_type"),
                permission_mode: str_field(event, "permission_mode"),
                transcript_path: str_field(event, "transcript_path"),
                hook_event_name: str_field(event, "hook_event_name"),
            },
            tool: ToolMeta {
                name: str_field(event, "tool_name"),
                use_id: str_field(event, "tool_use_id"),
                input_sha256: sha256_hex(input_full.as_bytes()),
                input,
                input_truncated,
            },
            cwd: str_field(event, "cwd"),
            ..Default::default()
        }
    }

    /// Record the wire verdict once. Later calls are ignored so the first
    /// responder (deny short-circuit, reaper, completion) wins.
    pub fn set_final(&mut self, verdict: &Verdict, source: &'static str) {
        if self.final_verdict.is_none() {
            self.final_verdict = Some((verdict.clone(), source));
        }
    }

    fn to_value(&self, seq: u64, prev_hash: &str) -> serde_json::Value {
        let ts_ms = now_ms();
        let falco_verdict = if self.falco.iter().any(|h| h.kind == "deny") {
            "deny"
        } else if self.falco.iter().any(|h| h.kind == "ask") {
            "ask"
        } else {
            "none"
        };
        let (final_label, final_reason, final_source) = match &self.final_verdict {
            Some((v, src)) => {
                let (label, reason) = verdict_parts(v);
                (label, reason, *src)
            }
            None => ("none", String::new(), ""),
        };
        serde_json::json!({
            "v": RECORD_VERSION,
            "kind": "request",
            "seq": seq,
            "ts_ms": ts_ms,
            "correlation_id": self.correlation_id,
            "mode": self.mode,
            "agent": {
                "name": self.agent.name,
                "pid": self.agent.pid,
                "session_id": self.agent.session_id,
                "agent_id": self.agent.agent_id,
                "agent_type": self.agent.agent_type,
                "permission_mode": self.agent.permission_mode,
                "transcript_path": self.agent.transcript_path,
                "hook_event_name": self.agent.hook_event_name,
            },
            "tool": {
                "name": self.tool.name,
                "use_id": self.tool.use_id,
                "input": self.tool.input,
                "input_sha256": self.tool.input_sha256,
                "input_truncated": self.tool.input_truncated,
            },
            "cwd": self.cwd,
            "falco": {
                "verdict": falco_verdict,
                "rules": self.falco.iter().map(|h| serde_json::json!({
                    "rule": h.rule,
                    "kind": h.kind,
                    "message": h.message,
                })).collect::<Vec<_>>(),
            },
            "llm": {
                "status": self.llm.status,
                "verdict": self.llm.verdict,
                "reason": self.llm.reason,
                "roe_clause": self.llm.roe_clause,
                "model": self.llm.model,
                "roe_sha256": self.llm.roe_sha256,
                "latency_ms": self.llm.latency_ms,
                "attempts": self.llm.attempts,
            },
            "final": {
                "verdict": final_label,
                "reason": final_reason,
                "source": final_source,
            },
            "signoff": {
                "status": self.signoff_status,
            },
            "latency_ms": self.started.elapsed().as_millis() as u64,
            "prev_hash": prev_hash,
        })
    }
}

/// Outcome of a hardware-key sign-off on a held request. Appended as its
/// own `kind: "signoff"` record right after the decision, chained like any
/// other record; `request_hash` ties it to the held request's record.
#[derive(Clone, Debug, Default)]
pub struct SignoffRecord {
    pub correlation_id: u64,
    pub request_seq: u64,
    pub request_hash: String,
    /// `approve` | `deny` | `expired`.
    pub decision: &'static str,
    pub reason: String,
    pub rp_id: String,
    pub key_label: String,
    pub credential_id: String,
    pub sign_count: u32,
    pub user_present: bool,
    pub user_verified: bool,
    pub auth_data: String,
    pub signature: String,
    pub held_ms: u64,
}

impl SignoffRecord {
    fn to_value(&self, seq: u64, prev_hash: &str) -> serde_json::Value {
        serde_json::json!({
            "v": RECORD_VERSION,
            "kind": "signoff",
            "seq": seq,
            "ts_ms": now_ms(),
            "correlation_id": self.correlation_id,
            "request_seq": self.request_seq,
            "request_hash": self.request_hash,
            "decision": self.decision,
            "reason": self.reason,
            "rp_id": self.rp_id,
            "key": {
                "label": self.key_label,
                "credential_id": self.credential_id,
                "sign_count": self.sign_count,
                "user_present": self.user_present,
                "user_verified": self.user_verified,
            },
            "proof": {
                "auth_data": self.auth_data,
                "signature": self.signature,
            },
            "held_ms": self.held_ms,
            "prev_hash": prev_hash,
        })
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `(label, reason)` for a verdict.
pub fn verdict_parts(v: &Verdict) -> (&'static str, String) {
    match v {
        Verdict::Allow => ("allow", String::new()),
        Verdict::Deny(r) => ("deny", r.clone()),
        Verdict::Ask(r) => ("ask", r.clone()),
        Verdict::Defer => ("defer", String::new()),
    }
}

/// Serialize with object keys sorted, no whitespace. This is the byte
/// sequence the chain hash covers, so it must not depend on serde_json's
/// `preserve_order` feature or on insertion order anywhere.
pub fn canonical_json(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
            out.push('{');
            let mut first = true;
            for (k, val) in sorted {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&serde_json::Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Chain hash over `prev_hash` and the canonical body (record minus `hash`).
pub fn chain_hash(prev_hash: &str, canonical_body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical_body.as_bytes());
    let mut out = String::with_capacity(64);
    for b in hasher.finalize() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Verify one record line against the expected previous hash. Returns the
/// record's `(seq, hash)` on success. The production verifier lives in
/// `premptictl audit verify`; this copy keeps the writer honest in tests.
#[cfg(test)]
pub fn verify_line(line: &str, expected_prev: &str) -> Result<(u64, String), String> {
    let mut v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("malformed JSON: {e}"))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| "record is not an object".to_string())?;
    let hash = obj
        .remove("hash")
        .and_then(|h| h.as_str().map(|s| s.to_string()))
        .ok_or_else(|| "record has no hash".to_string())?;
    let seq = obj
        .get("seq")
        .and_then(|s| s.as_u64())
        .ok_or_else(|| "record has no seq".to_string())?;
    let prev = obj.get("prev_hash").and_then(|s| s.as_str()).unwrap_or("");
    if prev != expected_prev {
        return Err(format!(
            "seq {seq}: prev_hash mismatch (expected {expected_prev}, found {prev})"
        ));
    }
    let computed = chain_hash(expected_prev, &canonical_json(&v));
    if computed != hash {
        return Err(format!("seq {seq}: hash mismatch"));
    }
    Ok((seq, hash))
}

struct AuditInner {
    file: BufWriter<File>,
    seq: u64,
    prev_hash: String,
}

/// Single-writer append-only sink. The mutex keeps `seq` and `prev_hash`
/// consistent across the broker's worker threads.
pub struct AuditSink {
    inner: Mutex<AuditInner>,
    path: String,
}

impl AuditSink {
    /// Open (or create) the audit file and recover the chain head from its
    /// last line. A corrupt last line is reported and the chain restarts
    /// from that line's `seq`/`hash` as written — verification will flag it.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let (seq, prev_hash) = match read_last_line(path)? {
            Some(line) => {
                let v: serde_json::Value = serde_json::from_str(&line).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("audit file {} last line is not JSON: {e}", path.display()),
                    )
                })?;
                let seq = v.get("seq").and_then(|s| s.as_u64()).unwrap_or(0);
                let hash = v
                    .get("hash")
                    .and_then(|h| h.as_str())
                    .unwrap_or(GENESIS_HASH)
                    .to_string();
                (seq, hash)
            }
            None => (0, GENESIS_HASH.to_string()),
        };
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        log::info!("audit sink {} (resuming at seq {seq})", path.display());
        Ok(AuditSink {
            inner: Mutex::new(AuditInner {
                file: BufWriter::new(file),
                seq,
                prev_hash,
            }),
            path: path.display().to_string(),
        })
    }

    /// Seal `draft` into the next record and append it. Returns the
    /// record's `(seq, hash)`, or `None` if the write failed.
    pub fn append(&self, draft: &AuditDraft) -> Option<(u64, String)> {
        self.append_with(|seq, prev| draft.to_value(seq, prev))
    }

    /// Append a sign-off outcome record.
    pub fn append_signoff(&self, rec: &SignoffRecord) -> Option<(u64, String)> {
        self.append_with(|seq, prev| rec.to_value(seq, prev))
    }

    fn append_with(
        &self,
        build: impl FnOnce(u64, &str) -> serde_json::Value,
    ) -> Option<(u64, String)> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let seq = inner.seq + 1;
        let mut value = build(seq, &inner.prev_hash);
        let body = canonical_json(&value);
        let hash = chain_hash(&inner.prev_hash, &body);
        if let Some(obj) = value.as_object_mut() {
            obj.insert("hash".to_string(), serde_json::Value::String(hash.clone()));
        }
        let line = canonical_json(&value);
        if let Err(e) = writeln!(inner.file, "{line}").and_then(|_| inner.file.flush()) {
            log::error!("audit: failed to append to {}: {e}", self.path);
            return None;
        }
        inner.seq = seq;
        inner.prev_hash = hash.clone();
        Some((seq, hash))
    }

    #[allow(dead_code)]
    pub fn seq(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).seq
    }
}

/// Last non-empty line of `path`, scanning at most the final
/// `RECOVERY_TAIL_BYTES`. `Ok(None)` when the file is missing or empty.
fn read_last_line(path: &Path) -> std::io::Result<Option<String>> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let start = len.saturating_sub(RECOVERY_TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    Ok(text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("prempti-audit-{}-{}", std::process::id(), label));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("audit.jsonl")
    }

    fn sample(correlation_id: u64) -> AuditDraft {
        let event = serde_json::json!({
            "session_id": "s1", "tool_name": "Bash", "tool_use_id": "t1",
            "tool_input": {"command": "echo hi"}, "cwd": "/tmp",
            "agent_id": "sub-1", "agent_type": "Explore",
        });
        let mut d = AuditDraft::from_event(correlation_id, "claude_code", 42, &event, 1024);
        d.mode = "guardrails";
        d.set_final(&Verdict::Allow, "floor");
        d
    }

    fn verify_file(path: &Path) -> Result<u64, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut prev = GENESIS_HASH.to_string();
        let mut last = 0;
        for line in text.lines() {
            let (seq, hash) = verify_line(line, &prev)?;
            prev = hash;
            last = seq;
        }
        Ok(last)
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let v = serde_json::json!({"b": 1, "a": {"z": [1, {"y": 2, "x": 3}], "c": "s"}});
        assert_eq!(
            canonical_json(&v),
            r#"{"a":{"c":"s","z":[1,{"x":3,"y":2}]},"b":1}"#
        );
    }

    #[test]
    fn chain_verifies_and_detects_tamper() {
        let path = temp_path("chain");
        {
            let sink = AuditSink::open(&path).unwrap();
            sink.append(&sample(1));
            sink.append(&sample(2));
            sink.append(&sample(3));
        }
        assert_eq!(verify_file(&path).unwrap(), 3);

        // Flip a byte inside the second record's tool input.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replacen("echo hi", "echo ho", 1);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let err = verify_file(&path).unwrap_err();
        assert!(err.starts_with("seq 2"), "{err}");
    }

    #[test]
    fn reopen_recovers_chain_head() {
        let path = temp_path("reopen");
        {
            let sink = AuditSink::open(&path).unwrap();
            sink.append(&sample(1));
            sink.append(&sample(2));
        }
        {
            let sink = AuditSink::open(&path).unwrap();
            assert_eq!(sink.seq(), 2);
            sink.append(&sample(3));
        }
        assert_eq!(verify_file(&path).unwrap(), 3);
    }

    #[test]
    fn signoff_record_chains_after_request_record() {
        let path = temp_path("signoff");
        let sink = AuditSink::open(&path).unwrap();
        let mut d = sample(5);
        d.signoff_status = "pending";
        let (req_seq, req_hash) = sink.append(&d).unwrap();
        let rec = SignoffRecord {
            correlation_id: 5,
            request_seq: req_seq,
            request_hash: req_hash.clone(),
            decision: "approve",
            key_label: "yubi".into(),
            ..Default::default()
        };
        let (seq, _) = sink.append_signoff(&rec).unwrap();
        assert_eq!(seq, req_seq + 1);
        assert_eq!(verify_file(&path).unwrap(), 2);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[0]["kind"], "request");
        assert_eq!(lines[0]["signoff"]["status"], "pending");
        assert_eq!(lines[1]["kind"], "signoff");
        assert_eq!(lines[1]["request_hash"], req_hash);
        assert_eq!(lines[1]["key"]["label"], "yubi");
        assert_eq!(lines[1]["prev_hash"], req_hash);
    }

    #[test]
    fn draft_from_event_hashes_full_input_and_truncates_stored_copy() {
        let event = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {"file_path": "/x", "content": "a".repeat(100)},
        });
        let d = AuditDraft::from_event(7, "claude_code", 0, &event, 16);
        assert!(d.tool.input_truncated);
        assert_eq!(d.tool.input.len(), 16);
        let full = event["tool_input"].to_string();
        assert_eq!(d.tool.input_sha256, sha256_hex(full.as_bytes()));
        assert_eq!(d.tool.name, "Write");
    }

    #[test]
    fn record_carries_agent_and_falco_fields() {
        let path = temp_path("fields");
        let sink = AuditSink::open(&path).unwrap();
        let mut d = sample(9);
        d.falco.push(FalcoHit {
            rule: "Deny x".into(),
            kind: "deny",
            message: "Deny x: blocked".into(),
        });
        d.final_verdict = None;
        d.set_final(&Verdict::Deny("Deny x: blocked".into()), "falco");
        sink.append(&d);
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v["agent"]["agent_type"], "Explore");
        assert_eq!(v["falco"]["verdict"], "deny");
        assert_eq!(v["falco"]["rules"][0]["rule"], "Deny x");
        assert_eq!(v["final"]["verdict"], "deny");
        assert_eq!(v["final"]["source"], "falco");
        assert_eq!(v["llm"]["status"], "disabled");
        assert_eq!(v["prev_hash"], GENESIS_HASH);
    }
}
