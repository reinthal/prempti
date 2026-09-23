//! `premptictl audit` — read and verify the hash-chained audit trail written
//! by the plugin broker to `<prefix>/log/audit.jsonl`.
//!
//! The canonical-JSON and chain-hash rules here mirror
//! `plugins/coding-agents-plugin/src/audit.rs`. Keep the two in sync: a
//! record that verifies in one must verify in the other.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const DEFAULT_TAIL: usize = 50;
const FOLLOW_POLL: Duration = Duration::from_millis(500);

pub fn audit_path(prefix: &Path) -> PathBuf {
    prefix.join("log").join("audit.jsonl")
}

pub fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  premptictl audit verify            Walk the hash chain; exit 1 on the first broken record");
    eprintln!("  premptictl audit tail [flags]      Print recent audit records");
    eprintln!(
        "                     -n, --tail N    print last N records (default: {DEFAULT_TAIL})"
    );
    eprintln!("                     -f, --follow    stream new records");
    eprintln!(
        "                     --json          raw JSON lines instead of the one-line summary"
    );
    eprintln!("  premptictl audit serve [--addr HOST:PORT]");
    eprintln!("                                     Serve a live web UI for the audit trail");
    eprintln!(
        "                                     (default: {DEFAULT_SERVE_ADDR}, loopback only)"
    );
}

pub fn cli(prefix: &Path, args: &[&str]) {
    match args {
        ["verify"] => verify(prefix),
        ["tail", rest @ ..] => match parse_tail_args(rest) {
            Ok(opts) => tail(prefix, &opts),
            Err(e) => {
                eprintln!("{e}");
                eprintln!();
                print_usage();
                process::exit(2);
            }
        },
        ["serve", rest @ ..] => match parse_serve_args(rest) {
            Ok(addr) => serve(prefix, &addr),
            Err(e) => {
                eprintln!("{e}");
                eprintln!();
                print_usage();
                process::exit(2);
            }
        },
        _ => {
            print_usage();
            process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// Chain primitives (mirror of the plugin's audit.rs)
// ---------------------------------------------------------------------------

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

pub fn sha256_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(data) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

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

/// Verify one line against the expected previous hash; returns `(seq, hash)`.
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

/// Outcome of walking a whole file.
#[derive(Debug)]
pub struct ChainReport {
    pub records: u64,
    pub last_seq: u64,
    pub last_hash: String,
}

/// Walk every line; the error names the line number and the reason.
pub fn verify_reader<R: BufRead>(reader: R) -> Result<ChainReport, (usize, String)> {
    let mut prev = GENESIS_HASH.to_string();
    let mut report = ChainReport {
        records: 0,
        last_seq: 0,
        last_hash: GENESIS_HASH.to_string(),
    };
    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| (idx + 1, format!("read error: {e}")))?;
        if line.trim().is_empty() {
            continue;
        }
        let (seq, hash) = verify_line(&line, &prev).map_err(|e| (idx + 1, e))?;
        if seq != report.last_seq + 1 {
            return Err((
                idx + 1,
                format!("seq {seq}: expected seq {}", report.last_seq + 1),
            ));
        }
        prev = hash.clone();
        report.records += 1;
        report.last_seq = seq;
        report.last_hash = hash;
    }
    Ok(report)
}

fn verify(prefix: &Path) {
    let path = audit_path(prefix);
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open {}: {e}", path.display());
            process::exit(1);
        }
    };
    match verify_reader(BufReader::new(file)) {
        Ok(r) => {
            println!(
                "OK {} record(s), chain head seq={} hash={}",
                r.records, r.last_seq, r.last_hash
            );
        }
        Err((line_no, reason)) => {
            eprintln!("FAIL {} line {line_no}: {reason}", path.display());
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// tail
// ---------------------------------------------------------------------------

struct TailOpts {
    count: usize,
    follow: bool,
    json: bool,
}

fn parse_tail_args(args: &[&str]) -> Result<TailOpts, String> {
    let mut opts = TailOpts {
        count: DEFAULT_TAIL,
        follow: false,
        json: false,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        match a {
            "-f" | "--follow" => opts.follow = true,
            "--json" => opts.json = true,
            "-n" | "--tail" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| format!("{a} requires a value"))?;
                opts.count = v.parse().map_err(|_| format!("invalid {a} value: {v}"))?;
            }
            _ if a.starts_with("--tail=") => {
                let v = &a["--tail=".len()..];
                opts.count = v
                    .parse()
                    .map_err(|_| format!("invalid --tail value: {v}"))?;
            }
            _ => return Err(format!("unknown audit tail flag: {a}")),
        }
        i += 1;
    }
    Ok(opts)
}

fn tail(prefix: &Path, opts: &TailOpts) {
    let path = audit_path(prefix);
    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open {}: {e}", path.display());
            eprintln!("No audit records yet? The plugin writes the file on first request.");
            process::exit(1);
        }
    };
    let mut text = String::new();
    if let Err(e) = file.read_to_string(&mut text) {
        eprintln!("Cannot read {}: {e}", path.display());
        process::exit(1);
    }
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(opts.count);
    for line in &lines[start..] {
        print_record(line, opts.json);
    }
    if !opts.follow {
        return;
    }
    let mut offset = text.len() as u64;
    let mut pending = String::new();
    loop {
        std::thread::sleep(FOLLOW_POLL);
        let Ok(len) = file.metadata().map(|m| m.len()) else {
            continue;
        };
        if len < offset {
            // Truncated / replaced: start over from the top.
            offset = 0;
            pending.clear();
        }
        if len == offset {
            continue;
        }
        if file.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let mut chunk = String::new();
        if file.read_to_string(&mut chunk).is_err() {
            continue;
        }
        offset = len;
        pending.push_str(&chunk);
        while let Some(nl) = pending.find('\n') {
            let line = pending[..nl].to_string();
            pending.drain(..=nl);
            if !line.trim().is_empty() {
                print_record(&line, opts.json);
            }
        }
    }
}

fn print_record(line: &str, json: bool) {
    if json {
        println!("{line}");
        return;
    }
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(v) => println!("{}", summarize(&v)),
        Err(_) => println!("?? {line}"),
    }
}

fn s<'a>(v: &'a serde_json::Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str().unwrap_or("")
}

/// One-line summary: `ts seq session[/agent_type] tool final(source) falco=… llm=…`,
/// or for a sign-off record `ts seq signoff <decision> for #<request_seq> …`.
pub fn summarize(v: &serde_json::Value) -> String {
    let ts = v["ts_ms"].as_u64().map(format_ts_ms).unwrap_or_default();
    let seq = v["seq"].as_u64().unwrap_or(0);
    if v["kind"] == "signoff" {
        let decision = v["decision"].as_str().unwrap_or("?");
        let key = s(v, &["key", "label"]);
        let held = v["held_ms"].as_u64().unwrap_or(0) / 1000;
        let mut out = format!(
            "{ts} #{seq} signoff {decision} for #{} after {held}s",
            v["request_seq"].as_u64().unwrap_or(0)
        );
        if !key.is_empty() {
            out.push_str(&format!(" by key '{key}'"));
        }
        let reason = v["reason"].as_str().unwrap_or("");
        if !reason.is_empty() && decision != "approve" {
            out.push_str("  ");
            out.push_str(&short(reason, 60));
        }
        return out;
    }
    let session: String = s(v, &["agent", "session_id"]).chars().take(8).collect();
    let agent_type = s(v, &["agent", "agent_type"]);
    let who = if agent_type.is_empty() {
        session
    } else {
        format!("{session}/{agent_type}")
    };
    let tool = s(v, &["tool", "name"]);
    let final_verdict = s(v, &["final", "verdict"]);
    let source = s(v, &["final", "source"]);
    let falco_verdict = s(v, &["falco", "verdict"]);
    let rules: Vec<&str> = v["falco"]["rules"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| r["rule"].as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let falco = if rules.is_empty() {
        falco_verdict.to_string()
    } else {
        format!("{falco_verdict}[{}]", rules.join("; "))
    };
    let llm_status = s(v, &["llm", "status"]);
    let llm_verdict = s(v, &["llm", "verdict"]);
    let llm = if llm_status == "ok" {
        let ms = v["llm"]["latency_ms"].as_u64().unwrap_or(0);
        format!("{llm_verdict}({ms}ms)")
    } else {
        llm_status.to_string()
    };
    let detail = match tool {
        "Bash" => v["tool"]["input"]
            .as_str()
            .and_then(|i| serde_json::from_str::<serde_json::Value>(i).ok())
            .and_then(|i| i["command"].as_str().map(|c| short(c, 60)))
            .unwrap_or_default(),
        _ => String::new(),
    };
    let mut out =
        format!("{ts} #{seq} {who} {tool} {final_verdict}({source}) falco={falco} llm={llm}");
    if !detail.is_empty() {
        out.push_str("  ");
        out.push_str(&detail);
    }
    out
}

fn short(text: &str, max: usize) -> String {
    let one_line = text.replace('\n', " ");
    if one_line.chars().count() <= max {
        return one_line;
    }
    let cut: String = one_line.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

/// `YYYY-MM-DDTHH:MM:SSZ` from Unix milliseconds (UTC), no chrono dependency.
pub fn format_ts_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil-from-days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{sec:02}Z")
}

// ---------------------------------------------------------------------------
// serve: loopback web UI
// ---------------------------------------------------------------------------

const DEFAULT_SERVE_ADDR: &str = "127.0.0.1:2803";
/// Single-page UI, embedded so the binary stays self-contained.
const UI_HTML: &str = include_str!("audit_ui.html");
/// Cap on records returned by one `/api/records` call (the UI pages via `since`).
const SERVE_MAX_RECORDS: usize = 2000;

fn parse_serve_args(args: &[&str]) -> Result<String, String> {
    let mut addr = DEFAULT_SERVE_ADDR.to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--addr" => {
                i += 1;
                addr = args
                    .get(i)
                    .ok_or_else(|| "--addr requires a value".to_string())?
                    .to_string();
            }
            a if a.starts_with("--addr=") => addr = a["--addr=".len()..].to_string(),
            a => return Err(format!("unknown audit serve flag: {a}")),
        }
        i += 1;
    }
    if !is_loopback_addr(&addr) {
        return Err(format!(
            "refusing to bind {addr}: the audit trail contains tool inputs; serve on loopback only"
        ));
    }
    Ok(addr)
}

fn is_loopback_addr(addr: &str) -> bool {
    addr.starts_with("127.") || addr.starts_with("localhost:") || addr.starts_with("[::1]:")
}

fn serve(prefix: &Path, addr: &str) {
    let path = audit_path(prefix);
    let server = tiny_http::Server::http(addr).unwrap_or_else(|e| {
        eprintln!("cannot bind {addr}: {e}");
        process::exit(1);
    });
    println!("Audit UI: http://{addr}/  (reading {})", path.display());
    println!("Read-only, loopback only. Ctrl-C to stop.");
    for req in server.incoming_requests() {
        let url = req.url().to_string();
        let (status, ctype, body) = route(&path, &url);
        let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype.as_bytes())
            .expect("static header");
        let response = tiny_http::Response::from_string(body)
            .with_status_code(status)
            .with_header(header);
        let _ = req.respond(response);
    }
}

/// Dispatch one request path (with optional query) to `(status, content type, body)`.
fn route(path: &Path, url: &str) -> (u16, &'static str, String) {
    let (route, query) = url.split_once('?').unwrap_or((url, ""));
    match route {
        "/" | "/index.html" => (200, "text/html; charset=utf-8", UI_HTML.to_string()),
        "/api/records" => {
            let since = query_param(query, "since")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0u64);
            let limit = query_param(query, "limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(SERVE_MAX_RECORDS)
                .min(SERVE_MAX_RECORDS);
            (200, "application/json", records_since(path, since, limit))
        }
        "/api/verify" => (200, "application/json", verify_json(path)),
        "/api/signoff" => (200, "application/json", signoff_json(prefix_of(path))),
        _ => (404, "text/plain; charset=utf-8", "not found".to_string()),
    }
}

/// `<prefix>` from `<prefix>/log/audit.jsonl` (the broker socket lives
/// under the same prefix).
fn prefix_of(audit_path: &Path) -> &Path {
    audit_path
        .parent()
        .and_then(|log| log.parent())
        .unwrap_or(audit_path)
}

/// Held sign-offs from the live broker, for the UI banner. A broker that is
/// down or has sign-off disabled is reported, never an error.
fn signoff_json(prefix: &Path) -> String {
    match crate::signoff::fetch_held(prefix) {
        Ok((enabled, ttl_secs, held)) => serde_json::json!({
            "ok": true, "enabled": enabled, "ttl_secs": ttl_secs, "held": held,
        }),
        Err(e) => serde_json::json!({ "ok": false, "enabled": false, "held": [], "error": e }),
    }
    .to_string()
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// JSON array of the records with `seq > since`, keeping the newest `limit`.
/// Lines are passed through verbatim (they are already canonical JSON).
fn records_since(path: &Path, since: u64, limit: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty() && seq_of(l) > since)
        .collect();
    if lines.len() > limit {
        lines.drain(..lines.len() - limit);
    }
    format!("[{}]", lines.join(","))
}

/// Pull `seq` out of a canonical record line without a full parse; falls
/// back to serde for anything unexpected.
fn seq_of(line: &str) -> u64 {
    if let Some(idx) = line.find("\"seq\":") {
        let digits: String = line[idx + 6..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(n) = digits.parse() {
            return n;
        }
    }
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v["seq"].as_u64())
        .unwrap_or(0)
}

fn verify_json(path: &Path) -> String {
    let result = match File::open(path) {
        Ok(f) => verify_reader(BufReader::new(f)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ChainReport {
            records: 0,
            last_seq: 0,
            last_hash: GENESIS_HASH.to_string(),
        }),
        Err(e) => Err((0, e.to_string())),
    };
    match result {
        Ok(r) => serde_json::json!({
            "ok": true, "records": r.records, "last_seq": r.last_seq, "last_hash": r.last_hash,
        }),
        Err((line, error)) => serde_json::json!({ "ok": false, "line": line, "error": error }),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn temp_audit(lines: &[String]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ctl-audit-serve-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("audit-{}.jsonl", lines.len()));
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    #[test]
    fn route_serves_ui_and_404() {
        let path = temp_audit(&[]);
        let (status, ctype, body) = route(&path, "/");
        assert_eq!(status, 200);
        assert!(ctype.starts_with("text/html"));
        assert!(body.contains("audit trail</title>"), "title missing");
        assert!(body.contains("api/records"));
        assert_eq!(route(&path, "/nope").0, 404);
    }

    #[test]
    fn records_since_filters_and_limits() {
        let path = temp_audit(&chain(5));
        let all: Vec<serde_json::Value> =
            serde_json::from_str(&records_since(&path, 0, 100)).unwrap();
        assert_eq!(all.len(), 5);
        let newer: Vec<serde_json::Value> =
            serde_json::from_str(&records_since(&path, 3, 100)).unwrap();
        assert_eq!(
            newer
                .iter()
                .map(|r| r["seq"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![4, 5]
        );
        let capped: Vec<serde_json::Value> =
            serde_json::from_str(&records_since(&path, 0, 2)).unwrap();
        assert_eq!(
            capped
                .iter()
                .map(|r| r["seq"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![4, 5]
        );
        let via_route = route(&path, "/api/records?since=4&limit=10").2;
        let v: Vec<serde_json::Value> = serde_json::from_str(&via_route).unwrap();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn verify_json_reports_ok_missing_and_broken() {
        let ok: serde_json::Value =
            serde_json::from_str(&verify_json(&temp_audit(&chain(3)))).unwrap();
        assert_eq!(ok["ok"], true);
        assert_eq!(ok["records"], 3);
        let missing: serde_json::Value =
            serde_json::from_str(&verify_json(Path::new("/nonexistent/audit.jsonl"))).unwrap();
        assert_eq!(missing["ok"], true);
        assert_eq!(missing["records"], 0);
        let mut lines = chain(3);
        lines[1] = lines[1].replace("echo x2", "echo y2");
        let broken: serde_json::Value =
            serde_json::from_str(&verify_json(&temp_audit(&lines))).unwrap();
        assert_eq!(broken["ok"], false);
        assert_eq!(broken["line"], 2);
    }

    #[test]
    fn serve_args_default_and_loopback_guard() {
        assert_eq!(parse_serve_args(&[]).unwrap(), DEFAULT_SERVE_ADDR);
        assert_eq!(
            parse_serve_args(&["--addr", "127.0.0.1:9000"]).unwrap(),
            "127.0.0.1:9000"
        );
        assert_eq!(
            parse_serve_args(&["--addr=localhost:9000"]).unwrap(),
            "localhost:9000"
        );
        assert!(parse_serve_args(&["--addr", "0.0.0.0:9000"]).is_err());
        assert!(parse_serve_args(&["--bogus"]).is_err());
    }

    #[test]
    fn seq_of_fast_path_and_fallback() {
        assert_eq!(seq_of(r#"{"a":1,"seq":42,"z":0}"#), 42);
        assert_eq!(seq_of(r#"{  "seq" : 7 }"#), 7);
        assert_eq!(seq_of("garbage"), 0);
    }

    fn record(seq: u64, prev: &str, extra: &str) -> (String, String) {
        let body: serde_json::Value = serde_json::from_str(&format!(
            r#"{{"v":1,"seq":{seq},"ts_ms":1700000000000,"prev_hash":"{prev}","tool":{{"name":"Bash","input":"{{\"command\":\"echo {extra}\"}}"}},"agent":{{"session_id":"abcdef123456","agent_type":""}},"final":{{"verdict":"allow","source":"floor"}},"falco":{{"verdict":"none","rules":[]}},"llm":{{"status":"disabled","verdict":""}}}}"#
        ))
        .unwrap();
        let hash = chain_hash(prev, &canonical_json(&body));
        let mut with_hash = body.clone();
        with_hash["hash"] = serde_json::Value::String(hash.clone());
        (canonical_json(&with_hash), hash)
    }

    fn chain(n: u64) -> Vec<String> {
        let mut prev = GENESIS_HASH.to_string();
        let mut lines = Vec::new();
        for i in 1..=n {
            let (line, hash) = record(i, &prev, &format!("x{i}"));
            lines.push(line);
            prev = hash;
        }
        lines
    }

    #[test]
    fn verify_reader_accepts_valid_chain() {
        let text = chain(3).join("\n") + "\n";
        let r = verify_reader(Cursor::new(text)).unwrap();
        assert_eq!(r.records, 3);
        assert_eq!(r.last_seq, 3);
    }

    #[test]
    fn verify_reader_reports_tampered_line() {
        let mut lines = chain(3);
        lines[1] = lines[1].replace("echo x2", "echo y2");
        let err = verify_reader(Cursor::new(lines.join("\n"))).unwrap_err();
        assert_eq!(err.0, 2);
        assert!(err.1.contains("hash mismatch"), "{}", err.1);
    }

    #[test]
    fn verify_reader_reports_deleted_line() {
        let mut lines = chain(3);
        lines.remove(1);
        let err = verify_reader(Cursor::new(lines.join("\n"))).unwrap_err();
        assert_eq!(err.0, 2);
        assert!(err.1.contains("prev_hash mismatch"), "{}", err.1);
    }

    #[test]
    fn summarize_renders_one_line() {
        let (line, _) = record(7, GENESIS_HASH, "hi");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        let out = summarize(&v);
        assert!(
            out.starts_with(
                "2023-11-14T22:13:20Z #7 abcdef12 Bash allow(floor) falco=none llm=disabled"
            ),
            "{out}"
        );
        assert!(out.ends_with("echo hi"), "{out}");
    }

    #[test]
    fn summarize_renders_signoff_records() {
        let v = serde_json::json!({
            "kind": "signoff", "seq": 9, "ts_ms": 0, "request_seq": 8, "decision": "approve",
            "held_ms": 12_500, "key": {"label": "yubi"}, "reason": "approved with hardware key",
        });
        assert_eq!(
            summarize(&v),
            "1970-01-01T00:00:00Z #9 signoff approve for #8 after 12s by key 'yubi'"
        );
        let d = serde_json::json!({
            "kind": "signoff", "seq": 3, "ts_ms": 0, "request_seq": 2, "decision": "expired",
            "held_ms": 300_000, "key": {"label": ""}, "reason": "no operator decision within 300s",
        });
        assert_eq!(
            summarize(&d),
            "1970-01-01T00:00:00Z #3 signoff expired for #2 after 300s  no operator decision within 300s"
        );
    }

    #[test]
    fn signoff_route_reports_broker_down() {
        let path = temp_audit(&[]);
        let (status, ctype, body) = route(&path, "/api/signoff");
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["held"].as_array().unwrap().is_empty());
    }

    #[test]
    fn format_ts_ms_epoch_and_leap_year() {
        assert_eq!(format_ts_ms(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_ts_ms(951_782_400_000), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn tail_args_parse() {
        let o = parse_tail_args(&["-n", "5", "-f", "--json"]).unwrap();
        assert_eq!(o.count, 5);
        assert!(o.follow && o.json);
        assert!(parse_tail_args(&["--bogus"]).is_err());
        assert!(parse_tail_args(&["-n"]).is_err());
    }
}
