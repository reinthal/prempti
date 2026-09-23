//! `premptictl signoff` — hardware-key (FIDO2) sign-off of held tool calls.
//!
//! With `signoff.enabled` in the plugin config, the broker parks every `ask`
//! verdict instead of returning it to the agent. The operator sees the held
//! calls here (`list` / `watch`), and approves one by touching an enrolled
//! authenticator (`approve`): the key signs the held request's audit record
//! hash, the plugin verifies the assertion against `config/signoff_keys.json`
//! and only then releases the call as `allow`. `deny` needs no key.
//!
//! Talks to the broker over its Unix socket with the control requests
//! `signoff_list` and `signoff_resolve` (see the plugin's `socket_server.rs`).
//! USB HID access to the authenticator lives behind the `fido2` cargo
//! feature so hosts without libudev can still build the rest of the CLI.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use uds_windows::UnixStream;

/// Key store schema version (mirrors the plugin's `signoff::KEYS_VERSION`).
const KEYS_VERSION: u64 = 1;
/// Relying-party id used when the plugin config has no `signoff:` block.
const DEFAULT_RP_ID: &str = "prempti.local";
/// `watch` poll interval.
const WATCH_POLL: Duration = Duration::from_secs(1);
/// Broker socket read/write timeout for control requests.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// DER prefix of a P-256 SubjectPublicKeyInfo (uncompressed point follows).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

pub fn keys_path(prefix: &Path) -> PathBuf {
    prefix.join("config").join("signoff_keys.json")
}

pub fn print_usage() {
    eprintln!("Usage:");
    eprintln!(
        "  premptictl signoff status                Sign-off configuration and enrolled keys"
    );
    eprintln!("  premptictl signoff enroll [--label L] [--pin]");
    eprintln!(
        "                                            Register the connected FIDO2 key (touch it)"
    );
    eprintln!("  premptictl signoff keys                  List enrolled keys");
    eprintln!("  premptictl signoff list                  Tool calls waiting for sign-off");
    eprintln!("  premptictl signoff approve SEQ [--pin]   Release call SEQ with a key touch");
    eprintln!("  premptictl signoff deny SEQ [--reason R] Deny call SEQ (no key needed)");
    eprintln!(
        "  premptictl signoff watch [--pin]         Prompt for each new held call as it arrives"
    );
    eprintln!();
    eprintln!("SEQ is the audit record number shown by `list` (or the correlation id).");
    eprintln!("--pin asks for the authenticator PIN (user verification); default is touch only.");
}

pub fn cli(prefix: &Path, args: &[&str]) {
    match args {
        [] | ["status"] => status(prefix),
        ["keys"] => keys_list(prefix),
        ["enroll", rest @ ..] => match parse_enroll_args(rest) {
            Ok((label, pin)) => enroll(prefix, &label, pin),
            Err(e) => usage_error(&e),
        },
        ["list"] => list(prefix),
        ["approve", id, rest @ ..] => match parse_pin_flag(rest, "approve") {
            Ok(pin) => approve(prefix, id, pin),
            Err(e) => usage_error(&e),
        },
        ["deny", id, rest @ ..] => match parse_deny_args(rest) {
            Ok(reason) => deny(prefix, id, &reason),
            Err(e) => usage_error(&e),
        },
        ["watch", rest @ ..] => match parse_pin_flag(rest, "watch") {
            Ok(pin) => watch(prefix, pin),
            Err(e) => usage_error(&e),
        },
        _ => {
            print_usage();
            process::exit(2);
        }
    }
}

fn usage_error(msg: &str) -> ! {
    eprintln!("{msg}");
    eprintln!();
    print_usage();
    process::exit(2);
}

fn parse_enroll_args(args: &[&str]) -> Result<(String, bool), String> {
    let mut label = String::new();
    let mut pin = false;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--label" => {
                i += 1;
                label = args
                    .get(i)
                    .ok_or_else(|| "--label requires a value".to_string())?
                    .to_string();
            }
            a if a.starts_with("--label=") => label = a["--label=".len()..].to_string(),
            "--pin" => pin = true,
            a => return Err(format!("unknown signoff enroll flag: {a}")),
        }
        i += 1;
    }
    if label.is_empty() {
        label = default_label();
    }
    Ok((label, pin))
}

fn default_label() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "operator".to_string());
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default();
    if host.is_empty() {
        user
    } else {
        format!("{user}@{host}")
    }
}

fn parse_pin_flag(args: &[&str], cmd: &str) -> Result<bool, String> {
    let mut pin = false;
    for a in args {
        match *a {
            "--pin" => pin = true,
            other => return Err(format!("unknown signoff {cmd} flag: {other}")),
        }
    }
    Ok(pin)
}

fn parse_deny_args(args: &[&str]) -> Result<String, String> {
    let mut reason = String::new();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--reason" => {
                i += 1;
                reason = args
                    .get(i)
                    .ok_or_else(|| "--reason requires a value".to_string())?
                    .to_string();
            }
            a if a.starts_with("--reason=") => reason = a["--reason=".len()..].to_string(),
            a => return Err(format!("unknown signoff deny flag: {a}")),
        }
        i += 1;
    }
    if reason.trim().is_empty() {
        reason = "denied by operator".to_string();
    }
    Ok(reason)
}

// ---------------------------------------------------------------------------
// Plugin config
// ---------------------------------------------------------------------------

/// The `signoff:` block of the plugin config, with the plugin's defaults.
pub struct Settings {
    pub configured: bool,
    pub enabled: bool,
    pub ttl_secs: u64,
    pub rp_id: String,
    pub require_uv: bool,
    pub keys_path: Option<String>,
}

pub fn settings(prefix: &Path) -> Settings {
    let data = std::fs::read_to_string(prefix.join("config/falco.coding_agents_plugin.yaml"))
        .unwrap_or_default();
    parse_settings(&data)
}

pub fn parse_settings(yaml: &str) -> Settings {
    let mut s = Settings {
        configured: false,
        enabled: false,
        ttl_secs: 300,
        rp_id: DEFAULT_RP_ID.to_string(),
        require_uv: false,
        keys_path: None,
    };
    let Some(block) = crate::parse_block(yaml, "signoff:") else {
        return s;
    };
    s.configured = true;
    for (key, value) in block {
        match key.as_str() {
            "enabled" => s.enabled = value == "true",
            "ttl_secs" => {
                if let Ok(v) = value.parse() {
                    s.ttl_secs = v;
                }
            }
            "rp_id" => {
                if !value.is_empty() {
                    s.rp_id = value;
                }
            }
            "require_uv" => s.require_uv = value == "true",
            "keys_path" if !value.is_empty() => s.keys_path = Some(value),
            _ => {}
        }
    }
    s
}

fn effective_keys_path(prefix: &Path, s: &Settings) -> PathBuf {
    s.keys_path
        .as_deref()
        .map(|p| PathBuf::from(crate::hook::expand_home(p)))
        .unwrap_or_else(|| keys_path(prefix))
}

// ---------------------------------------------------------------------------
// Key store (same file the plugin reads)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyEntry {
    pub label: String,
    /// Hex.
    pub credential_id: String,
    /// Hex SubjectPublicKeyInfo DER (P-256).
    pub public_key_der: String,
    #[serde(default)]
    pub aaguid: String,
    #[serde(default)]
    pub rp_id: String,
    #[serde(default)]
    pub enrolled_at_ms: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct KeyFile {
    pub v: u64,
    pub keys: Vec<KeyEntry>,
}

pub fn load_keys(path: &Path) -> Result<KeyFile, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(KeyFile {
                v: KEYS_VERSION,
                keys: Vec::new(),
            })
        }
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let file: KeyFile = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a key store: {e}", path.display()))?;
    if file.v != KEYS_VERSION {
        return Err(format!(
            "{}: unsupported key store version {}",
            path.display(),
            file.v
        ));
    }
    Ok(file)
}

pub fn save_keys(path: &Path, file: &KeyFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let text = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    std::fs::write(path, format!("{text}\n"))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// A P-256 SubjectPublicKeyInfo is exactly 26 header bytes + 65-byte point.
pub fn is_p256_spki(der: &[u8]) -> bool {
    der.len() == 91 && der[..26] == P256_SPKI_PREFIX && der[26] == 0x04
}

/// Normalize what the authenticator library hands back to SPKI DER: it is
/// either already SPKI or the raw 65-byte uncompressed SEC1 point (which is
/// what `ctap-hid-fido2` produces from the COSE key). Anything else (Ed25519,
/// compressed point) is not usable for ES256 sign-off.
pub fn normalize_p256_public_key(bytes: &[u8]) -> Option<Vec<u8>> {
    if is_p256_spki(bytes) {
        return Some(bytes.to_vec());
    }
    if bytes.len() == 65 && bytes[0] == 0x04 {
        let mut der = P256_SPKI_PREFIX.to_vec();
        der.extend_from_slice(bytes);
        return Some(der);
    }
    None
}

// ---------------------------------------------------------------------------
// Broker control channel
// ---------------------------------------------------------------------------

fn broker_socket(prefix: &Path) -> PathBuf {
    let raw = prefix.join("run/broker.sock");
    #[cfg(windows)]
    {
        PathBuf::from(raw.to_string_lossy().replace('\\', "/"))
    }
    #[cfg(unix)]
    {
        raw
    }
}

/// One control round-trip: a JSON line in, a JSON line back. The `kind`
/// key must be serialized first (the broker sniffs it); `serde_json::json!`
/// keeps insertion order only with `preserve_order`, so build the line by
/// hand.
pub fn control(
    prefix: &Path,
    kind: &str,
    fields: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let socket = broker_socket(prefix);
    let mut stream = UnixStream::connect(&socket).map_err(|e| {
        format!(
            "cannot connect to the broker at {} ({e}); is the service running?",
            socket.display()
        )
    })?;
    let _ = stream.set_read_timeout(Some(CONTROL_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONTROL_TIMEOUT));
    let mut body = String::new();
    if let Some(obj) = fields.as_object() {
        for (k, v) in obj {
            body.push(',');
            body.push_str(&serde_json::Value::String(k.clone()).to_string());
            body.push(':');
            body.push_str(&v.to_string());
        }
    }
    let line = format!(
        "{{\"kind\":{}{body}}}\n",
        serde_json::Value::String(kind.to_string())
    );
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("broker write failed: {e}"))?;
    let mut reply = String::new();
    BufReader::new(&stream)
        .read_line(&mut reply)
        .map_err(|e| format!("broker read failed: {e}"))?;
    if reply.trim().is_empty() {
        return Err("broker closed the connection without a reply".to_string());
    }
    serde_json::from_str(reply.trim()).map_err(|e| format!("broker reply is not JSON: {e}"))
}

/// `(enabled, ttl_secs, held)` from the broker.
pub fn fetch_held(prefix: &Path) -> Result<(bool, u64, Vec<serde_json::Value>), String> {
    let v = control(prefix, "signoff_list", &serde_json::json!({}))?;
    if v["ok"] != true {
        return Err(v["error"].as_str().unwrap_or("broker refused").to_string());
    }
    Ok((
        v["enabled"].as_bool().unwrap_or(false),
        v["ttl_secs"].as_u64().unwrap_or(0),
        v["held"].as_array().cloned().unwrap_or_default(),
    ))
}

/// Pick the held entry the operator named: its audit `request_seq` or its
/// correlation id.
pub fn find_target<'a>(held: &'a [serde_json::Value], id: &str) -> Option<&'a serde_json::Value> {
    let n: u64 = id.trim_start_matches('#').parse().ok()?;
    held.iter()
        .find(|h| h["request_seq"].as_u64() == Some(n))
        .or_else(|| {
            held.iter()
                .find(|h| h["correlation_id"].as_u64() == Some(n))
        })
}

fn resolve(
    prefix: &Path,
    correlation_id: u64,
    decision: &str,
    extra: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut fields = serde_json::json!({
        "correlation_id": correlation_id,
        "decision": decision,
    });
    if let (Some(dst), Some(src)) = (fields.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    let v = control(prefix, "signoff_resolve", &fields)?;
    if v["ok"] != true {
        return Err(v["error"].as_str().unwrap_or("broker refused").to_string());
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn status(prefix: &Path) {
    let s = settings(prefix);
    if !s.configured {
        println!(
            "Hardware-key sign-off: not configured (no `signoff:` block in the plugin config)"
        );
    } else {
        println!(
            "Hardware-key sign-off: {}",
            if s.enabled { "enabled" } else { "disabled" }
        );
    }
    println!("  {:<12} {}", "rp_id", s.rp_id);
    println!("  {:<12} {}s", "ttl", s.ttl_secs);
    println!("  {:<12} {}", "require_uv", s.require_uv);
    let path = effective_keys_path(prefix, &s);
    match load_keys(&path) {
        Ok(f) if f.keys.is_empty() => println!(
            "  {:<12} {} (no keys enrolled; run `premptictl signoff enroll`)",
            "keys",
            path.display()
        ),
        Ok(f) => {
            println!(
                "  {:<12} {} ({} enrolled)",
                "keys",
                path.display(),
                f.keys.len()
            );
            for k in &f.keys {
                println!(
                    "    - {} (credential {}…)",
                    k.label,
                    &k.credential_id[..k.credential_id.len().min(16)]
                );
            }
        }
        Err(e) => println!("  {:<12} {e}", "keys"),
    }
    println!(
        "  {:<12} {}",
        "fido2",
        if cfg!(feature = "fido2") {
            "built in"
        } else {
            "NOT built in (enroll/approve unavailable)"
        }
    );
    match fetch_held(prefix) {
        Ok((enabled, _, held)) => println!(
            "  {:<12} {} ({} call(s) waiting)",
            "broker",
            if enabled {
                "sign-off active"
            } else {
                "sign-off inactive"
            },
            held.len()
        ),
        Err(e) => println!("  {:<12} {e}", "broker"),
    }
}

fn keys_list(prefix: &Path) {
    let s = settings(prefix);
    let path = effective_keys_path(prefix, &s);
    match load_keys(&path) {
        Ok(f) if f.keys.is_empty() => println!("No keys enrolled in {}.", path.display()),
        Ok(f) => {
            println!("Enrolled keys ({}):", path.display());
            for k in &f.keys {
                println!(
                    "  {:<24} credential={}  aaguid={}  rp_id={}  enrolled={}",
                    k.label,
                    &k.credential_id[..k.credential_id.len().min(16)],
                    if k.aaguid.is_empty() { "-" } else { &k.aaguid },
                    if k.rp_id.is_empty() { "-" } else { &k.rp_id },
                    if k.enrolled_at_ms == 0 {
                        "-".to_string()
                    } else {
                        crate::audit::format_ts_ms(k.enrolled_at_ms)
                    }
                );
            }
        }
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    }
}

fn enroll(prefix: &Path, label: &str, use_pin: bool) {
    let s = settings(prefix);
    let path = effective_keys_path(prefix, &s);
    let mut file = load_keys(&path).unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });
    let pin = if use_pin {
        Some(read_secret("Authenticator PIN: "))
    } else {
        None
    };
    eprintln!(
        "Enrolling for rp_id `{}`. Touch the authenticator when it blinks.",
        s.rp_id
    );
    let key = fido::enroll(&s.rp_id, pin.as_deref()).unwrap_or_else(|e| {
        eprintln!("enroll failed: {e}");
        process::exit(1);
    });
    let Some(public_key_der) = normalize_p256_public_key(&key.public_key_der) else {
        eprintln!(
            "enroll failed: authenticator returned a non-P-256 credential ({} byte key)",
            key.public_key_der.len()
        );
        process::exit(1);
    };
    let credential_id = hex_encode(&key.credential_id);
    if file.keys.iter().any(|k| k.credential_id == credential_id) {
        eprintln!("This credential is already enrolled.");
        process::exit(1);
    }
    file.keys.push(KeyEntry {
        label: label.to_string(),
        credential_id: credential_id.clone(),
        public_key_der: hex_encode(&public_key_der),
        aaguid: hex_encode(&key.aaguid),
        rp_id: s.rp_id.clone(),
        enrolled_at_ms: now_ms(),
    });
    save_keys(&path, &file).unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });
    println!(
        "Enrolled `{label}` (credential {}…) in {}",
        &credential_id[..16],
        path.display()
    );
    println!("The plugin reads the key store at start: restart the service (`premptictl restart`) to activate it.");
    if !s.enabled {
        println!("Note: `signoff.enabled` is not set in the plugin config; held sign-offs stay off until it is.");
    }
}

fn list(prefix: &Path) {
    let (enabled, ttl, held) = fetch_held(prefix).unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });
    if !enabled {
        println!("Hardware-key sign-off is not active in the running plugin.");
    }
    if held.is_empty() {
        println!("No tool calls waiting for sign-off.");
        return;
    }
    println!("Tool calls waiting for sign-off (denied after {ttl}s without a decision):");
    for h in &held {
        print_held(h);
    }
    println!();
    println!("approve: premptictl signoff approve <seq>    deny: premptictl signoff deny <seq>");
}

fn print_held(h: &serde_json::Value) {
    let seq = h["request_seq"].as_u64().unwrap_or(0);
    let tool = h["tool"].as_str().unwrap_or("?");
    let session: String = h["session_id"]
        .as_str()
        .unwrap_or("")
        .chars()
        .take(8)
        .collect();
    let agent_type = h["agent_type"].as_str().unwrap_or("");
    let who = if agent_type.is_empty() {
        session
    } else {
        format!("{session}/{agent_type}")
    };
    println!(
        "  #{seq}  {tool}  session {who}  waiting {}s, {}s left",
        h["age_secs"].as_u64().unwrap_or(0),
        h["expires_in_secs"].as_u64().unwrap_or(0)
    );
    println!("      call:   {}", call_summary(h));
    if let Some(cwd) = h["cwd"].as_str().filter(|c| !c.is_empty()) {
        println!("      cwd:    {cwd}");
    }
    println!("      reason: {}", h["reason"].as_str().unwrap_or(""));
    if let Some(clause) = h["llm_clause"].as_str().filter(|c| !c.is_empty()) {
        println!("      roe:    {clause}");
    }
    if let Some(rules) = h["falco_rules"].as_array().filter(|r| !r.is_empty()) {
        let names: Vec<&str> = rules.iter().filter_map(|r| r.as_str()).collect();
        println!("      falco:  {}", names.join("; "));
    }
    println!("      record: {}", h["request_hash"].as_str().unwrap_or(""));
}

/// The one line that says what the call does: command / path / whatever
/// the tool input carries, else the raw JSON.
pub fn call_summary(h: &serde_json::Value) -> String {
    let raw = h["input"].as_str().unwrap_or("");
    let text = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| {
            [
                "command",
                "file_path",
                "pattern",
                "url",
                "prompt",
                "description",
            ]
            .iter()
            .find_map(|k| v[*k].as_str().map(|s| s.to_string()))
        })
        .unwrap_or_else(|| raw.to_string());
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > 160 {
        let cut: String = one_line.chars().take(159).collect();
        format!("{cut}…")
    } else {
        one_line
    }
}

fn approve(prefix: &Path, id: &str, use_pin: bool) {
    let (_, _, held) = fetch_held(prefix).unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });
    let Some(target) = find_target(&held, id) else {
        eprintln!("No held call `{id}`. `premptictl signoff list` shows what is waiting.");
        process::exit(1);
    };
    match approve_target(prefix, target, use_pin) {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("approve failed: {e}");
            process::exit(1);
        }
    }
}

/// Sign the held call's record hash with the authenticator and send the
/// proof to the broker.
fn approve_target(
    prefix: &Path,
    target: &serde_json::Value,
    use_pin: bool,
) -> Result<String, String> {
    let s = settings(prefix);
    let keys = load_keys(&effective_keys_path(prefix, &s))?;
    if keys.keys.is_empty() {
        return Err("no keys enrolled; run `premptictl signoff enroll` first".to_string());
    }
    let seq = target["request_seq"].as_u64().unwrap_or(0);
    let correlation_id = target["correlation_id"]
        .as_u64()
        .ok_or_else(|| "held entry has no correlation id".to_string())?;
    let challenge = hex_decode(target["request_hash"].as_str().unwrap_or(""))
        .map_err(|e| format!("record hash {e}"))?;
    let cred_ids: Vec<Vec<u8>> = keys
        .keys
        .iter()
        .filter_map(|k| hex_decode(&k.credential_id).ok())
        .collect();
    let pin = if use_pin {
        Some(read_secret("Authenticator PIN: "))
    } else {
        None
    };
    eprintln!(
        "Approving #{seq} ({}): touch the authenticator.",
        call_summary(target)
    );
    let a = fido::assert(&s.rp_id, &challenge, &cred_ids, pin.as_deref())?;
    let credential_id = if a.credential_id.is_empty() && cred_ids.len() == 1 {
        // CTAP lets the authenticator omit the credential when the allow
        // list has exactly one entry.
        cred_ids[0].clone()
    } else {
        a.credential_id
    };
    let reply = resolve(
        prefix,
        correlation_id,
        "approve",
        serde_json::json!({
            "proof": {
                "credential_id": hex_encode(&credential_id),
                "auth_data": hex_encode(&a.auth_data),
                "signature": hex_encode(&a.signature),
            }
        }),
    )?;
    Ok(format!(
        "Approved #{seq} with key `{}` (sign-off record #{}). The agent's call proceeds.",
        reply["key_label"].as_str().unwrap_or("?"),
        reply["seq"].as_u64().unwrap_or(0)
    ))
}

fn deny(prefix: &Path, id: &str, reason: &str) {
    let (_, _, held) = fetch_held(prefix).unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });
    let Some(target) = find_target(&held, id) else {
        eprintln!("No held call `{id}`. `premptictl signoff list` shows what is waiting.");
        process::exit(1);
    };
    match deny_target(prefix, target, reason) {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("deny failed: {e}");
            process::exit(1);
        }
    }
}

fn deny_target(prefix: &Path, target: &serde_json::Value, reason: &str) -> Result<String, String> {
    let seq = target["request_seq"].as_u64().unwrap_or(0);
    let correlation_id = target["correlation_id"]
        .as_u64()
        .ok_or_else(|| "held entry has no correlation id".to_string())?;
    let reply = resolve(
        prefix,
        correlation_id,
        "deny",
        serde_json::json!({ "reason": reason }),
    )?;
    Ok(format!(
        "Denied #{seq} (sign-off record #{}). The agent sees: sign-off denied by operator: {reason}",
        reply["seq"].as_u64().unwrap_or(0)
    ))
}

/// Interactive loop: poll the broker, prompt for every new held call.
fn watch(prefix: &Path, use_pin: bool) {
    println!("Watching for tool calls that need sign-off (Ctrl-C to stop)…");
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut warned = false;
    loop {
        let held = match fetch_held(prefix) {
            Ok((enabled, _, held)) => {
                if !enabled && !warned {
                    println!(
                        "note: sign-off is not active in the running plugin; nothing will be held."
                    );
                    warned = true;
                }
                held
            }
            Err(e) => {
                if !warned {
                    println!("{e}");
                    warned = true;
                }
                std::thread::sleep(WATCH_POLL);
                continue;
            }
        };
        let live: std::collections::HashSet<u64> = held
            .iter()
            .filter_map(|h| h["correlation_id"].as_u64())
            .collect();
        seen.retain(|id| live.contains(id));
        for h in &held {
            let Some(id) = h["correlation_id"].as_u64() else {
                continue;
            };
            if seen.contains(&id) {
                continue;
            }
            println!();
            print_held(h);
            match prompt_choice() {
                Choice::Approve => match approve_target(prefix, h, use_pin) {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => println!("approve failed: {e} (still waiting)"),
                },
                Choice::Deny => match deny_target(prefix, h, "denied by operator") {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => println!("deny failed: {e}"),
                },
                Choice::Skip => {}
                Choice::Quit => return,
            }
            seen.insert(id);
        }
        std::thread::sleep(WATCH_POLL);
    }
}

enum Choice {
    Approve,
    Deny,
    Skip,
    Quit,
}

fn prompt_choice() -> Choice {
    loop {
        print!("  [a]pprove with key / [d]eny / [s]kip / [q]uit > ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
            return Choice::Quit;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "a" | "approve" | "y" | "yes" => return Choice::Approve,
            "d" | "deny" | "n" | "no" => return Choice::Deny,
            "s" | "skip" | "" => return Choice::Skip,
            "q" | "quit" => return Choice::Quit,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return Err("is not valid hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "is not valid hex".to_string()))
        .collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Read a line from the terminal with echo off (PIN entry).
fn read_secret(prompt: &str) -> String {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let stdin = std::io::stdin();
    #[cfg(unix)]
    let saved = rustix::termios::tcgetattr(&stdin).ok();
    #[cfg(unix)]
    if let Some(mut t) = saved.clone() {
        t.local_modes.remove(rustix::termios::LocalModes::ECHO);
        let _ = rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &t);
    }
    let mut line = String::new();
    let _ = stdin.read_line(&mut line);
    #[cfg(unix)]
    if let Some(t) = saved {
        let _ = rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &t);
    }
    eprintln!();
    line.trim_end_matches(['\n', '\r']).to_string()
}

// ---------------------------------------------------------------------------
// Authenticator access
// ---------------------------------------------------------------------------

pub struct EnrolledCredential {
    pub credential_id: Vec<u8>,
    pub public_key_der: Vec<u8>,
    pub aaguid: Vec<u8>,
}

pub struct AssertionOut {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[cfg(feature = "fido2")]
mod fido {
    use super::{AssertionOut, EnrolledCredential};
    use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
    use ctap_hid_fido2::{verifier, FidoKeyHidFactory, LibCfg};

    fn cfg() -> LibCfg {
        LibCfg::init().with_keep_alive_msg_to_stderr(true)
    }

    fn device() -> Result<ctap_hid_fido2::FidoKeyHid, String> {
        FidoKeyHidFactory::create(&cfg()).map_err(|e| {
            format!("{e} (is the key plugged in, and do udev rules allow hidraw access to it?)")
        })
    }

    pub fn enroll(rp_id: &str, pin: Option<&str>) -> Result<EnrolledCredential, String> {
        let device = device()?;
        let challenge = verifier::create_challenge();
        let mut b = MakeCredentialArgsBuilder::new(rp_id, &challenge);
        b = match pin {
            Some(p) => b.pin(p),
            None => b.without_pin_and_uv(),
        };
        let att = device
            .make_credential_with_args(&b.build())
            .map_err(|e| format!("{e} (if the key has a PIN set and refuses, retry with --pin)"))?;
        Ok(EnrolledCredential {
            credential_id: att.credential_descriptor.id.clone(),
            public_key_der: att.credential_publickey.der.clone(),
            aaguid: att.aaguid.clone(),
        })
    }

    pub fn assert(
        rp_id: &str,
        challenge: &[u8],
        credential_ids: &[Vec<u8>],
        pin: Option<&str>,
    ) -> Result<AssertionOut, String> {
        let device = device()?;
        let mut b = GetAssertionArgsBuilder::new(rp_id, challenge);
        for id in credential_ids {
            b = b.add_credential_id(id);
        }
        b = match pin {
            Some(p) => b.pin(p),
            None => b.without_pin_and_uv(),
        };
        let mut assertions = device
            .get_assertion_with_args(&b.build())
            .map_err(|e| format!("{e} (no enrolled credential on this key, or touch timed out)"))?;
        if assertions.is_empty() {
            return Err("authenticator returned no assertion".to_string());
        }
        let a = assertions.remove(0);
        Ok(AssertionOut {
            credential_id: a.credential_id,
            auth_data: a.auth_data,
            signature: a.signature,
        })
    }
}

#[cfg(not(feature = "fido2"))]
mod fido {
    use super::{AssertionOut, EnrolledCredential};

    const MSG: &str = "this premptictl was built without the `fido2` feature; enroll/approve need a build with it";

    pub fn enroll(_rp_id: &str, _pin: Option<&str>) -> Result<EnrolledCredential, String> {
        Err(MSG.to_string())
    }

    pub fn assert(
        _rp_id: &str,
        _challenge: &[u8],
        _credential_ids: &[Vec<u8>],
        _pin: Option<&str>,
    ) -> Result<AssertionOut, String> {
        Err(MSG.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_parse_defaults_and_values() {
        let none = parse_settings("plugins:\n  - name: x\n");
        assert!(!none.configured && !none.enabled);
        assert_eq!(none.ttl_secs, 300);
        assert_eq!(none.rp_id, DEFAULT_RP_ID);
        let yaml = "init_config:\n  mode: guardrails\n  signoff:\n    enabled: true\n    ttl_secs: 120 # two minutes\n    rp_id: \"corp.example\"\n    require_uv: true\n    keys_path: \"$HOME/.prempti/config/k.json\"\n  http_port: 2802\n";
        let s = parse_settings(yaml);
        assert!(s.configured && s.enabled && s.require_uv);
        assert_eq!(s.ttl_secs, 120);
        assert_eq!(s.rp_id, "corp.example");
        assert_eq!(s.keys_path.as_deref(), Some("$HOME/.prempti/config/k.json"));
    }

    #[test]
    fn key_file_round_trip_and_missing() {
        let dir = std::env::temp_dir().join(format!("ctl-signoff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("signoff_keys.json");
        let empty = load_keys(&path).unwrap();
        assert!(empty.keys.is_empty());
        let mut file = empty;
        file.keys.push(KeyEntry {
            label: "yubi".into(),
            credential_id: "0102".into(),
            public_key_der: "3059".into(),
            aaguid: String::new(),
            rp_id: "prempti.local".into(),
            enrolled_at_ms: 1,
        });
        save_keys(&path, &file).unwrap();
        let back = load_keys(&path).unwrap();
        assert_eq!(back.v, KEYS_VERSION);
        assert_eq!(back.keys[0].label, "yubi");
        std::fs::write(&path, r#"{"v":9,"keys":[]}"#).unwrap();
        assert!(load_keys(&path).unwrap_err().contains("version"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spki_check_and_hex() {
        let mut der = P256_SPKI_PREFIX.to_vec();
        der.push(0x04);
        der.extend(std::iter::repeat_n(0xab, 64));
        assert!(is_p256_spki(&der));
        assert!(!is_p256_spki(&der[..90]));
        // Raw SEC1 point (what the authenticator library returns) gets wrapped.
        assert_eq!(normalize_p256_public_key(&der[26..]).unwrap(), der);
        assert_eq!(normalize_p256_public_key(&der).unwrap(), der);
        assert!(normalize_p256_public_key(&[0u8; 32]).is_none());
        assert!(normalize_p256_public_key(&der[27..]).is_none());
        assert_eq!(hex_decode(&hex_encode(&der)).unwrap(), der);
        assert!(hex_decode("").is_err());
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn find_target_by_seq_or_correlation_id() {
        let held = vec![
            serde_json::json!({"request_seq": 12, "correlation_id": 900}),
            serde_json::json!({"request_seq": 13, "correlation_id": 901}),
        ];
        assert_eq!(find_target(&held, "13").unwrap()["correlation_id"], 901);
        assert_eq!(find_target(&held, "#12").unwrap()["correlation_id"], 900);
        assert_eq!(find_target(&held, "901").unwrap()["request_seq"], 13);
        assert!(find_target(&held, "7").is_none());
        assert!(find_target(&held, "x").is_none());
    }

    #[test]
    fn call_summary_prefers_command() {
        let h = serde_json::json!({"input": "{\"command\":\"nmap   -sV\\n10.0.0.5\"}"});
        assert_eq!(call_summary(&h), "nmap -sV 10.0.0.5");
        let w = serde_json::json!({"input": "{\"file_path\":\"/etc/x\",\"content\":\"y\"}"});
        assert_eq!(call_summary(&w), "/etc/x");
        let raw = serde_json::json!({"input": "not json"});
        assert_eq!(call_summary(&raw), "not json");
    }

    #[test]
    fn arg_parsing() {
        assert_eq!(
            parse_enroll_args(&["--label", "desk", "--pin"]).unwrap(),
            ("desk".to_string(), true)
        );
        assert_eq!(parse_enroll_args(&["--label=desk"]).unwrap().0, "desk");
        assert!(parse_enroll_args(&["--bogus"]).is_err());
        assert!(parse_pin_flag(&["--pin"], "approve").unwrap());
        assert!(parse_pin_flag(&["--x"], "approve").is_err());
        assert_eq!(parse_deny_args(&["--reason", "nope"]).unwrap(), "nope");
        assert_eq!(parse_deny_args(&[]).unwrap(), "denied by operator");
    }

    #[test]
    fn control_line_puts_kind_first() {
        // The broker sniffs `{"kind"` at the start of the line; a wrong
        // socket path just needs to fail before that matters.
        let err = control(
            Path::new("/nonexistent/prefix"),
            "signoff_list",
            &serde_json::json!({}),
        )
        .unwrap_err();
        assert!(err.contains("cannot connect"), "{err}");
    }
}
