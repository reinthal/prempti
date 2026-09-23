use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::interceptor::{self, AgentKind};

static NEXT_HARNESS_ID: AtomicU64 = AtomicU64::new(1);

/// E2E test harness managing a Falco process with the coding-agent plugin.
pub struct E2eHarness {
    falco: Child,
    pub socket_path: PathBuf,
    pub e2e_dir: PathBuf,
    pub http_port: u16,
    audit_path: PathBuf,
}

/// Find the Falco binary from the project's own build output.
/// Does NOT use system Falco — only looks in known build directories
/// and the FALCO env var (for CI to point at the built binary).
pub fn find_falco() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FALCO") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let candidates: Vec<PathBuf> = if cfg!(windows) {
        vec![
            root.join("build/stage-windows-x64/bin/falco.exe"),
            root.join("build/stage-windows-arm64/bin/falco.exe"),
            root.join("build/falco-0.44.0-windows-x64/falco.exe"),
            root.join("build/falco-0.44.0-windows-arm64/falco.exe"),
        ]
    } else if cfg!(target_os = "macos") {
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        vec![root.join(format!("build/falco-0.44.0-darwin-{arch}/falco"))]
    } else {
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        vec![root.join(format!("build/falco-0.44.0-{arch}/usr/bin/falco"))]
    };
    for c in candidates {
        if c.exists() {
            return Some(c);
        }
    }
    None
}

/// Find the plugin shared library.
pub fn find_plugin_lib() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let (prefix, ext) = if cfg!(windows) {
        ("", "dll")
    } else if cfg!(target_os = "macos") {
        ("lib", "dylib")
    } else {
        ("lib", "so")
    };
    let name = format!("{prefix}coding_agent.{ext}");
    // Check the workspace target/ tree first (cargo workspace layout);
    // fall back to the legacy per-crate target/ for older checkouts.
    let candidates = [
        root.join("target/release").join(&name),
        root.join("plugins/coding-agents-plugin/target/release")
            .join(&name),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Macro to skip a test if Falco or the plugin is not available.
#[macro_export]
macro_rules! skip_unless_falco {
    ($falco:ident, $plugin:ident) => {
        let Some($falco) = $crate::e2e::find_falco() else {
            eprintln!("SKIP: falco not found");
            return;
        };
        let Some($plugin) = $crate::e2e::find_plugin_lib() else {
            eprintln!("SKIP: plugin library not built");
            return;
        };
    };
}

/// LLM monitor settings for `E2eHarness::start_with_monitor`.
pub struct MonitorSpec {
    /// Base URL (`MockLlm::endpoint()`).
    pub endpoint: String,
    /// `ask` or `deny`.
    pub on_error: String,
    pub timeout_ms: u64,
    pub skip_tools: Vec<String>,
    /// Rules of Engagement text handed to the plugin.
    pub roe: String,
}

impl MonitorSpec {
    pub fn new(endpoint: String) -> Self {
        MonitorSpec {
            endpoint,
            on_error: "ask".to_string(),
            timeout_ms: 5000,
            skip_tools: Vec::new(),
            roe: "# Rules of Engagement\n\nIn scope: 10.0.0.0/24. Never touch production.\n"
                .to_string(),
        }
    }
}

/// Hardware-key sign-off settings for `E2eHarness::start_with_signoff`.
pub struct SignoffSpec {
    /// Seconds a held call waits before the reaper denies it.
    pub ttl_secs: u64,
    pub rp_id: String,
    pub require_uv: bool,
    /// Contents of `signoff_keys.json` (see `softkey::key_file`).
    pub keys_json: String,
    /// Also enable the LLM monitor against this endpoint.
    pub monitor: Option<MonitorSpec>,
}

impl SignoffSpec {
    pub fn new(keys_json: String) -> Self {
        SignoffSpec {
            ttl_secs: 300,
            rp_id: "prempti.local".to_string(),
            require_uv: false,
            keys_json,
            monitor: None,
        }
    }
}

/// Walk an audit file's hash chain (same rules as `premptictl audit
/// verify`). Returns the number of records.
pub fn verify_audit_chain(path: &Path) -> Result<usize, String> {
    use sha2::{Digest, Sha256};
    fn canonical(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                    out.push(':');
                    canonical(&map[*k], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    canonical(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut prev = "0".repeat(64);
    let mut count = 0;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("line {}: {e}", idx + 1))?;
        let hash = v["hash"].as_str().unwrap_or("").to_string();
        v.as_object_mut().unwrap().remove("hash");
        if v["prev_hash"].as_str() != Some(prev.as_str()) {
            return Err(format!("line {}: prev_hash mismatch", idx + 1));
        }
        let mut body = String::new();
        canonical(&v, &mut body);
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(body.as_bytes());
        let computed: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if computed != hash {
            return Err(format!("line {}: hash mismatch", idx + 1));
        }
        prev = hash;
        count += 1;
    }
    Ok(count)
}

impl E2eHarness {
    /// Start Falco with the plugin in the given mode and the plugin-default
    /// no-rule-match floor (`default_action = allow`).
    /// Returns `None` if Falco or the plugin is not available.
    pub fn start(mode: &str) -> Option<Self> {
        Self::start_with_default_action(mode, "allow")
    }

    /// Start Falco with the plugin in the given mode and no-rule-match floor
    /// (`default_action`, one of "allow" / "defer"). `default_action` governs
    /// guardrails mode only; monitor/passthrough always resolve as defer.
    /// Returns `None` if Falco or the plugin is not available.
    pub fn start_with_default_action(mode: &str, default_action: &str) -> Option<Self> {
        Self::start_internal(mode, default_action, false, None, None)
    }

    /// Start Falco with the repository's shipped default and seen rules.
    /// This is intentionally separate from the compact generated fixture:
    /// security regressions in production macros must be exercised against
    /// the exact YAML that users install.
    pub fn start_with_shipped_rules(mode: &str) -> Option<Self> {
        Self::start_internal(mode, "allow", true, None, None)
    }

    /// Start with the LLM monitor enabled against `spec.endpoint` (normally
    /// a `mock_llm::MockLlm`). The compact fixture rules are used.
    pub fn start_with_monitor(mode: &str, spec: &MonitorSpec) -> Option<Self> {
        Self::start_internal(mode, "allow", false, Some(spec), None)
    }

    /// Start with hardware-key sign-off enabled: every `ask` is held until
    /// a control request on the broker socket resolves it.
    pub fn start_with_signoff(mode: &str, spec: &SignoffSpec) -> Option<Self> {
        Self::start_internal(mode, "allow", false, spec.monitor.as_ref(), Some(spec))
    }

    fn start_internal(
        mode: &str,
        default_action: &str,
        shipped_rules: bool,
        monitor: Option<&MonitorSpec>,
        signoff: Option<&SignoffSpec>,
    ) -> Option<Self> {
        let falco_bin = find_falco()?;
        let plugin_lib = find_plugin_lib()?;
        // Skip only if NO interceptor is built. Per-test binary requirements
        // are checked by run_hook_for at spawn time, which fails loudly with
        // the exact missing path.
        let claude_bin = interceptor::interceptor_path_for(AgentKind::Claude);
        let codex_bin = interceptor::interceptor_path_for(AgentKind::Codex);
        if !claude_bin.exists() && !codex_bin.exists() {
            eprintln!("SKIP: no interceptor binary found (claude or codex)");
            return None;
        }

        let pid = std::process::id();
        let harness_id = NEXT_HARNESS_ID.fetch_add(1, Ordering::Relaxed);
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let e2e_dir = root.join(format!("build/e2e-{pid}-{harness_id}"));
        let _ = std::fs::create_dir_all(&e2e_dir);

        let rules_dir = e2e_dir.join("rules");
        let _ = std::fs::create_dir_all(&rules_dir);

        let socket_path = e2e_dir.join("broker.sock");
        let reserved_http_port = reserve_http_port();
        let http_port = reserved_http_port
            .as_ref()
            .and_then(|listener| listener.local_addr().ok())
            .map(|addr| addr.port())
            .unwrap_or(19000 + ((pid as u64 + harness_id) % 1000) as u16);

        let rules_files = if shipped_rules {
            vec![
                root.join("rules/default/coding_agents_rules.yaml"),
                root.join("rules/seen.yaml"),
            ]
        } else {
            write_rules(&rules_dir);
            vec![rules_dir.join("deny.yaml"), rules_dir.join("seen.yaml")]
        };

        // Audit trail always on: every E2E run leaves a verifiable chain.
        let audit_path = e2e_dir.join("audit.jsonl");
        let mut extra_init = format!(
            "      audit_path: \"{}\"\n",
            to_forward_slashes(&audit_path)
        );
        if let Some(spec) = monitor {
            let roe_path = e2e_dir.join("roe.md");
            std::fs::write(&roe_path, &spec.roe).expect("write RoE");
            let skip = spec
                .skip_tools
                .iter()
                .map(|t| format!("\"{t}\""))
                .collect::<Vec<_>>()
                .join(", ");
            extra_init.push_str(&format!(
                "      monitor:\n        enabled: true\n        endpoint: \"{}\"\n        model: \"mock-model\"\n        api_key_env: KEBNETRAILS_API_KEY\n        roe_path: \"{}\"\n        timeout_ms: {}\n        on_error: {}\n        max_transcript_bytes: 4096\n        workers: 2\n        skip_tools: [{}]\n",
                spec.endpoint,
                to_forward_slashes(&roe_path),
                spec.timeout_ms,
                spec.on_error,
                skip
            ));
        }

        if let Some(spec) = signoff {
            let keys_path = e2e_dir.join("signoff_keys.json");
            std::fs::write(&keys_path, &spec.keys_json).expect("write key store");
            extra_init.push_str(&format!(
                "      signoff:\n        enabled: true\n        ttl_secs: {}\n        rp_id: \"{}\"\n        require_uv: {}\n        keys_path: \"{}\"\n",
                spec.ttl_secs,
                spec.rp_id,
                spec.require_uv,
                to_forward_slashes(&keys_path)
            ));
        }

        // Write Falco config.
        let config_path = e2e_dir.join("falco.yaml");
        write_falco_config(
            &config_path,
            &plugin_lib,
            &socket_path,
            &rules_files,
            http_port,
            mode,
            default_action,
            &extra_init,
        );

        // Start Falco.
        let falco_dir = falco_bin.parent().unwrap_or(Path::new("."));
        let mut cmd = Command::new(&falco_bin);
        cmd.arg("-U")
            .arg("-c")
            .arg(&config_path)
            .arg("--disable-source")
            .arg("syscall")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(falco_dir);
        if monitor.is_some() {
            cmd.env("KEBNETRAILS_API_KEY", "e2e-test-key");
        }

        // Release the reserved port immediately before Falco/plugin startup.
        drop(reserved_http_port);

        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn falco at {}: {e}", falco_bin.display()));

        // Wait for broker socket to appear.
        let mut ready = false;
        for _ in 0..40 {
            if socket_path.exists() {
                ready = true;
                break;
            }
            if let Some(status) = child.try_wait().ok().flatten() {
                eprintln!("ERROR: Falco exited early with code {status}");
                // Drain stderr for diagnostics.
                if let Some(mut stderr) = child.stderr.take() {
                    let mut buf = String::new();
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut buf);
                    eprintln!("Falco stderr: {buf}");
                }
                let _ = std::fs::remove_dir_all(&e2e_dir);
                return None;
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        if !ready {
            eprintln!(
                "ERROR: Falco broker socket not found after 8s: {}",
                socket_path.display()
            );
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&e2e_dir);
            return None;
        }

        // Extra wait for HTTP server.
        std::thread::sleep(Duration::from_millis(500));

        Some(E2eHarness {
            falco: child,
            socket_path,
            e2e_dir,
            http_port,
            audit_path,
        })
    }

    /// One operator control round-trip on the broker socket (what
    /// `premptictl signoff` does): a `{"kind":…}` line in, a JSON line back.
    pub fn control(&self, kind: &str, fields: &serde_json::Value) -> serde_json::Value {
        use std::io::{BufRead, BufReader, Write};
        #[cfg(unix)]
        use std::os::unix::net::UnixStream;
        #[cfg(windows)]
        use uds_windows::UnixStream;

        let mut stream = UnixStream::connect(&self.socket_path).expect("connect broker");
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut body = String::new();
        for (k, v) in fields.as_object().into_iter().flatten() {
            body.push_str(&format!(",{}:{}", serde_json::Value::String(k.clone()), v));
        }
        let line = format!("{{\"kind\":\"{kind}\"{body}}}\n");
        stream.write_all(line.as_bytes()).expect("write control");
        let mut reply = String::new();
        BufReader::new(&stream)
            .read_line(&mut reply)
            .expect("read control reply");
        serde_json::from_str(reply.trim()).expect("control reply JSON")
    }

    /// Poll `signoff_list` until at least `n` calls are held (or 10 s pass).
    pub fn wait_for_held(&self, n: usize) -> Vec<serde_json::Value> {
        for _ in 0..100 {
            let v = self.control("signoff_list", &serde_json::json!({}));
            let held = v["held"].as_array().cloned().unwrap_or_default();
            if held.len() >= n {
                return held;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Vec::new()
    }

    /// Path of this instance's audit trail.
    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    /// Parsed audit records written so far.
    pub fn audit_records(&self) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(&self.audit_path).unwrap_or_default();
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("audit line JSON"))
            .collect()
    }

    /// Wait (up to ~3 s) until at least `n` audit records exist. The record
    /// is sealed a hair after the wire response, so callers poll.
    pub fn wait_for_audit_records(&self, n: usize) -> Vec<serde_json::Value> {
        for _ in 0..60 {
            let recs = self.audit_records();
            if recs.len() >= n {
                return recs;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.audit_records()
    }

    /// Run a Claude Code hook event with extra interceptor environment.
    pub fn run_hook_env(
        &self,
        input: &str,
        env: &[(&str, &str)],
    ) -> interceptor::InterceptorResult {
        interceptor::run_interceptor_for(
            AgentKind::Claude,
            input,
            &self.socket_path.to_string_lossy(),
            env,
        )
    }

    /// Run a Claude Code hook event through the interceptor against this
    /// Falco instance. Preserved for back-compat with existing tests.
    pub fn run_hook(&self, input: &str) -> interceptor::InterceptorResult {
        self.run_hook_for(AgentKind::Claude, input)
    }

    /// Run a hook event through the given agent's interceptor against this
    /// Falco instance.
    pub fn run_hook_for(&self, kind: AgentKind, input: &str) -> interceptor::InterceptorResult {
        interceptor::run_interceptor_for(kind, input, &self.socket_path.to_string_lossy(), &[])
    }

    /// Build a Claude Code hook JSON input string (PreToolUse).
    pub fn make_input(tool_name: &str, tool_input: &str, cwd: &str, tool_use_id: &str) -> String {
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"{}","tool_input":{},"session_id":"e2e-test","cwd":"{}","tool_use_id":"{}"}}"#,
            tool_name, tool_input, cwd, tool_use_id
        )
    }

    /// Build a Codex PreToolUse hook input string. All 10 required fields
    /// per the upstream schema, snake_case, single-line (RawValue passthrough
    /// would otherwise break the mock broker's read_line — and even though
    /// the real broker reads more carefully here, single-line keeps the
    /// inputs consistent and easy to scan in failure output).
    pub fn make_codex_pretool_input(
        tool_name: &str,
        tool_input: &str,
        cwd: &str,
        tool_use_id: &str,
    ) -> String {
        format!(
            r#"{{"session_id":"e2e-codex","turn_id":"e2e-turn","transcript_path":null,"cwd":"{cwd}","hook_event_name":"PreToolUse","model":"gpt-5-codex","permission_mode":"default","tool_name":"{tool_name}","tool_input":{tool_input},"tool_use_id":"{tool_use_id}"}}"#
        )
    }

    /// Build a Codex PermissionRequest hook input string. Same shape as
    /// PreToolUse minus tool_use_id (omitted per the upstream schema).
    pub fn make_codex_permreq_input(tool_name: &str, tool_input: &str, cwd: &str) -> String {
        format!(
            r#"{{"session_id":"e2e-codex","turn_id":"e2e-turn","transcript_path":null,"cwd":"{cwd}","hook_event_name":"PermissionRequest","model":"gpt-5-codex","permission_mode":"default","tool_name":"{tool_name}","tool_input":{tool_input}}}"#
        )
    }

    /// Build a Codex apply_patch PreToolUse input from a raw multi-line patch
    /// body. JSON-escapes newlines and quotes so the resulting wire request
    /// is a single line (the broker's read_line would truncate otherwise).
    /// `patch_body` is the full envelope including `*** Begin Patch` and
    /// `*** End Patch` markers.
    pub fn make_codex_apply_patch_input(patch_body: &str, cwd: &str, tool_use_id: &str) -> String {
        let escaped = serde_json::to_string(patch_body).expect("JSON-escape patch body");
        let tool_input = format!(r#"{{"command":{escaped}}}"#);
        Self::make_codex_pretool_input("apply_patch", &tool_input, cwd, tool_use_id)
    }
}

impl Drop for E2eHarness {
    fn drop(&mut self) {
        let _ = self.falco.kill();
        let _ = self.falco.wait();
        // Small delay to release file handles before cleanup.
        std::thread::sleep(Duration::from_millis(200));
        let _ = std::fs::remove_dir_all(&self.e2e_dir);
    }
}

fn reserve_http_port() -> Option<TcpListener> {
    TcpListener::bind(("127.0.0.1", 0)).ok()
}

fn to_forward_slashes(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

#[allow(clippy::too_many_arguments)]
fn write_falco_config(
    config_path: &Path,
    plugin_lib: &Path,
    socket_path: &Path,
    rules_files: &[PathBuf],
    http_port: u16,
    mode: &str,
    default_action: &str,
    extra_init_config: &str,
) {
    let rules_entries = rules_files
        .iter()
        .map(|path| format!("  - {}", to_forward_slashes(path)))
        .collect::<Vec<_>>()
        .join("\n");
    let plugin_path = to_forward_slashes(plugin_lib);
    let sock_path = to_forward_slashes(socket_path);

    let config = format!(
        r#"engine:
  kind: nodriver
plugins:
  - name: coding_agent
    library_path: {plugin_path}
    init_config:
      socket_path: "{sock_path}"
      http_port: {http_port}
      mode: {mode}
      default_action: {default_action}
{extra_init_config}load_plugins:
  - coding_agent
rules_files:
{rules_entries}
json_output: true
json_include_message_property: true
json_include_output_property: false
json_include_output_fields_property: true
json_include_tags_property: true
rule_matching: all
priority: debug
# Production appends correlation.id to every coding_agent alert. Shipped
# rules rely on that config-level field instead of repeating it in every
# output template, so the E2E harness must do the same or the broker cannot
# associate deny/ask alerts with the pending tool call.
append_output:
  - match:
      source: coding_agent
    extra_output: "| correlation=%correlation.id"
# Mirror production: hot-reload is disabled. ctl drives all config changes
# via stop -> rewrite -> start. See configs/falco.yaml for the rationale.
watch_config_files: false
http_output:
  enabled: true
  url: http://127.0.0.1:{http_port}
stdout_output:
  enabled: false
syslog_output:
  enabled: false
"#
    );
    std::fs::write(config_path, config).expect("failed to write falco config");
}

fn write_rules(rules_dir: &Path) {
    // On macOS, /etc is a symlink to /private/etc. The plugin resolves paths
    // via canonicalize() when the file exists, but falls back to lexical
    // normalization when it doesn't (common in tests). Rules must match both
    // forms: /etc/... and /private/etc/...
    //
    // is_write_tool mirrors the production macro from rules/default/
    // coding_agents_rules.yaml so the same path-based rules fire for both
    // Claude Code's Write/Edit and Codex's apply_patch synthetic events.
    let sensitive_write_condition = if cfg!(windows) {
        r#"is_write_tool and tool.real_file_path startswith "C:/Windows""#
    } else if cfg!(target_os = "macos") {
        r#"is_write_tool and (tool.real_file_path startswith "/etc" or tool.real_file_path startswith "/private/etc")"#
    } else {
        r#"is_write_tool and tool.real_file_path startswith "/etc""#
    };
    let sensitive_read_condition = if cfg!(windows) {
        r#"tool.name = "Read" and (tool.real_file_path startswith "C:/Windows" or tool.real_file_path contains ".ssh")"#
    } else if cfg!(target_os = "macos") {
        r#"tool.name = "Read" and (tool.real_file_path startswith "/etc" or tool.real_file_path startswith "/private/etc" or tool.real_file_path contains ".ssh" or tool.real_file_path contains ".aws")"#
    } else {
        r#"tool.name = "Read" and (tool.real_file_path startswith "/etc" or tool.real_file_path contains ".ssh" or tool.real_file_path contains ".aws")"#
    };

    let deny_rules = format!(
        r#"- macro: is_write_tool
  condition: tool.name in ("Write", "Edit") or (tool.name = "apply_patch" and tool.patch_op in ("Add", "Update", "Delete", "Move"))

- rule: Deny rm -rf
  desc: Block dangerous rm -rf commands
  condition: tool.name = "Bash" and tool.input_command contains "rm -rf"
  output: "Falco blocked rm -rf: %tool.input_command | correlation=%correlation.id agent_pid=%agent.pid"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Deny bash credential read
  desc: Block bash reads of credential paths (mirrors references_credential)
  condition: tool.name = "Bash" and (tool.input_command contains "/.kube/" or tool.input_command contains "/.config/gcloud/" or tool.input_command contains "/.azure/" or tool.input_command contains "/.git-credentials")
  output: "Falco blocked a bash credential read: %tool.input_command | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Deny writes to sensitive paths
  desc: Block writes to sensitive system directories
  condition: {sensitive_write_condition}
  output: "Falco blocked writing to %tool.real_file_path | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Deny writing to ssh dir
  desc: Block writes to .ssh directories
  condition: is_write_tool and tool.real_file_path contains "/.ssh/"
  output: "Falco blocked writing to %tool.real_file_path because .ssh is sensitive | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Ask write outside cwd
  desc: Require confirmation for writes outside working directory
  condition: is_write_tool and (agent.real_cwd = "" or (tool.real_file_path != val(agent.real_cwd) and not tool.real_file_path startswith val(agent.real_cwd_prefix)))
  output: "Falco asks about writing to %tool.real_file_path outside %agent.real_cwd | correlation=%correlation.id"
  priority: WARNING
  source: coding_agent
  tags: [coding_agent_ask]

- rule: Deny reading sensitive paths
  desc: Block reads from sensitive paths
  condition: {sensitive_read_condition}
  output: "Falco blocked reading %tool.real_file_path | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Audit read outside cwd
  desc: Log reads outside working directory (monitor only, no deny/ask)
  condition: tool.name = "Read" and (agent.real_cwd = "" or (tool.real_file_path != val(agent.real_cwd) and not tool.real_file_path startswith val(agent.real_cwd_prefix)))
  output: "Falco noticed read outside cwd %tool.real_file_path | correlation=%correlation.id"
  priority: NOTICE
  source: coding_agent
  tags: []

# --- Codex E2E sentinel rules ---
# These rules fire only for agent.name = "codex" and only on unique markers
# unlikely to appear elsewhere. They let the Codex E2E suite prove agent.name
# routing through Falco end-to-end without disturbing the agent-agnostic
# rules above (which fire for both Claude Code and Codex).

- rule: Codex sentinel deny
  desc: Sentinel deny rule used by Codex E2E tests to verify agent.name routing
  condition: agent.name = "codex" and tool.name = "Bash" and tool.input_command contains "codex-e2e-deny-marker"
  output: "Codex deny sentinel matched: %tool.input_command | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Codex sentinel ask
  desc: Sentinel ask rule used by Codex E2E tests to verify the PermissionRequest mount
  condition: agent.name = "codex" and tool.name = "Bash" and tool.input_command contains "codex-e2e-ask-marker"
  output: "Codex ask sentinel matched: %tool.input_command | correlation=%correlation.id"
  priority: WARNING
  source: coding_agent
  tags: [coding_agent_ask]

# Cross-match sentinel for apply_patch multi-file content isolation.
# The condition combines a content marker that only appears in hunk A
# (HUNK-A-ONLY-MARKER) with a path that only belongs to hunk B
# (.../crossmatch-b.txt). If per-hunk content isolation is broken (i.e.
# every synthetic event still carries the FULL patch as tool.input), this
# rule fires on the synthetic event for hunk B because tool.input contains
# the leaked marker from hunk A. With the fix, hunk B's tool.input only
# contains its own hunk text — the marker is not there — so the rule does
# not fire.
- rule: Codex apply_patch cross-match sentinel
  desc: Pins per-hunk content isolation across synthetic apply_patch events
  condition: agent.name = "codex" and tool.name = "apply_patch" and tool.input contains "HUNK-A-ONLY-MARKER" and tool.real_file_path endswith "crossmatch-b.txt"
  output: "Cross-match sentinel matched (hunk A content leaked into hunk B's event) | correlation=%correlation.id"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]
"#
    );
    std::fs::write(rules_dir.join("deny.yaml"), deny_rules).expect("failed to write deny rules");

    let seen_rule = r#"- rule: Coding Agent Event Seen
  desc: Catch-all rule signaling evaluation complete
  condition: correlation.id > 0
  output: "id=%correlation.id agent=%agent.name agent_id=%agent.id agent_type=%agent.type tool=%tool.name cwd=%agent.real_cwd path=%tool.real_file_path cmd=%tool.input_command"
  priority: DEBUG
  source: coding_agent
  tags: [coding_agent_seen]
"#;
    std::fs::write(rules_dir.join("seen.yaml"), seen_rule).expect("failed to write seen rule");
}
