use falco_plugin::schemars::JsonSchema;
use falco_plugin::serde::Deserialize;

/// Plugin configuration, received from falco.yaml `init_config`.
#[derive(Deserialize, JsonSchema, Clone)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
pub struct CodingAgentConfig {
    /// Operational mode. One of:
    /// - `guardrails` (default): verdicts enforced (deny / ask / allow).
    /// - `monitor`: rules are evaluated and logged, but all verdicts resolve
    ///   as `allow` after the synchronous rule-eval wait.
    /// - `passthrough` (Experimental): every interceptor request is resolved
    ///   as `allow` immediately at register, without waiting for rule
    ///   evaluation. Events are still enqueued so observability via
    ///   `http_output` / `falco.log` is preserved. Use only when embedding
    ///   Prempti inside a host agent that handles alerts through its own
    ///   pipeline.
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Action when a tool call matches no deny/ask rule (the "no-rule-match
    /// floor"). One of:
    /// - `allow` (default): Prempti actively approves, skipping the agent's
    ///   own permission prompt.
    /// - `defer`: Prempti steps aside; the agent's own permission system
    ///   decides (Claude Code's normal permission flow / Codex's
    ///   `PermissionRequest`), prompting if it normally would.
    ///
    /// Applies in `guardrails` mode only. In `monitor` and `passthrough`
    /// modes every request resolves as `defer` regardless of this setting.
    /// deny / ask verdicts are unaffected either way.
    #[serde(default = "default_default_action")]
    pub default_action: String,

    /// Broker listen address (Unix domain socket path on all platforms).
    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    /// Port for the HTTP alert receiver.
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Tags that indicate a deny verdict.
    #[serde(default = "default_deny_tags")]
    pub deny_tags: Vec<String>,

    /// Tags that indicate an ask verdict.
    #[serde(default = "default_ask_tags")]
    pub ask_tags: Vec<String>,

    /// Tags that indicate evaluation is complete (seen).
    #[serde(default = "default_seen_tags")]
    pub seen_tags: Vec<String>,

    /// Maximum size in bytes of a single wire request the broker will read
    /// from an interceptor connection. Default 5 MiB (5 * 1024 * 1024).
    /// Raise this if you see deny responses with reason `"read error"` and
    /// the interceptor was forwarding a very large `apply_patch` envelope;
    /// the matching limit on the interceptor side is
    /// `PREMPTI_INPUT_MAX_BYTES`. Clamped to `[4 KiB, 64 MiB]` at use site
    /// so a typo can't break the broker.
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: u64,

    /// Write one hash-chained JSON record per interceptor request to
    /// `audit_path`. Default true.
    #[serde(default = "default_audit_enabled")]
    pub audit_enabled: bool,

    /// Audit trail file. Append-only; never rotated by the supervisor
    /// (rotation would break the hash chain). Default
    /// `$HOME/.prempti/log/audit.jsonl`.
    #[serde(default = "default_audit_path")]
    pub audit_path: String,

    /// Maximum bytes of serialized `tool_input` stored verbatim in each audit
    /// record. The sha256 of the full input is always recorded. Default 16 KiB.
    #[serde(default = "default_audit_input_max_bytes")]
    pub audit_input_max_bytes: u64,

    /// LLM monitor (second verdict source). Disabled unless `monitor.enabled`.
    #[serde(default)]
    pub monitor: MonitorConfig,
}

/// LLM monitor settings. The monitor reviews every tool call (minus
/// `skip_tools`) against the Rules of Engagement and can escalate the
/// verdict to `ask` or `deny`; it can never downgrade a Falco verdict.
#[derive(Deserialize, JsonSchema, Clone, Debug)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
pub struct MonitorConfig {
    /// Enable the monitor. Default false.
    #[serde(default)]
    pub enabled: bool,

    /// OpenAI-compatible base URL, e.g. `https://api.deepseek.com/v1`.
    /// The plugin POSTs to `<endpoint>/chat/completions`.
    #[serde(default)]
    pub endpoint: String,

    /// Model name sent in the request body.
    #[serde(default = "default_monitor_model")]
    pub model: String,

    /// Environment variable holding the bearer token. Read once at plugin
    /// init. Falls back to `OPENAI_API_KEY`. Default `KEBNETRAILS_API_KEY`.
    #[serde(default = "default_monitor_api_key_env")]
    pub api_key_env: String,

    /// Rules of Engagement document (free-form text / Markdown). Read once
    /// at init; its sha256 is recorded in every audit record.
    /// Default `$HOME/.prempti/config/roe.md`.
    #[serde(default = "default_monitor_roe_path")]
    pub roe_path: String,

    /// Per-attempt HTTP timeout in milliseconds. Default 20000.
    #[serde(default = "default_monitor_timeout_ms")]
    pub timeout_ms: u64,

    /// Verdict when the monitor cannot produce one (transport error,
    /// unparseable reply, panic): `ask` (default) or `deny`.
    #[serde(default = "default_monitor_on_error")]
    pub on_error: String,

    /// Bytes read from the tail of the agent transcript for context.
    /// 0 disables transcript context. Default 32 KiB.
    #[serde(default = "default_monitor_max_transcript_bytes")]
    pub max_transcript_bytes: u64,

    /// Bytes of serialized `tool_input` forwarded to the model. Default 8 KiB.
    #[serde(default = "default_monitor_max_input_bytes")]
    pub max_input_bytes: u64,

    /// Worker threads (concurrent LLM calls). Default 4.
    #[serde(default = "default_monitor_workers")]
    pub workers: usize,

    /// Tool names never sent to the monitor (recorded as
    /// `skipped:tool_policy`). Default empty — review everything.
    #[serde(default)]
    pub skip_tools: Vec<String>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            enabled: false,
            endpoint: String::new(),
            model: default_monitor_model(),
            api_key_env: default_monitor_api_key_env(),
            roe_path: default_monitor_roe_path(),
            timeout_ms: default_monitor_timeout_ms(),
            on_error: default_monitor_on_error(),
            max_transcript_bytes: default_monitor_max_transcript_bytes(),
            max_input_bytes: default_monitor_max_input_bytes(),
            workers: default_monitor_workers(),
            skip_tools: Vec::new(),
        }
    }
}

fn default_monitor_model() -> String {
    "deepseek-v4.1-flash".to_string()
}

fn default_monitor_api_key_env() -> String {
    "KEBNETRAILS_API_KEY".to_string()
}

fn default_monitor_roe_path() -> String {
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            format!("{home}/.prempti/config/roe.md")
        } else {
            "/etc/prempti/roe.md".to_string()
        }
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            format!("{}/prempti/config/roe.md", local.replace('\\', "/"))
        } else {
            "C:/prempti-roe.md".to_string()
        }
    }
}

fn default_monitor_timeout_ms() -> u64 {
    20_000
}

fn default_monitor_on_error() -> String {
    "ask".to_string()
}

fn default_monitor_max_transcript_bytes() -> u64 {
    32 * 1024
}

fn default_monitor_max_input_bytes() -> u64 {
    8 * 1024
}

fn default_monitor_workers() -> usize {
    4
}

fn default_audit_enabled() -> bool {
    true
}

fn default_audit_path() -> String {
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            format!("{home}/.prempti/log/audit.jsonl")
        } else {
            "/tmp/prempti-audit.jsonl".to_string()
        }
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            format!("{}/prempti/log/audit.jsonl", local.replace('\\', "/"))
        } else {
            "C:/prempti-audit.jsonl".to_string()
        }
    }
}

fn default_audit_input_max_bytes() -> u64 {
    16 * 1024
}

fn default_mode() -> String {
    "guardrails".to_string()
}

fn default_default_action() -> String {
    "allow".to_string()
}

fn default_socket_path() -> String {
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            format!("{home}/.prempti/run/broker.sock")
        } else {
            "/tmp/prempti-broker.sock".to_string()
        }
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            format!("{}/prempti/run/broker.sock", local.replace('\\', "/"))
        } else {
            "C:/prempti-broker.sock".to_string()
        }
    }
}

fn default_http_port() -> u16 {
    2802
}

fn default_deny_tags() -> Vec<String> {
    vec!["coding_agent_deny".to_string()]
}

fn default_ask_tags() -> Vec<String> {
    vec!["coding_agent_ask".to_string()]
}

fn default_seen_tags() -> Vec<String> {
    vec!["coding_agent_seen".to_string()]
}

fn default_max_request_bytes() -> u64 {
    // 5 MiB: comfortably covers realistic apply_patch multi-file refactors
    // (the largest captured Codex payloads in dev were ~1 KiB, but model-
    // generated patches can easily exceed 64 KiB on big refactors). Leaves
    // headroom over the interceptor's 4 MiB default to account for the
    // {version, id, agent_name, agent_pid, event} envelope overhead.
    5 * 1024 * 1024
}
