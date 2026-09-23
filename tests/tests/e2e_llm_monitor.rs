//! E2E: the LLM monitor as a second verdict source, driven by a scripted
//! OpenAI-compatible mock server. Requires Falco + plugin + interceptor.

use prempti_tests::e2e::{verify_audit_chain, E2eHarness, MonitorSpec};
use prempti_tests::interceptor::{assert_decision, assert_empty_stdout, assert_reason_contains};
use prempti_tests::mock_llm::{MockLlm, Reply};

fn cwd() -> &'static str {
    if cfg!(windows) {
        "C:/Users/test/project"
    } else {
        "/tmp/myproject"
    }
}

fn allow() -> Reply {
    Reply::Verdict {
        verdict: "allow",
        reason: "in scope",
        clause: "Scope",
    }
}

/// Start Falco with the monitor pointed at `mock`; `None` skips the test.
fn start(mode: &str, mock: &MockLlm, tweak: impl FnOnce(&mut MonitorSpec)) -> Option<E2eHarness> {
    let mut spec = MonitorSpec::new(mock.endpoint());
    tweak(&mut spec);
    let h = E2eHarness::start_with_monitor(mode, &spec);
    if h.is_none() {
        eprintln!("SKIP: falco or plugin not available");
    }
    h
}

macro_rules! require {
    ($e:expr) => {
        match $e {
            Some(h) => h,
            None => return,
        }
    };
}

#[test]
fn llm_allow_resolves_via_floor() {
    let mock = MockLlm::start(vec![("", allow())]);
    let h = require!(start("guardrails", &mock, |_| {}));
    let input = E2eHarness::make_input("Bash", r#"{"command":"ls -la"}"#, cwd(), "llm-allow");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
    let recs = h.wait_for_audit_records(1);
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0]["llm"]["status"], "ok");
    assert_eq!(recs[0]["llm"]["verdict"], "allow");
    assert_eq!(recs[0]["llm"]["model"], "mock-model");
    assert_eq!(recs[0]["final"]["verdict"], "allow");
    assert_eq!(recs[0]["final"]["source"], "floor");
    assert_eq!(recs[0]["falco"]["verdict"], "none");
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn llm_ask_escalates_with_attribution() {
    let mock = MockLlm::start(vec![(
        "",
        Reply::Verdict {
            verdict: "ask",
            reason: "needs operator sign-off",
            clause: "Sign-off",
        },
    )]);
    let h = require!(start("guardrails", &mock, |_| {}));
    let input = E2eHarness::make_input("Bash", r#"{"command":"nmap 10.0.0.5"}"#, cwd(), "llm-ask");
    let r = h.run_hook(&input);
    assert_decision(&r, "ask");
    assert_reason_contains(
        &r,
        "LLM monitor (mock-model): needs operator sign-off [RoE: Sign-off]",
    );
    let recs = h.wait_for_audit_records(1);
    assert_eq!(recs[0]["final"]["source"], "llm");
    assert_eq!(recs[0]["llm"]["roe_clause"], "Sign-off");
}

#[test]
fn llm_deny_blocks() {
    let mock = MockLlm::start(vec![(
        "",
        Reply::Verdict {
            verdict: "deny",
            reason: "target out of scope",
            clause: "Scope",
        },
    )]);
    let h = require!(start("guardrails", &mock, |_| {}));
    let input = E2eHarness::make_input("Bash", r#"{"command":"nmap 8.8.8.8"}"#, cwd(), "llm-deny");
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "target out of scope");
    let recs = h.wait_for_audit_records(1);
    assert_eq!(recs[0]["final"]["verdict"], "deny");
    assert_eq!(recs[0]["final"]["source"], "llm");
}

#[test]
fn falco_deny_wins_and_llm_is_skipped_or_ignored() {
    // Falco denies `rm -rf /` regardless of what the LLM says; the record
    // still carries both signals.
    let mock = MockLlm::start(vec![("", allow())]);
    let h = require!(start("guardrails", &mock, |_| {}));
    let input = E2eHarness::make_input("Bash", r#"{"command":"rm -rf /"}"#, cwd(), "llm-falco");
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "Deny rm -rf");
    let recs = h.wait_for_audit_records(1);
    assert_eq!(recs[0]["falco"]["verdict"], "deny");
    assert_eq!(recs[0]["final"]["source"], "falco");
    let status = recs[0]["llm"]["status"].as_str().unwrap();
    assert!(
        status == "ok" || status == "skipped:already_responded",
        "unexpected llm status {status}"
    );
}

#[test]
fn http_500_falls_to_on_error_ask_after_retry() {
    let mock = MockLlm::start(vec![("", Reply::Http500)]);
    let h = require!(start("guardrails", &mock, |_| {}));
    let input = E2eHarness::make_input("Bash", r#"{"command":"whoami"}"#, cwd(), "llm-500");
    let r = h.run_hook(&input);
    assert_decision(&r, "ask");
    assert_reason_contains(&r, "LLM monitor (mock-model) unavailable, failing ask");
    let recs = h.wait_for_audit_records(1);
    assert!(recs[0]["llm"]["status"]
        .as_str()
        .unwrap()
        .starts_with("error:"));
    assert_eq!(recs[0]["llm"]["attempts"], 2);
    assert_eq!(mock.requests().len(), 2);
}

#[test]
fn garbage_reply_falls_to_on_error_deny() {
    let mock = MockLlm::start(vec![("", Reply::Garbage)]);
    let h = require!(start("guardrails", &mock, |s| s.on_error = "deny".to_string()));
    let input = E2eHarness::make_input("Bash", r#"{"command":"whoami"}"#, cwd(), "llm-garbage");
    let r = h.run_hook(&input);
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "unparseable reply");
}

#[test]
fn slow_reply_times_out_to_on_error() {
    let mock = MockLlm::start(vec![("", Reply::Sleep(2500))]);
    let h = require!(start("guardrails", &mock, |s| s.timeout_ms = 1000));
    let input = E2eHarness::make_input("Bash", r#"{"command":"whoami"}"#, cwd(), "llm-slow");
    let r = h.run_hook_env(&input, &[("PREMPTI_TIMEOUT_MS", "20000")]);
    assert_decision(&r, "ask");
    assert_reason_contains(&r, "timeout");
}

#[test]
fn skip_tools_bypasses_llm() {
    let mock = MockLlm::start(vec![("", allow())]);
    let h = require!(start("guardrails", &mock, |s| s.skip_tools =
        vec!["Read".to_string()]));
    let input = E2eHarness::make_input("Read", r#"{"file_path":"/tmp/x"}"#, cwd(), "llm-skip");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
    let recs = h.wait_for_audit_records(1);
    assert_eq!(recs[0]["llm"]["status"], "skipped:tool_policy");
    assert!(mock.requests().is_empty());
}

#[test]
fn monitor_mode_defers_but_records_would_deny() {
    let mock = MockLlm::start(vec![(
        "",
        Reply::Verdict {
            verdict: "deny",
            reason: "nope",
            clause: "",
        },
    )]);
    let h = require!(start("monitor", &mock, |_| {}));
    let input = E2eHarness::make_input("Bash", r#"{"command":"whoami"}"#, cwd(), "llm-mon");
    let r = h.run_hook(&input);
    assert_empty_stdout(&r);
    let recs = h.wait_for_audit_records(1);
    assert_eq!(recs[0]["mode"], "monitor");
    assert_eq!(recs[0]["llm"]["verdict"], "deny");
    assert_eq!(recs[0]["final"]["verdict"], "defer");
    assert_eq!(recs[0]["final"]["source"], "monitor");
}

#[test]
fn request_carries_roe_tool_call_and_delimiters() {
    let mock = MockLlm::start(vec![("", allow())]);
    let h = require!(start("guardrails", &mock, |s| {
        s.roe = "# RoE\nOnly hosts in 10.0.0.0/24. SENTINEL-ROE-TEXT\n".to_string()
    }));
    let input = E2eHarness::make_input(
        "Bash",
        r#"{"command":"curl http://10.0.0.7/login"}"#,
        cwd(),
        "llm-prompt",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&reqs[0]).unwrap();
    assert_eq!(body["model"], "mock-model");
    assert_eq!(body["response_format"]["type"], "json_object");
    let system = body["messages"][0]["content"].as_str().unwrap();
    assert!(system.contains("SENTINEL-ROE-TEXT"), "{system}");
    assert!(system.contains("untrusted data"));
    let user = body["messages"][1]["content"].as_str().unwrap();
    assert!(user.starts_with("<tool_call>"), "{user}");
    assert!(user.contains("curl http://10.0.0.7/login"));
    assert!(user.contains("\"session_id\":\"e2e-test\""));
}

#[test]
fn audit_chain_verifies_across_mixed_outcomes() {
    let mock = MockLlm::start(vec![
        (
            "nmap",
            Reply::Verdict {
                verdict: "ask",
                reason: "scan",
                clause: "",
            },
        ),
        ("", allow()),
    ]);
    let h = require!(start("guardrails", &mock, |_| {}));
    for (i, cmd) in ["ls", "nmap 10.0.0.1", "rm -rf /", "whoami"]
        .iter()
        .enumerate()
    {
        let input = E2eHarness::make_input(
            "Bash",
            &format!(r#"{{"command":"{cmd}"}}"#),
            cwd(),
            &format!("llm-chain-{i}"),
        );
        let _ = h.run_hook(&input);
    }
    let recs = h.wait_for_audit_records(4);
    assert_eq!(recs.len(), 4);
    assert_eq!(verify_audit_chain(h.audit_path()).unwrap(), 4);
    let seqs: Vec<u64> = recs.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4]);
}
