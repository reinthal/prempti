//! E2E: hardware-key sign-off. An `ask` verdict parks the tool call in the
//! broker; a software ES256 authenticator plays the YubiKey and releases it
//! through the same control requests `premptictl signoff` uses. Requires
//! Falco + plugin + interceptor.

use prempti_tests::e2e::{verify_audit_chain, E2eHarness, MonitorSpec, SignoffSpec};
use prempti_tests::interceptor::{assert_decision, assert_reason_contains};
use prempti_tests::mock_llm::{MockLlm, Reply};
use prempti_tests::softkey::SoftKey;

fn cwd() -> &'static str {
    if cfg!(windows) {
        "C:/Users/test/project"
    } else {
        "/tmp/myproject"
    }
}

/// A Write outside cwd: the fixture's "Ask write outside cwd" rule fires.
fn ask_input(id: &str) -> String {
    let path = if cfg!(windows) {
        "C:/Users/test/elsewhere/notes.txt"
    } else {
        "/tmp/elsewhere/notes.txt"
    };
    E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{path}","content":"hi"}}"#),
        cwd(),
        id,
    )
}

macro_rules! require {
    ($e:expr) => {
        match $e {
            Some(h) => h,
            None => {
                eprintln!("SKIP: falco or plugin not available");
                return;
            }
        }
    };
}

/// Run the hook on a thread so the test can act as the operator meanwhile.
fn hook_in_background(
    h: &E2eHarness,
    input: String,
    timeout_ms: u64,
) -> std::thread::JoinHandle<prempti_tests::interceptor::InterceptorResult> {
    let socket = h.socket_path.to_string_lossy().to_string();
    std::thread::spawn(move || {
        prempti_tests::interceptor::run_interceptor_for(
            prempti_tests::interceptor::AgentKind::Claude,
            &input,
            &socket,
            &[("PREMPTI_TIMEOUT_MS", &timeout_ms.to_string())],
        )
    })
}

#[test]
fn ask_is_held_and_released_by_key_touch() {
    let key = SoftKey::new(1, "desk-yubikey");
    let spec = SignoffSpec::new(SoftKey::key_file(&[&key]));
    let h = require!(E2eHarness::start_with_signoff("guardrails", &spec));

    let hook = hook_in_background(&h, ask_input("signoff-approve"), 30_000);
    let held = h.wait_for_held(1);
    assert_eq!(held.len(), 1, "call should be parked for sign-off");
    assert_eq!(held[0]["tool"], "Write");
    assert!(held[0]["reason"]
        .as_str()
        .unwrap()
        .contains("Ask write outside cwd"));
    assert_eq!(held[0]["falco_rules"][0], "Ask write outside cwd");
    let request_seq = held[0]["request_seq"].as_u64().unwrap();
    let correlation_id = held[0]["correlation_id"].as_u64().unwrap();

    // The request record is already sealed with the staged `ask`.
    let recs = h.wait_for_audit_records(1);
    assert_eq!(recs[0]["seq"], request_seq);
    assert_eq!(recs[0]["final"]["verdict"], "ask");
    assert_eq!(recs[0]["signoff"]["status"], "pending");
    assert_eq!(recs[0]["hash"], held[0]["request_hash"]);

    // Wrong key first: refused, still held.
    let stranger = SoftKey::new(2, "stranger");
    let refused = h.control(
        "signoff_resolve",
        &serde_json::json!({
            "correlation_id": correlation_id,
            "decision": "approve",
            "proof": stranger.approve("prempti.local", &held[0]),
        }),
    );
    assert_eq!(refused["ok"], false, "{refused}");
    assert!(refused["error"].as_str().unwrap().contains("not enrolled"));
    assert_eq!(h.wait_for_held(1).len(), 1);

    // Enrolled key: released as allow.
    let ok = h.control(
        "signoff_resolve",
        &serde_json::json!({
            "correlation_id": correlation_id,
            "decision": "approve",
            "proof": key.approve("prempti.local", &held[0]),
        }),
    );
    assert_eq!(ok["ok"], true, "{ok}");
    assert_eq!(ok["decision"], "approve");
    assert_eq!(ok["key_label"], "desk-yubikey");

    let r = hook.join().unwrap();
    assert_decision(&r, "allow");

    let recs = h.wait_for_audit_records(2);
    assert_eq!(recs[1]["kind"], "signoff");
    assert_eq!(recs[1]["decision"], "approve");
    assert_eq!(recs[1]["request_seq"], request_seq);
    assert_eq!(recs[1]["request_hash"], recs[0]["hash"]);
    assert_eq!(recs[1]["key"]["label"], "desk-yubikey");
    assert_eq!(recs[1]["key"]["user_present"], true);
    assert_eq!(verify_audit_chain(h.audit_path()).unwrap(), 2);
    assert!(h.wait_for_held(0).is_empty());
}

#[test]
fn operator_deny_needs_no_key() {
    let key = SoftKey::new(3, "k");
    let spec = SignoffSpec::new(SoftKey::key_file(&[&key]));
    let h = require!(E2eHarness::start_with_signoff("guardrails", &spec));

    let hook = hook_in_background(&h, ask_input("signoff-deny"), 30_000);
    let held = h.wait_for_held(1);
    assert_eq!(held.len(), 1);
    let v = h.control(
        "signoff_resolve",
        &serde_json::json!({
            "correlation_id": held[0]["correlation_id"],
            "decision": "deny",
            "reason": "out of scope for this engagement",
        }),
    );
    assert_eq!(v["ok"], true, "{v}");
    let r = hook.join().unwrap();
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "sign-off denied by operator: out of scope");
    let recs = h.wait_for_audit_records(2);
    assert_eq!(recs[1]["decision"], "deny");
    assert_eq!(recs[1]["reason"], "out of scope for this engagement");
    assert_eq!(verify_audit_chain(h.audit_path()).unwrap(), 2);
}

#[test]
fn unanswered_signoff_expires_to_deny() {
    let key = SoftKey::new(4, "k");
    let mut spec = SignoffSpec::new(SoftKey::key_file(&[&key]));
    spec.ttl_secs = 1;
    let h = require!(E2eHarness::start_with_signoff("guardrails", &spec));

    // The reaper runs every 10 s; the interceptor must outwait it.
    let hook = hook_in_background(&h, ask_input("signoff-expire"), 30_000);
    assert_eq!(h.wait_for_held(1).len(), 1);
    let r = hook.join().unwrap();
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "sign-off expired");
    let recs = h.wait_for_audit_records(2);
    assert_eq!(recs[1]["kind"], "signoff");
    assert_eq!(recs[1]["decision"], "expired");
    assert_eq!(verify_audit_chain(h.audit_path()).unwrap(), 2);
}

#[test]
fn allow_and_deny_are_not_held() {
    let key = SoftKey::new(5, "k");
    let spec = SignoffSpec::new(SoftKey::key_file(&[&key]));
    let h = require!(E2eHarness::start_with_signoff("guardrails", &spec));

    let r = h.run_hook(&E2eHarness::make_input(
        "Bash",
        r#"{"command":"ls -la"}"#,
        cwd(),
        "signoff-allow",
    ));
    assert_decision(&r, "allow");
    let r = h.run_hook(&E2eHarness::make_input(
        "Bash",
        r#"{"command":"rm -rf /"}"#,
        cwd(),
        "signoff-denyrule",
    ));
    assert_decision(&r, "deny");
    let recs = h.wait_for_audit_records(2);
    assert!(recs.iter().all(|r| r["signoff"]["status"] == "none"));
    assert!(h.wait_for_held(0).is_empty());
    assert_eq!(verify_audit_chain(h.audit_path()).unwrap(), 2);
}

#[test]
fn llm_ask_is_held_too() {
    let mock = MockLlm::start(vec![(
        "",
        Reply::Verdict {
            verdict: "ask",
            reason: "RoE requires sign-off for scans",
            clause: "Sign-off",
        },
    )]);
    let key = SoftKey::new(6, "k");
    let mut spec = SignoffSpec::new(SoftKey::key_file(&[&key]));
    spec.monitor = Some(MonitorSpec::new(mock.endpoint()));
    let h = require!(E2eHarness::start_with_signoff("guardrails", &spec));

    let input = E2eHarness::make_input(
        "Bash",
        r#"{"command":"nmap -sV 10.0.0.5"}"#,
        cwd(),
        "signoff-llm",
    );
    let hook = hook_in_background(&h, input, 30_000);
    let held = h.wait_for_held(1);
    assert_eq!(held.len(), 1);
    assert!(held[0]["reason"].as_str().unwrap().contains("LLM monitor"));
    assert_eq!(held[0]["llm_clause"], "Sign-off");
    let ok = h.control(
        "signoff_resolve",
        &serde_json::json!({
            "correlation_id": held[0]["correlation_id"],
            "decision": "approve",
            "proof": key.approve("prempti.local", &held[0]),
        }),
    );
    assert_eq!(ok["ok"], true, "{ok}");
    assert_decision(&hook.join().unwrap(), "allow");
    let recs = h.wait_for_audit_records(2);
    assert_eq!(recs[0]["llm"]["verdict"], "ask");
    assert_eq!(recs[0]["final"]["source"], "llm");
    assert_eq!(recs[1]["decision"], "approve");
}

#[test]
fn monitor_mode_does_not_hold() {
    let key = SoftKey::new(7, "k");
    let spec = SignoffSpec::new(SoftKey::key_file(&[&key]));
    let h = require!(E2eHarness::start_with_signoff("monitor", &spec));
    let r = h.run_hook(&ask_input("signoff-monitor"));
    prempti_tests::interceptor::assert_empty_stdout(&r);
    assert!(h.wait_for_held(0).is_empty());
}
