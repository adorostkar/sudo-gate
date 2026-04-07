use sudo_gate::config::{AllowRule, PolicyConfig};
use sudo_gate::policy::{evaluate, PolicyDecision, RequestPolicyInput};

fn input(argv: &[&str]) -> RequestPolicyInput {
    RequestPolicyInput {
        exe: argv[0].to_string(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn unknown_policy_mode_fails_closed() {
    let policy = PolicyConfig {
        mode: "mystery".to_string(),
        allow: vec![],
        deny: vec![],
    };

    let decision = evaluate(&policy, &input(&["/usr/bin/apt", "update"]));
    assert!(matches!(decision, PolicyDecision::Deny(_)));
}

#[test]
fn allowlist_requires_exact_executable_and_arg_prefix() {
    let policy = PolicyConfig {
        mode: "allowlist".to_string(),
        allow: vec![AllowRule {
            exe: "/usr/bin/apt".to_string(),
            args_prefix: Some(vec!["update".to_string()]),
        }],
        deny: vec![],
    };

    assert!(matches!(
        evaluate(&policy, &input(&["/usr/bin/apt", "update"])),
        PolicyDecision::Allow
    ));

    assert!(matches!(
        evaluate(&policy, &input(&["/usr/bin/apt", "install", "vim"])),
        PolicyDecision::Deny(_)
    ));

    assert!(matches!(
        evaluate(&policy, &input(&["/bin/sh", "-c", "apt update"])),
        PolicyDecision::Deny(_)
    ));
}
