use crate::config::{DenyRule, PolicyConfig};

pub enum PolicyDecision {
    Allow,
    Deny(String),
}

pub fn evaluate(policy: &PolicyConfig, argv: &[String]) -> PolicyDecision {
    // v1: support allow_all + empty deny list.
    // deny rules are parsed but currently only support a simple executable match.

    for r in &policy.deny {
        if rule_matches(r, argv) {
            return PolicyDecision::Deny(format!("denied by rule {}:{}", r.kind, r.value));
        }
    }

    match policy.mode.as_str() {
        "allow_all" => PolicyDecision::Allow,
        _ => PolicyDecision::Allow, // future: deny-by-default
    }
}

fn rule_matches(rule: &DenyRule, argv: &[String]) -> bool {
    if argv.is_empty() {
        return false;
    }
    match rule.kind.as_str() {
        // kind: "exe", value: "rm"
        "exe" => argv[0].ends_with(&rule.value),
        _ => false,
    }
}
