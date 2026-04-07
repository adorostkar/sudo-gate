use crate::config::{AllowRule, DenyRule, PolicyConfig};

#[derive(Debug, Clone)]
pub struct RequestPolicyInput {
    pub exe: String,
    pub argv: Vec<String>,
}

pub enum PolicyDecision {
    Allow,
    Deny(String),
}

pub fn evaluate(policy: &PolicyConfig, input: &RequestPolicyInput) -> PolicyDecision {
    for rule in &policy.deny {
        if deny_rule_matches(rule, input) {
            return PolicyDecision::Deny(format!("denied by rule {}:{}", rule.kind, rule.value));
        }
    }

    match policy.mode.as_str() {
        "allowlist" => {
            if policy
                .allow
                .iter()
                .any(|rule| allow_rule_matches(rule, input))
            {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny(format!("command is not allowed by policy: {}", input.exe))
            }
        }
        other => PolicyDecision::Deny(format!("unknown policy mode: {other}")),
    }
}

fn allow_rule_matches(rule: &AllowRule, input: &RequestPolicyInput) -> bool {
    if input.exe != rule.exe {
        return false;
    }

    match &rule.args_prefix {
        Some(prefix) => {
            if input.argv.len() < prefix.len() + 1 {
                return false;
            }
            input.argv[1..1 + prefix.len()] == prefix[..]
        }
        None => true,
    }
}

fn deny_rule_matches(rule: &DenyRule, input: &RequestPolicyInput) -> bool {
    match rule.kind.as_str() {
        "exe" => input.exe == rule.value,
        "argv_contains" => input.argv.iter().any(|arg| arg == &rule.value),
        _ => false,
    }
}
