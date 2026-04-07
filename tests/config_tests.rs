use sudo_gate::config::{AllowRule, Config, PolicyConfig, SecurityConfig, TelegramConfig};

fn telegram() -> TelegramConfig {
    TelegramConfig {
        bot_token: "token".to_string(),
        allowed_user_id: 123,
        allowed_chat_id: None,
        poll_interval_ms: 1500,
        result_mode: "summary".to_string(),
        result_max_chars: 1200,
    }
}

fn security() -> SecurityConfig {
    SecurityConfig {
        hmac_secret_hex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            .to_string(),
        request_ttl_seconds: 90,
        max_request_bytes: 4096,
        max_reason_len: 64,
        max_arg_count: 4,
        max_arg_len: 32,
        max_pending_requests: 8,
        per_uid_max_requests: 3,
        per_uid_window_seconds: 60,
        command_timeout_seconds: 30,
        requester_allow_uids: vec![],
    }
}

#[test]
fn config_requires_allowlist_mode() {
    let cfg = Config {
        telegram: telegram(),
        security: security(),
        policy: PolicyConfig {
            mode: "allow_all".to_string(),
            allow: vec![AllowRule {
                exe: "/usr/bin/apt".to_string(),
                args_prefix: Some(vec!["update".to_string()]),
            }],
            deny: vec![],
        },
    };

    assert!(cfg.validate().is_err());
}

#[test]
fn config_requires_absolute_allow_rule_paths() {
    let cfg = Config {
        telegram: telegram(),
        security: security(),
        policy: PolicyConfig {
            mode: "allowlist".to_string(),
            allow: vec![AllowRule {
                exe: "apt".to_string(),
                args_prefix: Some(vec!["update".to_string()]),
            }],
            deny: vec![],
        },
    };

    assert!(cfg.validate().is_err());
}
