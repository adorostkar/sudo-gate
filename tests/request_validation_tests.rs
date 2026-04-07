use sudo_gate::config::SecurityConfig;
use sudo_gate::ipc::Request;
use sudo_gate::request::{validate_request_shape, validate_requester, RequesterIdentity};

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
fn validate_request_rejects_empty_reason() {
    let req = Request {
        reason: "   ".to_string(),
        argv: vec!["/usr/bin/apt".to_string(), "update".to_string()],
    };

    assert!(validate_request_shape(&req, &security()).is_err());
}

#[test]
fn validate_request_rejects_too_many_args() {
    let req = Request {
        reason: "apt maintenance".to_string(),
        argv: vec![
            "/usr/bin/apt".to_string(),
            "install".to_string(),
            "vim".to_string(),
            "curl".to_string(),
            "git".to_string(),
        ],
    };

    assert!(validate_request_shape(&req, &security()).is_err());
}

#[test]
fn validate_request_accepts_small_valid_request() {
    let req = Request {
        reason: "refresh apt cache".to_string(),
        argv: vec!["/usr/bin/apt".to_string(), "update".to_string()],
    };

    assert!(validate_request_shape(&req, &security()).is_ok());
}

#[test]
fn validate_requester_respects_uid_allowlist() {
    let mut cfg = security();
    cfg.requester_allow_uids = vec![1001];

    let requester = RequesterIdentity {
        uid: 1000,
        gid: 1000,
        pid: 4242,
        username: "agent".to_string(),
    };

    assert!(validate_requester(&requester, &cfg).is_err());
}
