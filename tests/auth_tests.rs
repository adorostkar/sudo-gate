use sudo_gate::auth::{eq_ct, sign_trunc_hex};

#[test]
fn truncated_signature_is_stable_length() {
    let sig = sign_trunc_hex(b"supersecretkeymaterial", b"payload", 20);
    assert_eq!(sig.len(), 20);
}

#[test]
fn constant_time_compare_requires_exact_match() {
    assert!(eq_ct("abcd", "abcd"));
    assert!(!eq_ct("abcd", "abce"));
    assert!(!eq_ct("abcd", "abc"));
}
