use rev_core::domain::{compute_sha256, Evidence, EvidenceLedger};
use serde_json::json;

#[test]
fn test_evidence_deterministic_hashing() {
    let payload = json!({
        "function": "main",
        "entry": "0x1000",
        "has_canary": true
    });

    let ev1 = Evidence::new("/path/to/binary", "mock_digest_1234", "test_tool", &payload, vec![]);
    let ev2 = Evidence::new("/path/to/binary", "mock_digest_1234", "test_tool", &payload, vec![]);

    // Both should produce the exact same deterministic evidence ID
    assert_eq!(ev1.id, ev2.id);
    assert_eq!(ev1.target_digest, "mock_digest_1234");
}

#[test]
fn test_evidence_ledger_unknown_lifecycle() {
    let mut ledger = EvidenceLedger::new();

    let unknown_id = ledger.add_unknown(
        "Obfuscated Jump Target",
        "Indirect jump at 0x401240 cannot be resolved statically",
    );

    assert_eq!(ledger.open_unknowns_count(), 1);

    // Resolve unknown with evidence
    let resolved = ledger.resolve_unknown(&unknown_id, "evidence_hash_abcd");
    assert!(resolved);
    assert_eq!(ledger.open_unknowns_count(), 0);
}

#[test]
fn test_compute_sha256() {
    let data = b"hello reverse engineering world";
    let hash = compute_sha256(data);
    assert_eq!(hash.len(), 64);
}
