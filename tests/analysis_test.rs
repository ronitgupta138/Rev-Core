use rev_core::analysis::{analyze_entropy, calculate_entropy, scan_crypto_constants};

#[test]
fn test_entropy_calculation() {
    // Low entropy: repeated byte
    let zeroes = vec![0u8; 1024];
    let zero_entropy = calculate_entropy(&zeroes);
    assert_eq!(zero_entropy, 0.0);

    // High entropy: uniform random-ish byte distribution (0..255 repeated 4 times)
    let mut diverse = Vec::new();
    for _ in 0..4 {
        for b in 0..=255u8 {
            diverse.push(b);
        }
    }
    let report = analyze_entropy(&diverse);
    assert!(report.entropy > 7.9);
    assert!(report.is_likely_packed);
}

#[test]
fn test_crypto_signature_scanner() {
    // Synthetic buffer containing ChaCha20 magic bytes
    let mut payload = vec![0x90; 128];
    payload.extend_from_slice(b"expand 32-byte k");
    payload.extend_from_slice(&[0xcc; 64]);

    let findings = scan_crypto_constants(&payload);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].algorithm, "ChaCha20 / Poly1305");
    assert_eq!(findings[0].offset, 128);
    assert_eq!(findings[0].confidence, 1.0);
}
