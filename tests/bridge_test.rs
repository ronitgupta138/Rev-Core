use rev_core::bridge::DecompilerBridge;

#[tokio::test]
async fn test_decompiler_backend_detection() {
    let backends = DecompilerBridge::detect_backends().await;
    assert_eq!(backends.len(), 3);
    assert!(backends.iter().any(|b| b.backend.contains("Rizin")));
    assert!(backends.iter().any(|b| b.backend.contains("Radare2")));
    assert!(backends.iter().any(|b| b.backend.contains("Ghidra")));
}

#[tokio::test]
async fn test_decompile_nonexistent_binary_error() {
    let res = DecompilerBridge::decompile_symbol("/tmp/nonexistent_binary_xyz_123", "main", 5).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("does not exist"));
}
