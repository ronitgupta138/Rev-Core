use rev_core::wasm::analyze_wasm;

#[test]
fn test_synthetic_wasm_module_parsing() {
    // Magic (\0asm) + version 1
    let mut wasm_bytes = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    // Memory section (id = 5):
    // section_len = 3
    // count = 1, flags = 0 (only initial), initial = 2 pages
    wasm_bytes.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x02]);

    // Export section (id = 7):
    // section_len = 10
    // count = 1
    // str_len = 6, "memory", kind = 2 (Memory), index = 0
    wasm_bytes.extend_from_slice(&[
        0x07, 0x0a, 0x01, 0x06, b'm', b'e', b'm', b'o', b'r', b'y', 0x02, 0x00,
    ]);

    let report = analyze_wasm(&wasm_bytes).expect("Failed to parse WASM module");

    assert_eq!(report.version, 1);
    assert_eq!(report.sections_count, 2);

    let mem = report.memory.expect("Expected memory section");
    assert_eq!(mem.initial_pages, 2);
    assert_eq!(mem.maximum_pages, None);

    assert_eq!(report.exports.len(), 1);
    assert_eq!(report.exports[0].name, "memory");
    assert_eq!(report.exports[0].kind, "Memory");
}
