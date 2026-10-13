use rev_core::native::{build_cfg_x86_64, TerminatorType};

#[test]
fn test_cfg_branching_and_mermaid() {
    // Assembly:
    // 0x1000: cmp eax, 0    (83 f8 00)
    // 0x1003: je 0x1008     (74 03)
    // 0x1005: inc eax       (ff c0)
    // 0x1007: ret           (c3)
    // 0x1008: dec eax       (ff c8)
    // 0x100a: ret           (c3)
    let bytes = vec![0x83, 0xf8, 0x00, 0x74, 0x03, 0xff, 0xc0, 0xc3, 0xff, 0xc8, 0xc3];

    let cfg = build_cfg_x86_64(&bytes, 0x1000, 20).expect("Failed to build CFG");

    assert!(cfg.blocks.len() >= 2);
    assert_eq!(cfg.entry_ip, 0x1000);

    let first_block = &cfg.blocks[0];
    assert_eq!(first_block.start_ip, 0x1000);
    assert_eq!(first_block.terminator_type, TerminatorType::ConditionalBranch);
    assert!(first_block.successors.contains(&0x1008)); // je target
    assert!(first_block.successors.contains(&0x1005)); // fallthrough target

    let mermaid = cfg.to_mermaid();
    assert!(mermaid.starts_with("graph TD"));
    assert!(mermaid.contains("-->|branch|"));

    let ascii = cfg.to_ascii_summary();
    assert!(ascii.contains("Cyclomatic Complexity:"));
}
