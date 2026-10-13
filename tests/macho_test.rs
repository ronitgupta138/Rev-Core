use rev_core::native::analyze_macho;

#[test]
fn test_synthetic_macho_header_parse() {
    // Synthetic 64-bit Mach-O Header:
    // Magic: MH_MAGIC_64 (0xfeedfacf) -> cf fa ed fe (little endian)
    // CPUType: CPU_TYPE_X86_64 (0x01000007) -> 07 00 00 01
    // CPUSubtype: CPU_SUBTYPE_LIB64 | CPU_SUBTYPE_X86_64_ALL (0x80000003) -> 03 00 00 80
    // FileType: MH_EXECUTE (0x2) -> 02 00 00 00
    // Ncmds: 0 -> 00 00 00 00
    // Sizeofcmds: 0 -> 00 00 00 00
    // Flags: MH_PIE (0x00200000) | MH_NO_HEAP_EXECUTION (0x01000000) -> 00 00 20 01
    // Reserved: 0 -> 00 00 00 00
    let mut header = Vec::new();
    header.extend_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]); // magic
    header.extend_from_slice(&[0x07, 0x00, 0x00, 0x01]); // cputype
    header.extend_from_slice(&[0x03, 0x00, 0x00, 0x80]); // cpusubtype
    header.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // filetype
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ncmds
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // sizeofcmds
    header.extend_from_slice(&[0x00, 0x00, 0x20, 0x01]); // flags: PIE + NX
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved

    let report = analyze_macho(&header).expect("Failed to parse synthetic Mach-O");
    assert!(!report.is_fat);
    assert_eq!(report.architectures.len(), 1);

    let arch = &report.architectures[0];
    assert_eq!(arch.cpu_type, "x86_64");
    assert!(arch.is_64bit);
    assert!(arch.mitigations.pie);
    assert!(arch.mitigations.nx);
}
