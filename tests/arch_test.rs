use rev_core::native::{decode_universal_slice, TargetArch};

#[test]
fn test_decode_arm64_instructions() {
    // ARM64 Little Endian opcodes:
    // nop: 1f 20 03 d5 (0xd503201f)
    // ret: c0 03 5f d6 (0xd65f03c0)
    // svc #0x80: 01 10 00 d4 (0xd4001001)
    let bytes = vec![0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6, 0x01, 0x10, 0x00, 0xd4];

    let instrs = decode_universal_slice(&bytes, 0x1000, TargetArch::Arm64, 10).expect("Failed to decode ARM64");

    assert_eq!(instrs.len(), 3);
    assert_eq!(instrs[0].mnemonic, "nop");
    assert_eq!(instrs[1].mnemonic, "ret");
    assert_eq!(instrs[2].mnemonic, "svc");
    assert!(instrs[2].op_str.contains("svc #0x80"));
}

#[test]
fn test_decode_riscv64_instructions() {
    // RISC-V Little Endian opcodes:
    // nop: 13 00 00 00 (0x00000013)
    // ret: 67 80 00 00 (0x00008067)
    // ecall: 73 00 00 00 (0x00000073)
    let bytes = vec![0x13, 0x00, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00];

    let instrs = decode_universal_slice(&bytes, 0x2000, TargetArch::Riscv64, 10).expect("Failed to decode RISC-V");

    assert_eq!(instrs.len(), 3);
    assert_eq!(instrs[0].mnemonic, "nop");
    assert_eq!(instrs[1].mnemonic, "ret");
    assert_eq!(instrs[2].mnemonic, "ecall");
}
