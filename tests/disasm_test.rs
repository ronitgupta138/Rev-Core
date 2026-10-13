use rev_core::native::disassemble_x86_64;

#[test]
fn test_disassemble_known_x86_64_bytes() {
    // endbr64 (f3 0f 1e fa)
    // xor ebp, ebp (31 ed)
    // mov r9, rdx (49 89 d1)
    let bytes = vec![0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x49, 0x89, 0xd1];

    let instrs = disassemble_x86_64(&bytes, 0x1000, 10).expect("Disassembly failed");

    assert_eq!(instrs.len(), 3);
    assert_eq!(instrs[0].ip, 0x1000);
    assert_eq!(instrs[0].bytes, "f30f1efa");
    assert_eq!(instrs[0].op_str, "endbr64");

    assert_eq!(instrs[1].ip, 0x1004);
    assert_eq!(instrs[1].bytes, "31ed");
    assert_eq!(instrs[1].op_str, "xor ebp,ebp");

    assert_eq!(instrs[2].ip, 0x1006);
    assert_eq!(instrs[2].bytes, "4989d1");
    assert_eq!(instrs[2].op_str, "mov r9,rdx");
}
