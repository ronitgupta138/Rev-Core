use rev_core::decompile::lift_cfg_to_pseudocode;
use rev_core::native::build_cfg_x86_64;

#[test]
fn test_lift_x86_64_function_prologue_and_return() {
    // Machine code for:
    // push rbp
    // mov rbp, rsp
    // mov eax, 0
    // pop rbp
    // ret
    let code: [u8; 11] = [
        0x55,                   // push rbp
        0x48, 0x89, 0xe5,       // mov rbp, rsp
        0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
        0x5d,                   // pop rbp
        0xc3,                   // ret
    ];

    let cfg = build_cfg_x86_64(&code, 0x1000, 10).expect("CFG must build");
    let pseudocode = lift_cfg_to_pseudocode(&cfg, Some("test_main"));

    assert!(pseudocode.contains("int64_t test_main"));
    assert!(pseudocode.contains("return rax;"));
}
