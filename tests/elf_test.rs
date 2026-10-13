use rev_core::native::{analyze_elf, RelroStatus};
use std::fs;
use std::path::Path;

#[test]
fn test_analyze_real_system_elf() {
    let target = Path::new("/bin/ls");
    if !target.exists() {
        return;
    }

    let bytes = fs::read(target).expect("Failed to read /bin/ls");
    let report = analyze_elf(&bytes).expect("Failed to parse /bin/ls ELF");

    assert_eq!(report.class, "ELF64");
    assert_eq!(report.endianness, "Little Endian");
    assert!(report.entrypoint > 0);
    assert!(report.sections_count > 0);
    assert!(report.segments_count > 0);

    // Standard modern Linux /bin/ls mitigations
    assert!(report.mitigations.nx);
    assert!(report.mitigations.pie);
    assert_eq!(report.mitigations.relro, RelroStatus::Full);
    assert!(report.mitigations.stack_canary);
}
