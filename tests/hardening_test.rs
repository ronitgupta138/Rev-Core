use rev_core::analysis::audit_hardening;
use std::fs;
use std::path::Path;

#[test]
fn test_hardening_audit_system_binary() {
    let target = if Path::new("/bin/ls").exists() {
        "/bin/ls"
    } else if Path::new("/usr/bin/ls").exists() {
        "/usr/bin/ls"
    } else {
        "/bin/sh"
    };

    let bytes = fs::read(target).expect("Must read system binary");
    let report = audit_hardening(&bytes).expect("Hardening audit must succeed on ELF");

    assert_eq!(report.binary_format, "ELF");
    assert!(report.hardening_score > 0);
    assert!(!report.security_grade.is_empty());
    // Modern Linux binaries have NX enabled
    assert!(report.nx_dep);
}
