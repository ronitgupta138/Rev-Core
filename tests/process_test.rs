use rev_core::process::{parse_maps_content, parse_proc_maps};

#[test]
fn test_synthetic_maps_parsing() {
    let mock_maps = r#"
00400000-00452000 r-xp 00000000 08:02 173521     /usr/bin/sample_app
00651000-00652000 r--p 00051000 08:02 173521     /usr/bin/sample_app
00652000-00653000 rw-p 00052000 08:02 173521     /usr/bin/sample_app
01000000-01020000 rwxp 00000000 00:00 0          [heap]
7fff5be00000-7fff5be21000 rw-p 00000000 00:00 0   [stack]
"#;

    let report = parse_maps_content(1337, mock_maps).expect("Failed to parse mock maps");

    assert_eq!(report.pid, 1337);
    assert_eq!(report.regions.len(), 5);
    assert_eq!(report.executable_regions_count, 2); // r-xp and rwxp
    assert_eq!(report.rwx_regions_count, 1);
    assert_eq!(report.security_alerts.len(), 1);
    assert!(report.security_alerts[0].contains("CRITICAL: Memory page"));
}

#[test]
fn test_live_self_proc_maps() {
    // Current process PID
    let pid = std::process::id();
    let report = parse_proc_maps(pid).expect("Failed to read self /proc/[pid]/maps");

    assert_eq!(report.pid, pid);
    assert!(report.total_mapped_bytes > 0);
    assert!(report.regions.len() > 0);
}
