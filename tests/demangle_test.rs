use rev_core::native::{demangle_symbol, is_mangled};

#[test]
fn test_demangle_rust_symbols() {
    let legacy = "_ZN4core3fmt5write17h0123456789abcdefE";
    let demangled = demangle_symbol(legacy);
    assert!(demangled.contains("core::fmt::write"));
    assert!(is_mangled(legacy));
}

#[test]
fn test_demangle_cpp_symbols() {
    let itanium = "_Z3fooi";
    let demangled = demangle_symbol(itanium);
    assert_eq!(demangled, "foo(int)");
    assert!(is_mangled(itanium));
}

#[test]
fn test_demangle_unmangled_passthrough() {
    assert_eq!(demangle_symbol("main"), "main");
    assert!(!is_mangled("main"));
    assert_eq!(demangle_symbol("malloc"), "malloc");
    assert!(!is_mangled("malloc"));
}
