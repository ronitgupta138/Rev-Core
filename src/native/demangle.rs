//! High-Performance Symbol Demangling Engine for Rust and C++ ABI symbols.

use cpp_demangle::Symbol as CppSymbol;
use rustc_demangle::demangle as rust_demangle;

/// Demangles a symbol name if it originates from Rust (legacy or v0) or C++ (Itanium).
/// If the symbol is not mangled or cannot be parsed, the original string is returned.
pub fn demangle_symbol(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // 1. Check for Rust mangling (_ZN... or _R...)
    if trimmed.starts_with("_ZN") || trimmed.starts_with("_R") || trimmed.contains("::") {
        let rust_demangled = format!("{:#}", rust_demangle(trimmed));
        if rust_demangled != trimmed {
            return rust_demangled;
        }
    }

    // 2. Check for C++ Itanium mangling (_Z...)
    if trimmed.starts_with("_Z") {
        if let Ok(sym) = CppSymbol::new(trimmed.as_bytes()) {
            let demangled = sym.to_string();
            if demangled != trimmed {
                return demangled;
            }
        }
    }

    // 3. Fallback to rustc_demangle for arbitrary symbols
    let rust_demangled = format!("{}", rust_demangle(trimmed));
    if rust_demangled != trimmed {
        return rust_demangled;
    }

    trimmed.to_string()
}

/// Returns true if a symbol appears to be mangled by Rust or C++ compilers.
pub fn is_mangled(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.starts_with("_ZN") || trimmed.starts_with("_R") || trimmed.starts_with("_Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_legacy_demangle() {
        let mangled = "_ZN4core3fmt5write17h0123456789abcdefE";
        let demangled = demangle_symbol(mangled);
        assert!(demangled.contains("core::fmt::write"));
    }

    #[test]
    fn test_cpp_itanium_demangle() {
        let mangled = "_Z1fv";
        let demangled = demangle_symbol(mangled);
        assert_eq!(demangled, "f()");
    }

    #[test]
    fn test_unmangled_passthrough() {
        let plain = "main";
        assert_eq!(demangle_symbol(plain), "main");
        assert!(!is_mangled(plain));
    }
}
