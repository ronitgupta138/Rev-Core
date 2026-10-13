# Contributing to `rev-core`

Thank you for your interest in contributing to `rev-core`! We welcome contributions to binary diagnostics, architecture decoders, security mitigation heuristics, Electron AST scanners, and Model Context Protocol (MCP) tool extensions.

---

## 🛠️ Development Setup

### Prerequisites
- **Rust Toolchain:** 1.80+ (stable)
- **Cargo:** Bundled with Rust

### Build & Test
```bash
# Clone the repository
git clone https://github.com/ronitgupta138/rev-core.git
cd rev-core

# Run the complete test suite
cargo test

# Check code formatting and lints
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
```

---

## 📐 Architecture & Engineering Invariants

1. **Anti-Hallucination Evidence Guarantee:** Every analytical conclusion must be grounded in an immutable `Evidence` record with a deterministic SHA-256 payload digest. Never emit unsubstantiated claims to LLM contexts.
2. **Zero-Crash Memory Safety:** Parsers must handle truncated, adversarial, or malformed binaries gracefully using `RevResult<T>` without panicking.
3. **Zero Runtime Dependencies:** The core binary inspector, ASAR unpacker, and disassembler must remain 100% self-contained in native Rust without requiring external Node.js, Python, or Java runtimes.

---

## 🚀 Pull Request Checklist

- [ ] All unit and integration tests pass (`cargo test`).
- [ ] Zero compiler or clippy warnings (`cargo clippy --all-targets -- -D warnings`).
- [ ] Added test fixtures in `tests/` for any new binary formats or instruction patterns.
- [ ] Clean commit messages following Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- [ ] Maintained WCAG AA contrast and OCD-level formatting alignment.
