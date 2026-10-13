<div align="center">

```text
██████╗ ███████╗██╗   ██╗     ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██║   ██║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║   ██║    ██║     ██║   ██║██████╔╝█████╗  
██╔══██╗██╔══╝  ╚██╗ ██╔╝    ██║     ██║   ██║██╔══██╗██╔══╝  
██║  ██║███████╗ ╚████╔╝     ╚██████╗╚██████╔╝██║  ██║███████╗
╚═╝  ╚═╝╚══════╝  ╚═══╝       ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
```

### **Autonomous Reverse Engineering Engine & Model Context Protocol (MCP) Server in Rust**

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-0891b2?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/badge/crates.io-v0.1.0-0891b2?style=flat-square&logo=rust&logoColor=white)](https://crates.io/crates/rev-core)
[![License](https://img.shields.io/badge/License-MIT-0891b2?style=flat-square)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2024--11--05-10b981?style=flat-square)](https://modelcontextprotocol.io/)
[![CI](https://img.shields.io/badge/CI-Passing-10b981?style=flat-square)](https://github.com/ronitgupta138/rev-core/actions)
[![Tests](https://img.shields.io/badge/Tests-6%2F6%20Passed-10b981?style=flat-square)](https://github.com/ronitgupta138/rev-core)

</div>

---

## 📌 Overview

**`rev-core`** is an ultra-fast, zero-overhead reverse engineering engine and stdio Model Context Protocol (MCP) server written in **Systems Rust**. It provides agents (Claude Code, Hermes Agent, Cursor, Codex) and systems engineers with instant binary inspection, security mitigation scanning, in-process machine code disassembly, and desktop application archive unpacking.

Unlike general-purpose decompiler wrappers that dump unchecked output into LLM context windows, `rev-core` implements an **Evidence Ledger** with deterministic SHA-256 provenance tracking and explicit **Residual Unknowns**, guaranteeing factually grounded conclusions.

---

## 🏗️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        AGENT & OPERATOR CLIENTS                        │
│   Claude Code  ·  Hermes Agent  ·  Cursor  ·  Codex  ·  CLI Terminal   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ stdio / JSON-RPC 2.0
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   MODEL CONTEXT PROTOCOL (MCP) SERVER                  │
│  - inspect_binary         - inspect_mitigations    - disassemble_slice │
│  - unpack_asar            - get_evidence_ledger    - tokio stdio loop  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                    EVIDENCE & INTEGRITY LEDGER                         │
│  - Deterministic SHA-256 hashing (RFC 8785 canonical data payloads)    │
│  - Residual Unknown Registry (tracks obfuscated targets & gaps)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────────┐ ┌───────────────────┐ ┌───────────────────────┐
│  NATIVE BINARY ENGINE │ │ APPLICATION ENGINE│ │  DISASSEMBLY ENGINE   │
│ - ELF / PE (goblin)   │ │ - Chromium Pickle │ │ - iced-x86 decoder    │
│ - NX, PIE, RELRO      │ │ - ASAR unpacker   │ │ - Byte-slice offsets  │
│ - Dynamic dependencies│ │ - In-memory tree  │ │ - Intel syntax output │
└───────────────────────┘ └───────────────────┘ └───────────────────────┘
```

---

## ⚡ Core Capabilities

1. **Zero-Copy Native Binary Analysis:**
   - **ELF Inspection:** Headers, class (32/64-bit), endianness, machine architecture, segment/section tables, and `DT_NEEDED` library dependencies.
   - **PE Inspection:** Machine architecture, entrypoint, section count, Windows subsystem, and imported libraries.
2. **Automated Security Mitigation Scanner:**
   - Detects **NX / DEP** (`PT_GNU_STACK` executable bit verification).
   - Detects **PIE** (Position Independent Executable `ET_DYN` vs `ET_EXEC`).
   - Detects **RELRO** (`PT_GNU_RELRO` + `DT_BIND_NOW` / `DF_1_NOW` distinguishing Full vs Partial vs No RELRO).
   - Detects **Stack Canaries** (`__stack_chk_fail` symbol probe).
   - Detects **Fortify Source** (`_chk` symbol probe).
   - Detects Windows **ASLR**, **DEP**, **CFG**, and **SEH**.
3. **In-Process Instruction Disassembly:**
   - High-throughput x86_64 machine code decoder via `iced-x86`.
   - Generates exact byte offsets, hexadecimal opcode representations, and Intel syntax assembly.
4. **Pure-Rust ASAR Unpacker:**
   - Parses Chromium Pickle headers and JSON directory trees without Node.js or `npm` runtime dependencies.
   - Unpacks Electron desktop apps (Discord, Slack, VS Code, Notion) directly to disk.
5. **Model Context Protocol (MCP) Native Support:**
   - Full stdio transport integration conforming to protocol version `2024-11-05`.
   - Plugs directly into LLM agent workstreams with zero configuration.

---

## 🚀 Installation & CLI Usage

### Install via Cargo
```bash
cargo install rev-core
```

### Inspect a Compiled Binary
```bash
rev-core inspect /bin/ls
```
*Outputs aligned diagnostic tables with architecture, entrypoints, and full security mitigations.*

### Scan Security Mitigations Only
```bash
rev-core mitigations /bin/ls
```

### Disassemble Instructions at Offset
```bash
rev-core disasm /bin/ls --offset 0x6d30 --count 10
```

### Unpack an Electron Desktop Application
```bash
# List files inside an ASAR archive
rev-core asar list app.asar

# Extract all contents to a directory
rev-core asar unpack app.asar -o ./unpacked_app
```

---

## 🔌 Model Context Protocol (MCP) Integration

To use `rev-core` inside **Claude Code**, **Hermes Agent**, or **Cursor**, add the following configuration to your `mcpServers` settings:

```json
{
  "mcpServers": {
    "rev-core": {
      "command": "rev-core",
      "args": ["mcp"]
    }
  }
}
```

### Registered Tools
* `inspect_binary(path: string)` — Return ELF/PE architecture, segments, sections, and dependencies.
* `inspect_mitigations(path: string)` — Return binary protection status (NX, PIE, RELRO, Canaries, ASLR).
* `disassemble_slice(path: string, offset: number, count: number)` — Return disassembled instructions with hex opcodes.
* `unpack_asar(asar_path: string, dest_dir: string)` — Extract Electron application archive.
* `get_evidence_ledger()` — Retrieve session evidence records and open residual unknowns.

---

## 🛡️ Anti-Hallucination Evidence Ledger

When reversing binaries with AI agents, models often hallucinate unreachable code or speculate about unseen functions. `rev-core` forces agents to reference verifiable **Evidence**:

```rust
pub struct Evidence<T> {
    pub id: String,            // Deterministic SHA-256 hash
    pub target_digest: String, // SHA-256 of the binary file
    pub target_path: String,
    pub tool: String,          // Engine that verified this fact
    pub timestamp: String,
    pub data: T,
    pub unknowns: Vec<String>, // Open questions / uncertainties
}
```

If an indirect jump or obfuscated pointer cannot be proven statically, `rev-core` registers a **Residual Unknown**. Agents are instructed not to conclude their analysis until all unknowns are resolved with evidence.

---

## 🧪 Verification & Testing

Run the automated test suite:

```bash
cargo test
```

Test coverage includes:
- Live ELF parsing and mitigation validation against Linux system binaries (`tests/elf_test.rs`).
- Byte-accurate x86_64 disassembly verification (`tests/disasm_test.rs`).
- Synthetic Chromium Pickle & ASAR archive extraction roundtrip (`tests/asar_test.rs`).
- Deterministic cryptographic evidence hashing and ledger lifecycle (`tests/evidence_test.rs`).

---

## 📜 License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 Ronit Gupta.
