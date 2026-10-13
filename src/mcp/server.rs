use super::protocol::*;
use crate::app::asar::AsarArchive;
use crate::domain::{compute_sha256, Evidence, EvidenceLedger};
use crate::native::{analyze_elf, analyze_macho, analyze_pe, disassemble_x86_64};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

pub struct McpServer {
    ledger: Arc<Mutex<EvidenceLedger>>,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            ledger: Arc::new(Mutex::new(EvidenceLedger::new())),
        }
    }

    pub fn get_tools() -> Vec<McpTool> {
        vec![
            McpTool {
                name: "inspect_binary".into(),
                description: "Inspect ELF or PE binary headers, architecture, entrypoint, sections, and dependencies.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute or relative path to the binary file"
                        }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "inspect_mitigations".into(),
                description: "Scan binary security mitigations: NX/DEP, PIE, Full/Partial RELRO, Stack Canaries, and ASLR.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the binary file to analyze"
                        }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "disassemble_slice".into(),
                description: "Disassemble raw x86_64 machine code instructions at a given file offset or byte buffer.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to binary file"
                        },
                        "offset": {
                            "type": "integer",
                            "description": "File offset in bytes (defaults to 0)",
                            "default": 0
                        },
                        "length": {
                            "type": "integer",
                            "description": "Number of bytes to decode (defaults to 64)",
                            "default": 64
                        },
                        "max_instructions": {
                            "type": "integer",
                            "description": "Maximum instructions to decode (defaults to 20)",
                            "default": 20
                        }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "unpack_asar".into(),
                description: "Unpack an Electron ASAR package archive into a destination directory without external dependencies.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "asar_path": {
                            "type": "string",
                            "description": "Path to the .asar archive file"
                        },
                        "dest_dir": {
                            "type": "string",
                            "description": "Output directory where files will be extracted"
                        }
                    },
                    "required": ["asar_path", "dest_dir"]
                }),
            },
            McpTool {
                name: "generate_cfg".into(),
                description: "Reconstruct the Control Flow Graph (CFG), basic blocks, and branch targets from machine code, returning cyclomatic complexity and Mermaid diagram.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to binary file"
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Byte offset where function or code begins",
                            "default": 0
                        },
                        "max_instructions": {
                            "type": "integer",
                            "description": "Maximum instructions to trace (defaults to 100)",
                            "default": 100
                        }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "analyze_entropy".into(),
                description: "Compute Shannon entropy across file bytes to detect packed, compressed, or encrypted payloads.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to target file"
                        }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "scan_crypto".into(),
                description: "Scan target file for known cryptographic initialization constants (AES S-Box, ChaCha20, SHA, MD5).".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to target file"
                        }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "scan_electron".into(),
                description: "Scan an extracted Electron application directory for IPC communication channels, preload bridge endpoints, and security posture risks.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "dir": {
                            "type": "string",
                            "description": "Path to directory containing Electron scripts"
                        }
                    },
                    "required": ["dir"]
                }),
            },
            McpTool {
                name: "inspect_wasm".into(),
                description: "Inspect WebAssembly (WASM) binary structure, memory allocations, function imports, and exported APIs.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to .wasm file"
                        }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "decompile_symbol".into(),
                description: "Decompile a function symbol into C pseudocode using local headless decompiler bridges (rizin, radare2, or ghidra).".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to binary file"
                        },
                        "symbol": {
                            "type": "string",
                            "description": "Function symbol name (e.g. main, _start) or hex address"
                        },
                        "timeout_secs": {
                            "type": "integer",
                            "description": "Maximum execution time in seconds",
                            "default": 30
                        }
                    },
                    "required": ["path", "symbol"]
                }),
            },
            McpTool {
                name: "inspect_process_maps".into(),
                description: "Inspect live process memory maps (/proc/[pid]/maps) to detect memory layout, mapped libraries, and dangerous RWX pages.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "pid": {
                            "type": "integer",
                            "description": "Target Process ID (PID)"
                        }
                    },
                    "required": ["pid"]
                }),
            },
            McpTool {
                name: "get_evidence_ledger".into(),
                description: "Retrieve all verified cryptographic Evidence records and open residual unknowns for this session.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
        ]
    }

    pub async fn run_stdio(&self) -> anyhow::Result<()> {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin).lines();

        eprintln!("[rev-core] MCP server initialized over stdio transport.");

        while let Some(line) = reader.next_line().await? {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let request: Result<JsonRpcRequest, _> = serde_json::from_str(line);
            match request {
                Ok(req) => {
                    let id = req.id.clone();
                    let response = self.handle_request(req).await;
                    if let Some(resp) = response {
                        let resp_str = serde_json::to_string(&resp)?;
                        println!("{resp_str}");
                        std::io::stdout().flush()?;
                    } else if let Some(id_val) = id {
                        // In case of unhandled method that expects response
                        let err_resp = JsonRpcResponse::error(id_val, -32601, "Method not found");
                        println!("{}", serde_json::to_string(&err_resp)?);
                        std::io::stdout().flush()?;
                    }
                }
                Err(e) => {
                    let err_resp = JsonRpcResponse::error(Value::Null, -32700, format!("Parse error: {e}"));
                    println!("{}", serde_json::to_string(&err_resp)?);
                    std::io::stdout().flush()?;
                }
            }
        }

        Ok(())
    }

    async fn handle_request(&self, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let id = req.id?;

        match req.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "rev-core",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                });
                Some(JsonRpcResponse::success(id, result))
            }
            "notifications/initialized" => None,
            "ping" => Some(JsonRpcResponse::success(id, json!({}))),
            "tools/list" => {
                let tools = Self::get_tools();
                Some(JsonRpcResponse::success(id, json!({ "tools": tools })))
            }
            "tools/call" => {
                let params = req.params.unwrap_or(json!({}));
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));

                let result = self.execute_tool(tool_name, args).await;
                Some(JsonRpcResponse::success(id, serde_json::to_value(result).unwrap_or(json!({}))))
            }
            _ => Some(JsonRpcResponse::error(id, -32601, format!("Unknown method: {}", req.method))),
        }
    }

    async fn execute_tool(&self, name: &str, args: Value) -> McpToolCallResult {
        match name {
            "inspect_binary" => {
                let path_str = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'path'"),
                };

                let path = Path::new(path_str);
                let bytes = match fs::read(path) {
                    Ok(b) => b,
                    Err(e) => return error_result(format!("Failed to read file {path_str}: {e}")),
                };

                let digest = compute_sha256(&bytes);

                // Try ELF first
                if let Ok(elf) = analyze_elf(&bytes) {
                    let evidence = Evidence::new(path_str, &digest, "inspect_binary.elf", &elf, Vec::new());
                    if let Ok(mut l) = self.ledger.lock() {
                        l.record(&evidence);
                    }
                    return json_result(&evidence);
                }

                // Try PE
                if let Ok(pe) = analyze_pe(&bytes) {
                    let evidence = Evidence::new(path_str, &digest, "inspect_binary.pe", &pe, Vec::new());
                    if let Ok(mut l) = self.ledger.lock() {
                        l.record(&evidence);
                    }
                    return json_result(&evidence);
                }

                // Try Mach-O
                if let Ok(macho) = analyze_macho(&bytes) {
                    let evidence = Evidence::new(path_str, &digest, "inspect_binary.macho", &macho, Vec::new());
                    if let Ok(mut l) = self.ledger.lock() {
                        l.record(&evidence);
                    }
                    return json_result(&evidence);
                }

                error_result(format!("File at {path_str} is neither a valid ELF, PE, nor Mach-O binary"))
            }

            "inspect_mitigations" => {
                let path_str = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'path'"),
                };

                let bytes = match fs::read(path_str) {
                    Ok(b) => b,
                    Err(e) => return error_result(format!("Failed to read file: {e}")),
                };

                let digest = compute_sha256(&bytes);

                if let Ok(elf) = analyze_elf(&bytes) {
                    let evidence = Evidence::new(path_str, &digest, "inspect_mitigations.elf", &elf.mitigations, Vec::new());
                    if let Ok(mut l) = self.ledger.lock() {
                        l.record(&evidence);
                    }
                    return json_result(&evidence);
                }

                if let Ok(pe) = analyze_pe(&bytes) {
                    let evidence = Evidence::new(path_str, &digest, "inspect_mitigations.pe", &pe.mitigations, Vec::new());
                    if let Ok(mut l) = self.ledger.lock() {
                        l.record(&evidence);
                    }
                    return json_result(&evidence);
                }

                if let Ok(macho) = analyze_macho(&bytes) {
                    let evidence = Evidence::new(path_str, &digest, "inspect_mitigations.macho", &macho.architectures, Vec::new());
                    if let Ok(mut l) = self.ledger.lock() {
                        l.record(&evidence);
                    }
                    return json_result(&evidence);
                }

                error_result("Unable to extract security mitigations: unsupported binary format")
            }

            "disassemble_slice" => {
                let path_str = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'path'"),
                };

                let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let length = args.get("length").and_then(|v| v.as_u64()).unwrap_or(64) as usize;
                let max_instr = args.get("max_instructions").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

                let bytes = match fs::read(path_str) {
                    Ok(b) => b,
                    Err(e) => return error_result(format!("Failed to read file: {e}")),
                };

                if offset >= bytes.len() {
                    return error_result(format!("Offset {offset} is beyond file length ({})", bytes.len()));
                }

                let end = (offset + length).min(bytes.len());
                let slice = &bytes[offset..end];

                match disassemble_x86_64(slice, offset as u64, max_instr) {
                    Ok(instructions) => {
                        let digest = compute_sha256(slice);
                        let evidence = Evidence::new(path_str, &digest, "disassemble_slice.x86_64", &instructions, Vec::new());
                        if let Ok(mut l) = self.ledger.lock() {
                            l.record(&evidence);
                        }
                        json_result(&evidence)
                    }
                    Err(e) => error_result(format!("Disassembly error: {e}")),
                }
            }

            "generate_cfg" => {
                let path_str = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'path'"),
                };
                let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let max_instr = args.get("max_instructions").and_then(|v| v.as_u64()).unwrap_or(100) as usize;

                let bytes = match fs::read(path_str) {
                    Ok(b) => b,
                    Err(e) => return error_result(format!("Failed to read file: {e}")),
                };

                if offset >= bytes.len() {
                    return error_result(format!("Offset {offset} is beyond file length ({})", bytes.len()));
                }

                let slice = &bytes[offset..];
                match crate::native::build_cfg_x86_64(slice, offset as u64, max_instr) {
                    Ok(cfg) => {
                        let digest = compute_sha256(slice);
                        let mermaid = cfg.to_mermaid();
                        let result_payload = json!({
                            "entry_ip": format!("0x{:x}", cfg.entry_ip),
                            "total_blocks": cfg.blocks.len(),
                            "total_instructions": cfg.total_instructions,
                            "cyclomatic_complexity": cfg.cyclomatic_complexity,
                            "mermaid_diagram": mermaid,
                            "blocks": cfg.blocks,
                        });
                        let evidence = Evidence::new(path_str, &digest, "generate_cfg.x86_64", &result_payload, Vec::new());
                        if let Ok(mut l) = self.ledger.lock() {
                            l.record(&evidence);
                        }
                        json_result(&evidence)
                    }
                    Err(e) => error_result(format!("CFG generation error: {e}")),
                }
            }

            "unpack_asar" => {
                let asar_path = match args.get("asar_path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'asar_path'"),
                };
                let dest_dir = match args.get("dest_dir").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'dest_dir'"),
                };

                match AsarArchive::open(asar_path) {
                    Ok(archive) => match archive.extract_all(dest_dir) {
                        Ok(extracted) => {
                            let result_data = json!({
                                "asar_path": asar_path,
                                "dest_dir": dest_dir,
                                "files_extracted": extracted,
                                "total_files": archive.metadata.total_files,
                                "total_dirs": archive.metadata.total_dirs,
                                "total_size_bytes": archive.metadata.total_size,
                            });
                            json_result(&result_data)
                        }
                        Err(e) => error_result(format!("Failed to extract ASAR contents: {e}")),
                    },
                    Err(e) => error_result(format!("Failed to parse ASAR archive: {e}")),
                }
            }

            "analyze_entropy" => {
                let path_str = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'path'"),
                };
                let bytes = match fs::read(path_str) {
                    Ok(b) => b,
                    Err(e) => return error_result(format!("Failed to read file: {e}")),
                };

                let digest = compute_sha256(&bytes);
                let report = crate::analysis::analyze_entropy(&bytes);
                let evidence = Evidence::new(path_str, &digest, "analyze_entropy", &report, Vec::new());
                if let Ok(mut l) = self.ledger.lock() {
                    l.record(&evidence);
                }
                json_result(&evidence)
            }

            "scan_crypto" => {
                let path_str = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'path'"),
                };
                let bytes = match fs::read(path_str) {
                    Ok(b) => b,
                    Err(e) => return error_result(format!("Failed to read file: {e}")),
                };

                let digest = compute_sha256(&bytes);
                let findings = crate::analysis::scan_crypto_constants(&bytes);
                let evidence = Evidence::new(path_str, &digest, "scan_crypto", &findings, Vec::new());
                if let Ok(mut l) = self.ledger.lock() {
                    l.record(&evidence);
                }
                json_result(&evidence)
            }

            "scan_electron" => {
                let dir_str = match args.get("dir").and_then(|v| v.as_str()) {
                    Some(d) => d,
                    None => return error_result("Missing required argument: 'dir'"),
                };

                match crate::app::scan_electron_directory(dir_str) {
                    Ok(report) => {
                        let digest = compute_sha256(dir_str.as_bytes());
                        let evidence = Evidence::new(dir_str, &digest, "scan_electron", &report, Vec::new());
                        if let Ok(mut l) = self.ledger.lock() {
                            l.record(&evidence);
                        }
                        json_result(&evidence)
                    }
                    Err(e) => error_result(format!("Failed to scan Electron directory: {e}")),
                }
            }

            "inspect_wasm" => {
                let path_str = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'path'"),
                };
                let bytes = match fs::read(path_str) {
                    Ok(b) => b,
                    Err(e) => return error_result(format!("Failed to read file: {e}")),
                };

                match crate::wasm::analyze_wasm(&bytes) {
                    Ok(report) => {
                        let digest = compute_sha256(&bytes);
                        let evidence = Evidence::new(path_str, &digest, "inspect_wasm", &report, Vec::new());
                        if let Ok(mut l) = self.ledger.lock() {
                            l.record(&evidence);
                        }
                        json_result(&evidence)
                    }
                    Err(e) => error_result(format!("Failed to parse WASM module: {e}")),
                }
            }

            "decompile_symbol" => {
                let path_str = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return error_result("Missing required argument: 'path'"),
                };
                let symbol = match args.get("symbol").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => return error_result("Missing required argument: 'symbol'"),
                };
                let timeout_secs = args.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(30);

                match crate::bridge::DecompilerBridge::decompile_symbol(path_str, symbol, timeout_secs).await {
                    Ok(func) => {
                        let digest = compute_sha256(path_str.as_bytes());
                        let evidence = Evidence::new(path_str, &digest, "decompile_symbol", &func, Vec::new());
                        if let Ok(mut l) = self.ledger.lock() {
                            l.record(&evidence);
                        }
                        json_result(&evidence)
                    }
                    Err(e) => error_result(format!("Decompilation failed: {e}")),
                }
            }

            "inspect_process_maps" => {
                let pid = match args.get("pid").and_then(|v| v.as_u64()) {
                    Some(p) => p as u32,
                    None => return error_result("Missing required argument: 'pid'"),
                };

                match crate::process::parse_proc_maps(pid) {
                    Ok(report) => {
                        let digest = compute_sha256(format!("pid_{pid}_{}", report.total_mapped_bytes).as_bytes());
                        let evidence = Evidence::new(format!("proc_{pid}"), &digest, "inspect_process_maps", &report, Vec::new());
                        if let Ok(mut l) = self.ledger.lock() {
                            l.record(&evidence);
                        }
                        json_result(&evidence)
                    }
                    Err(e) => error_result(format!("Failed to inspect process {pid} memory maps: {e}")),
                }
            }

            "get_evidence_ledger" => {
                if let Ok(ledger) = self.ledger.lock() {
                    let value = serde_json::to_value(&*ledger).unwrap_or(json!({}));
                    json_result(&value)
                } else {
                    error_result("Failed to acquire ledger lock")
                }
            }

            _ => error_result(format!("Unknown tool: {name}")),
        }
    }
}

fn json_result<T: serde::Serialize>(data: &T) -> McpToolCallResult {
    let text = serde_json::to_string_pretty(data).unwrap_or_default();
    McpToolCallResult {
        content: vec![McpContent::Text { text }],
        is_error: false,
    }
}

fn error_result(msg: impl Into<String>) -> McpToolCallResult {
    McpToolCallResult {
        content: vec![McpContent::Text { text: msg.into() }],
        is_error: true,
    }
}
