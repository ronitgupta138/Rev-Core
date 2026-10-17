//! Embedded Assembly-to-C Pseudocode Heuristic Lifter.
//! Converts recovered BasicBlocks and ControlFlowGraphs into readable high-level C-like pseudocode.

use crate::native::cfg::{BasicBlock, ControlFlowGraph, TerminatorType};
use crate::native::demangle::demangle_symbol;
use std::collections::HashMap;

/// Emits human-readable C-like pseudocode from a reconstructed ControlFlowGraph.
pub fn lift_cfg_to_pseudocode(cfg: &ControlFlowGraph, function_name: Option<&str>) -> String {
    let fn_name = function_name
        .map(demangle_symbol)
        .unwrap_or_else(|| format!("sub_{:x}", cfg.entry_ip));

    let mut out = String::new();
    out.push_str(&format!("// Decompiled from entry 0x{:x} (Cyclomatic Complexity: {})\n", cfg.entry_ip, cfg.cyclomatic_complexity));
    out.push_str(&format!("int64_t {}(int64_t a0, int64_t a1, int64_t a2) {{\n", fn_name));

    // Map block start_ip to block id
    let mut ip_to_id: HashMap<u64, usize> = HashMap::new();
    for block in &cfg.blocks {
        ip_to_id.insert(block.start_ip, block.id);
    }

    for (idx, block) in cfg.blocks.iter().enumerate() {
        if idx > 0 {
            out.push_str(&format!("\nloc_{:x}:\n", block.start_ip));
        }

        lift_block_instructions(block, &mut out);

        match block.terminator_type {
            TerminatorType::Return => {
                out.push_str("    return rax;\n");
            }
            TerminatorType::ConditionalBranch => {
                if let Some(target) = block.successors.first() {
                    let target_name = ip_to_id
                        .get(target)
                        .map(|id| format!("loc_{:x} /* block {} */", target, id))
                        .unwrap_or_else(|| format!("loc_{:x}", target));
                    out.push_str(&format!("    if (cond) goto {};\n", target_name));
                }
                if let Some(fallthrough) = block.successors.get(1) {
                    out.push_str(&format!("    goto loc_{:x};\n", fallthrough));
                }
            }
            TerminatorType::UnconditionalBranch => {
                if let Some(target) = block.successors.first() {
                    out.push_str(&format!("    goto loc_{:x};\n", target));
                }
            }
            TerminatorType::Call => {
                if let Some(succ) = block.successors.first() {
                    out.push_str(&format!("    // Call target: 0x{:x}\n", succ));
                }
            }
            TerminatorType::Fallthrough => {}
            _ => {}
        }
    }

    out.push_str("}\n");
    out
}

fn lift_block_instructions(block: &BasicBlock, out: &mut String) {
    for instr in &block.instructions {
        let op = instr.op_str.to_lowercase();
        let parts: Vec<&str> = op.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let mnemonic = parts[0];
        let operands = parts[1..].join(" ");

        match mnemonic {
            "push" => {
                if operands.contains("rbp") {
                    out.push_str("    // Frame setup\n");
                } else {
                    out.push_str(&format!("    stack_push({});\n", operands));
                }
            }
            "pop" => {
                if operands.contains("rbp") {
                    out.push_str("    // Frame teardown\n");
                } else {
                    out.push_str(&format!("    {} = stack_pop();\n", operands));
                }
            }
            "mov" | "movabs" | "movsx" | "movzx" => {
                let op_split: Vec<&str> = operands.split(',').collect();
                if op_split.len() == 2 {
                    let dst = op_split[0].trim();
                    let src = op_split[1].trim();
                    if dst != "rbp" && src != "rsp" {
                        out.push_str(&format!("    {} = {};\n", dst, src));
                    }
                }
            }
            "add" => {
                let op_split: Vec<&str> = operands.split(',').collect();
                if op_split.len() == 2 {
                    out.push_str(&format!("    {} += {};\n", op_split[0].trim(), op_split[1].trim()));
                }
            }
            "sub" => {
                let op_split: Vec<&str> = operands.split(',').collect();
                if op_split.len() == 2 {
                    let dst = op_split[0].trim();
                    let src = op_split[1].trim();
                    if dst != "rsp" {
                        out.push_str(&format!("    {} -= {};\n", dst, src));
                    }
                }
            }
            "xor" => {
                let op_split: Vec<&str> = operands.split(',').collect();
                if op_split.len() == 2 && op_split[0].trim() == op_split[1].trim() {
                    out.push_str(&format!("    {} = 0;\n", op_split[0].trim()));
                } else if op_split.len() == 2 {
                    out.push_str(&format!("    {} ^= {};\n", op_split[0].trim(), op_split[1].trim()));
                }
            }
            "cmp" | "test" => {
                let op_split: Vec<&str> = operands.split(',').collect();
                if op_split.len() == 2 {
                    out.push_str(&format!("    cond = ({} == {});\n", op_split[0].trim(), op_split[1].trim()));
                }
            }
            "call" => {
                let target = operands.trim();
                let demangled = demangle_symbol(target);
                out.push_str(&format!("    rax = {}(rdi, rsi, rdx);\n", demangled));
            }
            "nop" => {}
            "ret" => {}
            _ => {
                if !mnemonic.starts_with('j') {
                    out.push_str(&format!("    /* 0x{:x} */ asm(\"{}\");\n", instr.ip, instr.op_str));
                }
            }
        }
    }
}
