use super::disasm::{disassemble_x86_64, DisassembledInstruction};
use crate::domain::{RevError, RevResult};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminatorType {
    UnconditionalBranch,
    ConditionalBranch,
    Call,
    Return,
    Interrupt,
    Fallthrough,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: usize,
    pub start_ip: u64,
    pub end_ip: u64,
    pub instructions: Vec<DisassembledInstruction>,
    pub terminator_type: TerminatorType,
    pub successors: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub entry_ip: u64,
    pub blocks: Vec<BasicBlock>,
    pub total_instructions: usize,
    pub cyclomatic_complexity: usize,
}

impl ControlFlowGraph {
    pub fn to_mermaid(&self) -> String {
        let mut out = String::from("graph TD\n");
        for block in &self.blocks {
            let label = format!("Block_{} [0x{:x}..0x{:x}]", block.id, block.start_ip, block.end_ip);
            let mut summary = String::new();
            for instr in block.instructions.iter().take(3) {
                summary.push_str(&format!("<br/>0x{:x}: {}", instr.ip, instr.op_str));
            }
            if block.instructions.len() > 3 {
                summary.push_str(&format!("<br/>... +{} more", block.instructions.len() - 3));
            }

            out.push_str(&format!("    B{}[\"{}{}\"]\n", block.id, label, summary));
        }

        // Add edges
        for block in &self.blocks {
            for succ_ip in &block.successors {
                if let Some(target) = self.blocks.iter().find(|b| b.start_ip == *succ_ip) {
                    let edge_label = match block.terminator_type {
                        TerminatorType::ConditionalBranch => "branch",
                        TerminatorType::UnconditionalBranch => "jump",
                        TerminatorType::Call => "call",
                        _ => "flow",
                    };
                    out.push_str(&format!("    B{} -->|{}| B{}\n", block.id, edge_label, target.id));
                } else {
                    out.push_str(&format!("    B{} -.->|external| Ext_0x{:x}[0x{:x}]\n", block.id, succ_ip, succ_ip));
                }
            }
        }

        out
    }

    pub fn to_ascii_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Entry IP: 0x{:x} | Total Blocks: {} | Total Instructions: {} | Cyclomatic Complexity: {}\n",
            self.entry_ip,
            self.blocks.len(),
            self.total_instructions,
            self.cyclomatic_complexity
        ));
        for block in &self.blocks {
            out.push_str(&format!(
                "  [Block {:02}] 0x{:08x}..0x{:08x} ({:>2} instrs) -> Terminator: {:?}, Successors: {:?}\n",
                block.id,
                block.start_ip,
                block.end_ip,
                block.instructions.len(),
                block.terminator_type,
                block.successors.iter().map(|s| format!("0x{:x}", s)).collect::<Vec<_>>()
            ));
        }
        out
    }
}

pub fn build_cfg_x86_64(bytes: &[u8], rip: u64, max_instructions: usize) -> RevResult<ControlFlowGraph> {
    if bytes.is_empty() {
        return Err(RevError::Disassembly("Empty byte buffer cannot form a CFG".into()));
    }

    let mut decoder = Decoder::with_ip(64, bytes, rip, DecoderOptions::NONE);
    let mut decoded: Vec<Instruction> = Vec::new();
    let mut instr = Instruction::default();

    while decoder.can_decode() && decoded.len() < max_instructions {
        decoder.decode_out(&mut instr);
        decoded.push(instr);
        if instr.flow_control() == FlowControl::Return {
            // Reached function end or bounded return
            break;
        }
    }

    if decoded.is_empty() {
        return Err(RevError::Disassembly("No valid instructions decoded for CFG".into()));
    }

    // Pass 1: Identify leaders (entrypoints of basic blocks)
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(rip); // Entry is leader

    for (i, instr) in decoded.iter().enumerate() {
        let next_ip = instr.next_ip();
        match instr.flow_control() {
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                let target = instr.near_branch_target();
                if target != 0 {
                    leaders.insert(target);
                }
                if i + 1 < decoded.len() {
                    leaders.insert(next_ip);
                }
            }
            FlowControl::Call => {
                if i + 1 < decoded.len() {
                    leaders.insert(next_ip);
                }
            }
            FlowControl::Return | FlowControl::Interrupt => {
                if i + 1 < decoded.len() {
                    leaders.insert(next_ip);
                }
            }
            _ => {}
        }
    }

    // Pass 2: Partition decoded instructions into contiguous blocks
    let mut block_map: BTreeMap<u64, Vec<Instruction>> = BTreeMap::new();
    let mut current_leader = rip;
    block_map.insert(current_leader, Vec::new());

    for instr in &decoded {
        let ip = instr.ip();
        if leaders.contains(&ip) && ip != current_leader {
            current_leader = ip;
            block_map.insert(current_leader, Vec::new());
        }
        if let Some(list) = block_map.get_mut(&current_leader) {
            list.push(*instr);
        }
    }

    // Pass 3: Convert into BasicBlock structures and calculate edges
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut edges_count = 0;

    for (block_id, (leader_ip, instrs)) in block_map.into_iter().enumerate() {
        if instrs.is_empty() {
            continue;
        }

        let start_ip = leader_ip;
        let last_instr = instrs.last().unwrap();
        let end_ip = last_instr.next_ip();

        let (terminator_type, successors) = match last_instr.flow_control() {
            FlowControl::ConditionalBranch => {
                let mut succs = Vec::new();
                let target = last_instr.near_branch_target();
                if target != 0 {
                    succs.push(target);
                }
                succs.push(last_instr.next_ip());
                (TerminatorType::ConditionalBranch, succs)
            }
            FlowControl::UnconditionalBranch => {
                let target = last_instr.near_branch_target();
                let succs = if target != 0 { vec![target] } else { Vec::new() };
                (TerminatorType::UnconditionalBranch, succs)
            }
            FlowControl::Call => {
                let target = last_instr.near_branch_target();
                let mut succs = Vec::new();
                if target != 0 {
                    succs.push(target);
                }
                succs.push(last_instr.next_ip());
                (TerminatorType::Call, succs)
            }
            FlowControl::Return => (TerminatorType::Return, Vec::new()),
            FlowControl::Interrupt => (TerminatorType::Interrupt, Vec::new()),
            _ => (TerminatorType::Fallthrough, vec![last_instr.next_ip()]),
        };

        edges_count += successors.len();

        // Convert instructions to formatted DisassembledInstruction
        let start_offset = (start_ip - rip) as usize;
        let end_offset = (end_ip - rip) as usize;
        let slice = if end_offset <= bytes.len() {
            &bytes[start_offset..end_offset]
        } else {
            &bytes[start_offset..]
        };

        let formatted = disassemble_x86_64(slice, start_ip, instrs.len()).unwrap_or_default();

        blocks.push(BasicBlock {
            id: block_id,
            start_ip,
            end_ip,
            instructions: formatted,
            terminator_type,
            successors,
        });
    }

    let node_count = blocks.len();
    // Cyclomatic Complexity M = E - N + 2P where P = 1 (single connected component)
    let cyclomatic_complexity = if node_count > 0 && edges_count >= node_count {
        edges_count - node_count + 2
    } else {
        1
    };

    Ok(ControlFlowGraph {
        entry_ip: rip,
        blocks,
        total_instructions: decoded.len(),
        cyclomatic_complexity,
    })
}
