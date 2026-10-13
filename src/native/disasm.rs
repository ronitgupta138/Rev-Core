use crate::domain::{RevError, RevResult};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembledInstruction {
    pub ip: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub op_str: String,
}

pub fn disassemble_x86_64(bytes: &[u8], rip: u64, max_instructions: usize) -> RevResult<Vec<DisassembledInstruction>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let mut decoder = Decoder::with_ip(64, bytes, rip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instructions = Vec::new();

    let mut instruction = iced_x86::Instruction::default();
    while decoder.can_decode() && instructions.len() < max_instructions {
        decoder.decode_out(&mut instruction);

        let mut output = String::new();
        formatter.format(&instruction, &mut output);

        let start_index = (instruction.ip() - rip) as usize;
        let instr_bytes = if start_index + instruction.len() <= bytes.len() {
            hex::encode(&bytes[start_index..start_index + instruction.len()])
        } else {
            String::new()
        };

        let mnemonic = format!("{:?}", instruction.mnemonic()).to_lowercase();

        instructions.push(DisassembledInstruction {
            ip: instruction.ip(),
            bytes: instr_bytes,
            mnemonic,
            op_str: output,
        });
    }

    if instructions.is_empty() && !bytes.is_empty() {
        return Err(RevError::Disassembly("Could not decode any valid instructions from buffer".into()));
    }

    Ok(instructions)
}
