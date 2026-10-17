use crate::domain::{RevError, RevResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TargetArch {
    #[default]
    X86_64,
    Arm64,
    Riscv64,
}

impl std::str::FromStr for TargetArch {
    type Err = RevError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "x86_64" | "x64" | "amd64" => Ok(TargetArch::X86_64),
            "arm64" | "aarch64" => Ok(TargetArch::Arm64),
            "riscv" | "riscv64" | "rv64" => Ok(TargetArch::Riscv64),
            other => Err(RevError::UnsupportedFormat(format!(
                "Unsupported architecture '{}'. Supported: x86_64, arm64, riscv64",
                other
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalInstruction {
    pub ip: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub op_str: String,
    pub arch: TargetArch,
}

pub fn decode_universal_slice(
    bytes: &[u8],
    base_ip: u64,
    arch: TargetArch,
    max_instructions: usize,
) -> RevResult<Vec<UniversalInstruction>> {
    match arch {
        TargetArch::X86_64 => {
            let instrs = super::disasm::disassemble_x86_64(bytes, base_ip, max_instructions)?;
            Ok(instrs
                .into_iter()
                .map(|i| UniversalInstruction {
                    ip: i.ip,
                    bytes: i.bytes,
                    mnemonic: i.mnemonic,
                    op_str: i.op_str,
                    arch: TargetArch::X86_64,
                })
                .collect())
        }
        TargetArch::Arm64 => decode_arm64_slice(bytes, base_ip, max_instructions),
        TargetArch::Riscv64 => decode_riscv64_slice(bytes, base_ip, max_instructions),
    }
}

fn decode_arm64_slice(
    bytes: &[u8],
    base_ip: u64,
    max_instructions: usize,
) -> RevResult<Vec<UniversalInstruction>> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset + 4 <= bytes.len() && instructions.len() < max_instructions {
        let chunk: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
        let word = u32::from_le_bytes(chunk);
        let ip = base_ip + offset as u64;
        let hex_bytes = hex::encode(chunk);

        let (mnemonic, op_str) = decode_arm64_word(word);

        instructions.push(UniversalInstruction {
            ip,
            bytes: hex_bytes,
            mnemonic,
            op_str,
            arch: TargetArch::Arm64,
        });

        offset += 4;
    }

    Ok(instructions)
}

fn decode_arm64_word(word: u32) -> (String, String) {
    if word == 0xd503201f {
        return ("nop".into(), "nop".into());
    }
    if word == 0xd65f03c0 {
        return ("ret".into(), "ret".into());
    }
    if (word & 0xff000000) == 0xd4000000 {
        let imm = (word >> 5) & 0xffff;
        return ("svc".into(), format!("svc #0x{:x}", imm));
    }
    if (word & 0xfc000000) == 0x14000000 {
        // B (unconditional branch)
        let imm26 = word & 0x03ffffff;
        let sign_extended = if (imm26 & 0x02000000) != 0 {
            (imm26 as i32) | !0x03ffffff
        } else {
            imm26 as i32
        };
        let offset = sign_extended * 4;
        return ("b".into(), format!("b #{:+}", offset));
    }
    if (word & 0xfc000000) == 0x94000000 {
        // BL (branch with link)
        let imm26 = word & 0x03ffffff;
        let sign_extended = if (imm26 & 0x02000000) != 0 {
            (imm26 as i32) | !0x03ffffff
        } else {
            imm26 as i32
        };
        let offset = sign_extended * 4;
        return ("bl".into(), format!("bl #{:+}", offset));
    }
    if (word & 0xff000000) == 0x54000000 {
        // B.cond
        let cond = word & 0xf;
        let cond_str = match cond {
            0 => "eq",
            1 => "ne",
            2 => "cs",
            3 => "cc",
            10 => "ge",
            11 => "lt",
            12 => "gt",
            13 => "le",
            _ => "cond",
        };
        return (format!("b.{cond_str}"), format!("b.{} <target>", cond_str));
    }

    // Generic AArch64 instruction fallback
    ("inst".into(), format!("word 0x{:08x}", word))
}

fn decode_riscv64_slice(
    bytes: &[u8],
    base_ip: u64,
    max_instructions: usize,
) -> RevResult<Vec<UniversalInstruction>> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset + 4 <= bytes.len() && instructions.len() < max_instructions {
        let chunk: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
        let word = u32::from_le_bytes(chunk);
        let ip = base_ip + offset as u64;
        let hex_bytes = hex::encode(chunk);

        let (mnemonic, op_str) = decode_riscv64_word(word);

        instructions.push(UniversalInstruction {
            ip,
            bytes: hex_bytes,
            mnemonic,
            op_str,
            arch: TargetArch::Riscv64,
        });

        offset += 4;
    }

    Ok(instructions)
}

fn decode_riscv64_word(word: u32) -> (String, String) {
    if word == 0x00000013 {
        return ("nop".into(), "nop".into());
    }
    if word == 0x00008067 {
        return ("ret".into(), "ret".into());
    }
    if word == 0x00000073 {
        return ("ecall".into(), "ecall".into());
    }
    if word == 0x00100073 {
        return ("ebreak".into(), "ebreak".into());
    }

    let opcode = word & 0x7f;
    match opcode {
        0x37 => ("lui".into(), "lui <reg>, <imm>".into()),
        0x17 => ("auipc".into(), "auipc <reg>, <imm>".into()),
        0x6f => ("jal".into(), "jal <reg>, <imm>".into()),
        0x67 => ("jalr".into(), "jalr <reg>, <reg>, <imm>".into()),
        0x63 => ("branch".into(), "b.cond <reg>, <reg>, <imm>".into()),
        0x03 => ("load".into(), "load <reg>, offset(<reg>)".into()),
        0x23 => ("store".into(), "store <reg>, offset(<reg>)".into()),
        _ => ("inst".into(), format!("word 0x{:08x}", word)),
    }
}
