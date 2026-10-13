use crate::domain::{RevError, RevResult};
use goblin::elf::{header, program_header, Elf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelroStatus {
    Full,
    Partial,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfMitigations {
    pub nx: bool,
    pub pie: bool,
    pub relro: RelroStatus,
    pub stack_canary: bool,
    pub fortify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSummary {
    pub name: String,
    pub sh_type: u32,
    pub addr: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolSummary {
    pub name: String,
    pub addr: u64,
    pub is_import: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfReport {
    pub class: String,
    pub endianness: String,
    pub machine: String,
    pub entrypoint: u64,
    pub segments_count: usize,
    pub sections_count: usize,
    pub dependencies: Vec<String>,
    pub mitigations: ElfMitigations,
    pub sections: Vec<SectionSummary>,
    pub dynamic_symbols: Vec<SymbolSummary>,
}

pub fn analyze_elf(buffer: &[u8]) -> RevResult<ElfReport> {
    let elf = Elf::parse(buffer).map_err(|e| RevError::Parse(format!("Failed to parse ELF: {e}")))?;

    let class = if elf.is_64 { "ELF64" } else { "ELF32" }.to_string();
    let endianness = if elf.little_endian { "Little Endian" } else { "Big Endian" }.to_string();
    let machine = header::machine_to_str(elf.header.e_machine).to_string();
    let entrypoint = elf.entry;
    let segments_count = elf.program_headers.len();
    let sections_count = elf.section_headers.len();

    // 1. Mitigations
    // NX / DEP check via PT_GNU_STACK
    let mut nx = false;
    let mut has_gnu_stack = false;
    let mut has_gnu_relro = false;

    for ph in &elf.program_headers {
        if ph.p_type == program_header::PT_GNU_STACK {
            has_gnu_stack = true;
            // If executable flag (PF_X = 1) is NOT set, stack is non-executable
            if (ph.p_flags & program_header::PF_X) == 0 {
                nx = true;
            }
        } else if ph.p_type == program_header::PT_GNU_RELRO {
            has_gnu_relro = true;
        }
    }
    if !has_gnu_stack {
        // Without GNU_STACK segment, stack may be executable
        nx = false;
    }

    // PIE check via e_type (ET_DYN = 3)
    let pie = elf.header.e_type == header::ET_DYN;

    // RELRO check
    let mut has_bind_now = false;
    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            // DT_BIND_NOW = 24
            if dyn_entry.d_tag == 24 {
                has_bind_now = true;
            }
            // DT_FLAGS = 30 (DF_BIND_NOW = 0x8)
            if dyn_entry.d_tag == 30 && (dyn_entry.d_val & 0x8) != 0 {
                has_bind_now = true;
            }
            // DT_FLAGS_1 = 0x6ffffffb (DF_1_NOW = 0x1)
            if dyn_entry.d_tag == 0x6ffffffb && (dyn_entry.d_val & 0x1) != 0 {
                has_bind_now = true;
            }
        }
    }

    let relro = match (has_gnu_relro, has_bind_now) {
        (true, true) => RelroStatus::Full,
        (true, false) => RelroStatus::Partial,
        (false, _) => RelroStatus::None,
    };

    // Stack Canary & Fortify check via symbols
    let mut stack_canary = false;
    let mut fortify = false;
    let mut dynamic_symbols = Vec::new();

    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name.contains("__stack_chk_fail") || name.contains("__stack_smash_handler") {
                stack_canary = true;
            }
            if name.ends_with("_chk") {
                fortify = true;
            }
            dynamic_symbols.push(SymbolSummary {
                name: name.to_string(),
                addr: sym.st_value,
                is_import: sym.st_value == 0,
            });
        }
    }

    // Also check static syms if dynsyms didn't have canary
    if !stack_canary {
        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name.contains("__stack_chk_fail") || name.contains("__stack_smash_handler") {
                    stack_canary = true;
                    break;
                }
            }
        }
    }

    // 2. Sections
    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            sections.push(SectionSummary {
                name: name.to_string(),
                sh_type: sh.sh_type,
                addr: sh.sh_addr,
                size: sh.sh_size,
            });
        }
    }

    // 3. Dependencies
    let dependencies = elf.libraries.iter().map(|s| s.to_string()).collect();

    Ok(ElfReport {
        class,
        endianness,
        machine,
        entrypoint,
        segments_count,
        sections_count,
        dependencies,
        mitigations: ElfMitigations {
            nx,
            pie,
            relro,
            stack_canary,
            fortify,
        },
        sections,
        dynamic_symbols,
    })
}
