use crate::domain::{RevError, RevResult};
use goblin::pe::PE;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeMitigations {
    pub aslr: bool,
    pub dep_nx: bool,
    pub cfg: bool,
    pub seh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeReport {
    pub machine: String,
    pub entrypoint: u64,
    pub sections_count: usize,
    pub subsystem: u16,
    pub mitigations: PeMitigations,
    pub imports: Vec<String>,
}

pub fn analyze_pe(buffer: &[u8]) -> RevResult<PeReport> {
    let pe = PE::parse(buffer).map_err(|e| RevError::Parse(format!("Failed to parse PE: {e}")))?;

    let machine = match pe.header.coff_header.machine {
        0x8664 => "x86_64 / AMD64",
        0x014c => "i386 / x86",
        0xaa64 => "ARM64",
        0x01c0 => "ARM",
        _ => "Unknown",
    }
    .to_string();

    let entrypoint = pe.entry as u64;
    let sections_count = pe.sections.len();
    let mut subsystem = 0;
    let mut aslr = false;
    let mut dep_nx = false;
    let mut cfg = false;
    let mut seh = true;

    if let Some(opt) = pe.header.optional_header {
        subsystem = opt.windows_fields.subsystem;
        let dll_chars = opt.windows_fields.dll_characteristics;

        // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
        aslr = (dll_chars & 0x0040) != 0;
        // IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
        dep_nx = (dll_chars & 0x0100) != 0;
        // IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
        cfg = (dll_chars & 0x4000) != 0;
        // IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
        if (dll_chars & 0x0400) != 0 {
            seh = false;
        }
    }

    let imports = pe.libraries.iter().map(|s| s.to_string()).collect();

    Ok(PeReport {
        machine,
        entrypoint,
        sections_count,
        subsystem,
        mitigations: PeMitigations {
            aslr,
            dep_nx,
            cfg,
            seh,
        },
        imports,
    })
}
