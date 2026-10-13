use crate::domain::{RevError, RevResult};
use goblin::mach::{constants::cputype, Mach, MachO};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachoMitigations {
    pub pie: bool,
    pub nx: bool,
    pub restricted_segment: bool,
    pub code_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachoArchitectureSummary {
    pub cpu_type: String,
    pub cpu_subtype: u32,
    pub filetype: u32,
    pub is_64bit: bool,
    pub mitigations: MachoMitigations,
    pub segments: Vec<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachoReport {
    pub is_fat: bool,
    pub architectures: Vec<MachoArchitectureSummary>,
}

pub fn analyze_macho(buffer: &[u8]) -> RevResult<MachoReport> {
    let mach = Mach::parse(buffer).map_err(|e| RevError::Parse(format!("Failed to parse Mach-O: {e}")))?;

    match mach {
        Mach::Binary(macho) => {
            let summary = parse_single_macho(&macho);
            Ok(MachoReport {
                is_fat: false,
                architectures: vec![summary],
            })
        }
        Mach::Fat(fat) => {
            let mut architectures = Vec::new();
            for (idx, arch) in fat.iter_arches().enumerate() {
                if let Ok(arch_data) = arch {
                    let start = arch_data.offset as usize;
                    let end = start + arch_data.size as usize;
                    if end <= buffer.len() {
                        if let Ok(macho) = MachO::parse(&buffer[start..end], 0) {
                            architectures.push(parse_single_macho(&macho));
                        }
                    }
                } else {
                    architectures.push(MachoArchitectureSummary {
                        cpu_type: format!("Unknown Architecture index {idx}"),
                        cpu_subtype: 0,
                        filetype: 0,
                        is_64bit: false,
                        mitigations: MachoMitigations {
                            pie: false,
                            nx: false,
                            restricted_segment: false,
                            code_signed: false,
                        },
                        segments: Vec::new(),
                        dependencies: Vec::new(),
                    });
                }
            }
            Ok(MachoReport {
                is_fat: true,
                architectures,
            })
        }
    }
}

fn parse_single_macho(macho: &MachO) -> MachoArchitectureSummary {
    let cpu_type_str = match macho.header.cputype {
        cputype::CPU_TYPE_X86_64 => "x86_64".to_string(),
        cputype::CPU_TYPE_ARM64 => "ARM64 / Apple Silicon".to_string(),
        cputype::CPU_TYPE_X86 => "x86 32-bit".to_string(),
        cputype::CPU_TYPE_ARM => "ARM 32-bit".to_string(),
        other => format!("CPU Type 0x{:x}", other),
    };

    let flags = macho.header.flags;
    // MH_PIE = 0x00200000
    let pie = (flags & 0x00200000) != 0;
    // MH_NO_HEAP_EXECUTION = 0x01000000
    let nx = (flags & 0x01000000) != 0;

    let mut restricted_segment = false;
    let mut code_signed = false;
    let mut segments = Vec::new();

    for seg in &macho.segments {
        if let Ok(name) = seg.name() {
            segments.push(name.to_string());
            if name.eq_ignore_ascii_case("__RESTRICT") {
                restricted_segment = true;
            }
        }
    }

    // Check load commands for LC_CODE_SIGNATURE (0x1d)
    for cmd in &macho.load_commands {
        if cmd.command.cmd() == 0x1d {
            code_signed = true;
        }
    }

    let dependencies = macho.libs.iter().map(|s| s.to_string()).collect();

    MachoArchitectureSummary {
        cpu_type: cpu_type_str,
        cpu_subtype: macho.header.cpusubtype,
        filetype: macho.header.filetype,
        is_64bit: macho.is_64,
        mitigations: MachoMitigations {
            pie,
            nx,
            restricted_segment,
            code_signed,
        },
        segments,
        dependencies,
    }
}
