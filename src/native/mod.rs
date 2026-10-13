pub mod arch;
pub mod cfg;
pub mod disasm;
pub mod elf;
pub mod macho;
pub mod pe;

pub use arch::{decode_universal_slice, TargetArch, UniversalInstruction};
pub use cfg::{build_cfg_x86_64, BasicBlock, ControlFlowGraph, TerminatorType};
pub use disasm::{disassemble_x86_64, DisassembledInstruction};
pub use elf::{analyze_elf, ElfMitigations, ElfReport, RelroStatus};
pub use macho::{analyze_macho, MachoArchitectureSummary, MachoMitigations, MachoReport};
pub use pe::{analyze_pe, PeMitigations, PeReport};
