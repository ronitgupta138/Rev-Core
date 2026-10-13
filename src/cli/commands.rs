use crate::app::asar::AsarArchive;
use crate::domain::compute_sha256;
use crate::native::{analyze_elf, analyze_macho, analyze_pe, disassemble_x86_64, RelroStatus};
use colored::*;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};
use std::fs;
use std::path::Path;

pub fn cmd_inspect(path: &Path, json_mode: bool) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    let digest = compute_sha256(&bytes);

    if json_mode {
        if let Ok(elf) = analyze_elf(&bytes) {
            println!("{}", serde_json::to_string_pretty(&elf)?);
            return Ok(());
        }
        if let Ok(pe) = analyze_pe(&bytes) {
            println!("{}", serde_json::to_string_pretty(&pe)?);
            return Ok(());
        }
        if let Ok(macho) = analyze_macho(&bytes) {
            println!("{}", serde_json::to_string_pretty(&macho)?);
            return Ok(());
        }
        anyhow::bail!("Unsupported binary format");
    }

    println!("\n{}", format!("=== Target: {} ===", path.display()).cyan().bold());
    println!("SHA-256: {}", digest.yellow());
    println!("File Size: {} bytes\n", bytes.len());

    if let Ok(elf) = analyze_elf(&bytes) {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        table.set_header(vec![
            Cell::new("Property").fg(Color::Cyan),
            Cell::new("Value").fg(Color::Green),
        ]);

        table.add_row(vec![Cell::new("Format"), Cell::new(&elf.class)]);
        table.add_row(vec![Cell::new("Machine"), Cell::new(&elf.machine)]);
        table.add_row(vec![Cell::new("Endianness"), Cell::new(&elf.endianness)]);
        table.add_row(vec![Cell::new("Entrypoint"), Cell::new(format!("0x{:x}", elf.entrypoint))]);
        table.add_row(vec![Cell::new("Segments"), Cell::new(elf.segments_count.to_string())]);
        table.add_row(vec![Cell::new("Sections"), Cell::new(elf.sections_count.to_string())]);

        println!("{}\n", table);

        render_mitigations_table(&elf.mitigations.nx, &elf.mitigations.pie, &elf.mitigations.relro, &elf.mitigations.stack_canary, &elf.mitigations.fortify);

        if !elf.dependencies.is_empty() {
            println!("\n{}", "Dynamic Dependencies (DT_NEEDED):".bold());
            for dep in &elf.dependencies {
                println!("  ├── {}", dep.green());
            }
        }
        return Ok(());
    }

    if let Ok(pe) = analyze_pe(&bytes) {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        table.set_header(vec![
            Cell::new("Property").fg(Color::Cyan),
            Cell::new("Value").fg(Color::Green),
        ]);

        table.add_row(vec![Cell::new("Format"), Cell::new("Portable Executable (PE)")]);
        table.add_row(vec![Cell::new("Machine"), Cell::new(&pe.machine)]);
        table.add_row(vec![Cell::new("Entrypoint"), Cell::new(format!("0x{:x}", pe.entrypoint))]);
        table.add_row(vec![Cell::new("Sections"), Cell::new(pe.sections_count.to_string())]);
        table.add_row(vec![Cell::new("Subsystem"), Cell::new(format!("{}", pe.subsystem))]);

        println!("{}\n", table);

        let mut mit_table = Table::new();
        mit_table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        mit_table.set_header(vec![
            Cell::new("Mitigation").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Yellow),
        ]);

        add_mit_row(&mut mit_table, "ASLR (Dynamic Base)", pe.mitigations.aslr);
        add_mit_row(&mut mit_table, "DEP / NX Compat", pe.mitigations.dep_nx);
        add_mit_row(&mut mit_table, "Control Flow Guard (CFG)", pe.mitigations.cfg);
        add_mit_row(&mut mit_table, "Structured Exception Handling", pe.mitigations.seh);

        println!("{}\n", mit_table);

        if !pe.imports.is_empty() {
            println!("\n{}", "Imported Libraries:".bold());
            for imp in &pe.imports {
                println!("  ├── {}", imp.green());
            }
        }
        return Ok(());
    }

    if let Ok(macho) = analyze_macho(&bytes) {
        println!("{}", format!("Format: Mach-O (Fat/Universal: {})", macho.is_fat).green().bold());
        for (i, arch) in macho.architectures.iter().enumerate() {
            println!("\n--- Slice {} Architecture: {} ---", i, arch.cpu_type.cyan().bold());
            let mut table = Table::new();
            table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
            table.set_header(vec![
                Cell::new("Mitigation").fg(Color::Cyan),
                Cell::new("Status").fg(Color::Yellow),
            ]);
            add_mit_row(&mut table, "PIE (Position Independent Executable)", arch.mitigations.pie);
            add_mit_row(&mut table, "NX / No-Heap Execution", arch.mitigations.nx);
            add_mit_row(&mut table, "__RESTRICT Segment Protection", arch.mitigations.restricted_segment);
            add_mit_row(&mut table, "Code Signature Present", arch.mitigations.code_signed);
            println!("{}\n", table);

            if !arch.dependencies.is_empty() {
                println!("{}", "Linked Frameworks / Dylibs:".bold());
                for dep in &arch.dependencies {
                    println!("  ├── {}", dep.green());
                }
            }
        }
        return Ok(());
    }

    anyhow::bail!("Unrecognized or unsupported binary format for {}", path.display());
}

pub fn cmd_mitigations(path: &Path) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    println!("\n{}", format!("=== Mitigations for: {} ===", path.display()).cyan().bold());

    if let Ok(elf) = analyze_elf(&bytes) {
        render_mitigations_table(&elf.mitigations.nx, &elf.mitigations.pie, &elf.mitigations.relro, &elf.mitigations.stack_canary, &elf.mitigations.fortify);
        return Ok(());
    }

    if let Ok(pe) = analyze_pe(&bytes) {
        let mut mit_table = Table::new();
        mit_table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        mit_table.set_header(vec![
            Cell::new("Mitigation").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Yellow),
        ]);

        add_mit_row(&mut mit_table, "ASLR (Dynamic Base)", pe.mitigations.aslr);
        add_mit_row(&mut mit_table, "DEP / NX Compat", pe.mitigations.dep_nx);
        add_mit_row(&mut mit_table, "Control Flow Guard (CFG)", pe.mitigations.cfg);
        add_mit_row(&mut mit_table, "Structured Exception Handling", pe.mitigations.seh);

        println!("{}\n", mit_table);
        return Ok(());
    }

    if let Ok(macho) = analyze_macho(&bytes) {
        for (i, arch) in macho.architectures.iter().enumerate() {
            println!("\n--- Slice {} Mitigations ({}) ---", i, arch.cpu_type.cyan().bold());
            let mut table = Table::new();
            table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
            table.set_header(vec![
                Cell::new("Mitigation").fg(Color::Cyan),
                Cell::new("Status").fg(Color::Yellow),
            ]);
            add_mit_row(&mut table, "PIE (Position Independent Executable)", arch.mitigations.pie);
            add_mit_row(&mut table, "NX / No-Heap Execution", arch.mitigations.nx);
            add_mit_row(&mut table, "__RESTRICT Segment Protection", arch.mitigations.restricted_segment);
            add_mit_row(&mut table, "Code Signature Present", arch.mitigations.code_signed);
            println!("{}\n", table);
        }
        return Ok(());
    }

    anyhow::bail!("Could not parse binary to extract mitigations");
}

pub fn cmd_disasm(path: &Path, offset: u64, length: usize, max_instr: usize) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    let start = offset as usize;
    if start >= bytes.len() {
        anyhow::bail!("Offset 0x{:x} is outside binary boundaries ({} bytes)", offset, bytes.len());
    }

    let end = (start + length).min(bytes.len());
    let slice = &bytes[start..end];

    let instructions = disassemble_x86_64(slice, offset, max_instr)?;

    println!("\n{}", format!("=== Disassembly at 0x{:x} ({}) ===", offset, path.display()).cyan().bold());

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
    table.set_header(vec![
        Cell::new("Address").fg(Color::Cyan),
        Cell::new("Opcode (Hex)").fg(Color::DarkGrey),
        Cell::new("Instruction").fg(Color::Green),
    ]);

    for instr in instructions {
        table.add_row(vec![
            Cell::new(format!("0x{:08x}", instr.ip)),
            Cell::new(&instr.bytes),
            Cell::new(&instr.op_str),
        ]);
    }

    println!("{}\n", table);
    Ok(())
}

pub fn cmd_asar_list(path: &Path) -> anyhow::Result<()> {
    let archive = AsarArchive::open(path)?;
    println!("\n{}", format!("=== ASAR Archive: {} ===", path.display()).cyan().bold());
    println!("Total Files: {}", archive.metadata.total_files.to_string().green());
    println!("Total Directories: {}", archive.metadata.total_dirs.to_string().cyan());
    println!("Total Unpacked Size: {} bytes\n", archive.metadata.total_size.to_string().yellow());

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
    table.set_header(vec![
        Cell::new("Type").fg(Color::Cyan),
        Cell::new("Path").fg(Color::Green),
        Cell::new("Size (Bytes)").fg(Color::Yellow),
        Cell::new("Offset").fg(Color::DarkGrey),
    ]);

    for entry in archive.list() {
        let type_cell = if entry.is_dir {
            Cell::new("DIR").fg(Color::Cyan)
        } else {
            Cell::new("FILE").fg(Color::White)
        };

        table.add_row(vec![
            type_cell,
            Cell::new(&entry.path),
            Cell::new(entry.size.to_string()),
            Cell::new(format!("0x{:x}", entry.offset)),
        ]);
    }

    println!("{}\n", table);
    Ok(())
}

pub fn cmd_cfg(path: &Path, offset: u64, max_instr: usize, format: &str) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    let start = offset as usize;
    if start >= bytes.len() {
        anyhow::bail!("Offset 0x{:x} is outside binary boundaries ({} bytes)", offset, bytes.len());
    }

    let slice = &bytes[start..];
    let cfg = crate::native::build_cfg_x86_64(slice, offset, max_instr)?;

    println!("\n{}", format!("=== Control Flow Graph for: {} at 0x{:x} ===", path.display(), offset).cyan().bold());
    println!("{}", cfg.to_ascii_summary().yellow());

    if format.to_lowercase() == "mermaid" {
        println!("\n{}", "--- Mermaid Diagram ---".bold());
        println!("```mermaid\n{}\n```", cfg.to_mermaid());
    }

    Ok(())
}

pub fn cmd_entropy(path: &Path) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    let report = crate::analysis::analyze_entropy(&bytes);

    println!("\n{}", format!("=== Shannon Entropy Analysis: {} ===", path.display()).cyan().bold());
    println!("Total Bytes: {}", report.total_bytes.to_string().yellow());
    println!("Calculated Entropy: {:.4} / 8.0000", report.entropy);
    println!("Classification: {}", report.classification.green().bold());
    if report.is_likely_packed {
        println!("{}", "(!) Warning: High entropy indicates compressed, encrypted, or packed payload.".red().bold());
    }
    println!();
    Ok(())
}

pub fn cmd_crypto(path: &Path) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    let findings = crate::analysis::scan_crypto_constants(&bytes);

    println!("\n{}", format!("=== Cryptographic Magic Signature Scan: {} ===", path.display()).cyan().bold());
    if findings.is_empty() {
        println!("{}", "No standard hardcoded cryptographic state constants detected.".yellow());
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
    table.set_header(vec![
        Cell::new("Algorithm").fg(Color::Cyan),
        Cell::new("Offset").fg(Color::DarkGrey),
        Cell::new("Description").fg(Color::Green),
        Cell::new("Confidence").fg(Color::Yellow),
    ]);

    for f in findings {
        table.add_row(vec![
            Cell::new(&f.algorithm),
            Cell::new(format!("0x{:x}", f.offset)),
            Cell::new(&f.description),
            Cell::new(format!("{:.0}%", f.confidence * 100.0)),
        ]);
    }

    println!("{}\n", table);
    Ok(())
}

pub fn cmd_wasm(path: &Path) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    let report = crate::wasm::analyze_wasm(&bytes)?;

    println!("\n{}", format!("=== WebAssembly Module: {} ===", path.display()).cyan().bold());
    println!("WASM Version: {}", report.version.to_string().yellow());
    println!("Sections Count: {}", report.sections_count.to_string().green());
    println!("Declared Functions: {}", report.functions_count.to_string().cyan());

    if let Some(mem) = report.memory {
        println!("Memory Limits: Initial {} pages ({} KB), Max {:?}", mem.initial_pages, mem.initial_pages * 64, mem.maximum_pages);
    }

    if !report.exports.is_empty() {
        println!("\n{}", "Exported Symbols:".bold());
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        table.set_header(vec![
            Cell::new("Name").fg(Color::Cyan),
            Cell::new("Kind").fg(Color::Green),
            Cell::new("Index").fg(Color::Yellow),
        ]);
        for exp in &report.exports {
            table.add_row(vec![
                Cell::new(&exp.name),
                Cell::new(&exp.kind),
                Cell::new(exp.index.to_string()),
            ]);
        }
        println!("{}\n", table);
    }

    if !report.imports.is_empty() {
        println!("{}", "Imported Signatures:".bold());
        for imp in &report.imports {
            println!("  ├── {}::{} ({})", imp.module.cyan(), imp.name.green(), imp.kind);
        }
    }

    Ok(())
}

pub fn cmd_electron(path: &Path) -> anyhow::Result<()> {
    let report = crate::app::scan_electron_directory(path)?;

    println!("\n{}", format!("=== Electron Application Security Scan: {} ===", path.display()).cyan().bold());
    println!("Total Script Files Analyzed: {}", report.total_script_files.to_string().yellow());
    println!("Identified IPC Endpoints: {}", report.ipc_channels.len().to_string().green());
    println!("Security Risk Score: {} / 100", if report.risk_score > 50 { report.risk_score.to_string().red().bold() } else { report.risk_score.to_string().green() });

    if !report.risk_summary.is_empty() {
        println!("\n{}", "Identified Security Flags & Risks:".bold());
        for risk in &report.risk_summary {
            println!("  [!] {}", risk.red());
        }
    }

    if !report.ipc_channels.is_empty() {
        println!("\n{}", "IPC Communication Channels:".bold());
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        table.set_header(vec![
            Cell::new("Channel Name").fg(Color::Cyan),
            Cell::new("Direction / Type").fg(Color::Green),
            Cell::new("Source Location").fg(Color::Yellow),
        ]);

        for c in &report.ipc_channels {
            table.add_row(vec![
                Cell::new(&c.channel),
                Cell::new(&c.call_type),
                Cell::new(format!("{}:{}", c.file, c.line)),
            ]);
        }
        println!("{}\n", table);
    }

    Ok(())
}

pub fn cmd_asar_unpack(path: &Path, dest_dir: &Path) -> anyhow::Result<()> {
    println!("\n{}", format!("Unpacking ASAR: {} -> {}", path.display(), dest_dir.display()).cyan().bold());
    let archive = AsarArchive::open(path)?;
    let count = archive.extract_all(dest_dir)?;
    println!("{}", format!("Successfully extracted {} files to {}!", count, dest_dir.display()).green().bold());
    Ok(())
}

fn render_mitigations_table(nx: &bool, pie: &bool, relro: &RelroStatus, canary: &bool, fortify: &bool) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
    table.set_header(vec![
        Cell::new("Mitigation").fg(Color::Cyan),
        Cell::new("Status").fg(Color::Yellow),
    ]);

    add_mit_row(&mut table, "NX / DEP (No-Execute)", *nx);
    add_mit_row(&mut table, "PIE (Position Independent Executable)", *pie);

    let (relro_str, relro_color) = match relro {
        RelroStatus::Full => ("Full RELRO", Color::Green),
        RelroStatus::Partial => ("Partial RELRO", Color::Yellow),
        RelroStatus::None => ("No RELRO", Color::Red),
    };
    table.add_row(vec![
        Cell::new("RELRO (Read-Only Relocations)"),
        Cell::new(relro_str).fg(relro_color),
    ]);

    add_mit_row(&mut table, "Stack Canary (__stack_chk_fail)", *canary);
    add_mit_row(&mut table, "Fortify Source (_chk)", *fortify);

    println!("{}\n", table);
}

fn add_mit_row(table: &mut Table, name: &str, enabled: bool) {
    let (text, color) = if enabled {
        ("Enabled", Color::Green)
    } else {
        ("Disabled", Color::Red)
    };
    table.add_row(vec![Cell::new(name), Cell::new(text).fg(color)]);
}
