//! Comprehensive Binary Hardening & Security Posture Auditor.

use crate::domain::RevResult;
use crate::native::{analyze_elf, analyze_macho, analyze_pe, RelroStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsecureFunctionFinding {
    pub function: String,
    pub risk: RiskLevel,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningAuditReport {
    pub binary_format: String,
    pub architecture: String,
    pub canary: bool,
    pub nx_dep: bool,
    pub pie_aslr: bool,
    pub relro: Option<RelroStatus>,
    pub fortify: bool,
    pub insecure_rpaths: Vec<String>,
    pub dangerous_functions: Vec<InsecureFunctionFinding>,
    pub hardening_score: u32,
    pub security_grade: String,
}

/// Audit known dangerous C standard library functions.
fn inspect_dangerous_functions(symbols: &[String]) -> Vec<InsecureFunctionFinding> {
    let mut findings = Vec::new();

    for sym in symbols {
        let name = sym.trim();
        match name {
            "gets" => findings.push(InsecureFunctionFinding {
                function: name.to_string(),
                risk: RiskLevel::Critical,
                description: "Unbounded buffer read without length check; inherent remote code execution hazard.".to_string(),
                recommendation: "Replace with fgets() or getline().".to_string(),
            }),
            "strcpy" | "wcscpy" => findings.push(InsecureFunctionFinding {
                function: name.to_string(),
                risk: RiskLevel::Critical,
                description: "Unbounded string copy susceptible to stack/heap buffer overflow.".to_string(),
                recommendation: "Replace with strncpy_s(), strlcpy(), or snprintf().".to_string(),
            }),
            "strcat" | "wcscat" => findings.push(InsecureFunctionFinding {
                function: name.to_string(),
                risk: RiskLevel::High,
                description: "Unbounded string concatenation susceptible to memory corruption.".to_string(),
                recommendation: "Replace with strncat_s() or strlcat().".to_string(),
            }),
            "sprintf" | "vsprintf" => findings.push(InsecureFunctionFinding {
                function: name.to_string(),
                risk: RiskLevel::High,
                description: "Unbounded formatted output into buffer susceptible to buffer overflow.".to_string(),
                recommendation: "Replace with snprintf() or vsnprintf().".to_string(),
            }),
            "system" | "popen" => findings.push(InsecureFunctionFinding {
                function: name.to_string(),
                risk: RiskLevel::High,
                description: "Spawns shell interpreter directly, vulnerable to shell injection vulnerabilities.".to_string(),
                recommendation: "Replace with execve() or POSIX spawn with sanitized argument arrays.".to_string(),
            }),
            "scanf" | "sscanf" | "fscanf" => findings.push(InsecureFunctionFinding {
                function: name.to_string(),
                risk: RiskLevel::Medium,
                description: "Format string specifiers (%s) without explicit width modifier risk buffer overflow.".to_string(),
                recommendation: "Use explicit width limits (e.g. %255s) or fgets() + parsing.".to_string(),
            }),
            _ => {}
        }
    }

    findings
}

/// Audit security mitigations across ELF, PE, and Mach-O binaries.
pub fn audit_hardening(buffer: &[u8]) -> RevResult<HardeningAuditReport> {
    // 1. Try ELF
    if buffer.starts_with(b"\x7fELF") {
        let elf_report = analyze_elf(buffer)?;
        let mut symbols: Vec<String> = elf_report
            .dynamic_symbols
            .iter()
            .map(|s| s.name.clone())
            .collect();

        // Also check imports/dependencies
        symbols.extend(elf_report.dependencies.clone());

        let dangerous = inspect_dangerous_functions(&symbols);

        // Check insecure RPATHs
        let mut insecure_rpaths = Vec::new();
        for dep in &elf_report.dependencies {
            if dep.contains("$ORIGIN") || dep.contains("/tmp") || dep == "." {
                insecure_rpaths.push(dep.clone());
            }
        }

        let mut score: u32 = 0;
        if elf_report.mitigations.nx { score += 25; }
        if elf_report.mitigations.pie { score += 25; }
        match elf_report.mitigations.relro {
            RelroStatus::Full => score += 25,
            RelroStatus::Partial => score += 10,
            RelroStatus::None => {}
        }
        if elf_report.mitigations.stack_canary { score += 20; }
        if elf_report.mitigations.fortify { score += 5; }

        if !dangerous.is_empty() {
            let penalty = (dangerous.len() as u32 * 10).min(30);
            score = score.saturating_sub(penalty);
        }

        let grade = match score {
            95..=100 => "A+".to_string(),
            85..=94 => "A".to_string(),
            70..=84 => "B".to_string(),
            55..=69 => "C".to_string(),
            40..=54 => "D".to_string(),
            _ => "F".to_string(),
        };

        return Ok(HardeningAuditReport {
            binary_format: "ELF".to_string(),
            architecture: elf_report.machine,
            canary: elf_report.mitigations.stack_canary,
            nx_dep: elf_report.mitigations.nx,
            pie_aslr: elf_report.mitigations.pie,
            relro: Some(elf_report.mitigations.relro),
            fortify: elf_report.mitigations.fortify,
            insecure_rpaths,
            dangerous_functions: dangerous,
            hardening_score: score,
            security_grade: grade,
        });
    }

    // 2. Try PE
    if buffer.starts_with(b"MZ") {
        let pe_report = analyze_pe(buffer)?;
        let dangerous = inspect_dangerous_functions(&pe_report.imports);

        let mut score: u32 = 0;
        if pe_report.mitigations.dep_nx { score += 30; }
        if pe_report.mitigations.aslr { score += 30; }
        if pe_report.mitigations.cfg { score += 20; }
        if pe_report.mitigations.seh { score += 20; }

        if !dangerous.is_empty() {
            let penalty = (dangerous.len() as u32 * 10).min(30);
            score = score.saturating_sub(penalty);
        }

        let grade = match score {
            90..=100 => "A".to_string(),
            75..=89 => "B".to_string(),
            60..=74 => "C".to_string(),
            _ => "F".to_string(),
        };

        return Ok(HardeningAuditReport {
            binary_format: "PE / Windows Executable".to_string(),
            architecture: pe_report.machine,
            canary: pe_report.mitigations.seh,
            nx_dep: pe_report.mitigations.dep_nx,
            pie_aslr: pe_report.mitigations.aslr,
            relro: None,
            fortify: pe_report.mitigations.cfg,
            insecure_rpaths: vec![],
            dangerous_functions: dangerous,
            hardening_score: score,
            security_grade: grade,
        });
    }

    // 3. Try Mach-O
    let macho_report = analyze_macho(buffer)?;
    if let Some(arch) = macho_report.architectures.first() {
        let dangerous = inspect_dangerous_functions(&arch.dependencies);

        let mut score: u32 = 0;
        if arch.mitigations.nx { score += 35; }
        if arch.mitigations.pie { score += 35; }
        if arch.mitigations.code_signed { score += 30; }

        let grade = match score {
            90..=100 => "A".to_string(),
            70..=89 => "B".to_string(),
            _ => "C".to_string(),
        };

        return Ok(HardeningAuditReport {
            binary_format: "Mach-O (macOS)".to_string(),
            architecture: arch.cpu_type.clone(),
            canary: arch.mitigations.code_signed,
            nx_dep: arch.mitigations.nx,
            pie_aslr: arch.mitigations.pie,
            relro: None,
            fortify: arch.mitigations.restricted_segment,
            insecure_rpaths: vec![],
            dangerous_functions: dangerous,
            hardening_score: score,
            security_grade: grade,
        });
    }

    Err(crate::domain::RevError::UnsupportedFormat(
        "Unknown or unsupported binary format for hardening audit".to_string(),
    ))
}
