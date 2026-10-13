use crate::domain::{RevError, RevResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExport {
    pub name: String,
    pub kind: String, // "Function", "Table", "Memory", "Global"
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmMemorySummary {
    pub initial_pages: u32,
    pub maximum_pages: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmReport {
    pub version: u32,
    pub sections_count: usize,
    pub functions_count: usize,
    pub memory: Option<WasmMemorySummary>,
    pub exports: Vec<WasmExport>,
    pub imports: Vec<WasmImport>,
    pub custom_sections: Vec<String>,
}

pub fn analyze_wasm(bytes: &[u8]) -> RevResult<WasmReport> {
    if bytes.len() < 8 {
        return Err(RevError::UnsupportedFormat("WASM binary too short".into()));
    }

    // Magic: \0asm (0x00, 0x61, 0x73, 0x6d)
    if &bytes[0..4] != b"\0asm" {
        return Err(RevError::UnsupportedFormat("Invalid WASM magic header".into()));
    }

    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let mut offset = 8;

    let mut sections_count = 0;
    let mut functions_count = 0;
    let mut memory = None;
    let mut exports = Vec::new();
    let mut imports = Vec::new();
    let mut custom_sections = Vec::new();

    while offset < bytes.len() {
        let section_id = bytes[offset];
        offset += 1;
        sections_count += 1;

        let (section_len, leb_len) = read_u32_leb128(&bytes[offset..])
            .map_err(|e| RevError::Parse(format!("Failed to read section length: {e}")))?;
        offset += leb_len;

        let section_end = offset + (section_len as usize);
        if section_end > bytes.len() {
            break;
        }

        let section_payload = &bytes[offset..section_end];

        match section_id {
            0 => {
                // Custom section (e.g. name)
                if let Ok((name, _)) = read_string(section_payload) {
                    custom_sections.push(name);
                }
            }
            2 => {
                // Import section
                if let Ok(imp_list) = parse_imports(section_payload) {
                    imports.extend(imp_list);
                }
            }
            3 => {
                // Function section (vector of type indices)
                if let Ok((count, _)) = read_u32_leb128(section_payload) {
                    functions_count += count as usize;
                }
            }
            5 => {
                // Memory section
                if let Ok(mem) = parse_memory(section_payload) {
                    memory = Some(mem);
                }
            }
            7 => {
                // Export section
                if let Ok(exp_list) = parse_exports(section_payload) {
                    exports.extend(exp_list);
                }
            }
            _ => {}
        }

        offset = section_end;
    }

    Ok(WasmReport {
        version,
        sections_count,
        functions_count,
        memory,
        exports,
        imports,
        custom_sections,
    })
}

fn read_u32_leb128(bytes: &[u8]) -> Result<(u32, usize), &'static str> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut read_bytes = 0;

    for &byte in bytes {
        read_bytes += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Ok((result, read_bytes));
        }
        shift += 7;
        if shift >= 35 {
            return Err("LEB128 integer overflow");
        }
    }
    Err("Unexpected EOF while parsing LEB128")
}

fn read_string(bytes: &[u8]) -> Result<(String, usize), &'static str> {
    let (len, leb_len) = read_u32_leb128(bytes)?;
    let start = leb_len;
    let end = start + (len as usize);
    if end > bytes.len() {
        return Err("String length out of bounds");
    }
    let s = std::str::from_utf8(&bytes[start..end]).map_err(|_| "Invalid UTF-8 string")?;
    Ok((s.to_string(), end))
}

fn parse_memory(bytes: &[u8]) -> Result<WasmMemorySummary, &'static str> {
    let (count, mut offset) = read_u32_leb128(bytes)?;
    if count == 0 || offset >= bytes.len() {
        return Err("No memory declarations");
    }
    let flags = bytes[offset];
    offset += 1;
    let (initial, leb_len) = read_u32_leb128(&bytes[offset..])?;
    offset += leb_len;

    let maximum = if (flags & 0x01) != 0 && offset < bytes.len() {
        let (max, _) = read_u32_leb128(&bytes[offset..])?;
        Some(max)
    } else {
        None
    };

    Ok(WasmMemorySummary {
        initial_pages: initial,
        maximum_pages: maximum,
    })
}

fn parse_exports(bytes: &[u8]) -> Result<Vec<WasmExport>, &'static str> {
    let (count, mut offset) = read_u32_leb128(bytes)?;
    let mut list = Vec::new();

    for _ in 0..count {
        if offset >= bytes.len() {
            break;
        }
        let (name, str_len) = read_string(&bytes[offset..])?;
        offset += str_len;
        if offset >= bytes.len() {
            break;
        }
        let kind_byte = bytes[offset];
        offset += 1;
        let (index, idx_len) = read_u32_leb128(&bytes[offset..])?;
        offset += idx_len;

        let kind = match kind_byte {
            0 => "Function",
            1 => "Table",
            2 => "Memory",
            3 => "Global",
            _ => "Unknown",
        }
        .to_string();

        list.push(WasmExport { name, kind, index });
    }

    Ok(list)
}

fn parse_imports(bytes: &[u8]) -> Result<Vec<WasmImport>, &'static str> {
    let (count, mut offset) = read_u32_leb128(bytes)?;
    let mut list = Vec::new();

    for _ in 0..count {
        if offset >= bytes.len() {
            break;
        }
        let (mod_name, m_len) = read_string(&bytes[offset..])?;
        offset += m_len;
        if offset >= bytes.len() {
            break;
        }
        let (field_name, f_len) = read_string(&bytes[offset..])?;
        offset += f_len;
        if offset >= bytes.len() {
            break;
        }
        let kind_byte = bytes[offset];
        offset += 1;

        let kind = match kind_byte {
            0 => {
                let (_, len) = read_u32_leb128(&bytes[offset..])?;
                offset += len;
                "Function"
            }
            1 => "Table",
            2 => {
                let _ = parse_memory(&bytes[offset..]);
                "Memory"
            }
            3 => "Global",
            _ => "Unknown",
        }
        .to_string();

        list.push(WasmImport {
            module: mod_name,
            name: field_name,
            kind,
        });
    }

    Ok(list)
}
