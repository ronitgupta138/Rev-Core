use crate::domain::{RevError, RevResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsarEntry {
    pub path: String,
    pub size: u64,
    pub offset: u64,
    pub is_dir: bool,
    pub unpacked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsarMetadata {
    pub header_size: u32,
    pub total_files: usize,
    pub total_dirs: usize,
    pub total_size: u64,
    pub entries: Vec<AsarEntry>,
}

pub struct AsarArchive {
    data: Vec<u8>,
    header_offset: usize,
    pub metadata: AsarMetadata,
}

impl AsarArchive {
    pub fn open(path: impl AsRef<Path>) -> RevResult<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        if data.len() < 16 {
            return Err(RevError::InvalidAsar("File too small to be a valid ASAR archive".into()));
        }

        // Parse 16-byte Chromium Pickle header
        // Offset 12..16 gives the JSON header length
        let json_size = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        let header_offset = 16 + json_size;

        if data.len() < header_offset {
            return Err(RevError::InvalidAsar(format!(
                "Corrupted ASAR: expected header of {header_offset} bytes, but file has {}",
                data.len()
            )));
        }

        let json_str = std::str::from_utf8(&data[16..header_offset])
            .map_err(|e| RevError::InvalidAsar(format!("Header JSON is not valid UTF-8: {e}")))?;

        let header_json: Value = serde_json::from_str(json_str)
            .map_err(|e| RevError::InvalidAsar(format!("Failed to parse header JSON: {e}")))?;

        let mut entries = Vec::new();
        let mut total_files = 0;
        let mut total_dirs = 0;
        let mut total_size = 0;

        if let Some(files_map) = header_json.get("files").and_then(|v| v.as_object()) {
            parse_directory_tree(files_map, "", &mut entries, &mut total_files, &mut total_dirs, &mut total_size);
        }

        let metadata = AsarMetadata {
            header_size: json_size as u32,
            total_files,
            total_dirs,
            total_size,
            entries,
        };

        Ok(Self {
            data,
            header_offset,
            metadata,
        })
    }

    pub fn list(&self) -> &[AsarEntry] {
        &self.metadata.entries
    }

    pub fn read_file(&self, entry: &AsarEntry) -> RevResult<&[u8]> {
        if entry.is_dir || entry.unpacked {
            return Err(RevError::InvalidAsar(format!("Cannot read contents of directory or unpacked file: {}", entry.path)));
        }

        let start = self.header_offset + (entry.offset as usize);
        let end = start + (entry.size as usize);

        if end > self.data.len() {
            return Err(RevError::InvalidAsar(format!("File slice out of bounds for {}: {}..{} > {}", entry.path, start, end, self.data.len())));
        }

        Ok(&self.data[start..end])
    }

    pub fn extract_all(&self, dest_dir: impl AsRef<Path>) -> RevResult<usize> {
        let root = dest_dir.as_ref();
        fs::create_dir_all(root)?;

        let mut extracted_count = 0;
        for entry in &self.metadata.entries {
            let target_path = root.join(&entry.path);
            if entry.is_dir {
                fs::create_dir_all(&target_path)?;
            } else if !entry.unpacked {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let bytes = self.read_file(entry)?;
                let mut out = File::create(&target_path)?;
                out.write_all(bytes)?;
                extracted_count += 1;
            }
        }

        Ok(extracted_count)
    }
}

fn parse_directory_tree(
    files: &serde_json::Map<String, Value>,
    prefix: &str,
    entries: &mut Vec<AsarEntry>,
    total_files: &mut usize,
    total_dirs: &mut usize,
    total_size: &mut u64,
) {
    for (name, val) in files {
        let current_path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if let Some(sub_files) = val.get("files").and_then(|v| v.as_object()) {
            *total_dirs += 1;
            entries.push(AsarEntry {
                path: current_path.clone(),
                size: 0,
                offset: 0,
                is_dir: true,
                unpacked: false,
            });
            parse_directory_tree(sub_files, &current_path, entries, total_files, total_dirs, total_size);
        } else {
            *total_files += 1;
            let size = val.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            *total_size += size;
            let offset_str = val.get("offset").and_then(|o| o.as_str()).unwrap_or("0");
            let offset = offset_str.parse::<u64>().unwrap_or(0);
            let unpacked = val.get("unpacked").and_then(|u| u.as_bool()).unwrap_or(false);

            entries.push(AsarEntry {
                path: current_path,
                size,
                offset,
                is_dir: false,
                unpacked,
            });
        }
    }
}
