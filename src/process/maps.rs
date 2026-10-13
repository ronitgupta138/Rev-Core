use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start_addr: u64,
    pub end_addr: u64,
    pub size_bytes: u64,
    pub perms: String,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
    pub is_private: bool,
    pub is_rwx: bool,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessForensicReport {
    pub pid: u32,
    pub total_mapped_bytes: u64,
    pub rwx_regions_count: usize,
    pub executable_regions_count: usize,
    pub anonymous_regions_count: usize,
    pub regions: Vec<MemoryRegion>,
    pub security_alerts: Vec<String>,
}

pub fn parse_proc_maps(pid: u32) -> anyhow::Result<ProcessForensicReport> {
    let maps_path = format!("/proc/{pid}/maps");
    let content = fs::read_to_string(&maps_path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {e}", maps_path))?;

    parse_maps_content(pid, &content)
}

pub fn parse_maps_content(pid: u32, content: &str) -> anyhow::Result<ProcessForensicReport> {
    let mut regions = Vec::new();
    let mut total_mapped_bytes = 0;
    let mut rwx_regions_count = 0;
    let mut executable_regions_count = 0;
    let mut anonymous_regions_count = 0;
    let mut security_alerts = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        // 1. Address range: 00400000-00452000
        let addrs: Vec<&str> = parts[0].split('-').collect();
        if addrs.len() != 2 {
            continue;
        }
        let start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addrs[1], 16).unwrap_or(0);
        let size = end.saturating_sub(start);
        total_mapped_bytes += size;

        // 2. Perms: r-xp
        let perms = parts[1].to_string();
        let is_readable = perms.contains('r');
        let is_writable = perms.contains('w');
        let is_executable = perms.contains('x');
        let is_private = perms.contains('p');
        let is_rwx = is_readable && is_writable && is_executable;

        if is_executable {
            executable_regions_count += 1;
        }
        if is_rwx {
            rwx_regions_count += 1;
            security_alerts.push(format!(
                "CRITICAL: Memory page [0x{:x}..0x{:x}] has RWX permissions (Writable + Executable)",
                start, end
            ));
        }

        // 3. Offset
        let offset = u64::from_str_radix(parts[2], 16).unwrap_or(0);

        // 4. Dev
        let dev = parts[3].to_string();

        // 5. Inode
        let inode = parts[4].parse::<u64>().unwrap_or(0);

        // 6. Pathname
        let pathname = if parts.len() >= 6 {
            Some(parts[5..].join(" "))
        } else {
            anonymous_regions_count += 1;
            None
        };

        regions.push(MemoryRegion {
            start_addr: start,
            end_addr: end,
            size_bytes: size,
            perms,
            is_readable,
            is_writable,
            is_executable,
            is_private,
            is_rwx,
            offset,
            dev,
            inode,
            pathname,
        });
    }

    Ok(ProcessForensicReport {
        pid,
        total_mapped_bytes,
        rwx_regions_count,
        executable_regions_count,
        anonymous_regions_count,
        regions,
        security_alerts,
    })
}
