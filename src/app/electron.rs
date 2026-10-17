use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcChannel {
    pub channel: String,
    pub call_type: String, // "renderer_send", "renderer_invoke", "main_handle", "main_on", "context_bridge"
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectronSecurityPosture {
    pub node_integration: Option<bool>,
    pub context_isolation: Option<bool>,
    pub web_security: Option<bool>,
    pub sandbox: Option<bool>,
    pub enable_remote_module: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectronScanReport {
    pub root_dir: String,
    pub total_script_files: usize,
    pub ipc_channels: Vec<IpcChannel>,
    pub security_posture: ElectronSecurityPosture,
    pub risk_score: u32,
    pub risk_summary: Vec<String>,
}

pub fn scan_electron_directory(dir: impl AsRef<Path>) -> anyhow::Result<ElectronScanReport> {
    let root = dir.as_ref();
    let mut script_files = Vec::new();
    find_scripts(root, &mut script_files)?;

    let mut ipc_channels = Vec::new();
    let mut posture = ElectronSecurityPosture {
        node_integration: None,
        context_isolation: None,
        web_security: None,
        sandbox: None,
        enable_remote_module: None,
    };

    for file_path in &script_files {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = file_path
            .strip_prefix(root)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        scan_script_for_ipc(&content, &rel_path, &mut ipc_channels);
        scan_script_for_security(&content, &mut posture);
    }

    let (risk_score, risk_summary) = evaluate_security_risk(&posture, &ipc_channels);

    Ok(ElectronScanReport {
        root_dir: root.display().to_string(),
        total_script_files: script_files.len(),
        ipc_channels,
        security_posture: posture,
        risk_score,
        risk_summary,
    })
}

fn find_scripts(dir: &Path, scripts: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name != "node_modules" && !name.starts_with('.') {
                find_scripts(&path, scripts)?;
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "js" | "mjs" | "cjs" | "ts") {
                scripts.push(path);
            }
        }
    }
    Ok(())
}

fn scan_script_for_ipc(content: &str, file: &str, channels: &mut Vec<IpcChannel>) {
    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;

        if let Some(chan) = extract_first_arg(line, "ipcRenderer.send") {
            channels.push(IpcChannel {
                channel: chan,
                call_type: "renderer_send".to_string(),
                file: file.to_string(),
                line: line_num,
            });
        }
        if let Some(chan) = extract_first_arg(line, "ipcRenderer.invoke") {
            channels.push(IpcChannel {
                channel: chan,
                call_type: "renderer_invoke".to_string(),
                file: file.to_string(),
                line: line_num,
            });
        }
        if let Some(chan) = extract_first_arg(line, "ipcMain.handle") {
            channels.push(IpcChannel {
                channel: chan,
                call_type: "main_handle".to_string(),
                file: file.to_string(),
                line: line_num,
            });
        }
        if let Some(chan) = extract_first_arg(line, "ipcMain.on") {
            channels.push(IpcChannel {
                channel: chan,
                call_type: "main_on".to_string(),
                file: file.to_string(),
                line: line_num,
            });
        }
        if let Some(chan) = extract_first_arg(line, "contextBridge.exposeInMainWorld") {
            channels.push(IpcChannel {
                channel: chan,
                call_type: "context_bridge".to_string(),
                file: file.to_string(),
                line: line_num,
            });
        }
    }
}

fn extract_first_arg(line: &str, pattern: &str) -> Option<String> {
    if let Some(idx) = line.find(pattern) {
        let rest = &line[idx + pattern.len()..];
        if let Some(start_paren) = rest.find('(') {
            let inside = rest[start_paren + 1..].trim_start();
            let quote = inside.chars().next()?;
            if quote == '\'' || quote == '"' || quote == '`' {
                let inside_str = &inside[1..];
                if let Some(end_quote) = inside_str.find(quote) {
                    return Some(inside_str[..end_quote].to_string());
                }
            }
        }
    }
    None
}

fn scan_script_for_security(content: &str, posture: &mut ElectronSecurityPosture) {
    if content.contains("nodeIntegration: true") || content.contains("nodeIntegration:true") {
        posture.node_integration = Some(true);
    } else if (content.contains("nodeIntegration: false") || content.contains("nodeIntegration:false"))
        && posture.node_integration.is_none() {
        posture.node_integration = Some(false);
    }

    if content.contains("contextIsolation: false") || content.contains("contextIsolation:false") {
        posture.context_isolation = Some(false);
    } else if (content.contains("contextIsolation: true") || content.contains("contextIsolation:true"))
        && posture.context_isolation.is_none() {
        posture.context_isolation = Some(true);
    }

    if content.contains("webSecurity: false") || content.contains("webSecurity:false") {
        posture.web_security = Some(false);
    }

    if content.contains("enableRemoteModule: true") || content.contains("enableRemoteModule:true") {
        posture.enable_remote_module = Some(true);
    }

    if content.contains("sandbox: false") || content.contains("sandbox:false") {
        posture.sandbox = Some(false);
    } else if (content.contains("sandbox: true") || content.contains("sandbox:true"))
        && posture.sandbox.is_none() {
        posture.sandbox = Some(true);
    }
}

fn evaluate_security_risk(posture: &ElectronSecurityPosture, channels: &[IpcChannel]) -> (u32, Vec<String>) {
    let mut score = 0;
    let mut reasons = Vec::new();

    if posture.node_integration == Some(true) {
        score += 40;
        reasons.push("Critical: nodeIntegration is enabled in renderer window".to_string());
    }

    if posture.context_isolation == Some(false) {
        score += 30;
        reasons.push("High: contextIsolation is explicitly disabled".to_string());
    }

    if posture.web_security == Some(false) {
        score += 25;
        reasons.push("High: webSecurity is disabled (bypasses Same-Origin Policy)".to_string());
    }

    if posture.enable_remote_module == Some(true) {
        score += 15;
        reasons.push("Medium: enableRemoteModule is enabled (deprecated remote bridge)".to_string());
    }

    if channels.len() > 15 {
        score += 10;
        reasons.push(format!("Large IPC Attack Surface: {} channels registered", channels.len()));
    }

    (score, reasons)
}
