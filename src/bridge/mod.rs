use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerStatus {
    pub backend: String,
    pub available: bool,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledFunction {
    pub symbol: String,
    pub backend: String,
    pub pseudocode: String,
    pub execution_time_ms: u64,
}

pub struct DecompilerBridge;

impl DecompilerBridge {
    pub async fn detect_backends() -> Vec<DecompilerStatus> {
        let mut backends = Vec::new();

        // Check rizin
        let rizin_path = which_cmd("rizin").await.or(which_cmd("rz-bin").await);
        backends.push(DecompilerStatus {
            backend: "Rizin (rz-bin)".to_string(),
            available: rizin_path.is_some(),
            path: rizin_path,
        });

        // Check radare2
        let r2_path = which_cmd("radare2").await;
        backends.push(DecompilerStatus {
            backend: "Radare2 (r2)".to_string(),
            available: r2_path.is_some(),
            path: r2_path,
        });

        // Check ghidra headless
        let ghidra_path = which_cmd("analyzeHeadless").await;
        backends.push(DecompilerStatus {
            backend: "Ghidra (analyzeHeadless)".to_string(),
            available: ghidra_path.is_some(),
            path: ghidra_path,
        });

        backends
    }

    pub async fn decompile_symbol(
        binary_path: impl AsRef<Path>,
        symbol: &str,
        timeout_secs: u64,
    ) -> Result<DecompiledFunction, String> {
        let path = binary_path.as_ref();
        if !path.exists() {
            return Err(format!("Binary file does not exist: {}", path.display()));
        }

        // Try rizin or r2 first
        if let Some(rz) = which_cmd("rizin").await.or(which_cmd("radare2").await) {
            let t0 = std::time::Instant::now();
            let mut cmd = Command::new(&rz);
            // -q: quiet, -c: run commands (aa: analyze, s <sym>: seek, pdc: pseudo decompilation)
            cmd.arg("-q")
                .arg("-c")
                .arg(format!("aaa; s {}; pdc", symbol))
                .arg(path.as_os_str())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let child = cmd.spawn().map_err(|e| format!("Failed to spawn {rz}: {e}"))?;

            let res = timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await;
            match res {
                Ok(Ok(output)) => {
                    let pseudocode = String::from_utf8_lossy(&output.stdout).to_string();
                    if !pseudocode.trim().is_empty() {
                        return Ok(DecompiledFunction {
                            symbol: symbol.to_string(),
                            backend: rz,
                            pseudocode,
                            execution_time_ms: t0.elapsed().as_millis() as u64,
                        });
                    }
                }
                Ok(Err(e)) => return Err(format!("Decompiler execution failed: {e}")),
                Err(_) => return Err(format!("Decompilation timed out after {timeout_secs}s")),
            }
        }

        Err(format!(
            "No headless decompiler (rizin, radare2, or ghidra) found in PATH. Install rizin via your package manager or use 'rev-core disasm' / 'rev-core cfg' for native in-process x86_64 analysis."
        ))
    }
}

async fn which_cmd(name: &str) -> Option<String> {
    let mut cmd = Command::new("which");
    cmd.arg(name).stdout(Stdio::piped()).stderr(Stdio::null());
    if let Ok(output) = cmd.output().await {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() {
                return Some(path_str);
            }
        }
    }
    None
}
