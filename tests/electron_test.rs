use rev_core::app::scan_electron_directory;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn test_electron_ipc_and_posture_scanner() {
    let temp_dir = std::env::temp_dir().join("rev_core_electron_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let preload_js = temp_dir.join("preload.js");
    let mut f1 = File::create(preload_js).unwrap();
    writeln!(
        f1,
        r#"
        const {{ ipcRenderer, contextBridge }} = require('electron');
        contextBridge.exposeInMainWorld('api', {{
            fetchData: () => ipcRenderer.invoke('get-user-data', 123),
            notify: (msg) => ipcRenderer.send('app-notify', msg)
        }});
        "#
    )
    .unwrap();

    let main_js = temp_dir.join("main.js");
    let mut f2 = File::create(main_js).unwrap();
    writeln!(
        f2,
        r#"
        const {{ app, BrowserWindow, ipcMain }} = require('electron');
        ipcMain.handle('get-user-data', async (e, id) => {{ return {{ id }}; }});
        ipcMain.on('app-notify', (e, msg) => {{ console.log(msg); }});

        const win = new BrowserWindow({{
            webPreferences: {{
                nodeIntegration: true,
                contextIsolation: false
            }}
        }});
        "#
    )
    .unwrap();

    let report = scan_electron_directory(&temp_dir).expect("Failed to scan directory");

    assert_eq!(report.total_script_files, 2);
    assert!(report.ipc_channels.iter().any(|c| c.channel == "get-user-data" && c.call_type == "renderer_invoke"));
    assert!(report.ipc_channels.iter().any(|c| c.channel == "app-notify" && c.call_type == "renderer_send"));
    assert!(report.ipc_channels.iter().any(|c| c.channel == "get-user-data" && c.call_type == "main_handle"));
    assert!(report.ipc_channels.iter().any(|c| c.channel == "api" && c.call_type == "context_bridge"));

    assert_eq!(report.security_posture.node_integration, Some(true));
    assert_eq!(report.security_posture.context_isolation, Some(false));
    assert!(report.risk_score >= 70);

    let _ = fs::remove_dir_all(&temp_dir);
}
