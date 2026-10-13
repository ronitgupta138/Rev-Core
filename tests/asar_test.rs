use rev_core::app::AsarArchive;
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn test_synthetic_asar_roundtrip() {
    let temp_dir = std::env::temp_dir().join("rev_core_asar_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    let asar_path = temp_dir.join("test.asar");
    let extract_dir = temp_dir.join("extracted");

    // File 1: "package.json" -> "{\"name\": \"test-app\"}"
    let file1_content = b"{\"name\": \"test-app\"}";
    // File 2: "src/main.js" -> "console.log('hello');"
    let file2_content = b"console.log('hello');";

    let header_json = json!({
        "files": {
            "package.json": {
                "size": file1_content.len(),
                "offset": "0"
            },
            "src": {
                "files": {
                    "main.js": {
                        "size": file2_content.len(),
                        "offset": file1_content.len().to_string()
                    }
                }
            }
        }
    });

    let header_bytes = serde_json::to_vec(&header_json).unwrap();
    let json_size = header_bytes.len() as u32;

    // Build 16-byte pickle header
    let mut asar_bytes = Vec::new();
    asar_bytes.extend_from_slice(&4u32.to_le_bytes()); // uint32 size
    asar_bytes.extend_from_slice(&(json_size + 8).to_le_bytes()); // header pickle payload size
    asar_bytes.extend_from_slice(&4u32.to_le_bytes()); // inner payload size
    asar_bytes.extend_from_slice(&json_size.to_le_bytes()); // json string byte size
    asar_bytes.extend_from_slice(&header_bytes); // json string
    asar_bytes.extend_from_slice(file1_content);
    asar_bytes.extend_from_slice(file2_content);

    let mut f = File::create(&asar_path).unwrap();
    f.write_all(&asar_bytes).unwrap();
    drop(f);

    // Open and verify with AsarArchive
    let archive = AsarArchive::open(&asar_path).expect("Failed to open valid ASAR");
    assert_eq!(archive.metadata.total_files, 2);
    assert_eq!(archive.metadata.total_dirs, 1);

    // Extract all
    let extracted = archive.extract_all(&extract_dir).expect("Failed to extract");
    assert_eq!(extracted, 2);

    let extracted_pkg = fs::read(extract_dir.join("package.json")).unwrap();
    assert_eq!(extracted_pkg, file1_content);

    let extracted_js = fs::read(extract_dir.join("src/main.js")).unwrap();
    assert_eq!(extracted_js, file2_content);

    let _ = fs::remove_dir_all(&temp_dir);
}
