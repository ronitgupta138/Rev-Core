use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFinding {
    pub algorithm: String,
    pub description: String,
    pub offset: usize,
    pub confidence: f32,
}

pub fn scan_crypto_constants(data: &[u8]) -> Vec<CryptoFinding> {
    let mut findings = Vec::new();

    // 1. AES S-Box prefix: 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    let aes_sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ];
    if let Some(pos) = find_subsequence(data, &aes_sbox) {
        findings.push(CryptoFinding {
            algorithm: "AES (Rijndael)".to_string(),
            description: "Forward S-Box substitution table identified".to_string(),
            offset: pos,
            confidence: 0.99,
        });
    }

    // 2. AES Inverted S-Box prefix: 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
    let aes_inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    ];
    if let Some(pos) = find_subsequence(data, &aes_inv_sbox) {
        findings.push(CryptoFinding {
            algorithm: "AES (Rijndael)".to_string(),
            description: "Inverse S-Box substitution table identified".to_string(),
            offset: pos,
            confidence: 0.99,
        });
    }

    // 3. ChaCha20 constant string: "expand 32-byte k"
    let chacha_magic = b"expand 32-byte k";
    if let Some(pos) = find_subsequence(data, chacha_magic) {
        findings.push(CryptoFinding {
            algorithm: "ChaCha20 / Poly1305".to_string(),
            description: "Quarter-round state initialization constant ('expand 32-byte k')".to_string(),
            offset: pos,
            confidence: 1.00,
        });
    }

    // 4. SHA-256 K-constants (first 4 words in Little Endian: 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5)
    let sha256_k_le = [
        0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71, 0xcf, 0xfb, 0xc0, 0xb5, 0xa5, 0xdb, 0xb5, 0xe9,
    ];
    if let Some(pos) = find_subsequence(data, &sha256_k_le) {
        findings.push(CryptoFinding {
            algorithm: "SHA-256".to_string(),
            description: "SHA-256 round constant sequence (K[0..3] Little-Endian)".to_string(),
            offset: pos,
            confidence: 0.99,
        });
    }

    // 5. MD5 Initial State Words: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 (Little Endian)
    let md5_state = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    if let Some(pos) = find_subsequence(data, &md5_state) {
        findings.push(CryptoFinding {
            algorithm: "MD5".to_string(),
            description: "MD5 state buffer initialization constants (A, B, C, D)".to_string(),
            offset: pos,
            confidence: 0.98,
        });
    }

    findings
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}
