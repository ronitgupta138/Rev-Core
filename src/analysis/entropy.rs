use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    pub total_bytes: usize,
    pub entropy: f64,
    pub is_likely_packed: bool,
    pub classification: String,
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

pub fn analyze_entropy(data: &[u8]) -> EntropyReport {
    let entropy = calculate_entropy(data);
    let is_likely_packed = entropy > 7.2;

    let classification = if entropy > 7.5 {
        "High Entropy (Likely Encrypted or Heavily Packed)".to_string()
    } else if entropy > 7.0 {
        "Elevated Entropy (Compressed Code or Packed Sections)".to_string()
    } else if entropy > 5.5 {
        "Standard Native Code / Instruction Density".to_string()
    } else {
        "Low Entropy (Plaintext or Sparse Structured Data)".to_string()
    };

    EntropyReport {
        total_bytes: data.len(),
        entropy,
        is_likely_packed,
        classification,
    }
}
