pub mod error;
pub mod evidence;

pub use error::{RevError, RevResult};
pub use evidence::{compute_sha256, Evidence, EvidenceLedger, ResidualUnknown};
