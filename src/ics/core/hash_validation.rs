use sha2::{Digest, Sha256};
use thiserror::Error;

pub fn validate_hash(hash: impl AsRef<[u8]>) -> Result<(), HashValidationError> {
    let hash = hash.as_ref();

    if hash.len() > 0 && hash.len() != Sha256::output_size() {
        return Err(HashValidationError::InvalidLength {
            expected: Sha256::output_size(),
            actual: hash.len(),
        });
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum HashValidationError {
    #[error("expected hash size to be {expected} bytes, got {actual} bytes")]
    InvalidLength { expected: usize, actual: usize },
}
