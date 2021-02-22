use ibc_proto::ibc::lightclients::solomachine::v1::{DataType, SignatureAndData};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureAndDataError {
    #[error("signature cannot be empty")]
    EmptySignature,
    #[error("data for signature cannot be empty")]
    EmptySignatureData,
    #[error("data type cannot be UNSPECIFIED")]
    UnspecifiedDataType,
    #[error("timestamp cannot be 0")]
    ZeroTimestamp,
}

pub trait ISignatureAndData {
    /// Ensures that the signature and data fields are non-empty
    fn validate_basic(&self) -> Result<(), SignatureAndDataError>;
}

impl ISignatureAndData for SignatureAndData {
    fn validate_basic(&self) -> Result<(), SignatureAndDataError> {
        if self.signature.is_empty() {
            return Err(SignatureAndDataError::EmptySignature);
        }

        if self.data.is_empty() {
            return Err(SignatureAndDataError::EmptySignatureData);
        }

        if self.data_type() == DataType::UninitializedUnspecified {
            return Err(SignatureAndDataError::UnspecifiedDataType);
        }

        if self.timestamp == 0 {
            return Err(SignatureAndDataError::ZeroTimestamp);
        }

        Ok(())
    }
}
