use thiserror::Error;

use crate::{
    ics::client_semantics::validation::BasicValidation,
    proto::ibc::lightclients::solomachine::v1::{DataType, SignatureAndData},
};

impl BasicValidation for SignatureAndData {
    type Error = SignatureAndDataError;

    fn validate_basic(&self) -> Result<(), Self::Error> {
        if self.signature.is_empty() {
            return Err(SignatureAndDataError::EmptySignature);
        }

        if self.data.is_empty() {
            return Err(SignatureAndDataError::EmptySignatureData);
        }

        if self.data_type() == DataType::UninitializedUnspecified {
            return Err(SignatureAndDataError::UnspecifierDataType);
        }

        if self.timestamp == 0 {
            return Err(SignatureAndDataError::ZeroTimestamp);
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SignatureAndDataError {
    #[error("signature cannot be empty")]
    EmptySignature,
    #[error("data for signature cannot be empty")]
    EmptySignatureData,
    #[error("data type cannot be UNSPECIFIED")]
    UnspecifierDataType,
    #[error("timestamp cannot be 0")]
    ZeroTimestamp,
}
