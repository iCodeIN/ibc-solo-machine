use prost::{EncodeError, Message};
use thiserror::Error;

use super::{sign_bytes::misbehaviour_sign_bytes, signature_and_data::SignatureAndDataError};
use crate::{
    ics::{
        client_semantics::validation::BasicValidation,
        core::identifier_validation::{validate_client_id, IdentifierValidationError},
    },
    proto::ibc::{core::client::v1::Height, lightclients::solomachine::v1::Misbehaviour},
};

impl Misbehaviour {
    pub fn get_height(&self) -> Height {
        Height::new(0, self.sequence)
    }

    pub fn get_sign_bytes(
        &self,
        diversifier: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), MisbehaviourError> {
        let (sign_bytes_one, sign_bytes_two) = misbehaviour_sign_bytes(self, diversifier);

        let mut bytes_one = Vec::with_capacity(sign_bytes_one.encoded_len());
        sign_bytes_one.encode(&mut bytes_one)?;

        let mut bytes_two = Vec::with_capacity(sign_bytes_two.encoded_len());
        sign_bytes_two.encode(&mut bytes_two)?;

        Ok((bytes_one, bytes_two))
    }
}

impl BasicValidation for Misbehaviour {
    type Error = MisbehaviourError;

    fn validate_basic(&self) -> Result<(), Self::Error> {
        validate_client_id(&self.client_id)?;

        if self.sequence == 0 {
            return Err(MisbehaviourError::ZeroSequence);
        }

        self.signature_one
            .as_ref()
            .ok_or_else(|| MisbehaviourError::NoneSignatureOne)?
            .validate_basic()?;
        self.signature_two
            .as_ref()
            .ok_or_else(|| MisbehaviourError::NoneSignatureTwo)?
            .validate_basic()?;

        if self.signature_one == self.signature_two {
            return Err(MisbehaviourError::EqualSignatures);
        }

        if self.signature_one.as_ref().unwrap().data == self.signature_two.as_ref().unwrap().data {
            return Err(MisbehaviourError::EqualSignatureData);
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum MisbehaviourError {
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] EncodeError),
    #[error("misbehaviour signature data must be signed over different messages")]
    EqualSignatureData,
    #[error("misbehaviour signatures cannot be equal")]
    EqualSignatures,
    #[error("invalid client identifier for solo machine: {0}")]
    InvalidClientId(#[from] IdentifierValidationError),
    #[error("missing signature one")]
    NoneSignatureOne,
    #[error("missing signature two")]
    NoneSignatureTwo,
    #[error("signature and data error: {0}")]
    SignatureAndDataError(#[from] SignatureAndDataError),
    #[error("sequence cannot be 0")]
    ZeroSequence,
}
