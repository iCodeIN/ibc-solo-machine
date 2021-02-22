use ibc_proto::ibc::{core::client::v1::Height, lightclients::solomachine::v1::Misbehaviour};
use thiserror::Error;

use crate::{
    identifier_validator::{validate_client_id, IdentifierValidationError},
    signature_and_data::{ISignatureAndData, SignatureAndDataError},
};

#[derive(Debug, Error)]
pub enum MisbehaviourError {
    #[error("misbehaviour signature data must be signed over different messages")]
    EqualSignatureData,
    #[error("misbehaviour signatures cannot be equal")]
    EqualSignatures,
    #[error("invalid client identifier for solo machine: {0}")]
    InvalidClientIdentifier(#[from] IdentifierValidationError),
    #[error("invalid signature: {0}")]
    InvalidSignature(#[from] SignatureAndDataError),
    #[error("missing signature one")]
    MissingSignatureOne,
    #[error("missing signature two")]
    MissingSignatureTwo,
    #[error("sequence cannot be 0")]
    ZeroSequence,
}

pub trait IMisbehaviour {
    /// Returns the ID of the client that committed a misbehaviour
    fn get_client_id(&self) -> &str;

    /// Returns the sequence at which misbehaviour occurred
    ///
    /// # Note
    ///
    /// `revision_number` is always zero for solo machine
    fn get_height(&self) -> Height;

    /// Validates misbehaviour information
    fn validate_basic(&self) -> Result<(), MisbehaviourError>;
}

impl IMisbehaviour for Misbehaviour {
    fn get_client_id(&self) -> &str {
        &self.client_id
    }

    fn get_height(&self) -> Height {
        Height {
            revision_number: 0,
            revision_height: self.sequence,
        }
    }

    fn validate_basic(&self) -> Result<(), MisbehaviourError> {
        validate_client_id(&self.client_id)?;

        if self.sequence == 0 {
            return Err(MisbehaviourError::ZeroSequence);
        }

        match self.signature_one {
            None => return Err(MisbehaviourError::MissingSignatureOne),
            Some(ref signature) => signature.validate_basic()?,
        }

        match self.signature_two {
            None => return Err(MisbehaviourError::MissingSignatureTwo),
            Some(ref signature) => signature.validate_basic()?,
        }

        let signature_one = self.signature_one.as_ref().unwrap();
        let signature_two = self.signature_two.as_ref().unwrap();

        if signature_one == signature_two {
            return Err(MisbehaviourError::EqualSignatures);
        }

        if signature_one.data == signature_two.data {
            return Err(MisbehaviourError::EqualSignatureData);
        }

        Ok(())
    }
}
