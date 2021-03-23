use thiserror::Error;

use crate::{
    ics::{
        client_semantics::validation::BasicValidation,
        core::hash_validation::{validate_hash, HashValidationError},
    },
    proto::ibc::lightclients::tendermint::v1::ConsensusState,
};

impl BasicValidation for ConsensusState {
    type Error = ConsensusStateError;

    fn validate_basic(&self) -> Result<(), Self::Error> {
        if self
            .root
            .as_ref()
            .ok_or_else(|| ConsensusStateError::NoneRoot)?
            .hash
            .is_empty()
        {
            return Err(ConsensusStateError::EmptyRoot);
        }

        validate_hash(&self.next_validators_hash)?;

        if self
            .timestamp
            .as_ref()
            .ok_or_else(|| ConsensusStateError::NoneTimestamp)?
            .seconds
            <= 0
        {
            return Err(ConsensusStateError::NegativeTimestamp);
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ConsensusStateError {
    #[error("root cannot be empty")]
    EmptyRoot,
    #[error("hash validation error: {0}")]
    HashValidationError(#[from] HashValidationError),
    #[error("timestamp must be a positive Unix time")]
    NegativeTimestamp,
    #[error("consensus state `root` cannot be `None`")]
    NoneRoot,
    #[error("consensus state `timestamp` cannot be `None`")]
    NoneTimestamp,
}
