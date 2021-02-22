use ibc_proto::ibc::lightclients::solomachine::v1::ConsensusState;
use prost_types::Any;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConsensusStateError {
    #[error("diversifier cannot contain only spaces")]
    EmptyDiversifier,
    #[error("consensus state PublicKey cannot be `None`")]
    NonePublicKey,
    #[error("timestamp cannot be 0")]
    ZeroTimestamp,
}

pub trait IConsensusState {
    /// Returns timestamp in consensus state
    fn get_timestamp(&self) -> u64;

    /// Deserializes public key into concrete type. An error is returned if public key is `None` or the cached value is
    /// not a public key
    ///
    /// TODO: Return concrete public key type
    fn get_public_key(&self) -> Result<&Any, ConsensusStateError>;

    /// Defines basic validation for the solo machine consensus state
    fn validate_basic(&self) -> Result<(), ConsensusStateError>;
}

impl IConsensusState for ConsensusState {
    fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    fn get_public_key(&self) -> Result<&Any, ConsensusStateError> {
        match self.public_key {
            Some(ref public_key) => Ok(public_key), // TODO: Return concrete public key type
            None => Err(ConsensusStateError::NonePublicKey),
        }
    }

    fn validate_basic(&self) -> Result<(), ConsensusStateError> {
        if self.timestamp == 0 {
            return Err(ConsensusStateError::ZeroTimestamp);
        }

        if self.diversifier.trim().is_empty() {
            return Err(ConsensusStateError::EmptyDiversifier);
        }

        let _ = self.get_public_key()?; // TODO: Validate returned public key

        Ok(())
    }
}
