use std::convert::{TryFrom, TryInto};

use prost::{EncodeError, Message};
use prost_types::Any;
use thiserror::Error;

use crate::{
    ics::{
        client_semantics::{consensus_state::IConsensusState, validation::BasicValidation},
        core::crypto::{PublicKey, PublicKeyError},
    },
    proto::ibc::lightclients::solomachine::v1::ConsensusState,
};

const TYPE_URL: &str = "/ibc.lightclients.solomachine.v1.ConsensusState";

impl ConsensusState {
    pub fn get_public_key(&self) -> Result<PublicKey, ConsensusStateError> {
        self.public_key
            .as_ref()
            .ok_or_else(|| ConsensusStateError::NonePublicKey)?
            .try_into()
            .map_err(Into::into)
    }

    pub fn type_url() -> &'static str {
        TYPE_URL
    }
}

impl IConsensusState for ConsensusState {
    fn get_timestamp(&self) -> u64 {
        self.timestamp
    }
}

impl BasicValidation for ConsensusState {
    type Error = ConsensusStateError;

    fn validate_basic(&self) -> Result<(), Self::Error> {
        if self.timestamp == 0 {
            return Err(ConsensusStateError::ZeroTimestamp);
        }

        if self.diversifier.trim().is_empty() {
            return Err(ConsensusStateError::EmptyDiversifier);
        }

        if self.get_public_key()?.is_empty() {
            return Err(ConsensusStateError::EmptyPublicKey);
        }

        Ok(())
    }
}

impl TryFrom<&ConsensusState> for Any {
    type Error = ConsensusStateError;

    fn try_from(consensus_state: &ConsensusState) -> Result<Self, Self::Error> {
        let mut value = Vec::with_capacity(consensus_state.encoded_len());
        consensus_state.encode(&mut value)?;

        Ok(Any {
            type_url: ConsensusState::type_url().to_owned(),
            value,
        })
    }
}

#[derive(Debug, Error)]
pub enum ConsensusStateError {
    #[error("diversifier cannot contain only spaces")]
    EmptyDiversifier,
    #[error("public key cannot be empty")]
    EmptyPublicKey,
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] EncodeError),
    #[error("consensus state `public_key` cannot be `None`")]
    NonePublicKey,
    #[error("public key error: {0}")]
    PublicKeyError(#[from] PublicKeyError),
    #[error("timestamp cannot be 0")]
    ZeroTimestamp,
}
