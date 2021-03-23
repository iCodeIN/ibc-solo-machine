use std::convert::TryFrom;

use prost::{DecodeError, EncodeError, Message};
use prost_types::Any;
use thiserror::Error;

use super::{
    consensus_state::ConsensusStateError, header::HeaderError, misbehaviour::MisbehaviourError,
};
use crate::{
    ics::{
        client_semantics::{client_state::IClientState, validation::BasicValidation},
        core::crypto::{verify_signature, SignatureVerificationError},
    },
    proto::{
        cosmos::tx::signing::v1beta1::signature_descriptor::Data as Signature,
        ibc::{
            core::client::v1::Height,
            lightclients::solomachine::v1::{ClientState, ConsensusState, Header, Misbehaviour},
        },
    },
};

const TYPE_URL: &str = "/ibc.lightclients.solomachine.v1.ClientState";

impl ClientState {
    pub fn new(
        last_sequence: u64,
        consensus_state: ConsensusState,
        allow_update_after_proposal: bool,
    ) -> Self {
        Self {
            sequence: last_sequence,
            frozen_sequence: 0,
            consensus_state: Some(consensus_state),
            allow_update_after_proposal,
        }
    }

    pub fn get_latest_height(&self) -> Height {
        Height::new(0, self.sequence)
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen_sequence != 0
    }

    pub fn get_frozen_height(&self) -> Height {
        Height::new(0, self.frozen_sequence)
    }

    pub fn get_consensus_state(&self) -> Result<&ConsensusState, ClientStateError> {
        self.consensus_state
            .as_ref()
            .ok_or_else(|| ClientStateError::NoneConsensusState)
    }

    pub fn type_url() -> &'static str {
        TYPE_URL
    }
}

impl IClientState for ClientState {
    type ConsensusState = ConsensusState;
    type Error = ClientStateError;
    type Header = Header;
    type Misbehaviour = Misbehaviour;

    fn initialize(consensus_state: Self::ConsensusState) -> Self {
        Self::new(0, consensus_state, true)
    }

    fn check_header_and_update_state(&mut self, header: Self::Header) -> Result<(), Self::Error> {
        header.validate_basic().map_err(HeaderCheckError::from)?;
        self.validate_basic()?;

        let consensus_state = self.consensus_state.as_ref().unwrap();

        if header.sequence != self.sequence {
            return Err(HeaderCheckError::SequenceMismatch {
                header_sequence: header.sequence,
                state_sequence: self.sequence,
            }
            .into());
        }

        if header.timestamp < consensus_state.timestamp {
            return Err(HeaderCheckError::InvalidTimestamp {
                header_timestamp: header.timestamp,
                consensus_state_timestamp: consensus_state.timestamp,
            }
            .into());
        }

        let header_sign_bytes = header.get_sign_bytes().map_err(HeaderCheckError::from)?;
        let signature_data = Signature::decode(header.signature.as_ref())
            .map_err(HeaderCheckError::from)?
            .sum
            .ok_or_else(|| HeaderCheckError::MissingSignatureData)?;
        let public_key = consensus_state.get_public_key()?;

        verify_signature(&public_key, &header_sign_bytes, &signature_data)
            .map_err(HeaderCheckError::from)?;

        let mut consensus_state = self.consensus_state.as_mut().unwrap();

        consensus_state.public_key = header.new_public_key;
        consensus_state.diversifier = header.new_diversifier;
        consensus_state.timestamp = header.timestamp;

        self.sequence += 1;

        Ok(())
    }

    fn check_misbehaviour_and_update_state(
        &mut self,
        misbehaviour: Self::Misbehaviour,
    ) -> Result<(), Self::Error> {
        misbehaviour
            .validate_basic()
            .map_err(MisbehaviourCheckError::from)?;
        self.validate_basic()?;

        if self.is_frozen() {
            return Err(MisbehaviourCheckError::ClientFrozen.into());
        }

        let consensus_state = self.consensus_state.as_ref().unwrap();
        let signature_one = misbehaviour.signature_one.as_ref().unwrap();
        let signature_two = misbehaviour.signature_two.as_ref().unwrap();

        if signature_one.timestamp < consensus_state.timestamp {
            return Err(MisbehaviourCheckError::SignatureOneInvalidTimestamp {
                signature_timestamp: signature_one.timestamp,
                consensus_state_timestamp: consensus_state.timestamp,
            }
            .into());
        }
        if signature_two.timestamp < consensus_state.timestamp {
            return Err(MisbehaviourCheckError::SignatureTwoInvalidTimestamp {
                signature_timestamp: signature_two.timestamp,
                consensus_state_timestamp: consensus_state.timestamp,
            }
            .into());
        }

        let (sign_bytes_one, sign_bytes_two) = misbehaviour
            .get_sign_bytes(&consensus_state.diversifier)
            .map_err(MisbehaviourCheckError::from)?;

        let signature_data_one = Signature::decode(signature_one.signature.as_ref())
            .map_err(MisbehaviourCheckError::from)?
            .sum
            .ok_or_else(|| MisbehaviourCheckError::MissingSignatureOneData)?;
        let signature_data_two = Signature::decode(signature_two.signature.as_ref())
            .map_err(MisbehaviourCheckError::from)?
            .sum
            .ok_or_else(|| MisbehaviourCheckError::MissingSignatureOneData)?;

        let public_key = consensus_state.get_public_key()?;

        verify_signature(&public_key, &sign_bytes_one, &signature_data_one)
            .map_err(MisbehaviourCheckError::from)?;
        verify_signature(&public_key, &sign_bytes_two, &signature_data_two)
            .map_err(MisbehaviourCheckError::from)?;

        self.frozen_sequence = misbehaviour.sequence;

        Ok(())
    }
}

impl BasicValidation for ClientState {
    type Error = ClientStateError;

    fn validate_basic(&self) -> Result<(), Self::Error> {
        if self.sequence == 0 {
            return Err(ClientStateError::ZeroSequence);
        }

        self.consensus_state
            .as_ref()
            .ok_or_else(|| ClientStateError::NoneConsensusState)?
            .validate_basic()
            .map_err(Into::into)
    }
}

impl TryFrom<&ClientState> for Any {
    type Error = ClientStateError;

    fn try_from(client_state: &ClientState) -> Result<Self, Self::Error> {
        let mut value = Vec::with_capacity(client_state.encoded_len());
        client_state.encode(&mut value)?;

        Ok(Any {
            type_url: ClientState::type_url().to_owned(),
            value,
        })
    }
}

#[derive(Debug, Error)]
pub enum ClientStateError {
    #[error("consensus state error: {0}")]
    ConsensusStateError(#[from] ConsensusStateError),
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] EncodeError),
    #[error("header check error: {0}")]
    HeaderCheckError(#[from] HeaderCheckError),
    #[error("consensus state cannot be `None`")]
    NoneConsensusState,
    #[error("misbehaviour check error")]
    MisbehaviourCheckError(#[from] MisbehaviourCheckError),
    #[error("sequence cannot be 0")]
    ZeroSequence,
}

#[derive(Debug, Error)]
pub enum HeaderCheckError {
    #[error("protobuf decode error: {0}")]
    DecodeError(#[from] DecodeError),
    #[error("header error: {0}")]
    HeaderError(#[from] HeaderError),
    #[error("header timestamp is less than to the consensus state timestamp ({header_timestamp} < {consensus_state_timestamp})")]
    InvalidTimestamp {
        header_timestamp: u64,
        consensus_state_timestamp: u64,
    },
    #[error("missing signature data")]
    MissingSignatureData,
    #[error("header sequence does not match the client state sequence ({header_sequence} != {state_sequence})")]
    SequenceMismatch {
        header_sequence: u64,
        state_sequence: u64,
    },
    #[error("signature verification error: {0}")]
    SignatureVerificationError(#[from] SignatureVerificationError),
}

#[derive(Debug, Error)]
pub enum MisbehaviourCheckError {
    #[error("client is already frozen")]
    ClientFrozen,
    #[error("protobuf decode error: {0}")]
    DecodeError(#[from] DecodeError),
    #[error("misbehaviour error: {0}")]
    MisbehaviourError(#[from] MisbehaviourError),
    #[error("missing signature one data")]
    MissingSignatureOneData,
    #[error("missing signature two data")]
    MissingSignatureTwoData,
    #[error("signature one timestamp is less than to the consensus state timestamp ({signature_timestamp} < {consensus_state_timestamp})")]
    SignatureOneInvalidTimestamp {
        signature_timestamp: u64,
        consensus_state_timestamp: u64,
    },
    #[error("signature two timestamp is less than to the consensus state timestamp ({signature_timestamp} < {consensus_state_timestamp})")]
    SignatureTwoInvalidTimestamp {
        signature_timestamp: u64,
        consensus_state_timestamp: u64,
    },
    #[error("signature verification error: {0}")]
    SignatureVerificationError(#[from] SignatureVerificationError),
}
