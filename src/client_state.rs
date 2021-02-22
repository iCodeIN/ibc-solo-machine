use ibc_proto::ibc::{
    core::client::v1::Height,
    lightclients::solomachine::v1::{ClientState, ConsensusState},
};
use thiserror::Error;

use crate::consensus_state::{ConsensusStateError, IConsensusState};

#[derive(Debug, Error)]
pub enum ClientStateError {
    #[error("consensus state error: {0}")]
    ConsensusStateError(#[from] ConsensusStateError),
    #[error("consensus state cannot be `None`")]
    NoneConsensusState,
    #[error("sequence cannot be 0")]
    ZeroSequence,
}

pub trait IClientState {
    /// Creates a new instance of Client State
    fn initialize(
        last_sequence: u64,
        consensus_state: ConsensusState,
        allow_update_after_proposal: bool,
    ) -> Self;

    /// Returns the latest sequence number
    ///
    /// # Note
    ///
    /// `revision_number` is always zero for solo machine
    fn get_latest_height(&self) -> Height;

    /// Returns `true` if the client is frozen
    fn is_frozen(&self) -> bool;

    /// Returns frozen sequence of the client
    ///
    /// # Note
    ///
    /// `revision_number` is always zero for solo machine
    fn get_frozen_height(&self) -> Height;

    /// Performs basic validation of the client state fields
    fn validate(&self) -> Result<(), ClientStateError>;
}

impl IClientState for ClientState {
    fn initialize(
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

    fn get_latest_height(&self) -> Height {
        Height {
            revision_number: 0,
            revision_height: self.sequence,
        }
    }

    fn is_frozen(&self) -> bool {
        self.frozen_sequence != 0
    }

    fn get_frozen_height(&self) -> Height {
        Height {
            revision_number: 0,
            revision_height: self.frozen_sequence,
        }
    }

    fn validate(&self) -> Result<(), ClientStateError> {
        if self.sequence == 0 {
            return Err(ClientStateError::ZeroSequence);
        }

        match self.consensus_state {
            None => Err(ClientStateError::NoneConsensusState),
            Some(ref consensus_state) => consensus_state.validate_basic().map_err(Into::into),
        }
    }
}
