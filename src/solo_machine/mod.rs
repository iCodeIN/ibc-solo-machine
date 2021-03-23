use std::convert::TryInto;

use prost_types::Any;
use thiserror::Error;

use crate::{
    ics::{
        core::crypto::AddressError,
        solo_machine_client::{
            client_state::ClientStateError, consensus_state::ConsensusStateError,
        },
    },
    proto::ibc::{core::client::v1::MsgCreateClient, lightclients::solomachine::v1::ClientState},
};

pub struct SoloMachine {
    pub client_state: ClientState,
}

impl SoloMachine {
    pub fn get_msg_create_client(&self) -> Result<MsgCreateClient, SoloMachineError> {
        let consensus_state = self.client_state.get_consensus_state()?;
        let address = consensus_state.get_public_key()?.address()?;
        let client_state: Any = (&self.client_state).try_into()?;
        let consensus_state: Any = consensus_state.try_into()?;

        Ok(MsgCreateClient {
            client_state: Some(client_state),
            consensus_state: Some(consensus_state),
            signer: address,
        })
    }
}

#[derive(Debug, Error)]
pub enum SoloMachineError {
    #[error("address error: {0}")]
    AddressError(#[from] AddressError),
    #[error("client state error: {0}")]
    ClientStateError(#[from] ClientStateError),
    #[error("consensus state error: {0}")]
    ConsensusStateError(#[from] ConsensusStateError),
}
