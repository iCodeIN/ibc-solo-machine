use ibc_proto::ibc::{core::client::v1::Height, lightclients::solomachine::v1::Misbehaviour};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MisbehaviourError {}

pub trait IMisbehaviour {
    /// Returns the ID of the client that committed a misbehaviour
    fn get_client_id(&self) -> &str;

    /// Returns the sequence at which misbehaviour occurred
    ///
    /// # Note
    ///
    /// `revision_number` is always zero for solo machine
    fn get_height(&self) -> Height;
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
}
