use thiserror::Error;

use crate::{
    ics::client_semantics::validation::BasicValidation,
    proto::ibc::lightclients::tendermint::v1::Header,
};

impl BasicValidation for Header {
    type Error = HeaderError;

    fn validate_basic(&self) -> Result<(), Self::Error> {
        todo!()
    }
}

#[derive(Debug, Error)]
pub enum HeaderError {}
