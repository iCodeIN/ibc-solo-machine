use std::convert::TryInto;

use prost::{EncodeError, Message};
use thiserror::Error;

use super::sign_bytes::SignBytesError;
use crate::{
    ics::{
        client_semantics::validation::BasicValidation,
        core::crypto::{PublicKey, PublicKeyError},
    },
    proto::ibc::{
        core::client::v1::Height,
        lightclients::solomachine::v1::{Header, HeaderData, SignBytes},
    },
};

impl Header {
    pub fn get_height(&self) -> Height {
        Height::new(0, self.sequence)
    }

    pub fn get_public_key(&self) -> Result<PublicKey, HeaderError> {
        self.new_public_key
            .as_ref()
            .ok_or_else(|| HeaderError::NoneNewPublicKey)?
            .try_into()
            .map_err(Into::into)
    }

    pub fn get_sign_bytes(&self) -> Result<Vec<u8>, HeaderError> {
        let sign_bytes: SignBytes = self.try_into()?;
        let mut bytes = Vec::with_capacity(sign_bytes.encoded_len());
        sign_bytes.encode(&mut bytes)?;
        Ok(bytes)
    }
}

impl BasicValidation for Header {
    type Error = HeaderError;

    fn validate_basic(&self) -> Result<(), Self::Error> {
        if self.sequence == 0 {
            return Err(HeaderError::ZeroSequenceNumber);
        }

        if self.timestamp == 0 {
            return Err(HeaderError::ZeroTimestamp);
        }

        if self.new_diversifier.trim().is_empty() {
            return Err(HeaderError::EmptyDiversifier);
        }

        if self.get_public_key()?.is_empty() {
            return Err(HeaderError::EmptyNewPublicKey);
        }

        Ok(())
    }
}

impl From<&Header> for HeaderData {
    fn from(header: &Header) -> Self {
        HeaderData {
            new_pub_key: header.new_public_key.clone(),
            new_diversifier: header.new_diversifier.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("diversifier cannot contain only spaces")]
    EmptyDiversifier,
    #[error("new public key cannot be empty")]
    EmptyNewPublicKey,
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] EncodeError),
    #[error("header `new_public_key` cannot be `None`")]
    NoneNewPublicKey,
    #[error("public key error: {0}")]
    PublicKeyError(#[from] PublicKeyError),
    #[error("sign bytes error: {0}")]
    SignBytesError(#[from] SignBytesError),
    #[error("sequence number cannot be zero")]
    ZeroSequenceNumber,
    #[error("timestamp cannot be zero")]
    ZeroTimestamp,
}
