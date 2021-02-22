use ibc_proto::ibc::{core::client::v1::Height, lightclients::solomachine::v1::Header};
use prost_types::Any;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("diversifier cannot contain only spaces")]
    EmptyDiversifier,
    #[error("signature cannot be empty")]
    EmptySignature,
    #[error("header `new_public_key` cannot be `None`")]
    NoneNewPublicKey,
    #[error("sequence number cannot be zero")]
    ZeroSequenceNumber,
    #[error("timestamp cannot be zero")]
    ZeroTimestamp,
}

pub trait IHeader {
    /// Returns the current sequence number as the height
    ///
    /// # Note
    ///
    /// `revision_number` is always zero for solo machine
    fn get_height(&self) -> Height;

    /// Deserializes public key into concrete type. An error is returned if public key is `None` or the cached value is
    /// not a public key
    ///
    /// TODO: Return concrete public key type
    fn get_public_key(&self) -> Result<&Any, HeaderError>;

    /// Ensures that the sequence, signature and public key have all been initialized.
    fn validate_basic(&self) -> Result<(), HeaderError>;
}

impl IHeader for Header {
    fn get_height(&self) -> Height {
        Height {
            revision_number: 0,
            revision_height: self.sequence,
        }
    }

    fn get_public_key(&self) -> Result<&Any, HeaderError> {
        match self.new_public_key {
            Some(ref public_key) => Ok(public_key), // TODO: Return concrete public key type
            None => Err(HeaderError::NoneNewPublicKey),
        }
    }

    fn validate_basic(&self) -> Result<(), HeaderError> {
        if self.sequence == 0 {
            return Err(HeaderError::ZeroSequenceNumber);
        }

        if self.timestamp == 0 {
            return Err(HeaderError::ZeroTimestamp);
        }

        if self.new_diversifier.trim().is_empty() {
            return Err(HeaderError::EmptyDiversifier);
        }

        let _ = self.get_public_key()?; // TODO: Validate returned public key

        Ok(())
    }
}
