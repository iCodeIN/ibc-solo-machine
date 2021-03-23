use std::convert::TryFrom;

use prost::{EncodeError, Message};
use thiserror::Error;

use crate::proto::ibc::lightclients::solomachine::v1::{
    DataType, Header, HeaderData, Misbehaviour, SignBytes,
};

impl TryFrom<&Header> for SignBytes {
    type Error = SignBytesError;

    fn try_from(header: &Header) -> Result<Self, Self::Error> {
        let header_data = HeaderData::from(header);
        let mut header_data_bytes = Vec::with_capacity(header_data.encoded_len());
        header_data.encode(&mut header_data_bytes)?;

        let mut sign_bytes = Self {
            sequence: header.sequence,
            timestamp: header.timestamp,
            diversifier: header.new_diversifier.clone(),
            data_type: 0,
            data: header_data_bytes,
        };

        sign_bytes.set_data_type(DataType::Header);

        Ok(sign_bytes)
    }
}

pub fn misbehaviour_sign_bytes(
    misbehaviour: &Misbehaviour,
    diversifier: &str,
) -> (SignBytes, SignBytes) {
    let signature_one = misbehaviour.signature_one.as_ref().unwrap();
    let signature_two = misbehaviour.signature_two.as_ref().unwrap();

    let mut sign_bytes_one = SignBytes {
        sequence: misbehaviour.sequence,
        timestamp: signature_one.timestamp,
        diversifier: diversifier.to_owned(),
        data_type: 0,
        data: signature_one.data.clone(),
    };
    sign_bytes_one.set_data_type(signature_one.data_type());

    let mut sign_bytes_two = SignBytes {
        sequence: misbehaviour.sequence,
        timestamp: signature_two.timestamp,
        diversifier: diversifier.to_owned(),
        data_type: 0,
        data: signature_two.data.clone(),
    };
    sign_bytes_two.set_data_type(signature_two.data_type());

    (sign_bytes_one, sign_bytes_two)
}

#[derive(Debug, Error)]
pub enum SignBytesError {
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] EncodeError),
}
