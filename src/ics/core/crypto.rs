use std::convert::TryFrom;

use prost::{DecodeError, EncodeError, Message};
use prost_types::Any;
use ripemd160::{Digest, Ripemd160};
use sha2::Sha256;
use thiserror::Error;

use crate::proto::cosmos::{
    crypto::{
        ed25519::PubKey as Ed25519PubKey, multisig::LegacyAminoPubKey as MultisigPubKey,
        secp256k1::PubKey as Secp256k1PubKey,
    },
    tx::signing::v1beta1::signature_descriptor::data::{
        Multi as MultiSignatureData, Sum as SignatureData,
    },
};

pub const SECP256K1_PUB_KEY_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";
pub const ED25519_PUB_KEY_TYPE_URL: &str = "/cosmos.crypto.ed25519.PubKey";
pub const MULTISIG_PUB_KEY_TYPE_URL: &str = "/cosmos.crypto.multisig.LegacyAminoPubKey";

pub enum PublicKey {
    Secp256k1(Secp256k1PubKey),
    Ed25519(Ed25519PubKey),
    Multisig(MultisigPubKey),
}

impl PublicKey {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Secp256k1(Secp256k1PubKey { ref key }) => key.is_empty(),
            Self::Ed25519(Ed25519PubKey { ref key }) => key.is_empty(),
            Self::Multisig(ref key) => key.encoded_len() == 0,
        }
    }

    pub fn address(&self) -> Result<String, AddressError> {
        match self {
            Self::Secp256k1(ref key) => key.address(),
            Self::Ed25519(ref key) => key.address(),
            Self::Multisig(ref key) => key.address(),
        }
    }
}

impl TryFrom<&Any> for PublicKey {
    type Error = PublicKeyError;

    fn try_from(raw: &Any) -> Result<Self, Self::Error> {
        match raw.type_url.as_str() {
            SECP256K1_PUB_KEY_TYPE_URL => Secp256k1PubKey::decode(raw.value.as_ref())
                .map(PublicKey::Secp256k1)
                .map_err(Into::into),
            ED25519_PUB_KEY_TYPE_URL => Ed25519PubKey::decode(raw.value.as_ref())
                .map(PublicKey::Ed25519)
                .map_err(Into::into),
            MULTISIG_PUB_KEY_TYPE_URL => MultisigPubKey::decode(raw.value.as_ref())
                .map(PublicKey::Multisig)
                .map_err(Into::into),
            _ => Err(PublicKeyError::UnknownType(raw.type_url.to_owned())),
        }
    }
}

impl TryFrom<&PublicKey> for Any {
    type Error = PublicKeyError;

    fn try_from(public_key: &PublicKey) -> Result<Self, Self::Error> {
        match public_key {
            PublicKey::Secp256k1(public_key) => {
                let mut value = Vec::with_capacity(public_key.encoded_len());
                public_key.encode(&mut value)?;

                Ok(Self {
                    type_url: SECP256K1_PUB_KEY_TYPE_URL.to_owned(),
                    value,
                })
            }
            PublicKey::Ed25519(public_key) => {
                let mut value = Vec::with_capacity(public_key.encoded_len());
                public_key.encode(&mut value)?;

                Ok(Self {
                    type_url: ED25519_PUB_KEY_TYPE_URL.to_owned(),
                    value,
                })
            }
            PublicKey::Multisig(public_key) => {
                let mut value = Vec::with_capacity(public_key.encoded_len());
                public_key.encode(&mut value)?;

                Ok(Self {
                    type_url: MULTISIG_PUB_KEY_TYPE_URL.to_owned(),
                    value,
                })
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum PublicKeyError {
    #[error("protobuf decode error: {0}")]
    DecodeError(#[from] DecodeError),
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] EncodeError),
    #[error("unknown public key type: {0}")]
    UnknownType(String),
}

impl Secp256k1PubKey {
    pub fn verify_signature(
        &self,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError> {
        let verify_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(self.key.as_ref())?;
        let signature = k256::ecdsa::Signature::try_from(signature)?;
        k256::ecdsa::signature::Verifier::verify(&verify_key, msg, &signature).map_err(Into::into)
    }

    pub fn address(&self) -> Result<String, AddressError> {
        let verify_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(self.key.as_ref())?;

        let mut hasher = Sha256::new();
        hasher.update(verify_key.to_bytes());
        let result = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(result);
        let result = hasher.finalize();

        Ok(hex::encode(result))
    }
}

impl Ed25519PubKey {
    pub fn verify_signature(
        &self,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError> {
        if signature.len() != 64 {
            return Err(SignatureVerificationError::InvalidSignatureData(
                "signature length should be equal to 64".to_owned(),
            ));
        }

        let mut sig = [0; 64];
        sig.copy_from_slice(&signature);

        let signature = ed25519_dalek::Signature::new(sig);
        let public_key = ed25519_dalek::PublicKey::from_bytes(self.key.as_ref())?;

        ed25519_dalek::Verifier::verify(&public_key, msg, &signature).map_err(Into::into)
    }

    pub fn address(&self) -> Result<String, AddressError> {
        let public_key = ed25519_dalek::PublicKey::from_bytes(self.key.as_ref())?;

        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let result = hasher.finalize();

        Ok(hex::encode(&result[..20]))
    }
}

impl MultisigPubKey {
    pub fn verify_multi_signature(
        &self,
        msg: &[u8],
        signature_data: &MultiSignatureData,
    ) -> Result<(), SignatureVerificationError> {
        let threshold = usize::try_from(self.threshold).unwrap();

        let bit_array = signature_data.bitarray.as_ref().ok_or_else(|| {
            SignatureVerificationError::InvalidSignatureData(
                "missing bit array from signature data".to_owned(),
            )
        })?;
        let signatures = &signature_data.signatures;

        let size = bit_array.len();

        // ensure bit array is the correct size
        if self.public_keys.len() != size {
            return Err(SignatureVerificationError::InvalidSignatureData(format!(
                "bit array size is incorrect {}",
                size
            )));
        }

        // ensure size of signature list
        if signatures.len() < threshold || signatures.len() > size {
            return Err(SignatureVerificationError::InvalidSignatureData(format!(
                "signature size is incorrect {}",
                signatures.len()
            )));
        }

        // ensure at least k signatures are set
        if bit_array.num_true_bits_before(size) < threshold {
            return Err(SignatureVerificationError::InvalidSignatureData(format!(
                "minimum number of signatures not set, have {}, expected {}",
                bit_array.num_true_bits_before(size),
                threshold
            )));
        }

        let mut signature_index = 0;

        for i in 0..size {
            if bit_array.get(i) {
                let signature = &signatures[signature_index];

                let signature_data = signature.sum.as_ref().ok_or_else(|| {
                    SignatureVerificationError::InvalidSignatureData(
                        "missing signature data".to_owned(),
                    )
                })?;

                verify_signature(
                    &PublicKey::try_from(&self.public_keys[i])?,
                    msg,
                    &signature_data,
                )?;

                signature_index += 1;
            }
        }

        Ok(())
    }

    pub fn address(&self) -> Result<String, AddressError> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode(&mut bytes)?;

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();

        Ok(hex::encode(&result[..20]))
    }
}

pub fn verify_signature(
    public_key: &PublicKey,
    msg: &[u8],
    signature: &SignatureData,
) -> Result<(), SignatureVerificationError> {
    match (public_key, signature) {
        (PublicKey::Secp256k1(ref public_key), SignatureData::Single(ref signature_data)) => {
            public_key.verify_signature(msg, &signature_data.signature)
        }
        (PublicKey::Ed25519(ref public_key), SignatureData::Single(ref signature_data)) => {
            public_key.verify_signature(msg, signature_data.signature.as_ref())
        }
        (PublicKey::Multisig(ref public_key), SignatureData::Multi(ref signature_data)) => {
            public_key.verify_multi_signature(msg, signature_data)
        }
        _ => Err(SignatureVerificationError::InvalidPubKey),
    }
}

#[derive(Debug, Error)]
pub enum SignatureVerificationError {
    #[error("invalid public key for signature type")]
    InvalidPubKey,
    #[error("invalid signature data: {0}")]
    InvalidSignatureData(String),
    #[error("public key error: {0}")]
    PublicKeyError(#[from] PublicKeyError),
    #[error("signature error: {0}")]
    SignatureError(#[from] signature::Error),
}

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] EncodeError),
    #[error("signature error: {0}")]
    SignatureError(#[from] signature::Error),
}
