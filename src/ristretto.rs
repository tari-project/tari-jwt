// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
//! `Schnorr` algorithm implementation using `ristretto256`.

use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};

use anyhow::anyhow;
use std::borrow::Cow;

use crate::helpers::{JWTSchnorrSignature, Ristretto256Schnorr};
use jwt_compact::alg::{SecretBytes, SigningKey, VerifyingKey};
use jwt_compact::jwk::{JsonWebKey, JwkError};
use jwt_compact::Algorithm;
use rand::thread_rng;
use tari_crypto::keys::{PublicKey, SecretKey};
use tari_crypto::tari_utilities::ByteArray;

// Wrap types to work around local types not being allowed in trait impls

#[derive(Debug, Clone, Default)]
pub struct Ristretto256;
#[derive(Debug, Clone, Default)]
pub struct Ristretto256SigningKey(pub RistrettoSecretKey);
#[derive(Debug, Clone, Default)]
pub struct Ristretto256VerifyingKey(pub RistrettoPublicKey);

impl Algorithm for Ristretto256 {
    type SigningKey = Ristretto256SigningKey;
    type VerifyingKey = Ristretto256VerifyingKey;
    type Signature = Ristretto256Schnorr;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("Ristretto256")
    }

    fn sign(&self, sk: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let sig = JWTSchnorrSignature::sign(&sk.0, message, &mut thread_rng())
            .expect("Signing via SchnorrSignature::sign should be infallible.");
        Ristretto256Schnorr(sig)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        msg: &[u8],
    ) -> bool {
        signature.0.verify(&verifying_key.0, msg)
    }
}

impl VerifyingKey<Ristretto256> for <Ristretto256 as Algorithm>::VerifyingKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        let raw = <&[u8; RistrettoPublicKey::KEY_LEN]>::try_from(raw).map_err(|err| {
            anyhow::anyhow!(err).context("Ristretto public key has unexpected length")
        })?;
        let pk =
            RistrettoPublicKey::from_canonical_bytes(raw).map_err(|err| anyhow::anyhow!(err))?;
        Ok(Ristretto256VerifyingKey(pk))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.0.as_bytes())
    }
}

impl SigningKey<Ristretto256> for Ristretto256SigningKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        let secret = RistrettoSecretKey::from_canonical_bytes(raw)?;
        Ok(Ristretto256SigningKey(secret))
    }

    fn to_verifying_key(&self) -> Ristretto256VerifyingKey {
        let pubkey = RistrettoPublicKey::from_secret_key(&self.0);
        Ristretto256VerifyingKey(pubkey)
    }

    fn as_bytes(&self) -> SecretBytes<'_> {
        SecretBytes::borrowed(self.0.as_bytes())
    }
}

impl<'a> From<&'a Ristretto256VerifyingKey> for JsonWebKey<'a> {
    fn from(key: &'a Ristretto256VerifyingKey) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ristretto256"),
            x: Cow::Borrowed(key.0.as_bytes()),
            secret: None,
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for Ristretto256VerifyingKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        match jwk {
            JsonWebKey::KeyPair { curve, x, .. } => {
                if curve != "Ristretto256" {
                    return Err(JwkError::custom(anyhow!("Key is not a Ristretto key")));
                }
                if x.len() != RistrettoPublicKey::KEY_LEN {
                    return Err(JwkError::custom(anyhow!(
                        "Invalid key Ristretto key length"
                    )));
                }
                let pk = RistrettoPublicKey::from_canonical_bytes(x.as_ref())
                    .map_err(JwkError::custom)?;
                Ok(Ristretto256VerifyingKey(pk))
            }
            _ => Err(JwkError::custom(anyhow!(
                "JWK type is incorrect. Not a Ristretto key"
            ))),
        }
    }
}

impl<'a> From<&'a Ristretto256SigningKey> for JsonWebKey<'a> {
    fn from(signing_key: &'a Ristretto256SigningKey) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ristretto256"),
            x: Cow::Borrowed(signing_key.0.as_bytes()),
            secret: None,
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for Ristretto256SigningKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        match jwk {
            JsonWebKey::KeyPair { curve, x, .. } => {
                if curve != "Ed25519" {
                    return Err(JwkError::custom(anyhow!(
                        "Key is not a Ristretto secret key"
                    )));
                }
                if x.len() != RistrettoSecretKey::KEY_LEN {
                    return Err(JwkError::custom(anyhow!(
                        "Invalid Ed25519 public key length"
                    )));
                }
                let sk = RistrettoSecretKey::from_canonical_bytes(x.as_ref())
                    .map_err(JwkError::custom)?;
                Ok(Ristretto256SigningKey(sk))
            }
            _ => Err(JwkError::custom(anyhow!(
                "JWK type is incorrect. Not a Ristretto secret key"
            ))),
        }
    }
}
