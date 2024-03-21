// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
use jwt_compact::AlgorithmSignature;
use std::borrow::Cow;
use std::num::NonZeroUsize;
use tari_crypto::hash_domain;
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_crypto::signatures::SchnorrSignature;
use tari_crypto::tari_utilities::ByteArray;

pub const SIGNATURE_LENGTH: usize = 64;

hash_domain!(JWTChallenge, "com.tari.jwt-ristretto", 1);

pub type JWTSchnorrSignature =
    SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, JWTChallenge>;
pub struct Ristretto256Schnorr(pub JWTSchnorrSignature);

impl Ristretto256Schnorr {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut result = [0u8; SIGNATURE_LENGTH];
        result[0..32].clone_from_slice(self.0.get_public_nonce().as_bytes());
        result[32..].clone_from_slice(self.0.get_signature().as_bytes());
        result
    }
}

impl TryFrom<&[u8]> for Ristretto256Schnorr {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(anyhow::anyhow!("Invalid signature length"));
        }
        let public_nonce = RistrettoPublicKey::from_canonical_bytes(&bytes[0..32])?;
        let sig = RistrettoSecretKey::from_canonical_bytes(&bytes[32..])?;
        Ok(Ristretto256Schnorr(JWTSchnorrSignature::new(
            public_nonce,
            sig,
        )))
    }
}

impl AlgorithmSignature for Ristretto256Schnorr {
    const LENGTH: Option<NonZeroUsize> = NonZeroUsize::new(64);

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::try_from(bytes).map_err(|err| anyhow::anyhow!(err))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod test {
    use crate::helpers::JWTSchnorrSignature;
    use rand::thread_rng;
    use tari_crypto::keys::PublicKey;
    use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey};
    use tari_crypto::tari_utilities::hex::Hex;

    #[test]
    fn sign_and_verify() {
        let msg = "attaque at dawn";
        let (sk, pk) = RistrettoPublicKey::random_keypair(&mut thread_rng());
        let sig = JWTSchnorrSignature::sign(&sk, msg, &mut thread_rng()).unwrap();
        println!(
            "Signature: R={}, s={}, P={pk}",
            sig.get_public_nonce(),
            sig.get_signature().reveal()
        );
        assert!(sig.verify(&pk, msg));
    }

    #[test]
    #[allow(non_snake_case)]
    fn verify() {
        let msg = "attaque at dawn";
        let R = RistrettoPublicKey::from_hex(
            "bcd62ac684e4a8eece44885579d1525480f74b6766ef32123aa632292f757274",
        )
        .unwrap();
        let s = RistrettoSecretKey::from_hex(
            "b6c727b830fb5cb54d6362a9b6546145645150c6e96e71d280dd9bfd065cb50c",
        )
        .unwrap();
        let P = RistrettoPublicKey::from_hex(
            "9e692110ca71faeb99777ce3fdc035249d232139c9a1f6602671beea5ab62f02",
        )
        .unwrap();
        // Use the default domain separator
        let sig = RistrettoSchnorr::new(R.clone(), s.clone());
        assert_eq!(
            sig.verify(&P, msg),
            false,
            "Signature should not verify using default domain separator"
        );
        let sig = JWTSchnorrSignature::new(R, s);
        assert!(
            sig.verify(&P, msg),
            "Signature should verify using JWT domain separator"
        );
    }
}
