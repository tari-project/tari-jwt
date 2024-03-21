// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::{Ristretto256, Ristretto256SigningKey, Ristretto256VerifyingKey};
use assert_matches::assert_matches;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{Duration, TimeZone, Utc};
use const_decoder::Decoder::Hex;
use jwt_compact::alg::{SigningKey, VerifyingKey};
use jwt_compact::{Algorithm, AlgorithmExt, Claims, Header, UntrustedToken, ValidationError};
use rand::{seq::index::sample as sample_indexes, thread_rng};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub type Obj = serde_json::Map<String, serde_json::Value>;
const TOKEN: &str = "eyJhbGciOiJSaXN0cmV0dG8yNTYiLCJ0eXAiOiJKV1QifQ.\
eyJleHAiOjE3MDk4MDU2MDAsImlhdCI6MTcwOTIwMDgwMCwidXNlcm5hbWUiOiJhbGljZSIsImFkbWluIjp0cnVlfQ.\
Ji2VxhHUBDcK-knCNGmGeBbo395X9d2R1Y1ikr0-C1sFQKeooNXae9DQLpC0cAd1XsrnRiw9gmM7UR6wH_kxCg";
const KEY: [u8; 32] =
    Hex.decode(b"769524f0b08d986456730d1723cd28a1d0c5bc096cc05bc1347ea185dc08571e");
const SIGNING_KEY: [u8; 32] =
    Hex.decode(b"e4fc65ddca03c5e33ed494d99d735562e27718afee2d66210b36b2fe110e9f0a");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Info {
    username: String,
    admin: bool,
}

fn create_claims() -> Claims<Info> {
    let now = Utc
        .with_ymd_and_hms(2024, 2, 29, 10, 0, 0)
        .single()
        .unwrap();
    let now = now - Duration::nanoseconds(i64::from(now.timestamp_subsec_nanos()));

    let mut claims = Claims::new(Info {
        username: "alice".to_string(),
        admin: true,
    });
    claims.issued_at = Some(now);
    claims.expiration = Some(now + Duration::try_days(7).unwrap());
    claims
}

#[test]
fn check_key_traits() {
    fn check_traits<Sk, Vk>()
    where
        Sk: SigningKey<Ristretto256>,
        Vk: VerifyingKey<Ristretto256>,
        Ristretto256: Algorithm<SigningKey = Sk, VerifyingKey = Vk>,
    {
        let public_key = Vk::from_slice(&KEY).unwrap();
        assert_eq!(*public_key.as_bytes(), KEY);

        let secret_key = Sk::from_slice(&SIGNING_KEY).unwrap();
        assert_eq!(*secret_key.as_bytes(), SIGNING_KEY);
        assert_eq!(*secret_key.to_verifying_key().as_bytes(), KEY);
    }

    check_traits::<Ristretto256SigningKey, Ristretto256VerifyingKey>();
}

#[test]
fn algorithm() {
    let signing_key = Ristretto256SigningKey::from_slice(&SIGNING_KEY).unwrap();
    let verifying_key = Ristretto256VerifyingKey::from_slice(&KEY).unwrap();
    let claims = create_claims();
    let token_string = Ristretto256
        .token(&Header::empty(), &claims, &signing_key)
        .unwrap();
    let token = UntrustedToken::new(&token_string).unwrap();
    let token = Ristretto256
        .validator(&verifying_key)
        .validate(&token)
        .unwrap();
    assert_eq!(*token.claims(), claims);

    // Mutate signature bits.
    let signature = token_string.rsplit('.').next().unwrap();
    let signature_start = token_string.rfind('.').unwrap() + 1;
    let signature = Base64UrlUnpadded::decode_vec(signature).unwrap();
    let signature_bits = signature.len() * 8;

    const MAX_MANGLED_BITS: usize = 128;
    let mangled_bits: Box<dyn Iterator<Item = usize>> = if signature_bits <= MAX_MANGLED_BITS {
        Box::new(0..signature_bits)
    } else {
        let indexes = sample_indexes(&mut thread_rng(), signature_bits, MAX_MANGLED_BITS);
        Box::new(indexes.into_iter())
    };

    for i in mangled_bits {
        let mut mangled_signature = signature.clone();
        mangled_signature[i / 8] ^= 1 << (i % 8) as u8;
        let mangled_signature = Base64UrlUnpadded::encode_string(&mangled_signature);

        let mut mangled_str = token_string.clone();
        mangled_str.replace_range(signature_start.., &mangled_signature);
        let token = UntrustedToken::new(&mangled_str).unwrap();
        let err = Ristretto256
            .validator::<Obj>(&verifying_key)
            .validate(&token)
            .unwrap_err();
        match err {
            ValidationError::InvalidSignature | ValidationError::MalformedSignature(_) => {}
            err => panic!("Unexpected error: {err:?}"),
        }
    }

    // Mutate header.
    let mangled_header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, Ristretto256.name());
    let mangled_header = Base64UrlUnpadded::encode_string(mangled_header.as_bytes());
    let header_end = token_string.find('.').unwrap();
    assert_ne!(mangled_header, &token_string[..header_end]);
    let mut mangled_str = token_string.clone();
    mangled_str.replace_range(..header_end, &mangled_header);
    let token = UntrustedToken::new(&mangled_str).unwrap();
    let err = Ristretto256
        .validator::<Obj>(&verifying_key)
        .validate(&token)
        .unwrap_err();
    assert_matches!(err, ValidationError::InvalidSignature);

    // Mutate claims.
    let claims_string = Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&{
            let mut mangled_claims = claims;
            let issued_at = mangled_claims.issued_at.as_mut().unwrap();
            *issued_at += Duration::try_seconds(1).unwrap();
            mangled_claims
        })
        .unwrap(),
    );
    assert_ne!(
        claims_string,
        token_string[(header_end + 1)..(signature_start - 1)]
    );
    let mut mangled_str = token_string.clone();
    mangled_str.replace_range((header_end + 1)..(signature_start - 1), &claims_string);
    let token = UntrustedToken::new(&mangled_str).unwrap();
    let err = Ristretto256
        .validator::<Obj>(&verifying_key)
        .validate(&token)
        .unwrap_err();
    assert_matches!(err, ValidationError::InvalidSignature);
}

#[test]
fn create_ristretto_token() {
    let secret_key = Ristretto256SigningKey::from_slice(&SIGNING_KEY).unwrap();
    let claims = create_claims();
    let header = Header::empty().with_token_type("JWT");
    let token = Ristretto256.token(&header, &claims, &secret_key).unwrap();
    assert!(token.starts_with(&TOKEN[..46]));
}

#[test]
fn ristretto_json() {
    let public_key = Ristretto256VerifyingKey::from_slice(&KEY).unwrap();
    let token = UntrustedToken::new(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "Ristretto256");

    let token = Ristretto256
        .validator::<Obj>(&public_key)
        .validate(&token)
        .unwrap();
    assert_eq!(token.claims().issued_at.unwrap().timestamp(), 1_709_200_800);
    assert_eq!(
        token.claims().expiration.unwrap().timestamp(),
        1_709_805_600
    );

    let expected_claims = json!({
        "username": "alice",
        "admin": true,
    });
    assert_eq!(token.claims().custom, *expected_claims.as_object().unwrap());
}

#[test]
fn ristretto_serde() {
    let public_key = Ristretto256VerifyingKey::from_slice(&KEY).unwrap();
    let token = UntrustedToken::new(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "Ristretto256");

    let token = Ristretto256
        .validator::<Info>(&public_key)
        .validate(&token)
        .unwrap();
    let claims = token.claims().clone();
    assert_eq!(claims.issued_at.unwrap().timestamp(), 1_709_200_800);
    assert_eq!(claims.expiration.unwrap().timestamp(), 1_709_805_600);
    assert_eq!(claims.custom.username, "alice");
    assert_eq!(claims.custom.admin, true);
}
