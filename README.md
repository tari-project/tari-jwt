# Ristretto256 JSON Webtoken (JWT)

[![Coverage Status](https://coveralls.io/repos/github/tari-project/tari-jwt/badge.svg?branch=main)](https://coveralls.io/github/tari-project/tari-jwt?branch=main)

This is an implementation of a JWT using the Ristretto255 elliptic curve.

It extends the traits from the [jwt-compact](https://crates.io/crates/jwt-compact) crate, which in turn 
can be used as middleware in actix-web via 
[actix-jwt-auth-middleware](https://crates.io/crates/actix-jwt-auth-middleware).

## Usage
Web tokens are signed and verified using Ristretto keys, defined in [tari_crypto](https://crates.io/crates/tari_crypto).
        
### Creating a token
Create a token with a payload and a secret key:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LoginInfo {
    username: String,
    admin: bool,
}

let mut claims = Claims::new(Info {
        username: "alice".to_string(),
        admin: true,
    });
// Set claims.expiry etc...    

let signing_key = Ristretto256SigningKey::from_slice(&SIGNING_KEY).unwrap();
let verifying_key = Ristretto256VerifyingKey::from_slice(&KEY).unwrap();
let token = Ristretto256
    .token(&Header::empty(), &claims, &signing_key)
    .unwrap();
```

The token will be a JSON object that looks something like

        eyJhbGciOiJSaXN0cmV0dG8yNTYiLCJ0eXAiOiJKV1QifQ.
        eyJleHAiOjE3MDk4MDU2MDAsImlhdCI6MTcwOTIwMDgwMCwidXNlcm5hbWUiOiJhbGljZSIsImFkbWluIjp0cnVlfQ.
        Ji2VxhHUBDcK-knCNGmGeBbo395X9d2R1Y1ikr0-C1sFQKeooNXae9DQLpC0cAd1XsrnRiw9gmM7UR6wH_kxCg

### Verifying a token

To verify a token, use the `verify` method:

```rust
let token = "eyJhbGciOiJSa..."; // A token
let public_key = Ristretto256VerifyingKey::from_slice(&PUBLIC_KEY).unwrap();
let jwt = Ristretto256.validator::<LoginInfo>(&public_key)
        .validate(&token)
        .unwrap();
let login_info = token.claims().custom;
```
