//! # det-keygen
//!
//! This crate implements an *experimental* port of the Python [reference implementation](https://github.com/C2SP/C2SP/blob/main/det-keygen/ecdsa.py) of [C2SP](https://github.com/C2SP/C2SP)'s ECDSA [Deterministic Key Generation](https://c2sp.org/det-keygen).
//!
//! This specification enables the derivation of ECDSA private keys from arbitrary seeds (using FIPS 186-5 methods only) which
//! should contain at least 192 bits of entropy.
//! # Examples
//!
//! ```
//! // Generate a P-256 private key based on a 160-bit seed
//!
//! use det_keygen::{Keygen, P256};
//!
//! let seed = b"When in doubt, don't";
//!
//! let keygen = Keygen::<P256>::new(seed);
//! let key = keygen.generate();
//! ```

use crypto_bigint::{U256, Uint, Zero};

/// Tag represents a 256-bit hmac tag.
type Tag = [u8; 256 / 8];

/// Curve describes an implementation independent description of an elliptic curve.
pub trait Curve {
    /// Length of the curve's field element in bytes.
    const LEN: usize;

    /// Personalization string used in the key generation process.
    const PERSONALIZATION_STRING: &'static [u8];

    // FIXME: replace with with hybrid-array as soon as RFC2532 becomes stable
    /// Private key output of this curve.
    type Output;

    /// Generate a key pair from a seed.
    fn generate(temp: &[u8]) -> Option<Self::Output>;
}

/// Keygen derives a key for a curve following the c2sp.org/det-keygen.
pub struct Keygen<C: Curve> {
    k: Tag,
    v: Tag,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: Curve> Keygen<C> {
    /// Instantiate the key generation process. Seed must be at least 128-bits long with 160-bit of entropy preferred.
    pub fn new(seed: &[u8]) -> Self {
        let k = [0; 256 / 8];
        let v = [1; 256 / 8];

        let k = hmac256(
            k.as_ref(),
            [v.as_slice(), &[0u8], seed, C::PERSONALIZATION_STRING]
                .concat()
                .as_ref(),
        );

        let v = hmac256(k.as_ref(), &v);

        let k = hmac256(
            k.as_ref(),
            [v.as_slice(), &[1u8], seed, C::PERSONALIZATION_STRING]
                .concat()
                .as_ref(),
        );

        let v = hmac256(k.as_ref(), v.as_ref());

        Self {
            k,
            v,
            _phantom: std::marker::PhantomData,
        }
    }

    #[doc(hidden)]
    fn candidate(&mut self) -> Vec<u8> {
        let mut temp = vec![];

        while temp.len() < C::LEN {
            self.v = hmac256(self.k.as_ref(), self.v.as_ref());
            temp.extend_from_slice(self.v.as_ref());
        }

        temp
    }

    /// Generate the Curve output.
    pub fn generate(mut self) -> C::Output {
        let temp = self.candidate();
        let res = C::generate(&temp);

        res.unwrap_or_else(|| {
            // try once more
            self.k = hmac256(
                self.k.as_ref(),
                [self.v.as_slice(), &[0u8]].concat().as_ref(),
            );
            self.v = hmac256(self.k.as_slice(), self.v.as_ref());

            let temp = self.candidate();
            C::generate(&temp).unwrap()
        })
    }
}

/// P-256 Curve implementation.
pub struct P256 {}

impl Curve for P256 {
    const PERSONALIZATION_STRING: &'static [u8] = b"det ECDSA key gen P-256";
    const LEN: usize = 32;

    type Output = [u8; Self::LEN];

    fn generate(temp: &[u8]) -> Option<Self::Output> {
        const N: U256 =
            U256::from_be_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

        let d = bits2int(temp, 256);

        if d.is_zero().into() || d >= N {
            None
        } else {
            Some(d.to_be_bytes())
        }
    }
}

fn bits2int<const LIMBS: usize>(data: &[u8], qlen: usize) -> Uint<LIMBS> {
    let mut x = Uint::<LIMBS>::from_be_slice(data);

    let blen = data.len() * 8;

    if blen > qlen {
        let shift = blen - qlen;
        x >>= shift;
    }

    x
}

#[cfg(feature = "ring")]
fn hmac256(k: &[u8], v: &[u8]) -> Tag {
    use ring::hmac;

    let k = hmac::Key::new(hmac::HMAC_SHA256, k);
    hmac::sign(&k, v)
        .as_ref()
        .try_into()
        .expect("tag larger then 256 bits")
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs;

    use base64::{Engine as _, engine::general_purpose};
    use p256::SecretKey;
    use pkcs8::EncodePrivateKey;
    use proptest::prelude::*;
    use ring::{
        rand::SystemRandom,
        signature::{
            ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
            UnparsedPublicKey,
        },
    };
    use serde::{Deserialize, Deserializer};

    fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }

    #[derive(Deserialize, Debug)]
    struct TestVector {
        curve: String,
        #[serde(deserialize_with = "deserialize_base64")]
        seed: Vec<u8>,
        private_key_pkcs8: String,
    }

    proptest! {
    #[test]
    fn test_fuzz_p256(seed: Vec<u8>) {
        prop_assume!(!seed.is_empty());

        const MSG: &[u8] = b"hello world";

            let rng = SystemRandom::new();

            let g = Keygen::<P256>::new(&seed);
            let key = g.generate();

            let key = SecretKey::from_bytes(&key.into()).unwrap();
            let key = key.to_pkcs8_der().unwrap();
            let keys =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.as_bytes(), &rng)
                    .unwrap();

            let signature = keys.sign(&rng, MSG).unwrap();

            let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, keys.public_key());

            let _sig = public_key.verify(MSG, signature.as_ref()).unwrap();
        }
    }

    #[test]
    fn test_vectors() {
        let rng = SystemRandom::new();

        let vectors = fs::read_to_string("src/escdsa.json").unwrap();
        let vectors: Vec<TestVector> = serde_json::from_str(&vectors).unwrap();

        for vector in vectors.iter().filter(|v| v.curve == "secp256r1") {
            let g = Keygen::<P256>::new(&vector.seed);

            let key = g.generate();
            let key = SecretKey::from_bytes(&key.into()).unwrap();
            let key = key.to_pkcs8_der().unwrap();
            let key = key.as_bytes();

            let _keys = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key, &rng);

            let key = general_purpose::STANDARD.encode(key);
            assert_eq!(
                key, vector.private_key_pkcs8,
                "testing with key {:?}",
                vector.private_key_pkcs8
            );
        }
    }
}
