# ECDSA Deterministic Key Generation

This is an *experimental* port of the Python [reference implementation](https://github.com/C2SP/C2SP/blob/main/det-keygen/ecdsa.py) of [C2SP](https://github.com/C2SP/C2SP)'s ECDSA [Deterministic Key Generation](https://c2sp.org/det-keygen). This specification enables the derivation of ECDSA private keys from arbitrary seeds (using FIPS 186-5 methods only) which should contain at least 192 bits of entropy.

Currently this crate does only support P256, not P-224, P-384, or P-521 (which are also covered by the specification).

Usage:

```
let keygen = Keygen::<P256>::new(&seed);
let key = keygen.generate();
```
