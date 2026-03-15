# Randomizable signatures by David Pointcheval and Olivier Sanders.

## From the CT-RSA 2016 paper [Short Randomizable signatures](https://eprint.iacr.org/2015/525) which uses interactive assumptions

### Signature and proof of knowledge of signature
Implements 2 variations as described in the paper in sections 4.2 and 6.1 respectively. Scheme in 6.1 was 
presented to make blind signatures efficient however there are ways to do blind signatures with 4.2 but they 
are relatively inefficient. One way to do so is described in [Coconut](https://arxiv.org/pdf/1802.07344.pdf).

The signature scheme from section 4.2 does not allow blind signatures straightaway and the paper does not 
describe any technique to do so. But less efficient techniques from Coconut or others can be used. The scheme 
is implemented as described in the paper.  

The code for this lives in signature.rs, blind_signature.rs and pok_sig.rs. For generating keys use `keys::keygen`
      
The signature scheme from section 6.1 of the paper allows for signing blinded messages as well. 
Demonstrated by test `test_signature_blinded_messages`.  
Implementing proof of knowledge of a signature from section 6.2 of paper. Demonstrated by test `test_PoK_sig`.  
In addition to proof of knowledge, the user can also reveal some of the messages under the signature without revealing all messages or signature.
Demonstrated in test `test_PoK_sig_reveal_messages`.  
A more comprehensive test where a user gets signature over a mix of messages where some of them are known while 
others are committed to and then a proof of knowledge is done for signature with selectively revealing some messages. 
Demonstrated in the test `test_scenario_1`.
2 variation of scheme in section 6.1 are implemented, one of the variations follows the paper as it is.   
But another variations implemented with some modifications. The public key is split into 2 parts, the 
tilde elements (X_tilde and Y_tilde) and non-tilde elements (X, Y). Now the verifier only needs the former 
(tilde elements) and thus verifier's storage requirements go down. Keygen and signing are modified as:
- Keygen: Rather than only keeping X as the secret key, signer keeps x, y_1, y_2, ..y_r as secret key. 
The public key is unchanged, i.e. (g, Y_1, Y_2,..., Y_tilde_1, Y_tilde_2, ...)
- Sign: Lets say the signer wants to sign a multi-message of 10 messages where only 1 message is blinded. 
If we go by the paper where signer does not have y_1, y_2, .. y_10, signer will pick a random u and compute signature as 
(g^u, (XC)^u.Y_2^{m_2*u}.Y_3^{m_3*u}...Y_10^{m_10*u}), Y_1 is omitted as the first message was blinded. Of course the term 
(XC)^u.Y_2^{m_2*u}.Y_3^{m_3*u}...Y_10^{m_10*u} can be computed using efficient multi-exponentiation techniques but it would be more efficient 
if the signer could instead compute (g^u, C^u.g^{(x+y_2.m_2+y_3.m_3+...y_10.m_10).u}). The resulting signature will have the same form 
and can be unblinded in the same way as described in the paper.  
This will make signer's secret key storage a bit more but will make the signing more efficient, especially in cases 
where the signature has only a few blinded messages but most messages are known to the signer which is usually the case with 
anonymous credentials where the user's secret key is blinded (its not known to signer) in the signature. This variation makes 
signing considerably faster unless the no of unblinded messages is very small compared to no of blinded messages. 
Run test `timing_comparison_for_both_blind_signature_schemes` to see the difference 

### Multi-signature
Multiple PS signatures can be aggregated using the same principle BLS signatures since the secrets are in the exponents like BLS signatures.
Signatures are aggregated by multiplying them together like BLS signatures and verification keys can be aggregated by multiplying the 
corresponding parts together. The signers should however use the same `Params` and while signing create deterministic signatures using 
`Signature::new_deterministic` which hashes the messages to create a group generator. Look at the test `test_multi_signature_all_known_messages`.


## From the CT-RSA 2018 paper [Reassessing Security of Randomizable Signatures](https://eprint.iacr.org/2017/1197) which uses non-interactive assumptions

The code for this lives in signature_2018.rs and pok_sig_2018.rs. For generating keys use `keys::keygen_2018`. For multi-signatures, use methods
`MultiSignatureFast::from_sigs_2018` and `MultiSignatureFast::verify_2018`. Since majority of the protocol of signing (known) and proof of knowledge 
of signature is same as the CT-RSA 2016 paper, there is a lot of code reuse. Currently there is no implementation of blind signature using this 
new scheme but it can be done by using the ideas from Coconut where the committed attributes are individually committed using Elgamal encryption.

Blind signatures are currently implemented and tested only for the 2016 scheme.

## Implementation Details

This library uses the [arkworks](https://arkworks.rs/) ecosystem for elliptic curve operations and supports:
- **no_std environments** (embedded systems, WASM)
- **Multiple pairing-friendly curves** (BLS12-381, BLS12-377, BN254)
- **Serialization** using arkworks' canonical serialization

### Curve Selection

The library is generic over pairing-friendly curves. In tests and examples, we use:
- `ark_bls12_381::Bls12_381` (recommended for production use)
- `ark_bls12_377::Bls12_377`
- `ark_bn254::Bn254`

All implementations use the standard convention:
- **G1** for signatures (shorter, faster signing)
- **G2** for verification keys (faster verification via multi-exponentiation in G1)

### Usage Example

```rust
use ark_bls12_381::Bls12_381;
use ps_sig::keys::{keygen, Params};
use ps_sig::signature::Signature;
use sha2::Sha256;
use ark_std::test_rng;

// Generate parameters
let params = Params::<Bls12_381>::new::<Sha256>(b"my-domain");

// Generate keys for 5 messages
let (sigkey, verkey) = keygen(5, &params, &mut test_rng());

// Sign messages
let sig = Signature::new(&messages, &sigkey, &params, &mut test_rng())?;

// Verify
assert!(sig.verify(&messages, &verkey, &params)?);
```

### Running Tests

Run all tests with default features (std):
```bash
cargo test --release
```

Run tests for no_std:
```bash
cargo test --release --no-default-features
```

Build for WASM:
```bash
cargo build --release --no-default-features --target wasm32-unknown-unknown
```

### Test Vectors

Test vectors are stored in `tests/data` and `tests/data/2018`.

Verification tests (read existing vectors, do not generate):
```bash
cargo test verify_with_test_vectors
cargo test verify_with_test_vectors_2018
cargo test verify_blind_signature_with_test_vectors
```

Generation tests (ignored by default, run explicitly when updating vectors):
```bash
cargo test generate_test_vectors -- --ignored
cargo test generate_test_vectors_2018 -- --ignored
cargo test generate_blind_signature_test_vectors -- --ignored
```

### Features

- `std` (default): Enables standard library support

