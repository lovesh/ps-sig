// Test vector generation and verification for PS signatures
// Generates test vectors for parameters, keys, signatures, and proofs

use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::Zero;
use ps_sig::blind_signature::BlindSignature;
use ps_sig::keys::{keygen, keygen_2018, Params, Sigkey, Verkey};
use ps_sig::pok_sig::{PoKOfSignature, PoKOfSignatureProof};
use ps_sig::pok_sig_2018;
use ps_sig::signature::Signature;
use ps_sig::signature_2018;
use sha2::Sha256;
use std::fs;
use std::path::Path;

const TEST_DATA_DIR: &str = "tests/data";
const TEST_DATA_DIR_2018: &str = "tests/data/2018";
const TEST_DATA_DIR_BLIND: &str = "tests/data/blind";

#[derive(Debug)]
struct TestVectors {
    // Serialized bytes
    params_bytes: Vec<u8>,
    verkey_bytes: Vec<u8>,
    sigkey_bytes: Vec<u8>,
    messages_bytes: Vec<Vec<u8>>,
    signature_bytes: Vec<u8>,
    pok_proof_bytes: Vec<u8>,
    revealed_indices: Vec<usize>,
    revealed_messages_bytes: Vec<(usize, Vec<u8>)>,
}

impl TestVectors {
    fn generate() -> Self {
        // Use deterministic RNG for reproducible test vectors
        let mut rng = StdRng::seed_from_u64(42);

        // Generate parameters deterministically
        let params = Params::<E>::new::<Sha256>(b"test-vectors-v1");

        // Generate keys
        let count_messages = 5;
        let (sigkey, verkey) = keygen(count_messages, &params, &mut rng);

        // Generate messages
        let messages: Vec<<E as Pairing>::ScalarField> = (0..count_messages)
            .map(|_| <E as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        // Create signature
        let signature = Signature::new(&messages, &sigkey, &params, &mut rng).unwrap();

        // Create proof of knowledge with some revealed messages
        let mut revealed_indices = BTreeSet::new();
        revealed_indices.insert(1);
        revealed_indices.insert(3);

        let pok = PoKOfSignature::init(
            &signature,
            &verkey,
            &params,
            messages.clone(),
            None,
            revealed_indices.clone(),
            &mut rng,
        )
        .unwrap();

        // Generate challenge using the new gen_challenge method
        let challenge = pok.gen_challenge::<Sha256>().unwrap();

        // Generate proof
        let proof = pok.gen_proof(challenge).unwrap();

        // Serialize everything
        let mut params_bytes = Vec::new();
        params.serialize_compressed(&mut params_bytes).unwrap();

        let mut verkey_bytes = Vec::new();
        verkey.serialize_compressed(&mut verkey_bytes).unwrap();

        let mut sigkey_bytes = Vec::new();
        sigkey.serialize_compressed(&mut sigkey_bytes).unwrap();

        let messages_bytes: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| {
                let mut bytes = Vec::new();
                m.serialize_compressed(&mut bytes).unwrap();
                bytes
            })
            .collect();

        let mut signature_bytes = Vec::new();
        signature
            .serialize_compressed(&mut signature_bytes)
            .unwrap();

        let mut pok_proof_bytes = Vec::new();
        proof.serialize_compressed(&mut pok_proof_bytes).unwrap();

        let revealed_messages_bytes: Vec<(usize, Vec<u8>)> = revealed_indices
            .iter()
            .map(|&idx| {
                let mut bytes = Vec::new();
                messages[idx].serialize_compressed(&mut bytes).unwrap();
                (idx, bytes)
            })
            .collect();

        TestVectors {
            params_bytes,
            verkey_bytes,
            sigkey_bytes,
            messages_bytes,
            signature_bytes,
            pok_proof_bytes,
            revealed_indices: revealed_indices.into_iter().collect(),
            revealed_messages_bytes,
        }
    }

    fn save(&self) {
        fs::create_dir_all(TEST_DATA_DIR).unwrap();

        fs::write(
            Path::new(TEST_DATA_DIR).join("params.bin"),
            &self.params_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR).join("verkey.bin"),
            &self.verkey_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR).join("sigkey.bin"),
            &self.sigkey_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR).join("signature.bin"),
            &self.signature_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR).join("pok_proof.bin"),
            &self.pok_proof_bytes,
        )
        .unwrap();

        // Save messages
        for (i, msg_bytes) in self.messages_bytes.iter().enumerate() {
            fs::write(
                Path::new(TEST_DATA_DIR).join(format!("message_{}.bin", i)),
                msg_bytes,
            )
            .unwrap();
        }

        // Save revealed indices and messages
        let revealed_indices_str = self
            .revealed_indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        fs::write(
            Path::new(TEST_DATA_DIR).join("revealed_indices.txt"),
            revealed_indices_str,
        )
        .unwrap();

        for (idx, msg_bytes) in &self.revealed_messages_bytes {
            fs::write(
                Path::new(TEST_DATA_DIR).join(format!("revealed_message_{}.bin", idx)),
                msg_bytes,
            )
            .unwrap();
        }
    }

    fn load() -> Self {
        let params_bytes = fs::read(Path::new(TEST_DATA_DIR).join("params.bin")).unwrap();
        let verkey_bytes = fs::read(Path::new(TEST_DATA_DIR).join("verkey.bin")).unwrap();
        let sigkey_bytes = fs::read(Path::new(TEST_DATA_DIR).join("sigkey.bin")).unwrap();
        let signature_bytes = fs::read(Path::new(TEST_DATA_DIR).join("signature.bin")).unwrap();
        let pok_proof_bytes = fs::read(Path::new(TEST_DATA_DIR).join("pok_proof.bin")).unwrap();

        // Load messages
        let mut messages_bytes = Vec::new();
        for i in 0..5 {
            let msg_bytes =
                fs::read(Path::new(TEST_DATA_DIR).join(format!("message_{}.bin", i))).unwrap();
            messages_bytes.push(msg_bytes);
        }

        // Load revealed indices
        let revealed_indices_str =
            fs::read_to_string(Path::new(TEST_DATA_DIR).join("revealed_indices.txt")).unwrap();
        let revealed_indices: Vec<usize> = revealed_indices_str
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();

        // Load revealed messages
        let revealed_messages_bytes: Vec<(usize, Vec<u8>)> = revealed_indices
            .iter()
            .map(|&idx| {
                let bytes = fs::read(
                    Path::new(TEST_DATA_DIR).join(format!("revealed_message_{}.bin", idx)),
                )
                .unwrap();
                (idx, bytes)
            })
            .collect();

        TestVectors {
            params_bytes,
            verkey_bytes,
            sigkey_bytes,
            messages_bytes,
            signature_bytes,
            pok_proof_bytes,
            revealed_indices,
            revealed_messages_bytes,
        }
    }
}

// Test vectors for 2018 scheme
#[derive(Debug)]
struct TestVectors2018 {
    // Serialized bytes
    params_bytes: Vec<u8>,
    verkey_bytes: Vec<u8>,
    sigkey_bytes: Vec<u8>,
    messages_bytes: Vec<Vec<u8>>,
    signature_bytes: Vec<u8>,
    pok_proof_bytes: Vec<u8>,
    revealed_indices: Vec<usize>,
    revealed_messages_bytes: Vec<(usize, Vec<u8>)>,
}

impl TestVectors2018 {
    fn generate() -> Self {
        // Use deterministic RNG for reproducible test vectors
        let mut rng = StdRng::seed_from_u64(2018);

        // Generate parameters deterministically
        let params = Params::<E>::new::<Sha256>(b"test-vectors-2018-v1");

        // Generate keys
        let count_messages = 5;
        let (sigkey, verkey) = keygen_2018(count_messages, &params, &mut rng);

        // Generate messages
        let messages: Vec<<E as Pairing>::ScalarField> = (0..count_messages)
            .map(|_| <E as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        // Create signature
        let signature = signature_2018::Signature::new(&messages, &sigkey, &mut rng).unwrap();

        // Create proof of knowledge with some revealed messages
        let mut revealed_indices = BTreeSet::new();
        revealed_indices.insert(0);
        revealed_indices.insert(2);
        revealed_indices.insert(4);

        let pok = pok_sig_2018::PoKOfSignature::init(
            &signature,
            &verkey,
            &params,
            messages.clone(),
            None,
            revealed_indices.clone(),
            &mut rng,
        )
        .unwrap();

        // Generate challenge using the new gen_challenge method
        let challenge = pok.gen_challenge::<Sha256>().unwrap();

        // Generate proof
        let proof = pok.gen_proof(challenge).unwrap();

        // Serialize everything
        let mut params_bytes = Vec::new();
        params.serialize_compressed(&mut params_bytes).unwrap();

        let mut verkey_bytes = Vec::new();
        verkey.serialize_compressed(&mut verkey_bytes).unwrap();

        let mut sigkey_bytes = Vec::new();
        sigkey.serialize_compressed(&mut sigkey_bytes).unwrap();

        let messages_bytes: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| {
                let mut bytes = Vec::new();
                m.serialize_compressed(&mut bytes).unwrap();
                bytes
            })
            .collect();

        let mut signature_bytes = Vec::new();
        signature
            .serialize_compressed(&mut signature_bytes)
            .unwrap();

        let mut pok_proof_bytes = Vec::new();
        proof.serialize_compressed(&mut pok_proof_bytes).unwrap();

        let revealed_messages_bytes: Vec<(usize, Vec<u8>)> = revealed_indices
            .iter()
            .map(|&idx| {
                let mut bytes = Vec::new();
                messages[idx].serialize_compressed(&mut bytes).unwrap();
                (idx, bytes)
            })
            .collect();

        TestVectors2018 {
            params_bytes,
            verkey_bytes,
            sigkey_bytes,
            messages_bytes,
            signature_bytes,
            pok_proof_bytes,
            revealed_indices: revealed_indices.into_iter().collect(),
            revealed_messages_bytes,
        }
    }

    fn save(&self) {
        fs::create_dir_all(TEST_DATA_DIR_2018).unwrap();

        fs::write(
            Path::new(TEST_DATA_DIR_2018).join("params.bin"),
            &self.params_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR_2018).join("verkey.bin"),
            &self.verkey_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR_2018).join("sigkey.bin"),
            &self.sigkey_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR_2018).join("signature.bin"),
            &self.signature_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR_2018).join("pok_proof.bin"),
            &self.pok_proof_bytes,
        )
        .unwrap();

        // Save messages
        for (i, msg_bytes) in self.messages_bytes.iter().enumerate() {
            fs::write(
                Path::new(TEST_DATA_DIR_2018).join(format!("message_{}.bin", i)),
                msg_bytes,
            )
            .unwrap();
        }

        // Save revealed indices and messages
        let revealed_indices_str = self
            .revealed_indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        fs::write(
            Path::new(TEST_DATA_DIR_2018).join("revealed_indices.txt"),
            revealed_indices_str,
        )
        .unwrap();

        for (idx, msg_bytes) in &self.revealed_messages_bytes {
            fs::write(
                Path::new(TEST_DATA_DIR_2018).join(format!("revealed_message_{}.bin", idx)),
                msg_bytes,
            )
            .unwrap();
        }
    }

    fn load() -> Self {
        let params_bytes = fs::read(Path::new(TEST_DATA_DIR_2018).join("params.bin")).unwrap();
        let verkey_bytes = fs::read(Path::new(TEST_DATA_DIR_2018).join("verkey.bin")).unwrap();
        let sigkey_bytes = fs::read(Path::new(TEST_DATA_DIR_2018).join("sigkey.bin")).unwrap();
        let signature_bytes =
            fs::read(Path::new(TEST_DATA_DIR_2018).join("signature.bin")).unwrap();
        let pok_proof_bytes =
            fs::read(Path::new(TEST_DATA_DIR_2018).join("pok_proof.bin")).unwrap();

        // Load messages
        let mut messages_bytes = Vec::new();
        for i in 0..5 {
            let msg_bytes =
                fs::read(Path::new(TEST_DATA_DIR_2018).join(format!("message_{}.bin", i))).unwrap();
            messages_bytes.push(msg_bytes);
        }

        // Load revealed indices
        let revealed_indices_str =
            fs::read_to_string(Path::new(TEST_DATA_DIR_2018).join("revealed_indices.txt")).unwrap();
        let revealed_indices: Vec<usize> = revealed_indices_str
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();

        // Load revealed messages
        let revealed_messages_bytes: Vec<(usize, Vec<u8>)> = revealed_indices
            .iter()
            .map(|&idx| {
                let bytes = fs::read(
                    Path::new(TEST_DATA_DIR_2018).join(format!("revealed_message_{}.bin", idx)),
                )
                .unwrap();
                (idx, bytes)
            })
            .collect();

        TestVectors2018 {
            params_bytes,
            verkey_bytes,
            sigkey_bytes,
            messages_bytes,
            signature_bytes,
            pok_proof_bytes,
            revealed_indices,
            revealed_messages_bytes,
        }
    }
}

#[derive(Debug)]
struct BlindSignatureTestVectors {
    params_bytes: Vec<u8>,
    verkey_bytes: Vec<u8>,
    messages_bytes: Vec<Vec<u8>>,
    blinding_bytes: Vec<u8>,
    blind_signature_bytes: Vec<u8>,
}

impl BlindSignatureTestVectors {
    fn generate() -> Self {
        use ps_sig::blind_signature::BlindingKey;

        let mut rng = StdRng::seed_from_u64(123);

        let params = Params::<E>::new::<Sha256>(b"blind-sig-test-v1");
        let count_msgs = 3;
        let count_blinded = 2;
        let (sigkey, verkey) = keygen(count_msgs, &params, &mut rng);

        let blinding_key = BlindingKey::new(&sigkey, &params);

        let messages: Vec<<E as Pairing>::ScalarField> = (0..count_msgs)
            .map(|_| <E as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        let blinding = <E as Pairing>::ScalarField::rand(&mut rng);

        let mut comm = <E as Pairing>::G1::zero();
        for i in 0..count_blinded {
            comm += blinding_key.Y[i] * messages[i];
        }
        comm += params.g * blinding;
        let comm = comm.into_affine();

        let sig_blinded = BlindSignature::new(
            &comm,
            &messages[count_blinded..],
            &sigkey,
            &blinding_key,
            &params,
            &mut rng,
        )
        .unwrap();

        let mut params_bytes = Vec::new();
        params.serialize_compressed(&mut params_bytes).unwrap();

        let mut verkey_bytes = Vec::new();
        verkey.serialize_compressed(&mut verkey_bytes).unwrap();

        let messages_bytes: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| {
                let mut bytes = Vec::new();
                m.serialize_compressed(&mut bytes).unwrap();
                bytes
            })
            .collect();

        let mut blinding_bytes = Vec::new();
        blinding.serialize_compressed(&mut blinding_bytes).unwrap();

        let mut blind_signature_bytes = Vec::new();
        sig_blinded
            .serialize_compressed(&mut blind_signature_bytes)
            .unwrap();

        Self {
            params_bytes,
            verkey_bytes,
            messages_bytes,
            blinding_bytes,
            blind_signature_bytes,
        }
    }

    fn save(&self) {
        fs::create_dir_all(TEST_DATA_DIR_BLIND).unwrap();

        fs::write(
            Path::new(TEST_DATA_DIR_BLIND).join("params.bin"),
            &self.params_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR_BLIND).join("verkey.bin"),
            &self.verkey_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR_BLIND).join("blinding.bin"),
            &self.blinding_bytes,
        )
        .unwrap();
        fs::write(
            Path::new(TEST_DATA_DIR_BLIND).join("blind_signature.bin"),
            &self.blind_signature_bytes,
        )
        .unwrap();

        fs::write(
            Path::new(TEST_DATA_DIR_BLIND).join("message_count.txt"),
            self.messages_bytes.len().to_string(),
        )
        .unwrap();

        for (i, msg_bytes) in self.messages_bytes.iter().enumerate() {
            fs::write(
                Path::new(TEST_DATA_DIR_BLIND).join(format!("message_{}.bin", i)),
                msg_bytes,
            )
            .unwrap();
        }
    }

    fn load() -> Self {
        let params_bytes = fs::read(Path::new(TEST_DATA_DIR_BLIND).join("params.bin")).unwrap();
        let verkey_bytes = fs::read(Path::new(TEST_DATA_DIR_BLIND).join("verkey.bin")).unwrap();
        let blinding_bytes = fs::read(Path::new(TEST_DATA_DIR_BLIND).join("blinding.bin")).unwrap();
        let blind_signature_bytes =
            fs::read(Path::new(TEST_DATA_DIR_BLIND).join("blind_signature.bin")).unwrap();

        let message_count: usize =
            fs::read_to_string(Path::new(TEST_DATA_DIR_BLIND).join("message_count.txt"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();

        let mut messages_bytes = Vec::with_capacity(message_count);
        for i in 0..message_count {
            let msg_bytes =
                fs::read(Path::new(TEST_DATA_DIR_BLIND).join(format!("message_{}.bin", i)))
                    .unwrap();
            messages_bytes.push(msg_bytes);
        }

        Self {
            params_bytes,
            verkey_bytes,
            messages_bytes,
            blinding_bytes,
            blind_signature_bytes,
        }
    }
}

#[test]
#[ignore = "Only run explicitly to regenerate test vectors: cargo test generate_test_vectors -- --ignored"]
fn generate_test_vectors() {
    let vectors = TestVectors::generate();
    vectors.save();
    println!("Test vectors generated and saved to {}/", TEST_DATA_DIR);
}

#[test]
fn verify_with_test_vectors() {
    // Load test vectors
    let vectors = TestVectors::load();

    // Deserialize parameters
    let params = Params::<E>::deserialize_compressed(&vectors.params_bytes[..]).unwrap();

    // Deserialize verification key
    let verkey = Verkey::<E>::deserialize_compressed(&vectors.verkey_bytes[..]).unwrap();

    // Deserialize signing key
    let sigkey = Sigkey::<E>::deserialize_compressed(&vectors.sigkey_bytes[..]).unwrap();

    // Deserialize messages
    let messages: Vec<<E as Pairing>::ScalarField> = vectors
        .messages_bytes
        .iter()
        .map(|bytes| <E as Pairing>::ScalarField::deserialize_compressed(&bytes[..]).unwrap())
        .collect();

    // Deserialize signature
    let signature = Signature::<E>::deserialize_compressed(&vectors.signature_bytes[..]).unwrap();

    // Deserialize PoK proof
    let pok_proof =
        PoKOfSignatureProof::<E>::deserialize_compressed(&vectors.pok_proof_bytes[..]).unwrap();

    // Verify keygen: check that verkey is consistent with sigkey and params
    assert_eq!(verkey.Y_tilde.len(), sigkey.y.len());
    assert_eq!(verkey.Y_tilde.len(), messages.len());

    // Verify signature
    assert!(
        signature.verify(&messages, &verkey, &params).unwrap(),
        "Signature verification failed"
    );

    // Verify proof of knowledge
    let revealed_msgs: BTreeMap<usize, <E as Pairing>::ScalarField> = vectors
        .revealed_messages_bytes
        .iter()
        .map(|(idx, bytes)| {
            let msg = <E as Pairing>::ScalarField::deserialize_compressed(&bytes[..]).unwrap();
            (*idx, msg)
        })
        .collect();

    // Verifier independently computes the challenge from public data
    // This is critical for security - never trust a challenge provided by the prover
    let revealed_indices: BTreeSet<usize> = vectors.revealed_indices.iter().copied().collect();
    let challenge = pok_proof
        .gen_challenge::<Sha256>(revealed_indices, &verkey, &params)
        .unwrap();

    assert!(
        pok_proof
            .verify(&verkey, &params, revealed_msgs, &challenge)
            .unwrap(),
        "Proof of knowledge verification failed"
    );

    println!("All test vector verifications passed!");
}

#[test]
#[ignore = "Only run explicitly to regenerate blind signature test vectors: cargo test generate_blind_signature_test_vectors -- --ignored"]
fn generate_blind_signature_test_vectors() {
    let vectors = BlindSignatureTestVectors::generate();
    vectors.save();
    println!(
        "Blind signature test vectors generated and saved to {}/",
        TEST_DATA_DIR_BLIND
    );
}

#[test]
fn verify_blind_signature_with_test_vectors() {
    let vectors = BlindSignatureTestVectors::load();

    let params = Params::<E>::deserialize_compressed(&vectors.params_bytes[..]).unwrap();
    let verkey = Verkey::<E>::deserialize_compressed(&vectors.verkey_bytes[..]).unwrap();
    let blinding =
        <E as Pairing>::ScalarField::deserialize_compressed(&vectors.blinding_bytes[..]).unwrap();
    let sig_blinded =
        Signature::<E>::deserialize_compressed(&vectors.blind_signature_bytes[..]).unwrap();
    let messages: Vec<<E as Pairing>::ScalarField> = vectors
        .messages_bytes
        .iter()
        .map(|bytes| <E as Pairing>::ScalarField::deserialize_compressed(&bytes[..]).unwrap())
        .collect();

    let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);

    assert!(
        sig_unblinded.verify(&messages, &verkey, &params).unwrap(),
        "Blind signature verification failed"
    );
}

#[test]
#[ignore = "Only run explicitly to regenerate 2018 scheme test vectors: cargo test generate_test_vectors_2018 -- --ignored"]
fn generate_test_vectors_2018() {
    let vectors = TestVectors2018::generate();
    vectors.save();
    println!(
        "2018 scheme test vectors generated and saved to {}/",
        TEST_DATA_DIR_2018
    );
}

#[test]
fn verify_with_test_vectors_2018() {
    // Load test vectors
    let vectors = TestVectors2018::load();

    // Deserialize parameters
    let params = Params::<E>::deserialize_compressed(&vectors.params_bytes[..]).unwrap();

    // Deserialize verification key
    let verkey = Verkey::<E>::deserialize_compressed(&vectors.verkey_bytes[..]).unwrap();

    // Deserialize signing key
    let sigkey = Sigkey::<E>::deserialize_compressed(&vectors.sigkey_bytes[..]).unwrap();

    // Deserialize messages
    let messages: Vec<<E as Pairing>::ScalarField> = vectors
        .messages_bytes
        .iter()
        .map(|bytes| <E as Pairing>::ScalarField::deserialize_compressed(&bytes[..]).unwrap())
        .collect();

    // Deserialize signature
    let signature =
        signature_2018::Signature::<E>::deserialize_compressed(&vectors.signature_bytes[..])
            .unwrap();

    // Deserialize PoK proof
    let pok_proof =
        PoKOfSignatureProof::<E>::deserialize_compressed(&vectors.pok_proof_bytes[..]).unwrap();

    // Verify keygen: check that verkey is consistent with sigkey and params
    // For 2018 scheme, verkey has one extra Y_tilde for blinding
    assert_eq!(verkey.Y_tilde.len(), sigkey.y.len());
    assert_eq!(verkey.Y_tilde.len(), messages.len() + 1);

    // Verify signature
    assert!(
        signature.verify(&messages, &verkey, &params).unwrap(),
        "2018 scheme signature verification failed"
    );

    // Verify proof of knowledge
    let revealed_msgs: BTreeMap<usize, <E as Pairing>::ScalarField> = vectors
        .revealed_messages_bytes
        .iter()
        .map(|(idx, bytes)| {
            let msg = <E as Pairing>::ScalarField::deserialize_compressed(&bytes[..]).unwrap();
            (*idx, msg)
        })
        .collect();

    // Verifier independently computes the challenge from public data
    // This is critical for security - never trust a challenge provided by the prover
    let revealed_indices: BTreeSet<usize> = vectors.revealed_indices.iter().copied().collect();
    let challenge = pok_proof
        .gen_challenge::<Sha256>(revealed_indices, &verkey, &params)
        .unwrap();

    assert!(
        pok_proof
            .verify(&verkey, &params, revealed_msgs, &challenge)
            .unwrap(),
        "2018 scheme proof of knowledge verification failed"
    );

    println!("All 2018 scheme test vector verifications passed!");
}
