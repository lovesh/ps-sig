//! Proof of knowledge of signature for signature defined in 2018 paper, CT-RSA 2018 (eprint 2017/1197).

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use ark_std::collections::BTreeSet;

use ark_ec::pairing::Pairing;
use rand_core::CryptoRngCore;

use crate::errors::PSError;
use crate::keys::{Params, Verkey};
use crate::pok_sig::{PoKOfSignature as PoKOfSignature16, PoKOfSignatureProof};
use crate::signature_2018::Signature;

#[derive(Clone, Debug)]
pub struct PoKOfSignature<E: Pairing>(pub PoKOfSignature16<E>);

/// Most of the protocol is same as followed for the 2016 scheme
impl<E: Pairing> PoKOfSignature<E> {
    pub fn init<R: CryptoRngCore>(
        sig: &Signature<E>,
        vk: &Verkey<E>,
        params: &Params<E>,
        messages: Vec<E::ScalarField>,
        blindings: Option<&[E::ScalarField]>,
        revealed_msg_indices: BTreeSet<usize>,
        rng: &mut R,
    ) -> Result<Self, PSError> {
        Signature::check_verkey_and_messages_compat(&messages, vk)?;

        // m_prime should never be revealed
        PoKOfSignature16::<E>::validate_revealed_indices(&messages, &revealed_msg_indices)?;

        let mut blindings =
            PoKOfSignature16::<E>::get_blindings(blindings, &messages, &revealed_msg_indices)?;

        let (t, sigma_prime) = PoKOfSignature16::<E>::transform_sig(&sig.sig, rng);

        let mut all_messages = messages;
        all_messages.push(sig.m_prime);
        // Choose blinding for m_prime randomly
        blindings.push(None);

        let (exponents, J, committed) = PoKOfSignature16::<E>::commit_for_pok(
            all_messages,
            blindings,
            &revealed_msg_indices,
            t,
            vk,
            params,
            rng,
        )?;
        Ok(Self(PoKOfSignature16 {
            secrets: exponents,
            sig: sigma_prime,
            J,
            pok_vc: committed,
        }))
    }

    /// Return byte representation of public elements so they can be used for challenge computation
    pub fn to_bytes(&self) -> Result<Vec<u8>, PSError> {
        self.0.to_bytes()
    }

    /// Generate challenge for Fiat-Shamir transformation.
    /// Both prover and verifier should independently call this method to get the same challenge.
    pub fn gen_challenge<H: digest::Digest>(&self) -> Result<E::ScalarField, PSError> {
        self.0.gen_challenge::<H>()
    }

    /// The proof generation protocol is same as for the 2016 scheme the resulting proof is same as
    /// the proof for the 2016 scheme and can be verified using its `verify method`
    pub fn gen_proof(self, challenge: E::ScalarField) -> Result<PoKOfSignatureProof<E>, PSError> {
        self.0.gen_proof(challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::keygen_2018;
    use crate::pok_vc::ProverCommitted;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_std::collections::BTreeMap;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use sha2::Sha256;

    #[test]
    fn test_PoK_sig() {
        fn check<E: Pairing>() {
            let count_msgs = 5;
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, vk) = keygen_2018(count_msgs, &params, &mut rng);

            let msgs = (0..count_msgs)
                .map(|_| E::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>();
            let sig = Signature::new(&msgs, &sk, &mut rng).unwrap();
            assert!(sig.verify(&msgs, &vk, &params).unwrap());

            let pok = PoKOfSignature::init(
                &sig,
                &vk,
                &params,
                msgs.clone(),
                None,
                BTreeSet::new(),
                &mut rng,
            )
            .unwrap();

            let pok_bytes = pok.to_bytes().unwrap();
            let chal_prover =
                ProverCommitted::<E::G1Affine>::gen_challenge_from_bytes::<Sha256>(&pok_bytes)
                    .unwrap();

            let proof = pok.gen_proof(chal_prover).unwrap();

            // The verifier generates the challenge on its own.
            let chal_bytes = proof
                .get_bytes_for_challenge(BTreeSet::new(), &vk, &params)
                .unwrap();
            let chal_verifier =
                ProverCommitted::<E::G1Affine>::gen_challenge_from_bytes::<Sha256>(&chal_bytes)
                    .unwrap();

            assert!(proof
                .verify(&vk, &params, BTreeMap::new(), &chal_verifier)
                .unwrap());

            // PoK with supplied blindings
            let blindings = (0..count_msgs)
                .map(|_| E::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>();
            let pok_1 = PoKOfSignature::init(
                &sig,
                &vk,
                &params,
                msgs,
                Some(&blindings),
                BTreeSet::new(),
                &mut rng,
            )
            .unwrap();
            let pok_1_bytes = pok_1.to_bytes().unwrap();
            let chal_prover =
                ProverCommitted::<E::G1Affine>::gen_challenge_from_bytes::<Sha256>(&pok_1_bytes)
                    .unwrap();
            let proof_1 = pok_1.gen_proof(chal_prover).unwrap();

            // The verifier generates the challenge on its own.
            let chal_bytes = proof_1
                .get_bytes_for_challenge(BTreeSet::new(), &vk, &params)
                .unwrap();
            let chal_verifier =
                ProverCommitted::<E::G1Affine>::gen_challenge_from_bytes::<Sha256>(&chal_bytes)
                    .unwrap();
            assert!(proof_1
                .verify(&vk, &params, BTreeMap::new(), &chal_verifier)
                .unwrap());
        }

        check::<Bls12_381>();
        check::<Bls12_377>();
    }

    #[test]
    fn test_PoK_sig_reveal_messages() {
        fn check<E: Pairing>() {
            let count_msgs = 10;
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, vk) = keygen_2018(count_msgs, &params, &mut rng);

            let msgs = (0..count_msgs)
                .map(|_| E::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>();

            let sig = Signature::new(&msgs, &sk, &mut rng).unwrap();
            assert!(sig.verify(&msgs, &vk, &params).unwrap());

            let mut revealed_msg_indices = BTreeSet::new();
            revealed_msg_indices.insert(2);
            revealed_msg_indices.insert(4);
            revealed_msg_indices.insert(9);

            let pok = PoKOfSignature::init(
                &sig,
                &vk,
                &params,
                msgs.clone(),
                None,
                revealed_msg_indices.clone(),
                &mut rng,
            )
            .unwrap();

            let pok_bytes = pok.to_bytes().unwrap();
            let chal_prover =
                ProverCommitted::<E::G1Affine>::gen_challenge_from_bytes::<Sha256>(&pok_bytes)
                    .unwrap();

            let proof = pok.gen_proof(chal_prover).unwrap();

            let mut revealed_msgs = BTreeMap::new();
            for i in &revealed_msg_indices {
                revealed_msgs.insert(*i, msgs[*i]);
            }
            // The verifier generates the challenge on its own.
            let chal_bytes = proof
                .get_bytes_for_challenge(revealed_msg_indices.clone(), &vk, &params)
                .unwrap();
            let chal_verifier =
                ProverCommitted::<E::G1Affine>::gen_challenge_from_bytes::<Sha256>(&chal_bytes)
                    .unwrap();
            assert!(proof
                .verify(&vk, &params, revealed_msgs.clone(), &chal_verifier)
                .unwrap());

            // Reveal wrong message
            let mut revealed_msgs_1 = revealed_msgs;
            revealed_msgs_1.insert(2, E::ScalarField::rand(&mut rng));
            assert!(!proof
                .verify(&vk, &params, revealed_msgs_1, &chal_verifier)
                .unwrap());
        }

        check::<Bls12_381>();
        check::<Bls12_377>();
    }
}
