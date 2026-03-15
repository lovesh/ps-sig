//! Proof of knowledge of signature for signature from 2016 paper, CT-RSA 2016 (eprint 2015/525), section 6.2

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use ark_std::collections::{BTreeMap, BTreeSet};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, Zero};
use digest::Digest;
use rand_core::CryptoRngCore;

use crate::errors::PSError;
use crate::keys::{Params, Verkey};
use crate::pok_vc::{Proof, ProverCommitted, ProverCommitting};
use crate::signature::Signature;

/// As [Short Randomizable signatures](https://eprint.iacr.org/2015/525), section 6.2 describes, for proving knowledge of a signature, the signature sigma is first randomized and also
/// transformed into a sequential aggregate signature with extra message t for public key g_tilde (and secret key 1).
/// 1. Say the signature sigma is transformed to sigma_prime = (sigma_prime_1, sigma_prime_2) like step 1 in 6.2
/// 1. The prover then sends sigma_prime and the value J = X_tilde * Y_tilde_1^m1 * Y_tilde_2^m2 * ..... * g_tilde^t and the proof J is formed correctly.
/// The verifier now checks whether e(sigma_prime_1, J) == e(sigma_prime_2, g_tilde). Since X_tilde is known,
/// the verifier can send following a modified value J' where J' = Y_tilde_1^m_1 * Y_tilde_2^m_2 * ..... * g_tilde^t with the proof of knowledge of elements of J'.
/// The verifier will then check the pairing e(sigma_prime_1, J'*X_tilde) == e(sigma_prime_2, g_tilde).
/// To reveal some of the messages from the signature but not all, in above protocol, construct J to be of the hidden values only, the verifier will
/// then add the revealed values (raised to the respective generators) to get a final J which will then be used in the pairing check.
#[derive(Clone, Debug)]
pub struct PoKOfSignature<E: Pairing> {
    pub secrets: Vec<E::ScalarField>,
    pub sig: Signature<E>,
    pub J: E::G2Affine,
    pub pok_vc: ProverCommitted<E::G2Affine>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKOfSignatureProof<E: Pairing> {
    pub sig: Signature<E>,
    pub J: E::G2Affine,
    pub proof_vc: Proof<E::G2Affine>,
}

impl<E: Pairing> PoKOfSignature<E> {
    /// Section 6.2 of paper
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
        Self::validate_revealed_indices(&messages, &revealed_msg_indices)?;

        let blindings = Self::get_blindings(blindings, &messages, &revealed_msg_indices)?;

        let (t, sigma_prime) = Self::transform_sig(sig, rng);

        let (exponents, J, committed) = Self::commit_for_pok(
            messages,
            blindings,
            &revealed_msg_indices,
            t,
            vk,
            params,
            rng,
        )?;

        Ok(Self {
            secrets: exponents,
            sig: sigma_prime,
            J,
            pok_vc: committed,
        })
    }

    /// Return byte representation of public elements so they can be used for challenge computation
    pub fn to_bytes(&self) -> Result<Vec<u8>, PSError> {
        let mut bytes = Vec::new();
        self.sig.to_bytes()?.iter().for_each(|b| bytes.push(*b));
        self.J
            .serialize_compressed(&mut bytes)
            .map_err(|_| PSError::SerializationError)?;
        self.pok_vc.to_bytes()?.iter().for_each(|b| bytes.push(*b));
        Ok(bytes)
    }

    /// Generate challenge for Fiat-Shamir transformation.
    /// Both prover and verifier should independently call this method to get the same challenge.
    /// This ensures the prover cannot manipulate the challenge.
    pub fn gen_challenge<H: Digest>(&self) -> Result<E::ScalarField, PSError> {
        let mut j_bytes = Vec::new();
        self.J
            .serialize_compressed(&mut j_bytes)
            .map_err(|_| PSError::SerializationError)?;
        self.pok_vc.gen_challenge::<H>(&j_bytes)
    }

    pub fn gen_proof(self, challenge: E::ScalarField) -> Result<PoKOfSignatureProof<E>, PSError> {
        let proof_vc = self.pok_vc.gen_proof(challenge, &self.secrets)?;
        Ok(PoKOfSignatureProof {
            sig: self.sig,
            J: self.J,
            proof_vc,
        })
    }

    pub(crate) fn validate_revealed_indices(
        messages: &[E::ScalarField],
        revealed_msg_indices: &BTreeSet<usize>,
    ) -> Result<(), PSError> {
        for idx in revealed_msg_indices {
            if *idx >= messages.len() {
                return Err(PSError::GeneralError {
                    msg: format!("Index {} should be less than {}", idx, messages.len()),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn get_blindings<'a>(
        blindings: Option<&'a [E::ScalarField]>,
        messages: &[E::ScalarField],
        revealed_msg_indices: &BTreeSet<usize>,
    ) -> Result<Vec<Option<&'a E::ScalarField>>, PSError> {
        let mut blindings = match blindings {
            Some(b) => {
                if (messages.len() - revealed_msg_indices.len()) != b.len() {
                    return Err(PSError::GeneralError {
                        msg: format!(
                            "No of blindings {} not equal to number of hidden messages {}",
                            b.len(),
                            (messages.len() - revealed_msg_indices.len())
                        ),
                    });
                }
                b.iter().map(Some).collect()
            }
            None => (0..(messages.len() - revealed_msg_indices.len()))
                .map(|_| None)
                .collect::<Vec<Option<&'a E::ScalarField>>>(),
        };

        // Choose blinding for g_tilde randomly
        blindings.insert(0, None);
        Ok(blindings)
    }

    /// Transform signature to an aggregate signature on (messages, t)
    pub(crate) fn transform_sig<R: CryptoRngCore>(
        sig: &Signature<E>,
        rng: &mut R,
    ) -> (E::ScalarField, Signature<E>) {
        let r = E::ScalarField::rand(rng);
        let t = E::ScalarField::rand(rng);

        // Transform signature to an aggregate signature on (messages, t)
        let sigma_prime_1 = (sig.sigma_1 * r).into_affine();
        let sigma_prime_2 = ((sig.sigma_2.into_group() + sig.sigma_1 * t) * r).into_affine();

        (
            t,
            Signature {
                sigma_1: sigma_prime_1,
                sigma_2: sigma_prime_2,
            },
        )
    }

    pub(crate) fn commit_for_pok<R: CryptoRngCore>(
        messages: Vec<E::ScalarField>,
        mut blindings: Vec<Option<&E::ScalarField>>,
        revealed_msg_indices: &BTreeSet<usize>,
        t: E::ScalarField,
        vk: &Verkey<E>,
        params: &Params<E>,
        rng: &mut R,
    ) -> Result<
        (
            Vec<E::ScalarField>,
            E::G2Affine,
            ProverCommitted<E::G2Affine>,
        ),
        PSError,
    > {
        // +1 for `t`
        let hidden_msg_count = vk.Y_tilde.len() - revealed_msg_indices.len() + 1;
        let mut bases = Vec::with_capacity(hidden_msg_count);
        let mut exponents = Vec::with_capacity(hidden_msg_count);
        bases.push(params.g_tilde);
        exponents.push(t);
        for (i, msg) in messages.into_iter().enumerate() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i]);
            exponents.push(msg);
        }

        // Prove knowledge of m_1, m_2, ... for all hidden m_i and t in J = Y_tilde_1^m_1 * Y_tilde_2^m_2 * ..... * g_tilde^t
        let J = E::G2::msm_unchecked(&bases, &exponents).into_affine();

        // For proving knowledge of messages in J.
        let mut committing = ProverCommitting::new();
        for b in &bases {
            match blindings.remove(0) {
                Some(blinding) => committing.commit(*b, *blinding),
                None => committing.commit_random(*b, rng),
            };
        }
        let committed = committing.finish();

        Ok((exponents, J, committed))
    }
}

impl<E: Pairing> PoKOfSignatureProof<E> {
    /// Return bytes that need to be hashed for generating challenge. Since the message only requires
    /// commitment to "non-revealed" messages of signature, generators of only those messages are
    /// to be considered for challenge creation.
    /// Takes bytes of the randomized signature, the "commitment" to non-revealed messages (J) and the
    /// generators and the commitment to randomness used in the proof of knowledge of "non-revealed" messages.
    pub fn get_bytes_for_challenge(
        &self,
        revealed_msg_indices: BTreeSet<usize>,
        vk: &Verkey<E>,
        params: &Params<E>,
    ) -> Result<Vec<u8>, PSError> {
        let mut bytes = Vec::new();
        self.sig.to_bytes()?.iter().for_each(|b| bytes.push(*b));
        self.J
            .serialize_compressed(&mut bytes)
            .map_err(|_| PSError::SerializationError)?;
        params
            .g_tilde
            .serialize_compressed(&mut bytes)
            .map_err(|_| PSError::SerializationError)?;
        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            vk.Y_tilde[i]
                .serialize_compressed(&mut bytes)
                .map_err(|_| PSError::SerializationError)?;
        }
        self.proof_vc
            .commitment
            .serialize_compressed(&mut bytes)
            .map_err(|_| PSError::SerializationError)?;
        Ok(bytes)
    }

    /// Generate challenge for Fiat-Shamir transformation from the proof.
    /// The verifier should call this method to independently compute the same challenge
    /// that the prover used. This prevents a malicious prover from using a different challenge.
    ///
    /// # Parameters
    /// * `revealed_msg_indices` - Set of indices of revealed messages
    /// * `vk` - Verification key
    /// * `params` - Public parameters
    ///
    /// # Security
    /// CRITICAL: The verifier must use this method (or equivalent) to compute the challenge
    /// independently. Never accept a challenge value from the prover directly.
    pub fn gen_challenge<H: Digest>(
        &self,
        revealed_msg_indices: BTreeSet<usize>,
        vk: &Verkey<E>,
        params: &Params<E>,
    ) -> Result<E::ScalarField, PSError> {
        // Reconstruct the same generators that were used by the prover
        // This matches the bases construction in PoKOfSignature::init
        let hidden_msg_count = vk.Y_tilde.len() - revealed_msg_indices.len() + 1;
        let mut gens = Vec::with_capacity(hidden_msg_count);
        gens.push(params.g_tilde);
        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            gens.push(vk.Y_tilde[i]);
        }

        // Hash generators and commitment, matching ProverCommitted.to_bytes() format
        let mut hasher = H::new();
        for g in &gens {
            let mut g_bytes = Vec::new();
            g.serialize_compressed(&mut g_bytes)
                .map_err(|_| PSError::SerializationError)?;
            hasher.update(&g_bytes);
        }
        let mut commitment_bytes = Vec::new();
        self.proof_vc
            .commitment
            .serialize_compressed(&mut commitment_bytes)
            .map_err(|_| PSError::SerializationError)?;
        hasher.update(&commitment_bytes);

        // Then hash J as extra data
        let mut j_bytes = Vec::new();
        self.J
            .serialize_compressed(&mut j_bytes)
            .map_err(|_| PSError::SerializationError)?;
        hasher.update(&j_bytes);

        let hash = hasher.finalize();

        // Convert hash to field element deterministically
        let mut seed = [0u8; 32];
        let hash_bytes = hash.as_slice();
        let copy_len = core::cmp::min(hash_bytes.len(), 32);
        seed[..copy_len].copy_from_slice(&hash_bytes[..copy_len]);

        let mut rng = crate::deterministic_rng_from_seed(seed);
        Ok(E::ScalarField::rand(&mut rng))
    }

    /// Get the response from post-challenge phase of the Sigma protocol for the given message index `msg_idx`.
    /// Used when comparing message equality
    pub fn get_resp_for_message(&self, msg_idx: usize) -> Result<E::ScalarField, PSError> {
        // 1 element in self.proof_vc.responses is reserved for the random `t`
        if msg_idx >= (self.proof_vc.responses.len() - 1) {
            return Err(PSError::GeneralError {
                msg: format!(
                    "Message index was given {} but should be less than {}",
                    msg_idx,
                    self.proof_vc.responses.len() - 1
                ),
            });
        }
        // 1 added to the index, since 0th index is reserved for randomization (`t`)
        Ok(self.proof_vc.responses[1 + msg_idx])
    }

    pub fn verify(
        &self,
        vk: &Verkey<E>,
        params: &Params<E>,
        revealed_msgs: BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
    ) -> Result<bool, PSError> {
        if self.sig.is_identity() {
            return Ok(false);
        }

        // +1 for `t`
        let hidden_msg_count = vk.Y_tilde.len() - revealed_msgs.len() + 1;
        let mut bases = Vec::with_capacity(hidden_msg_count);
        bases.push(params.g_tilde);
        for i in 0..vk.Y_tilde.len() {
            if revealed_msgs.contains_key(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i]);
        }
        if !self.proof_vc.verify(&bases, self.J, *challenge)? {
            return Ok(false);
        }
        // e(sigma_prime_1, J*X_tilde) == e(sigma_prime_2, g_tilde) => e(sigma_prime_1, J*X_tilde) * e(sigma_prime_2^-1, g_tilde) == 1
        let J = if revealed_msgs.is_empty() {
            self.J
        } else {
            let bases: Vec<_> = revealed_msgs.iter().map(|(i, _)| vk.Y_tilde[*i]).collect();
            let exps: Vec<_> = revealed_msgs.values().copied().collect();
            let revealed_contribution = E::G2::msm_unchecked(&bases, &exps);
            (self.J.into_group() + revealed_contribution).into_affine()
        };

        // e(sigma_1, (J + X_tilde)) == e(sigma_2, g_tilde) => e(sigma_1, (J + X_tilde)) * e(sigma_2, -g_tilde) == 0
        // Using multi_pairing for efficiency
        let J_plus_X = (J.into_group() + vk.X_tilde.into_group()).into_affine();
        let neg_g_tilde = (-params.g_tilde.into_group()).into_affine();
        let result = E::multi_pairing(
            &[self.sig.sigma_1, self.sig.sigma_2],
            &[J_plus_X, neg_g_tilde],
        );
        Ok(result.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::keygen;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use sha2::Sha256;

    #[test]
    fn test_PoK_VC_G2() {
        fn check<E: Pairing>() {
            crate::pok_vc::tests::test_pok_vc::<E::G2Affine, Sha256>(5);
        }

        check::<Bls12_381>();
    }

    #[test]
    fn test_PoK_VC_G1() {
        fn check<E: Pairing>() {
            crate::pok_vc::tests::test_pok_vc::<E::G1Affine, Sha256>(5);
        }

        check::<Bls12_381>();
    }

    #[test]
    fn test_PoK_sig() {
        fn check<E: Pairing>() {
            let count_msgs = 5;
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, vk) = keygen(count_msgs, &params, &mut rng);

            let msgs = (0..count_msgs)
                .map(|_| E::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>();
            let sig = Signature::new(&msgs, &sk, &params, &mut rng).unwrap();
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
            let (sk, vk) = keygen(count_msgs, &params, &mut rng);

            let msgs = (0..count_msgs)
                .map(|_| E::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>();

            let sig = Signature::new(&msgs, &sk, &params, &mut rng).unwrap();
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
