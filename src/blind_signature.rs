//! Scheme defined in in 2016 paper, CT-RSA 2016 (eprint 2015/525), section 6.1 supporting blind signatures

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand_core::CryptoRngCore;

use crate::errors::PSError;
use crate::keys::{Params, Sigkey};
use crate::signature::Signature;

// The public key described in the paper is split into `BlindingKey` and `Verkey`. Only `Verkey` is
// needed by the verifier. `BlindingKey` is used by the user to request a blind signature.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BlindingKey<E: Pairing> {
    pub X: E::G1Affine,
    pub Y: Vec<E::G1Affine>,
}

impl<E: Pairing> BlindingKey<E> {
    pub fn new(sig_key: &Sigkey<E>, params: &Params<E>) -> Self {
        let X = (params.g * sig_key.x).into_affine();
        let mut Y = Vec::with_capacity(sig_key.y.len());
        for i in 0..sig_key.y.len() {
            Y.push((params.g * sig_key.y[i]).into_affine());
        }
        Self { X, Y }
    }

    pub fn msg_count(&self) -> usize {
        self.Y.len()
    }
}

pub struct BlindSignature {}

impl BlindSignature {
    /// 1 or more messages are captured in a commitment `commitment`. The remaining known messages are in `messages`.
    /// The signing key `sigkey` differs from paper, it does not contain one group element but is the same as
    /// signing key described in the scheme from section 4.2
    /// The signing process differs slightly from the paper but results in the same signature. An example to illustrate the difference:
    /// Lets say the signer wants to sign a multi-message of 10 messages where only 1 message is blinded.
    /// If we go by the paper where signer does not have y_1, y_2, .. y_10, signer will pick a random u and compute signature as
    /// (g^u, (XC)^u.Y_2^u.m_2.Y_3^u.m_3...Y_10^u.m_10), Y_1 is omitted as the first message was blinded. Of course the term
    /// (XC)^u.Y_2^u.Y_3^u...Y_10^u can be computed using efficient multi-exponentiation techniques but it would be more efficient
    /// if the signer could instead compute (g^u, C^u.g^{(x+y_2.m_2+y_3.m_3+...y_10.m_10).u}). The resulting signature will have the same form
    /// and can be unblinded in the same way as described in the paper.
    pub fn new<E: Pairing, R: CryptoRngCore>(
        commitment: &E::G1Affine,
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
        blinding_key: &BlindingKey<E>,
        params: &Params<E>,
        rng: &mut R,
    ) -> Result<Signature<E>, PSError> {
        // There should be commitment to at least one message
        Self::check_blinding_key_and_messages_compat(messages, blinding_key)?;

        let u = E::ScalarField::rand(rng);
        let offset = blinding_key.msg_count() - messages.len();
        let (sigma_1, sigma_2_partial) = Signature::sign_with_sigma_1_generated_from_given_exp(
            messages, sigkey, &u, offset, &params.g,
        )?;
        let sigma_2 = (sigma_2_partial.into_group() + (*commitment * u)).into_affine();
        Ok(Signature { sigma_1, sigma_2 })
    }

    /// Scheme as described in the paper
    pub fn new_from_paper<E: Pairing, R: CryptoRngCore>(
        commitment: &E::G1Affine,
        messages: &[E::ScalarField],
        sigkey_X: &E::G1Affine, // The signing key consists of a single group element
        blinding_key: &BlindingKey<E>,
        params: &Params<E>,
        rng: &mut R,
    ) -> Result<Signature<E>, PSError> {
        // There should be commitment to at least one message
        Self::check_blinding_key_and_messages_compat(messages, blinding_key)?;

        let u = E::ScalarField::rand(rng);

        // sigma_1 = g^u
        let sigma_1 = (params.g * u).into_affine();

        // sigma_2 = {X + Y_i^{m_i} + commitment}^u
        let offset = blinding_key.msg_count() - messages.len();
        let bases: Vec<_> = blinding_key.Y[offset..].iter().copied().collect();
        let points_contribution = E::G1::msm_unchecked(&bases, &messages[..]);

        let sigma_2_pre = sigkey_X.into_group() + points_contribution + commitment.into_group();
        let sigma_2 = (sigma_2_pre * u).into_affine();
        Ok(Signature { sigma_1, sigma_2 })
    }

    /// Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    /// Takes the blinding used in the commitment.
    pub fn unblind<E: Pairing>(sig: &Signature<E>, blinding: &E::ScalarField) -> Signature<E> {
        let sigma_1 = sig.sigma_1;
        let sigma_1_t = sig.sigma_1 * blinding;
        let sigma_2 = (sig.sigma_2.into_group() - sigma_1_t).into_affine();
        Signature { sigma_1, sigma_2 }
    }

    pub fn check_blinding_key_and_messages_compat<E: Pairing>(
        messages: &[E::ScalarField],
        blinding_key: &BlindingKey<E>,
    ) -> Result<(), PSError> {
        if messages.len() >= blinding_key.msg_count() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: blinding_key.msg_count(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::keygen;
    use ark_bls12_381::Bls12_381;
    use ark_ec::CurveGroup;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use ark_std::Zero;
    use sha2::Sha256;

    #[test]
    fn test_blinding_key() {
        fn check<E: Pairing>() {
            let count_msgs = 5;
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, _vk) = keygen(count_msgs, &params, &mut rng);
            let blinding_key = BlindingKey::new(&sk, &params);
            assert_eq!(blinding_key.msg_count(), count_msgs);
        }

        check::<Bls12_381>();
    }

    #[test]
    fn test_signature_single_blinded_message() {
        fn check<E: Pairing>() {
            // Only 1 blinded message, no message known to signer
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for _ in 0..10 {
                let count_msgs = 1;
                let (sk, vk) = keygen(count_msgs, &params, &mut rng);

                let blinding_key = BlindingKey::new(&sk, &params);
                let msg = E::ScalarField::rand(&mut rng);
                let blinding = E::ScalarField::rand(&mut rng);

                // commitment = Y[0]^msg * g^blinding
                let comm = (blinding_key.Y[0] * msg + params.g * blinding).into_affine();

                let sig_blinded =
                    BlindSignature::new(&comm, &[], &sk, &blinding_key, &params, &mut rng).unwrap();
                let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
                assert!(sig_unblinded.verify(&[msg], &vk, &params).unwrap());
            }
        }

        check::<Bls12_381>();
    }

    #[test]
    fn test_signature_many_blinded_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 5) + 1;
                let (sk, vk) = keygen(count_msgs, &params, &mut rng);

                let blinding_key = BlindingKey::new(&sk, &params);
                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();
                let blinding = E::ScalarField::rand(&mut rng);

                // XXX: In production always use multi-scalar multiplication
                let mut comm = E::G1::zero();
                for i in 0..count_msgs {
                    comm += blinding_key.Y[i] * msgs[i];
                }
                comm += params.g * blinding;
                let comm = comm.into_affine();

                let sig_blinded =
                    BlindSignature::new(&comm, &[], &sk, &blinding_key, &params, &mut rng).unwrap();
                let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
                assert!(sig_unblinded.verify(&msgs, &vk, &params).unwrap());
            }
        }

        check::<Bls12_381>();
    }

    #[test]
    fn test_signature_known_and_blinded_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 6) + 1;
                let count_blinded_msgs = (i % count_msgs) + 1;
                let (sk, vk) = keygen(count_msgs, &params, &mut rng);

                let blinding_key = BlindingKey::new(&sk, &params);
                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();
                let blinding = E::ScalarField::rand(&mut rng);

                // XXX: In production always use multi-scalar multiplication
                let mut comm = E::G1::zero();
                for i in 0..count_blinded_msgs {
                    comm += blinding_key.Y[i] * msgs[i];
                }
                comm += params.g * blinding;
                let comm = comm.into_affine();

                let sig_blinded = BlindSignature::new(
                    &comm,
                    &msgs[count_blinded_msgs..count_msgs],
                    &sk,
                    &blinding_key,
                    &params,
                    &mut rng,
                )
                .unwrap();
                let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
                assert!(sig_unblinded.verify(&msgs, &vk, &params).unwrap());
            }
        }

        check::<Bls12_381>();
    }
}
