#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Zero;

use crate::errors::PSError;
use crate::keys::{Params, Verkey};
use crate::signature::Signature;
use crate::signature_2018::Signature as Signature18;

/// PS multi-signatures using the same idea as BLS multi-signatures.
///
/// TODO: Add Proof of possesion of private key. Can be a verifiable signature on a standard message or
/// can be a proof of knowledge of secret key. Proof of knowledge should be better since it will not involve any pairing during verification.
/// But is signature sufficient for elements of both group?
pub struct AggregatedVerkeyFast {}

impl AggregatedVerkeyFast {
    pub fn from_verkeys<E: Pairing>(ver_keys: Vec<&Verkey<E>>) -> Result<Verkey<E>, PSError> {
        if ver_keys.is_empty() {
            return Err(PSError::GeneralError {
                msg: String::from("Provide at least one key"),
            });
        }
        let y_len = ver_keys[0].Y_tilde.len();
        if !ver_keys.iter().all(|vk| vk.Y_tilde.len() == y_len) {
            return Err(PSError::IncompatibleVerkeysForAggregation);
        }
        let mut X_tilde = E::G2::zero();
        let mut Y_tilde = vec![E::G2::zero(); y_len];
        for vk in ver_keys {
            X_tilde += vk.X_tilde.into_group();
            for i in 0..y_len {
                Y_tilde[i] += vk.Y_tilde[i].into_group();
            }
        }
        let X_tilde = X_tilde.into_affine();
        let Y_tilde = Y_tilde.into_iter().map(|y| y.into_affine()).collect();
        Ok(Verkey { X_tilde, Y_tilde })
    }
}

pub struct MultiSignatureFast {}

impl MultiSignatureFast {
    /// Create a multi-signature from signature scheme defined in 2016 paper, CT-RSA 2016
    pub fn from_sigs<E: Pairing>(sigs: Vec<&Signature<E>>) -> Result<Signature<E>, PSError> {
        if sigs.is_empty() {
            return Err(PSError::GeneralError {
                msg: String::from("Provide at least one signature"),
            });
        }
        Self::combine(sigs)
    }

    /// Create a multi-signature from signature scheme defined in 2018 paper, CT-RSA 2018
    pub fn from_sigs_2018<E: Pairing>(
        sigs: Vec<&Signature18<E>>,
    ) -> Result<Signature18<E>, PSError> {
        if sigs.is_empty() {
            return Err(PSError::GeneralError {
                msg: String::from("Provide at least one signature"),
            });
        }
        let m_prime = sigs[0].m_prime;
        if !sigs.iter().all(|sig| sig.m_prime == m_prime) {
            return Err(PSError::IncompatibleSigsForAggregation);
        }
        let sig = Self::combine(
            sigs.into_iter()
                .map(|s| &s.sig)
                .collect::<Vec<&Signature<E>>>(),
        )?;
        Ok(Signature18 { m_prime, sig })
    }

    /// Helper for common logic
    fn combine<E: Pairing>(sigs: Vec<&Signature<E>>) -> Result<Signature<E>, PSError> {
        let sigma_1 = sigs[0].sigma_1;
        if !sigs.iter().all(|sig| sig.sigma_1 == sigma_1) {
            return Err(PSError::IncompatibleSigsForAggregation);
        }
        let mut sigma_2 = E::G1::zero();
        for s in sigs {
            sigma_2 += s.sigma_2.into_group();
        }
        Ok(Signature {
            sigma_1,
            sigma_2: sigma_2.into_affine(),
        })
    }

    /// An aggregate Verkey is created from `ver_keys`. When verifying signature using the same
    /// set of keys frequently generate a verkey once and then use `Signature::verify`
    /// For verifying a multi-signature from signature scheme defined in 2016 paper, CT-RSA 2016
    pub fn verify<E: Pairing>(
        sig: &Signature<E>,
        messages: &[E::ScalarField],
        ver_keys: Vec<&Verkey<E>>,
        params: &Params<E>,
    ) -> Result<bool, PSError> {
        let avk = AggregatedVerkeyFast::from_verkeys(ver_keys)?;
        sig.verify(messages, &avk, params)
    }

    /// For verifying a multi-signature from signature scheme defined in 2018 paper, CT-RSA 2018
    pub fn verify_2018<E: Pairing>(
        sig: &Signature18<E>,
        messages: &[E::ScalarField],
        ver_keys: Vec<&Verkey<E>>,
        params: &Params<E>,
    ) -> Result<bool, PSError> {
        let avk = AggregatedVerkeyFast::from_verkeys(ver_keys)?;
        sig.verify(messages, &avk, params)
    }

    // For verifying multiple multi-signatures from the same signers,
    // an aggregated verkey should be created once and then used for each signature verification
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{keygen, keygen_2018};
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use sha2::Sha256;

    #[test]
    fn test_multi_signature_all_known_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 5) + 1;
                let (sk_1, vk_1) = keygen(count_msgs, &params, &mut rng);
                let (sk_2, vk_2) = keygen(count_msgs, &params, &mut rng);
                let (sk_3, vk_3) = keygen(count_msgs, &params, &mut rng);

                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();

                let sig_1 = Signature::new_deterministic::<Sha256>(&msgs, &sk_1).unwrap();
                let sig_2 = Signature::new_deterministic::<Sha256>(&msgs, &sk_2).unwrap();
                let sig_3 = Signature::new_deterministic::<Sha256>(&msgs, &sk_3).unwrap();

                let multi_sig =
                    MultiSignatureFast::from_sigs(vec![&sig_1, &sig_2, &sig_3]).unwrap();

                assert!(MultiSignatureFast::verify(
                    &multi_sig,
                    &msgs,
                    vec![&vk_1, &vk_2, &vk_3],
                    &params
                )
                .unwrap())
            }
        }

        check::<Bls12_381>();
    }

    #[test]
    fn test_multi_signature_2018_all_known_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 5) + 1;
                let (sk_1, vk_1) = keygen_2018(count_msgs, &params, &mut rng);
                let (sk_2, vk_2) = keygen_2018(count_msgs, &params, &mut rng);
                let (sk_3, vk_3) = keygen_2018(count_msgs, &params, &mut rng);

                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();

                let sig_1 = Signature18::new_deterministic::<Sha256>(&msgs, &sk_1).unwrap();
                let sig_2 = Signature18::new_deterministic::<Sha256>(&msgs, &sk_2).unwrap();
                let sig_3 = Signature18::new_deterministic::<Sha256>(&msgs, &sk_3).unwrap();

                let multi_sig =
                    MultiSignatureFast::from_sigs_2018(vec![&sig_1, &sig_2, &sig_3]).unwrap();

                assert!(MultiSignatureFast::verify_2018(
                    &multi_sig,
                    &msgs,
                    vec![&vk_1, &vk_2, &vk_3],
                    &params
                )
                .unwrap())
            }
        }

        check::<Bls12_381>();
    }

    // TODO: For aggregating blind signature, a Coconut like approach is needed.
}
