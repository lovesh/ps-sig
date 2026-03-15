// Scheme defined in 2016 paper, CT-RSA 2016 (eprint 2015/525), section 4.2.
// The idea for blind signatures can be taken from Coconut

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use digest::Digest;
use rand_core::CryptoRngCore;

use crate::errors::PSError;
use crate::keys::{Params, Sigkey, Verkey};

const DST_SIGMA_1: &[u8] = b"PS-SIG-V1-SIGMA-1";

/// Created by the signer when no blinded messages. Also the receiver of a blind signature can get
/// this by unblinding the blind signature.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<E: Pairing> {
    pub sigma_1: E::G1Affine,
    pub sigma_2: E::G1Affine,
}

impl<E: Pairing> Signature<E> {
    /// Create a new signature. The signature generation involves generating a random value for `sigma_1` so different
    /// calls to this method with same messages, signing key and params will give different value
    pub fn new<R: CryptoRngCore>(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
        params: &Params<E>,
        rng: &mut R,
    ) -> Result<Self, PSError> {
        Self::check_sigkey_and_messages_compat(messages, sigkey)?;
        // A random h should be generated which is same as generating a random u and then computing h = g^u
        let u = E::ScalarField::rand(rng);
        let (sigma_1, sigma_2) =
            Self::sign_with_sigma_1_generated_from_given_exp(messages, sigkey, &u, 0, &params.g)?;
        Ok(Self { sigma_1, sigma_2 })
    }

    /// Create a new signature. The signature generation doesn't involve generating a random value but
    /// the messages are hashed to get a pseudorandom value for `sigma_1`. Hence different calls to this method
    /// with same messages and signing key will give same value
    pub fn new_deterministic<H: Digest>(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
    ) -> Result<Self, PSError> {
        Self::check_sigkey_and_messages_compat(messages, sigkey)?;
        let sigma_1 = Self::generate_sigma_1_from_messages::<H>(messages);
        let sigma_2 = Self::sign_with_given_sigma_1(messages, sigkey, 0, &sigma_1)?;
        Ok(Self { sigma_1, sigma_2 })
    }

    /// Generate signature when first element of signature tuple is generated using given exponent
    /// Does only 1 scalar multiplication
    pub fn sign_with_sigma_1_generated_from_given_exp(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
        u: &E::ScalarField,
        offset: usize,
        g: &E::G1Affine,
    ) -> Result<(E::G1Affine, E::G1Affine), PSError> {
        // h = g^u
        let h = (*g * u).into_affine();
        let h_exp = Self::sign_with_given_sigma_1(messages, sigkey, offset, &h)?;
        Ok((h, h_exp))
    }

    /// Generate signature when first element of signature tuple is given
    pub fn sign_with_given_sigma_1(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
        offset: usize,
        h: &E::G1Affine,
    ) -> Result<E::G1Affine, PSError> {
        if sigkey.y.len() != offset + messages.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: offset + messages.len(),
                given: sigkey.y.len(),
            });
        }
        // h^(x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ...) = g^{u * (x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ...)}
        let mut exp = sigkey.x;
        for i in 0..messages.len() {
            exp += sigkey.y[offset + i] * messages[i];
        }
        let h_exp = (*h * exp).into_affine();
        Ok(h_exp)
    }

    /// Verify a signature. Can verify unblinded sig received from a signer and the aggregate sig as well.
    pub fn verify(
        &self,
        messages: &[E::ScalarField],
        vk: &Verkey<E>,
        params: &Params<E>,
    ) -> Result<bool, PSError> {
        if vk.Y_tilde.len() != messages.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: vk.Y_tilde.len(),
                given: messages.len(),
            });
        }
        if self.is_identity() {
            return Ok(false);
        }

        Ok(self.pairing_check(messages, vk, params))
    }

    /// Byte representation of the signature
    pub fn to_bytes(&self) -> Result<Vec<u8>, PSError> {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)
            .map_err(|_| PSError::SerializationError)?;
        Ok(bytes)
    }

    pub fn check_verkey_and_messages_compat(
        messages: &[E::ScalarField],
        verkey: &Verkey<E>,
    ) -> Result<(), PSError> {
        if messages.len() != verkey.Y_tilde.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: verkey.Y_tilde.len(),
            });
        }
        Ok(())
    }

    pub fn check_sigkey_and_messages_compat(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
    ) -> Result<(), PSError> {
        if sigkey.y.len() != messages.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: sigkey.y.len(),
            });
        }
        Ok(())
    }

    /// Checks if a signature has identity elements. A valid signature should not have identity elements.
    pub fn is_identity(&self) -> bool {
        self.sigma_1.is_zero() || self.sigma_2.is_zero()
    }

    /// Do the multi-exp and pairing check during verification.
    pub(crate) fn pairing_check(
        &self,
        messages: &[E::ScalarField],
        vk: &Verkey<E>,
        params: &Params<E>,
    ) -> bool {
        // Y_m = X_tilde * Y_tilde[1]^m_1 * Y_tilde[2]^m_2 * ...Y_tilde[i]^m_i
        let Y_m_partial = E::G2::msm_unchecked(&vk.Y_tilde, messages);
        let Y_m = (vk.X_tilde.into_group() + Y_m_partial).into_affine();

        // e(sigma_1, Y_m) == e(sigma_2, g_tilde) => e(sigma_1, Y_m) * e(sigma_2, -g_tilde) == 1
        let neg_g_tilde = (-params.g_tilde.into_group()).into_affine();
        let result = E::multi_pairing(&[self.sigma_1, self.sigma_2], &[Y_m, neg_g_tilde]);
        result.is_zero()
    }

    /// Generate first element of the signature by hashing the messages. Since all messages are of
    /// same size, the is no need of a delimiter between the byte representation of the messages.
    fn generate_sigma_1_from_messages<H: Digest>(messages: &[E::ScalarField]) -> E::G1Affine {
        let mut hasher = H::new();
        hasher.update(DST_SIGMA_1);
        for m in messages {
            let mut bytes = Vec::new();
            m.serialize_compressed(&mut bytes).unwrap();
            hasher.update(&bytes);
        }
        let hash = hasher.finalize();

        // Use hash output as seed for deterministic generator
        let mut seed = [0u8; 32];
        let hash_bytes = hash.as_slice();
        let copy_len = core::cmp::min(hash_bytes.len(), 32);
        seed[..copy_len].copy_from_slice(&hash_bytes[..copy_len]);

        let mut rng = crate::deterministic_rng_from_seed(seed);
        E::G1::rand(&mut rng).into_affine()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::keygen;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use sha2::Sha256;

    #[test]
    fn test_signature_all_known_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 5) + 1;
                let (sk, vk) = keygen(count_msgs, &params, &mut rng);
                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();
                let sig = Signature::new(&msgs, &sk, &params, &mut rng).unwrap();
                assert!(sig.verify(&msgs, &vk, &params).unwrap());
            }
        }

        check::<Bls12_381>();
        check::<Bls12_377>();
        check::<Bn254>();
    }

    #[test]
    fn test_deterministic_signature_all_known_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 5) + 1;
                let (sk, vk) = keygen(count_msgs, &params, &mut rng);
                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();
                let sig = Signature::new_deterministic::<Sha256>(&msgs, &sk).unwrap();
                assert!(sig.verify(&msgs, &vk, &params).unwrap());
            }
        }

        check::<Bls12_381>();
        check::<Bls12_377>();
        check::<Bn254>();
    }
}
