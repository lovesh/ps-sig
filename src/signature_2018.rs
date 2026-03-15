// Scheme defined in 2018 paper, CT-RSA 2018 (eprint 2017/1197), section 4.2.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use digest::Digest;
use rand_core::CryptoRngCore;

use crate::errors::PSError;
use crate::keys::{Params, Sigkey, Verkey};
use crate::signature::Signature as Sig16;

const DST_M_PRIME: &[u8] = b"PS-SIG-V1-M-PRIME-2018";
const DST_SIGMA_1_2018: &[u8] = b"PS-SIG-V1-SIGMA-1-2018";

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<E: Pairing> {
    pub m_prime: E::ScalarField,
    pub sig: Sig16<E>,
}

impl<E: Pairing> Signature<E> {
    /// Create a new signature. The signature generation involves generating random values for `m'`
    /// and `sigma_1` so different calls to this method with same messages and signing key will give
    /// different value
    pub fn new<R: CryptoRngCore>(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
        rng: &mut R,
    ) -> Result<Self, PSError> {
        let m_prime = E::ScalarField::rand(rng);
        let sigma_1 = E::G1::rand(rng).into_affine();
        let sigma_2 = Self::sign_with_given_sigma_1(messages, &m_prime, sigkey, 0, &sigma_1)?;
        Ok(Self {
            m_prime,
            sig: Sig16 { sigma_1, sigma_2 },
        })
    }

    /// Create a new signature. The signature generation involves generating `m'` by hashing the messages
    /// but generating a random value for `sigma_1` so different calls to this method with same messages
    /// and signing key will give different value
    pub fn new_with_deterministic_m<H: Digest, R: CryptoRngCore>(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
        rng: &mut R,
    ) -> Result<Self, PSError> {
        let m_prime = Self::generate_m_prime_from_messages::<H>(messages);
        let sigma_1 = E::G1::rand(rng).into_affine();
        let sigma_2 = Self::sign_with_given_sigma_1(messages, &m_prime, sigkey, 0, &sigma_1)?;
        Ok(Self {
            m_prime,
            sig: Sig16 { sigma_1, sigma_2 },
        })
    }

    /// Create a new signature. The signature generation doesn't involve generating any random value
    /// but the messages are hashed to get a pseudorandom values for `m'` and `sigma_1`. Hence different
    /// calls to this method with same messages and signing key will give same value
    pub fn new_deterministic<H: Digest>(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
    ) -> Result<Self, PSError> {
        let (m_prime, sigma_1) = Self::generate_m_prime_and_sigma_1_from_messages::<H>(messages);
        let sigma_2 = Self::sign_with_given_sigma_1(messages, &m_prime, sigkey, 0, &sigma_1)?;
        Ok(Self {
            m_prime,
            sig: Sig16 { sigma_1, sigma_2 },
        })
    }

    /// Verify a signature. Most of the logic is same as from the 2016 scheme
    pub fn verify(
        &self,
        messages: &[E::ScalarField],
        vk: &Verkey<E>,
        params: &Params<E>,
    ) -> Result<bool, PSError> {
        if vk.Y_tilde.len() != (messages.len() + 1) {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: vk.Y_tilde.len(),
                given: messages.len() + 1,
            });
        }
        if self.sig.is_identity() {
            return Ok(false);
        }

        // Append m_prime to messages for verification
        let mut all_messages = messages.to_vec();
        all_messages.push(self.m_prime);

        Ok(Sig16::pairing_check(&self.sig, &all_messages, vk, params))
    }

    /// Byte representation of the signature
    pub fn to_bytes(&self) -> Result<Vec<u8>, PSError> {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)
            .map_err(|_| PSError::SerializationError)?;
        Ok(bytes)
    }

    /// Generate signature when first element of signature tuple is given
    fn sign_with_given_sigma_1(
        messages: &[E::ScalarField],
        m_prime: &E::ScalarField,
        sigkey: &Sigkey<E>,
        offset: usize,
        h: &E::G1Affine,
    ) -> Result<E::G1Affine, PSError> {
        if sigkey.y.len() != (offset + messages.len() + 1) {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: offset + messages.len() + 1,
                given: sigkey.y.len(),
            });
        }
        // h^(x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ... + y_last*m') = g^{u * (x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ... + y_last*m')}
        let mut exp = sigkey.x;
        for i in 0..messages.len() {
            exp += sigkey.y[offset + i] * messages[i];
        }
        exp += sigkey.y[offset + messages.len()] * m_prime;
        let h_exp = (*h * exp).into_affine();
        Ok(h_exp)
    }

    /// Generate m' by hashing the messages. Since all messages are of
    /// same size, the is no need of a delimiter between the byte representation of the messages.
    fn generate_m_prime_from_messages<H: Digest>(messages: &[E::ScalarField]) -> E::ScalarField {
        let mut hasher = H::new();
        hasher.update(DST_M_PRIME);
        for m in messages {
            let mut bytes = Vec::new();
            m.serialize_compressed(&mut bytes).unwrap();
            hasher.update(&bytes);
        }
        let hash = hasher.finalize();

        // Use hash output as seed for deterministic field element
        let mut seed = [0u8; 32];
        let hash_bytes = hash.as_slice();
        let copy_len = core::cmp::min(hash_bytes.len(), 32);
        seed[..copy_len].copy_from_slice(&hash_bytes[..copy_len]);

        let mut rng = crate::deterministic_rng_from_seed(seed);
        E::ScalarField::rand(&mut rng)
    }

    /// Generate m' and sigma_1, by hashing the messages. Since all messages are of
    /// same size, the is no need of a delimiter between the byte representation of the messages.
    fn generate_m_prime_and_sigma_1_from_messages<H: Digest>(
        messages: &[E::ScalarField],
    ) -> (E::ScalarField, E::G1Affine) {
        let m_prime = Self::generate_m_prime_from_messages::<H>(messages);

        // Generate sigma_1 deterministically from messages
        let mut hasher = H::new();
        hasher.update(DST_SIGMA_1_2018);
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
        let sigma_1 = E::G1::rand(&mut rng).into_affine();
        (m_prime, sigma_1)
    }

    pub fn check_verkey_and_messages_compat(
        messages: &[E::ScalarField],
        verkey: &Verkey<E>,
    ) -> Result<(), PSError> {
        // `Y_tilde` would have a value corresponding to `m'` as well
        if (messages.len() + 1) != verkey.Y_tilde.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: messages.len() + 1,
                given: verkey.Y_tilde.len(),
            });
        }
        Ok(())
    }

    pub fn check_sigkey_and_messages_compat(
        messages: &[E::ScalarField],
        sigkey: &Sigkey<E>,
    ) -> Result<(), PSError> {
        // `y` would have a value corresponding to `m'` as well
        if sigkey.y.len() != (messages.len() + 1) {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: messages.len() + 1,
                given: sigkey.y.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::keygen_2018;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use sha2::Sha256;

    #[test]
    fn test_signature_all_known_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 5) + 1;
                let (sk, vk) = keygen_2018(count_msgs, &params, &mut rng);
                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();
                let sig = Signature::new(&msgs, &sk, &mut rng).unwrap();
                assert!(sig.verify(&msgs, &vk, &params).unwrap());
            }
        }

        check::<Bls12_381>();
        check::<Bls12_377>();
    }

    #[test]
    fn test_signature_deterministic_m_all_known_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 5) + 1;
                let (sk, vk) = keygen_2018(count_msgs, &params, &mut rng);
                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();
                let sig =
                    Signature::new_with_deterministic_m::<Sha256, _>(&msgs, &sk, &mut rng).unwrap();
                assert!(sig.verify(&msgs, &vk, &params).unwrap());
            }
        }

        check::<Bls12_381>();
    }

    #[test]
    fn test_deterministic_signature_all_known_messages() {
        fn check<E: Pairing>() {
            let params = Params::<E>::new::<Sha256>(b"test");
            let mut rng = StdRng::seed_from_u64(0u64);
            for i in 0..10 {
                let count_msgs = (i % 5) + 1;
                let (sk, vk) = keygen_2018(count_msgs, &params, &mut rng);
                let msgs = (0..count_msgs)
                    .map(|_| E::ScalarField::rand(&mut rng))
                    .collect::<Vec<_>>();
                let sig = Signature::new_deterministic::<Sha256>(&msgs, &sk).unwrap();
                assert!(sig.verify(&msgs, &vk, &params).unwrap());
            }
        }

        check::<Bls12_381>();
    }
}
