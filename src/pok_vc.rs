//! Proof of knowledge of committed values in a vector Pedersen commitment.
//! `ProverCommitting` will contains vectors of generators and random values.
//! `ProverCommitting` has a `commit` method that optionally takes a value as blinding, if not provided, it creates its own.
//! `ProverCommitting` has a `finish` method that results in creation of `ProverCommitted` object after consuming `ProverCommitting`
//! `ProverCommitted` marks the end of commitment phase and has the final commitment.
//! `ProverCommitted` has a method to generate the challenge by hashing all generators and commitment. It is optional
//! to use this method as the challenge may come from a super-protocol or from verifier. It takes a vector of bytes that it includes for hashing for computing the challenge
//! `ProverCommitted` has a method `gen_proof` to generate proof. It takes the secrets and the challenge to generate responses.
//! During response generation `ProverCommitted` is consumed to create `Proof` object containing the commitments and responses.
//! `Proof` can then be verified by the verifier.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use digest::Digest;
use rand_core::CryptoRngCore;

use crate::errors::PSError;

/// Proof of knowledge of messages in a vector commitment.
/// Commit for each message.
#[derive(Clone, Debug)]
pub struct ProverCommitting<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize + Copy,
{
    gens: Vec<G>,
    blindings: Vec<G::ScalarField>,
}

/// Receive or generate challenge. Compute response and proof
#[derive(Clone, Debug)]
pub struct ProverCommitted<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize + Copy,
{
    gens: Vec<G>,
    blindings: Vec<G::ScalarField>,
    commitment: G,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize + Copy,
{
    pub commitment: G,
    pub responses: Vec<G::ScalarField>,
}

impl<G> Default for ProverCommitting<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize + Copy,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<G> ProverCommitting<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize + Copy,
{
    pub fn new() -> Self {
        Self {
            gens: Vec::new(),
            blindings: Vec::new(),
        }
    }

    /// Commit with an explicit blinding value
    pub fn commit(&mut self, gen: G, blinding: G::ScalarField) -> usize {
        let idx = self.gens.len();
        self.gens.push(gen);
        self.blindings.push(blinding);
        idx
    }

    /// Commit with a randomly generated blinding value
    pub fn commit_random<R: CryptoRngCore>(&mut self, gen: G, rng: &mut R) -> usize {
        let blinding = G::ScalarField::rand(rng);
        self.commit(gen, blinding)
    }

    /// Add pairwise product of (`self.gens`, self.blindings). Uses multi-exponentiation (const-time).
    pub fn finish(self) -> ProverCommitted<G> {
        let commitment =
            <G::Group as VariableBaseMSM>::msm_unchecked(&self.gens, &self.blindings).into_affine();
        ProverCommitted {
            gens: self.gens,
            blindings: self.blindings,
            commitment,
        }
    }

    pub fn get_index(&self, idx: usize) -> Result<(&G, &G::ScalarField), PSError> {
        if idx >= self.gens.len() {
            return Err(PSError::GeneralError {
                msg: format!("index {} greater than size {}", idx, self.gens.len()),
            });
        }
        Ok((&self.gens[idx], &self.blindings[idx]))
    }
}

impl<G> ProverCommitted<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize + Copy,
{
    pub fn to_bytes(&self) -> Result<Vec<u8>, PSError> {
        let mut bytes = Vec::new();
        for g in &self.gens {
            g.serialize_compressed(&mut bytes)
                .map_err(|_| PSError::SerializationError)?;
        }
        self.commitment
            .serialize_compressed(&mut bytes)
            .map_err(|_| PSError::SerializationError)?;
        Ok(bytes)
    }

    /// This step will be done by the main protocol for which this PoK is a sub-protocol
    pub fn gen_challenge<H: Digest>(&self, extra: &[u8]) -> Result<G::ScalarField, PSError> {
        let mut hasher = H::new();
        let bytes = self.to_bytes()?;
        hasher.update(&bytes);
        hasher.update(extra);
        let hash = hasher.finalize();

        // Use hash output as seed for deterministic field element
        let mut seed = [0u8; 32];
        let hash_bytes = hash.as_slice();
        let copy_len = core::cmp::min(hash_bytes.len(), 32);
        seed[..copy_len].copy_from_slice(&hash_bytes[..copy_len]);

        let mut rng = crate::deterministic_rng_from_seed(seed);
        Ok(G::ScalarField::rand(&mut rng))
    }

    /// Generate a challenge by hashing the given bytes directly (no commitment bytes prepended).
    pub fn gen_challenge_from_bytes<H: Digest>(bytes: &[u8]) -> Result<G::ScalarField, PSError> {
        let mut hasher = H::new();
        hasher.update(bytes);
        let hash = hasher.finalize();

        let mut seed = [0u8; 32];
        let hash_bytes = hash.as_slice();
        let copy_len = core::cmp::min(hash_bytes.len(), 32);
        seed[..copy_len].copy_from_slice(&hash_bytes[..copy_len]);

        let mut rng = crate::deterministic_rng_from_seed(seed);
        Ok(G::ScalarField::rand(&mut rng))
    }

    /// For each secret, generate a response as self.blinding[i] - challenge*secrets[i].
    pub fn gen_proof(
        self,
        challenge: G::ScalarField,
        secrets: &[G::ScalarField],
    ) -> Result<Proof<G>, PSError> {
        if secrets.len() != self.gens.len() {
            return Err(PSError::UnequalNoOfBasesExponents {
                bases: self.gens.len(),
                exponents: secrets.len(),
            });
        }
        let mut responses = Vec::with_capacity(self.gens.len());
        for i in 0..self.gens.len() {
            responses.push(self.blindings[i] - (challenge * secrets[i]));
        }
        Ok(Proof {
            commitment: self.commitment,
            responses,
        })
    }
}

impl<G> Proof<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize + Copy,
{
    /// Verify that bases[0]^responses[0] * bases[1]^responses[1] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
    pub fn verify(
        &self,
        bases: &[G],
        commitment: G,
        challenge: G::ScalarField,
    ) -> Result<bool, PSError> {
        // bases[0]^responses[0] * bases[1]^responses[1] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
        // =>
        // bases[0]^responses[0] * bases[1]^responses[1] * ... bases[i]^responses[i] * commitment^challenge - random_commitment == 0
        if bases.len() != self.responses.len() {
            return Err(PSError::UnequalNoOfBasesExponents {
                bases: bases.len(),
                exponents: self.responses.len(),
            });
        }
        let mut points = bases.to_vec();
        let mut scalars = self.responses.clone();
        points.push(commitment);
        scalars.push(challenge);
        let pr = <G::Group as VariableBaseMSM>::msm_unchecked(&points, &scalars)
            - self.commitment.into_group();
        Ok(pr.is_zero())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::VariableBaseMSM;

    use sha2::Sha256;

    pub(crate) fn test_pok_vc<G, H>(n: usize)
    where
        G: ark_ec::AffineRepr,
        H: digest::Digest,
    {
        use ark_ec::CurveGroup;
        use ark_std::rand::{rngs::StdRng, SeedableRng};
        use ark_std::UniformRand;

        let mut rng = StdRng::seed_from_u64(0u64);
        let mut rng2 = StdRng::seed_from_u64(1u64);

        let mut gens = Vec::with_capacity(n);
        let mut secrets = Vec::with_capacity(n);
        let mut committing = ProverCommitting::<G>::new();
        for _ in 0..n - 1 {
            let g = G::Group::rand(&mut rng).into_affine();
            committing.commit_random(g, &mut rng);
            gens.push(g);
            secrets.push(G::ScalarField::rand(&mut rng));
        }

        // Add one of the blindings externally
        let g = G::Group::rand(&mut rng).into_affine();
        let r = G::ScalarField::rand(&mut rng);
        committing.commit(g, r);
        let (g_, r_) = committing.get_index(n - 1).unwrap();
        assert_eq!(g, *g_);
        assert_eq!(r, *r_);
        gens.push(g);
        secrets.push(G::ScalarField::rand(&mut rng));

        let committed = committing.finish();

        let commitment = G::Group::msm_unchecked(&gens, &secrets).into_affine();
        let mut commitment_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&commitment, &mut commitment_bytes)
            .unwrap();
        let challenge = committed.gen_challenge::<H>(&commitment_bytes).unwrap();
        let proof = committed.gen_proof(challenge, &secrets).unwrap();

        assert!(proof.verify(&gens, commitment, challenge).unwrap());
        assert!(!proof
            .verify(&gens, G::Group::rand(&mut rng2).into_affine(), challenge)
            .unwrap());
        assert!(!proof
            .verify(&gens, commitment, G::ScalarField::rand(&mut rng2))
            .unwrap());
    }

    #[test]
    fn test_PoK_VC_G1() {
        // Proof of knowledge of committed values in a vector commitment. The committment lies in group G1.
        test_pok_vc::<G1Affine, Sha256>(5);
    }

    #[test]
    fn test_PoK_VC_G2() {
        // Proof of knowledge of committed values in a vector commitment. The committment lies in group G2.
        test_pok_vc::<G2Affine, Sha256>(5);
    }
}
