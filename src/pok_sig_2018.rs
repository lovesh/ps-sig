// Proof of knowledge of signature for signature defined in 2018 paper, CT-RSA 2018 (eprint 2017/1197).

use crate::pok_sig::{PoKOfSignature as PoKOfSignature16, PoKOfSignatureProof};
use amcl_wrapper::field_elem::FieldElement;
use crate::signature_2018::Signature;
use crate::keys::{Verkey, Params};
use crate::errors::PSError;
use std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoKOfSignature(pub PoKOfSignature16);

/// Most of the protocol is same as followed for the 2016 scheme
impl PoKOfSignature {
    pub fn init(
        sig: &Signature,
        vk: &Verkey,
        params: &Params,
        mut messages: Vec<FieldElement>,
        blindings: Option<&[FieldElement]>,
        revealed_msg_indices: HashSet<usize>,
    ) -> Result<Self, PSError> {
        Signature::check_verkey_and_messages_compat(messages.as_slice(), vk)?;

        // m_prime should never be revealed
        PoKOfSignature16::validate_revealed_indices(messages.as_slice(), &revealed_msg_indices)?;

        let mut blindings = PoKOfSignature16::get_blindings(blindings, messages.as_slice(), &revealed_msg_indices)?;

        let (t, sigma_prime) = PoKOfSignature16::transform_sig(&sig.sig);

        messages.push(sig.m_prime.clone());
        // Choose blinding for m_prime randomly
        blindings.push(None);

        let (exponents, J, committed) = PoKOfSignature16::commit_for_pok(messages, blindings, &revealed_msg_indices, t, vk, params);
        Ok(Self(PoKOfSignature16 {
            secrets: exponents,
            sig: sigma_prime,
            J,
            pok_vc: committed,
        }))
    }

    /// Return byte representation of public elements so they can be used for challenge computation
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// The proof generation protocol is same as for the 2016 scheme the resulting proof is same as
    /// the proof for the 2016 scheme and can be verified using its `verify method`
    pub fn gen_proof(self, challenge: &FieldElement) -> Result<PoKOfSignatureProof, PSError> {
        self.0.gen_proof(challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use crate::keys::keygen_2018;
    use std::collections::HashMap;
    use amcl_wrapper::field_elem::FieldElementVector;

    #[test]
    fn test_PoK_sig() {
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen_2018(count_msgs, &params);

        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let sig = Signature::new(msgs.as_slice(), &sk).unwrap();
        assert!(sig.verify(msgs.clone(), &vk, &params).unwrap());

        let pok = PoKOfSignature::init(&sig, &vk, &params, msgs.clone(), None, HashSet::new()).unwrap();

        let chal_prover = FieldElement::from_msg_hash(&pok.to_bytes());

        let proof = pok.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let chal_bytes = proof.get_bytes_for_challenge(HashSet::new(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);

        assert!(proof.verify(&vk, &params, HashMap::new(), &chal_verifier).unwrap());

        // PoK with supplied blindings
        let blindings = FieldElementVector::random(count_msgs);
        let pok_1 = PoKOfSignature::init(
            &sig,
            &vk,
            &params,
            msgs,
            Some(blindings.as_slice()),
            HashSet::new(),
        )
            .unwrap();
        let chal_prover = FieldElement::from_msg_hash(&pok_1.to_bytes());
        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let chal_bytes = proof_1.get_bytes_for_challenge(HashSet::new(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
        assert!(proof_1
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
    }

    #[test]
    fn test_PoK_sig_reveal_messages() {
        let count_msgs = 10;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen_2018(count_msgs, &params);

        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();

        let sig = Signature::new(msgs.as_slice(), &sk).unwrap();
        assert!(sig.verify(msgs.clone(), &vk, &params).unwrap());

        let mut revealed_msg_indices = HashSet::new();
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
        )
            .unwrap();

        let chal_prover = FieldElement::from_msg_hash(&pok.to_bytes());

        let proof = pok.gen_proof(&chal_prover).unwrap();

        let mut revealed_msgs = HashMap::new();
        for i in &revealed_msg_indices {
            revealed_msgs.insert(i.clone(), msgs[*i].clone());
        }
        // The verifier generates the challenge on its own.
        let chal_bytes = proof.get_bytes_for_challenge(revealed_msg_indices.clone(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
        assert!(proof
            .verify(&vk, &params, revealed_msgs.clone(), &chal_verifier)
            .unwrap());

        // Reveal wrong message
        let mut revealed_msgs_1 = revealed_msgs.clone();
        revealed_msgs_1.insert(2, FieldElement::random());
        assert!(!proof.verify(&vk, &params, revealed_msgs_1.clone(), &chal_verifier).unwrap());
    }
}