use crate::keys::{Verkey, Params};
use crate::{VerkeyGroup, SignatureGroup};
use crate::amcl_wrapper::group_elem::GroupElement;
use crate::signature::Signature;
use crate::signature_2018::Signature as Signature18;
use amcl_wrapper::field_elem::FieldElement;
use crate::errors::PSError;

/// PS multi-signatures using the same idea as BLS multi-signatures.

// TODO: Add Proof of possesion of private key. Can be a verifiable signature on a standard message or
// can be a proof of knowledge of secret key. Proof of knowledge should be better since it will not involve any pairing during verification.
// But is signature sufficient for elements of both group?

pub struct AggregatedVerkeyFast {}

impl AggregatedVerkeyFast {
    pub fn from_verkeys(ver_keys: Vec<&Verkey>) -> Result<Verkey, PSError> {
        if ver_keys.is_empty() {
            return Err(PSError::GeneralError {
                msg: String::from("Provide at least one key"),
            });
        }
        let y_len = ver_keys[0].Y_tilde.len();
        if !ver_keys.iter().all(|vk| vk.Y_tilde.len() == y_len) {
            return Err(PSError::IncompatibleVerkeysForAggregation)
        }
        let mut X_tilde = VerkeyGroup::new();
        let mut Y_tilde = (0..y_len).map(|_| VerkeyGroup::new()).collect::<Vec<VerkeyGroup>>();
        for vk in ver_keys {
            X_tilde += &vk.X_tilde;
            for i in 0..y_len {
                Y_tilde[i] += &vk.Y_tilde[i];
            }
        }
        Ok(Verkey {X_tilde, Y_tilde})
    }
}

pub struct MultiSignatureFast {}

impl MultiSignatureFast {
    /// Create a multi-signature from signature scheme defined in 2016 paper, CT-RSA 2016
    pub fn from_sigs(sigs: Vec<&Signature>) -> Result<Signature, PSError> {
        if sigs.is_empty() {
            return Err(PSError::GeneralError {
                msg: String::from("Provide at least one signature"),
            });
        }
        Self::combine(sigs)
    }

    /// Create a multi-signature from signature scheme defined in 2018 paper, CT-RSA 2018
    pub fn from_sigs_2018(sigs: Vec<&Signature18>) -> Result<Signature18, PSError> {
        if sigs.is_empty() {
            return Err(PSError::GeneralError {
                msg: String::from("Provide at least one signature"),
            });
        }
        let m_prime = sigs[0].m_prime.clone();
        if !sigs.iter().all(|sig| sig.m_prime == m_prime) {
            return Err(PSError::IncompatibleSigsForAggregation)
        }
        let sig = Self::combine(sigs.into_iter().map(|s|&s.sig).collect::<Vec<&Signature>>())?;
        Ok(Signature18 {m_prime, sig})
    }

    /// Helper for common logic
    fn combine(sigs: Vec<&Signature>) -> Result<Signature, PSError> {
        let sigma_1 = &sigs[0].sigma_1;
        if !sigs.iter().all(|sig| sig.sigma_1 == *sigma_1) {
            return Err(PSError::IncompatibleSigsForAggregation)
        }
        let mut sigma_2 = SignatureGroup::identity();
        for s in sigs {
            sigma_2 += &s.sigma_2;
        }
        Ok(Signature { sigma_1: sigma_1.clone(), sigma_2 })
    }

    /// An aggregate Verkey is created from `ver_keys`. When verifying signature using the same
    /// set of keys frequently generate a verkey once and then use `Signature::verify`
    /// For verifying a multi-signature from signature scheme defined in 2016 paper, CT-RSA 2016
    pub fn verify(sig: &Signature, messages: Vec<FieldElement>, ver_keys: Vec<&Verkey>, params: &Params) -> Result<bool, PSError> {
        let avk = AggregatedVerkeyFast::from_verkeys(ver_keys)?;
        sig.verify(messages, &avk, params)
    }

    /// For verifying a multi-signature from signature scheme defined in 2018 paper, CT-RSA 2018
    pub fn verify_2018(sig: &Signature18, messages: Vec<FieldElement>, ver_keys: Vec<&Verkey>, params: &Params) -> Result<bool, PSError> {
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
    use amcl_wrapper::field_elem::FieldElementVector;

    #[test]
    fn test_multi_signature_all_known_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk_1, vk_1) = keygen(count_msgs, &params);
            let (sk_2, vk_2) = keygen(count_msgs, &params);
            let (sk_3, vk_3) = keygen(count_msgs, &params);

            let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();

            let sig_1 = Signature::new_deterministic(msgs.as_slice(), &sk_1).unwrap();
            let sig_2 = Signature::new_deterministic(msgs.as_slice(), &sk_2).unwrap();
            let sig_3 = Signature::new_deterministic(msgs.as_slice(), &sk_3).unwrap();

            let multi_sig = MultiSignatureFast::from_sigs(vec![&sig_1, &sig_2, &sig_3]).unwrap();

            assert!(MultiSignatureFast::verify(&multi_sig, msgs, vec![&vk_1, &vk_2, &vk_3], &params).unwrap())
        }
    }

    #[test]
    fn test_multi_signature_2018_all_known_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk_1, vk_1) = keygen_2018(count_msgs, &params);
            let (sk_2, vk_2) = keygen_2018(count_msgs, &params);
            let (sk_3, vk_3) = keygen_2018(count_msgs, &params);

            let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();

            let sig_1 = Signature18::new_deterministic(msgs.as_slice(), &sk_1).unwrap();
            let sig_2 = Signature18::new_deterministic(msgs.as_slice(), &sk_2).unwrap();
            let sig_3 = Signature18::new_deterministic(msgs.as_slice(), &sk_3).unwrap();

            let multi_sig = MultiSignatureFast::from_sigs_2018(vec![&sig_1, &sig_2, &sig_3]).unwrap();

            assert!(MultiSignatureFast::verify_2018(&multi_sig, msgs, vec![&vk_1, &vk_2, &vk_3], &params).unwrap())
        }
    }

    // TODO: For aggregating blind signature, a Coconut like approach is needed.
}