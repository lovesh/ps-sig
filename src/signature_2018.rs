// Scheme defined in 2018 paper, CT-RSA 2018 (eprint 2017/1197), section 4.2.

use crate::{SignatureGroup, VerkeyGroupVec, ate_2_pairing};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use crate::keys::{Sigkey, Params, Verkey};
use crate::errors::PSError;
use crate::signature::Signature as Sig16;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub m_prime: FieldElement,
    pub sig: Sig16
}

impl Signature {
    /// Create a new signature. The signature generation involves generating random values for `m'`
    /// and `sigma_1` so different calls to this method with same messages and signing key will give
    /// different value
    pub fn new(messages: &[FieldElement], sigkey: &Sigkey) -> Result<Self, PSError> {
        let m_prime = FieldElement::random();
        let sigma_1 = SignatureGroup::random();
        let sigma_2 = Self::sign_with_given_sigma_1(messages, &m_prime, sigkey, 0, &sigma_1)?;
        Ok(Self { m_prime, sig: Sig16 {sigma_1, sigma_2} })
    }

    /// Create a new signature. The signature generation involves generating `m'` by hashing the messages
    /// but generating a random value for `sigma_1` so different calls to this method with same messages
    /// and signing key will give different value
    pub fn new_with_deterministic_m(messages: &[FieldElement], sigkey: &Sigkey) -> Result<Self, PSError> {
        let m_prime = Self::generate_m_prime_from_messages(messages);
        let sigma_1 = SignatureGroup::random();
        let sigma_2 = Self::sign_with_given_sigma_1(messages, &m_prime, sigkey, 0, &sigma_1)?;
        Ok(Self { m_prime, sig: Sig16 {sigma_1, sigma_2} })
    }

    /// Create a new signature. The signature generation doesn't involve generating any random value
    /// but the messages are hashed to get a pseudorandom values for `m'` and `sigma_1`. Hence different
    /// calls to this method with same messages and signing key will give same value
    pub fn new_deterministic(messages: &[FieldElement], sigkey: &Sigkey) -> Result<Self, PSError> {
        let (m_prime, sigma_1) = Self::generate_m_prime_and_sigma_1_from_messages(messages);
        let sigma_2 = Self::sign_with_given_sigma_1(messages, &m_prime, sigkey, 0, &sigma_1)?;
        Ok(Self { m_prime, sig: Sig16 {sigma_1, sigma_2} })
    }

    /// Verify a signature. Most of the logic is same as from the 2016 scheme
    pub fn verify(
        &self,
        mut messages: Vec<FieldElement>,
        vk: &Verkey,
        params: &Params,
    ) -> Result<bool, PSError> {
        if vk.Y_tilde.len() != (messages.len() + 1) {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: vk.Y_tilde.len(),
                given: messages.len() + 1
            });
        }
        if self.sig.is_identity() {
            return Ok(false);
        }

        messages.push(self.m_prime.clone());

        Ok(Sig16::pairing_check(&self.sig, messages, vk, params))
    }

    /// Byte representation of the signature
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.m_prime.to_bytes());
        bytes.append(&mut self.sig.to_bytes());
        bytes
    }

    /// Generate signature when first element of signature tuple is given
    fn sign_with_given_sigma_1(messages: &[FieldElement],
                                   m_prime: &FieldElement,
                                   sigkey: &Sigkey,
                                   offset: usize,
                                   h: &SignatureGroup) -> Result<SignatureGroup, PSError> {
        if sigkey.y.len() != (offset + messages.len() + 1) {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: offset + messages.len() + 1,
                given: sigkey.y.len()
            });
        }
        // h^(x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ... + y_last*m') = g^{u * (x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ... + y_last*m')}
        let mut exp = sigkey.x.clone();
        for i in 0..messages.len() {
            exp += &sigkey.y[offset + i] * &messages[i];
        }
        exp += &sigkey.y[offset + messages.len()] * m_prime;
        let h_exp = h * &exp;
        Ok(h_exp)
    }

    /// Generate m' by hashing the messages. Since all messages are of
    /// same size, the is no need of a delimiter between the byte representation of the messages.
    fn generate_m_prime_from_messages(messages: &[FieldElement]) -> FieldElement {
        let mut msg_bytes = vec![];
        for i in messages {
            msg_bytes.append(&mut i.to_bytes());
        }
        FieldElement::from_msg_hash(&msg_bytes)
    }

    /// Generate m' and sigma_1, by hashing the messages. Since all messages are of
    /// same size, the is no need of a delimiter between the byte representation of the messages.
    fn generate_m_prime_and_sigma_1_from_messages(messages: &[FieldElement]) -> (FieldElement, SignatureGroup) {
        let mut msg_bytes = vec![];
        for i in messages {
            msg_bytes.append(&mut i.to_bytes());
        }
        // TODO: Hashing twice is inefficient. Expose API (a macro probably) in the wrapper to return any
        // number of group or field elements. The macro would take types like G1, G2, etc as args and count
        // them to decide the number of bytes the XOF should return and then call iterate over them and call
        // the type's from_msg_hash on the appropriate byte slice
        let m_prime = FieldElement::from_msg_hash(&msg_bytes);
        let sigma_1 = SignatureGroup::from_msg_hash(&msg_bytes);
        (m_prime, sigma_1)
    }

    pub fn check_verkey_and_messages_compat(
        messages: &[FieldElement],
        verkey: &Verkey,
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
        messages: &[FieldElement],
        sigkey: &Sigkey,
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

    #[test]
    fn test_signature_all_known_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, vk) = keygen_2018(count_msgs, &params);
            let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
            let sig = Signature::new(msgs.as_slice(), &sk).unwrap();
            assert!(sig.verify(msgs, &vk, &params).unwrap());
        }
    }

    #[test]
    fn test_signature_deterministic_m_all_known_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, vk) = keygen_2018(count_msgs, &params);
            let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
            let sig = Signature::new_with_deterministic_m(msgs.as_slice(), &sk).unwrap();
            assert!(sig.verify(msgs, &vk, &params).unwrap());
        }
    }

    #[test]
    fn test_deterministic_signature_all_known_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, vk) = keygen_2018(count_msgs, &params);
            let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
            let sig = Signature::new_deterministic(msgs.as_slice(), &sk).unwrap();
            assert!(sig.verify(msgs, &vk, &params).unwrap());
        }
    }
}