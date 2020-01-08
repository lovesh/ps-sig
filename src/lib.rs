#![allow(non_snake_case)]

#[cfg(all(feature = "SignatureG2", feature = "SignatureG1"))]
compile_error!("features `SignatureG2` and `SignatureG1` are mutually exclusive");

#[macro_use]
extern crate amcl_wrapper;

use amcl_wrapper::extension_field_gt::GT;

#[cfg(feature = "SignatureG2")]
pub type SignatureGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "SignatureG2")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "SignatureG2")]
pub type VerkeyGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "SignatureG2")]
pub type VerkeyGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "SignatureG2")]
pub fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &VerkeyGroup,
    h1: &SignatureGroup,
    h2: &VerkeyGroup,
) -> GT {
    GT::ate_2_pairing(g2, g1, h2, h1)
}

#[cfg(feature = "SignatureG1")]
pub type SignatureGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "SignatureG1")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "SignatureG1")]
pub type VerkeyGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "SignatureG1")]
pub type VerkeyGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "SignatureG1")]
pub fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &VerkeyGroup,
    h1: &SignatureGroup,
    h2: &VerkeyGroup,
) -> GT {
    GT::ate_2_pairing(g1, g2, h1, h2)
}

extern crate rand;
#[macro_use]
extern crate failure;

extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod errors;
#[macro_use]
pub mod pok_vc;
pub mod keys;
pub mod pok_sig;
pub mod signature;
pub mod blind_signature;
