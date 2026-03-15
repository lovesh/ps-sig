#[cfg(not(feature = "std"))]
use alloc::string::String;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PSError {
    #[error("Verkey valid for {expected} messages but given {given} messages")]
    UnsupportedNoOfMessages { expected: usize, given: usize },

    #[error("Same no of bases and exponents required. {bases} bases and {exponents} exponents")]
    UnequalNoOfBasesExponents { bases: usize, exponents: usize },

    #[error("All verification keys should have equal number of Y_tilde elements")]
    IncompatibleVerkeysForAggregation,

    #[error(
        "All signatures should have same first element (sigma_1). m' should be same as well if using 2018 scheme"
    )]
    IncompatibleSigsForAggregation,

    #[error("Error with message {msg:?}")]
    GeneralError { msg: String },

    #[error("Serialization error")]
    SerializationError,
}
