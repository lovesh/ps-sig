use failure::Error;

#[derive(Debug, Fail)]
pub enum PSError {
    #[fail(
        display = "Verkey valid for {} messages but given {} messages",
        expected, given
    )]
    UnsupportedNoOfMessages { expected: usize, given: usize },

    #[fail(
        display = "Same no of bases and exponents required. {} bases and {} exponents",
        bases, exponents
    )]
    UnequalNoOfBasesExponents { bases: usize, exponents: usize },

    #[fail(
    display = "All verification keys should have equal number of Y_tilde elements"
    )]
    IncompatibleVerkeysForAggregation,

    #[fail(
    display = "All signatures should have same first element (sigma_1). m' should be same as well if using 2018 scheme"
    )]
    IncompatibleSigsForAggregation,

    #[fail(display = "Error with message {:?}", msg)]
    GeneralError { msg: String },
}
