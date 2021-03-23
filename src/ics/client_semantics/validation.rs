pub trait BasicValidation {
    type Error;

    fn validate_basic(&self) -> Result<(), Self::Error>;
}
