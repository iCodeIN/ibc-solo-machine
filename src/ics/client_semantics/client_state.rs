pub trait IClientState {
    type ConsensusState;
    type Error;
    type Header;
    type Misbehaviour;

    fn initialize(consensus_state: Self::ConsensusState) -> Self;

    fn check_header_and_update_state(&mut self, header: Self::Header) -> Result<(), Self::Error>;

    fn check_misbehaviour_and_update_state(
        &mut self,
        misbehaviour: Self::Misbehaviour,
    ) -> Result<(), Self::Error>;
}
