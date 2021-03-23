pub trait IConsensusState {
    fn get_timestamp(&self) -> u64;
}
