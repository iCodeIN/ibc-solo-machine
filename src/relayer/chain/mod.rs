pub mod solo;
pub mod tendermint;

use self::{solo::SoloChain, tendermint::TendermintChain};

pub enum Chain {
    Tendermint(TendermintChain),
    Solo(SoloChain),
}
