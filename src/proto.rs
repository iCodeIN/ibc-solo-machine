#![allow(rustdoc::non_autolinks)]

pub mod cosmos {
    pub mod base {
        pub mod query {
            pub mod v1beta1 {
                include!(concat!(env!("OUT_DIR"), "/cosmos.base.query.v1beta1.rs"));
            }
        }

        pub mod v1beta1 {
            include!(concat!(env!("OUT_DIR"), "/cosmos.base.v1beta1.rs"));
        }
    }

    pub mod crypto {
        pub mod ed25519 {
            include!(concat!(env!("OUT_DIR"), "/cosmos.crypto.ed25519.rs"));
        }

        pub mod multisig {
            include!(concat!(env!("OUT_DIR"), "/cosmos.crypto.multisig.rs"));

            pub mod v1beta1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/cosmos.crypto.multisig.v1beta1.rs"
                ));
            }
        }

        pub mod secp256k1 {
            include!(concat!(env!("OUT_DIR"), "/cosmos.crypto.secp256k1.rs"));
        }

        pub mod secp256r1 {
            include!(concat!(env!("OUT_DIR"), "/cosmos.crypto.secp256r1.rs"));
        }
    }

    pub mod tx {
        pub mod signing {
            pub mod v1beta1 {
                include!(concat!(env!("OUT_DIR"), "/cosmos.tx.signing.v1beta1.rs"));
            }
        }
    }

    pub mod upgrade {
        pub mod v1beta1 {
            include!(concat!(env!("OUT_DIR"), "/cosmos.upgrade.v1beta1.rs"));
        }
    }
}

pub mod ibc {
    pub mod apps {
        pub mod transfer {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/ibcgo.apps.transfer.v1.rs"));
            }
        }
    }

    pub mod core {
        pub mod channel {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/ibcgo.core.channel.v1.rs"));
            }
        }

        pub mod client {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/ibcgo.core.client.v1.rs"));
            }
        }

        pub mod commitment {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/ibcgo.core.commitment.v1.rs"));
            }
        }

        pub mod connection {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/ibcgo.core.connection.v1.rs"));
            }
        }

        pub mod types {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/ibcgo.core.types.v1.rs"));
            }
        }
    }

    pub mod lightclients {
        pub mod localhost {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/ibcgo.lightclients.localhost.v1.rs"
                ));
            }
        }

        pub mod solomachine {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/ibcgo.lightclients.solomachine.v1.rs"
                ));
            }
        }

        pub mod tendermint {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/ibcgo.lightclients.tendermint.v1.rs"
                ));
            }
        }
    }
}

pub mod ics23 {
    include!(concat!(env!("OUT_DIR"), "/ics23.rs"));
}

pub mod tendermint {
    pub mod crypto {
        include!(concat!(env!("OUT_DIR"), "/tendermint.crypto.rs"));
    }

    pub mod types {
        include!(concat!(env!("OUT_DIR"), "/tendermint.types.rs"));
    }

    pub mod version {
        include!(concat!(env!("OUT_DIR"), "/tendermint.version.rs"));
    }
}
