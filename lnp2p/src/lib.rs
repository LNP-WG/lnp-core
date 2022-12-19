// LNP P2P library, plmeneting both bolt (BOLT) and Bifrost P2P messaging
// system for Lightning network protocol (LNP)
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate internet2;
#[cfg(feature = "bolt")]
#[macro_use]
extern crate lightning_encoding;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;
#[cfg(feature = "strict_encoding")]
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;

#[cfg(feature = "bifrost")]
use crate::bifrost::LNP2P_BIFROST_PORT;
#[cfg(feature = "bolt")]
use crate::bolt::LNP2P_BOLT_PORT;

macro_rules! dumb_pubkey {
    () => {
        secp256k1::PublicKey::from_secret_key(
            secp256k1::SECP256K1,
            &secp256k1::ONE_KEY,
        )
    };
}

#[cfg(feature = "bifrost")]
pub mod bifrost;
#[cfg(feature = "bolt")]
pub mod bolt;

/// Version of the lightning network P2P protocol
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode), network_encoding( by_value, repr = u16))]
#[repr(u16)]
pub enum Protocol {
    #[cfg(feature = "bolt")]
    /// Protocol based on BOLT specifications.
    #[display("bolt")]
    Bolt = LNP2P_BOLT_PORT,

    #[cfg(feature = "bifrost")]
    /// Protocol based on LNPBP Bifrost specifications.
    #[display("bifrost")]
    Bifrost = LNP2P_BIFROST_PORT,
}

impl Protocol {
    pub fn default_port(self) -> u16 {
        self as u16
    }
}
