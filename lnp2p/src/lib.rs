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

#![recursion_limit = "256"]
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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate internet2;
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

use std::str::FromStr;

use internet2::addr::{AddrParseError, NodeAddr, NodeAddrParseError};

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
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
pub enum Protocol {
    /// Protocol based on BOLT specifications.
    #[display("bolt")]
    Bolt,

    /// Protocol based on LNPBP Bifrost specifications.
    #[display("bifrost")]
    Bifrost,
}

/// LNP node address containing both node address and the used protocol
#[derive(Clone, PartialEq, Eq, Debug, Display, NetworkEncode, NetworkDecode)]
#[display("{protocol}://{addr}")]
pub struct LnpAddr {
    /// Protocol used for connection.
    pub protocol: Protocol,

    /// Remote peer address for connecting to.
    pub addr: NodeAddr,
}

impl LnpAddr {
    /// Construct BOLT-compatible node address.
    pub fn bolt(addr: NodeAddr) -> LnpAddr {
        LnpAddr {
            protocol: Protocol::Bolt,
            addr,
        }
    }

    /// Construct Bifrost-compatible node address.
    pub fn bifrost(addr: NodeAddr) -> LnpAddr {
        LnpAddr {
            protocol: Protocol::Bifrost,
            addr,
        }
    }
}

impl FromStr for LnpAddr {
    type Err = NodeAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split("://");
        match (
            split.next().map(str::to_lowercase).as_deref(),
            split.next(),
            split.next(),
        ) {
            (Some("bolt"), Some(addr), None) => {
                NodeAddr::from_str(addr).map(LnpAddr::bolt)
            }
            (Some("bifrost"), Some(addr), None) => {
                NodeAddr::from_str(addr).map(LnpAddr::bifrost)
            }
            (Some(unknown), ..) => {
                Err(AddrParseError::UnknownProtocolError(unknown.to_owned())
                    .into())
            }
            _ => Err(AddrParseError::WrongAddrFormat(s.to_owned()).into()),
        }
    }
}
