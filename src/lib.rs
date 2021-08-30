// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2019 by
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
extern crate strict_encoding;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate internet2;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub mod channel;
pub mod extension;
pub mod factories;
pub mod features;
pub mod message;
pub mod payment;
pub mod prometheus;
pub mod storm;

pub use extension::{
    ChannelExtension, Extension, GossipExtension, RoutingExtension,
};
pub use features::{
    Bolt11Context, ChannelAnnouncementContext, Feature, FeatureContext,
    InitContext, InitFeatures, NoRequiredFeatureError, NodeAnnouncementContext,
};
pub use message::{Messages, OnionPacket, LNPWP_UNMARSHALLER};
pub use payment::{ChannelId, TempChannelId};

pub const LIGHTNING_P2P_DEFAULT_PORT: u16 = 9735;

lazy_static! {
    pub static ref SECP256K1_PUBKEY_DUMB: secp256k1::PublicKey =
        secp256k1::PublicKey::from_secret_key(
            secp256k1::SECP256K1,
            &secp256k1::key::ONE_KEY,
        );
}
