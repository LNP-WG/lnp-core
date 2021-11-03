// LNP P2P library, plmeneting both legacy (BOLT) and Bifrost P2P messaging
// system for Lightning network protocol (LNP)
//
// Written in 2020-2021 by
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
extern crate lazy_static;
#[macro_use]
extern crate internet2;
#[cfg(feature = "lightning_encoding")]
#[macro_use]
extern crate lightning_encoding;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;
#[cfg(feature = "strict_encoding")]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;

macro_rules! dumb_pubkey {
    () => {
        bitcoin::secp256k1::PublicKey::from_secret_key(
            bitcoin::secp256k1::SECP256K1,
            &bitcoin::secp256k1::key::ONE_KEY,
        )
    };
}

#[cfg(feature = "bifrost")]
pub mod bifrost;
#[cfg(feature = "legacy")]
pub mod legacy;
