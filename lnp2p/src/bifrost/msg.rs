// LNP P2P library, plmeneting both bolt (BOLT) and Bifrost P2P messaging
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

use super::BifrostApp;

/// Message specific to a particular Bifrost application (Layer 3).
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display("msg({app}, ...)")]
pub struct Msg {
    /// Application identifier.
    pub app: BifrostApp,

    /// Application-specific message payload.
    pub payload: Box<[u8]>,
}
