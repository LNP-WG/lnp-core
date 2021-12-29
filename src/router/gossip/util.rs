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

use p2p::legacy::{ChannelAnnouncement, ChannelUpdate};
use secp256k1::PublicKey;

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictEncode, StrictDecode)]
/// Information about channel used for route construction and re-broadcasting
/// gossip messages.
pub struct ChannelInfo {
    /// Node identities consituting channel
    pub nodes: (PublicKey, PublicKey),

    /// Information about each channel direction.
    ///
    /// The first tuple field corresponds to the direction from the first
    /// node id (see [`ChannelInfo::nodes`]) to the second one – and the second
    /// tuple field to the opposite direction.
    pub directions: (Option<ChannelUpdate>, Option<ChannelUpdate>),

    /// The channel capacity, known only for local channels - or if it can be
    /// deduced from on-chain data, if they are available
    pub capacity_sats: Option<u64>,

    /// Original channel announcement message from which we've got this
    /// information. Absent for manually added channels and may be absent for
    /// local channels.
    pub announcement: Option<ChannelAnnouncement>,
}
