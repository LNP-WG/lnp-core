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

use amplify::Slice32;
use p2p::legacy::{
    ChannelAnnouncement, ChannelId, ChannelUpdate, ShortChannelId,
};
use secp256k1::PublicKey;

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictEncode, StrictDecode)]
/// Information about channel used for route construction and re-broadcasting
/// gossip messages.
pub struct GossipChannelInfo {
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

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
/// Information about channel used for route construction and re-broadcasting
/// gossip messages.
pub struct DirectChannelInfo {
    /// Other node identity
    pub remote_node: PublicKey,

    /// Full channel id
    pub channel_id: ChannelId,

    /// Short Channel Id
    pub short_channel_id: ShortChannelId,

    /// Chainhash
    pub chain_hash: Slice32,

    pub inbound_capacity_msat: u64,

    pub outboud_capacity_msat: u64,

    /// CLTV expiry delta
    pub cltv_expiry: u16,

    /// minimum HTLC in msat
    pub htlc_minimum_msat: u64,

    /// maximum HTLC in msat
    pub htlc_maximum_msat: u64,

    /// base fee in msat
    pub fee_base_msat: u32,

    /// fee proportional millionth
    pub fee_proportional_millionths: u32,
}
