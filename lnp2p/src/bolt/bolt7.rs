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

//! Bolt 7 Gossip messages

use amplify::Slice32;
use internet2::addr::NodeId;
use secp256k1::ecdsa::Signature;

use super::{
    AddressList, Alias, ChannelId, InitFeatures, NodeColor, ShortChannelId,
};
use crate::bolt::ChannelFeatures;

/// This is a direct message between the two endpoints of a channel and serves
/// as an opt-in mechanism to allow the announcement of the channel to the rest
/// of the network. It contains the necessary signatures, by the sender, to
/// construct the `channel_announcement` message.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
    "announcement_signature({channel_id}, {short_channel_id}, ...signatures)"
)]
pub struct AnnouncementSignatures {
    /// The channel ID
    pub channel_id: ChannelId,

    /// Short channel Id
    pub short_channel_id: ShortChannelId,

    /// Node Signature
    pub node_signature: Signature,

    /// Bitcoin Signature
    pub bitcoin_signature: Signature,
}

/// This gossip message contains ownership information regarding a channel. It
/// ties each on-chain Bitcoin key to the associated Lightning node key, and
/// vice-versa. The channel is not practically usable until at least one side
/// has announced its fee levels and expiry, using channel_update.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("channel_announcement({chain_hash}, {short_channel_id}, ...)")]
pub struct ChannelAnnouncement {
    /// Node Signature 1
    pub node_signature_1: Signature,

    /// Node Signature 2
    pub node_signature_2: Signature,

    /// Bitcoin Signature 1
    pub bitcoin_signature_1: Signature,

    /// Bitcoin Signature 2
    pub bitcoin_signature_2: Signature,

    /// feature bytes
    pub features: ChannelFeatures,

    /// chain hash
    pub chain_hash: Slice32,

    /// Short channel ID
    pub short_channel_id: ShortChannelId,

    /// Node Id 1
    pub node_id_1: NodeId,

    /// Node Id 2
    pub node_id_2: NodeId,

    /// Bitcoin key 1
    pub bitcoin_key_1: NodeId,

    /// Bitcoin key 2
    pub bitcoin_key_2: NodeId,
}

/// This gossip message allows a node to indicate extra data associated with it,
/// in addition to its public key. To avoid trivial denial of service attacks,
/// nodes not associated with an already known channel are ignored.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("node_announcement({node_id}, {alias}, {addresses}, ...)")]
pub struct NodeAnnouncements {
    /// Signature
    pub signature: Signature,

    /// feature bytes
    pub features: InitFeatures,

    /// Time stamp
    pub timestamp: u32,

    /// Node Id
    pub node_id: NodeId,

    /// RGB colour code
    pub rgb_color: NodeColor,

    /// Node Alias
    pub alias: Alias,

    /// Node address
    pub addresses: AddressList,
}

/// After a channel has been initially announced, each side independently
/// announces the fees and minimum expiry delta it requires to relay HTLCs
/// through this channel. Each uses the 8-byte channel `shortid` that matches  
/// the `channel_announcement` and the 1-bit `channel_flags` field to indicate
/// which end of the channel it's on (origin or final). A node can do this
/// multiple times, in order to change fees.
// TODO: Do custom encoding due to `message_flags` and `option_channel_htlc_max`
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("channel_id({chain_hash}, {short_channel_id}, {timestamp}, ...)")]
pub struct ChannelUpdate {
    /// Signature
    pub signature: Signature,

    /// Chainhash
    pub chain_hash: Slice32,

    /// Short Channel Id
    pub short_channel_id: ShortChannelId,

    /// Time stamp
    pub timestamp: u32,

    /// message flags
    // TODO: Introduce a dedicated data type
    pub message_flags: u8,

    /// channel flags
    // TODO: Introduce a dedicated data type
    pub channel_flags: u8,

    /// CLTV expiry delta
    pub cltv_expiry_delta: u16,

    /// minimum HTLC in msat
    pub htlc_minimum_msat: u64,

    /// base fee in msat
    pub fee_base_msat: u32,

    /// fee proportional millionth
    pub fee_proportional_millionths: u32,

    /// Used only if `option_channel_htlc_max` in `message_flags` is set
    pub htlc_maximum_msat: u64,
}

/// Extended Gossip messages
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("query_short_channel_ids({chain_hash}, {short_ids:#?}, ...tlvs)")]
pub struct QueryShortChannelIds {
    /// chain hash
    pub chain_hash: Slice32,

    /// short ids to query
    pub short_ids: Vec<ShortChannelId>,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("reply_short_channel_ids_end({chain_hash}, {full_information})")]
pub struct ReplyShortChannelIdsEnd {
    /// chain hash
    pub chain_hash: Slice32,

    /// full information
    pub full_information: u8,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
    "query_channel_range({chain_hash}, {first_blocknum}, {number_of_blocks}, \
     ...tlvs)"
)]
pub struct QueryChannelRange {
    /// chain hash
    pub chain_hash: Slice32,

    /// first block number
    pub first_blocknum: u32,

    /// number of blocks
    pub number_of_blocks: u32,
    /* TODO: define custom type
    #[lightning_encoding(tlv = 1)]
    #[cfg_attr(feature = "strict_encoding", strict_encoding(tlv = 1))]
    pub query_short_channel_ids_tlvs: (),
     */
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
    "reply_channel_range({chain_hash}, {first_blocknum}, {number_of_blocks}, \
     ...)"
)]
pub struct ReplyChannelRange {
    /// chain hash
    pub chain_hash: Slice32,

    /// first block number
    pub first_blocknum: u32,

    /// number of blocks
    pub number_of_blocks: u32,

    /// full information
    pub full_information: u8,

    /// encoded short ids
    pub encoded_short_ids: Vec<ShortChannelId>,
    /* reply channel range tlvs
    TODO: Implement channel range data types
    *pub reply_channel_range_tlvs: BTreeMap<u8, Vec<u8>>, */
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
    "gossip_time_stamp_filter({chain_hash}, {first_timestamp}, \
     {timestamp_range})"
)]
pub struct GossipTimestampFilter {
    /// chain hash
    pub chain_hash: Slice32,

    /// first timestamp
    pub first_timestamp: u32,

    /// timestamp range
    pub timestamp_range: u32,
}
