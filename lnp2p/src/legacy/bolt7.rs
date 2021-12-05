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

use bitcoin::secp256k1::{PublicKey, Signature};
use lnpbp::chain::AssetId;

use super::{
    AddressList, Alias, ChannelId, InitFeatures, NodeColor, ShortChannelId,
};

/// Bolt 7 Gossip messages
#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
    "announcement_signature({channel_id}, {short_channel_id}, ...signatures)"
)]
pub struct AnnouncementSignatures {
    /// The channel ID
    pub channel_id: ChannelId,

    /// Short channel Id
    pub short_channel_id: ShortChannelId, //TODO

    /// Node Signature
    pub node_signature: Signature,

    /// Bitcoin Signature
    pub bitcoin_signature: Signature,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("channel_announcement({chain_hash}, {short_channel_id}, ...)")]
pub struct ChannelAnnouncements {
    /// Node Signature 1
    pub node_signature_1: Signature,

    /// Node Signature 2
    pub node_signature_2: Signature,

    /// Bitcoin Signature 1
    pub bitcoin_signature_1: Signature,

    /// Bitcoin Signature 2
    pub bitcoin_signature_2: Signature,

    /// feature bytes
    pub features: InitFeatures,

    /// chain hash
    pub chain_hash: AssetId,

    /// Short channel ID
    pub short_channel_id: ShortChannelId,

    /// Node Id 1
    pub node_id_1: PublicKey,

    /// Node Id 2
    pub node_id_2: PublicKey,

    /// Bitcoin key 1
    pub bitcoin_key_1: PublicKey,

    /// Bitcoin key 2
    pub bitcoin_key_2: PublicKey,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
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
    pub node_id: PublicKey,

    /// RGB colour code
    pub rgb_color: NodeColor,

    /// Node Alias
    pub alias: Alias,

    /// Node address
    pub addresses: AddressList,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("channel_id({chain_hash}, {short_channel_id}, {timestamp}, ...)")]
pub struct ChannelUpdate {
    /// Signature
    pub signature: Signature,

    /// Chainhash
    pub chain_hash: AssetId,

    /// Short Channel Id
    pub short_channel_id: ShortChannelId,

    /// Time stamp
    pub timestamp: u32,

    /// message flags
    pub message_flags: u8,

    /// channle flags
    pub channle_flags: u8,

    /// cltv expiry delta
    pub cltv_expiry_delta: u16,

    /// minimum HTLC in msat
    pub htlc_minimum_msal: u64,

    /// base fee in msat
    pub fee_base_msat: u32,

    /// fee proportional millionth
    pub fee_proportional_millionths: u32,

    /// if option_channel_htlc_max is set
    pub htlc_maximum_msat: u64,
}

/// Extended Gossip messages
#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("query_short_channel_ids({chain_hash}, {short_ids:#?}, ...tlvs)")]
pub struct QueryShortChannelIds {
    /// chain hash
    pub chain_hash: AssetId,

    /// short ids to query
    pub short_ids: Vec<ShortChannelId>,
    /*short id tlv stream
     * TODO: uncomment once tlv implementation is complete
     * pub short_id_tlvs: BTreeMap<u8, Vec<u8>>, */
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("reply_short_channel_ids_end({chain_hash}, {full_information})")]
pub struct ReplyShortChannelIdsEnd {
    /// chain hash
    pub chain_hash: AssetId,

    /// full information
    pub full_information: u8,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
"querry_channel_range({chain_hash}, {first_blocknum}, {number_of_blocks}, ...tlvs)"
)]
pub struct QueryChannelRange {
    /// chain hash
    pub chain_hash: AssetId,

    /// first block number
    pub first_blocknum: u32,

    /// number of blocks
    pub number_of_blocks: u32,
    /*channel range queries
    TODO: Implement channel range data types
     * pub query_channel_range_tlvs: BTreeMap<u8, Vec<u8>>, */
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
"reply_channel_range({chain_hash}, {first_blocknum}, {number_of_blocks}, ...)"
)]
pub struct ReplyChannelRange {
    /// chain hash
    pub chain_hash: AssetId,

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

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("gossip_time_stamp_filter({chain_hash}, {first_timestamp}, {timestamp_range})")]
pub struct GossipTimestampFilter {
    /// chain hash
    pub chain_hash: AssetId,

    /// first timestamp
    pub first_timestamp: u32,

    /// timestamp range
    pub timestamp_range: u32,
}
