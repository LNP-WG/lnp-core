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

use std::collections::BTreeMap;

use bitcoin::secp256k1::schnorrsig::{PublicKey, Signature};
use wallet::psbt::Psbt;

use crate::bifrost::{ChannelId, ChannelProposal, ProtocolName};
use crate::legacy;

/// Algorithm for fee computing. Defines who pais the fees for common parts of
/// the transactions (outputs/inputs used by all peers in a channel).
pub enum CommonFeeAlgo {
    /// Common fees are paid by the channel coordinator
    ByCoordinator,

    /// Common fees are paid in proportional amounts by all participats
    SharedFee,
}

/// Channel parameters originating from the channel coordinator.
///
/// These parameters apply only during the channel construction workflow and
/// never changes, constituting the first part of the data for [`ChannelId`]
/// (the second part comes from the channel coordinator node id).
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[display("type: {channel_type:#x}, timestamp: {timestamp}")]
pub struct ChannelParams {
    /// Type of the channel.
    ///
    /// Type of the channel is a 64-bit number, which is not enumerated.
    ///
    /// Independent Bifrost application developers may create new channel types
    /// by taking first 64 bits of their channel unique standard name, like
    /// "ISO-1950". Numbers below 1000 are reserved for LNPBP-standardized
    /// channels.
    pub channel_type: u64,

    /// Chain on which the channel will operate
    pub chain: lnpbp::Chain,

    /// Parent channel, if any.
    ///
    /// If the channel does not exit, or based on a different chain than
    /// [`ChannelParams::chain`], the remote peer must response with
    /// [`Error`] containing errno code `BIFROST_ERR_CHAIN_MISMATCH`.
    pub parent_channel: Option<ChannelId>,

    /// Algorithm for detecting fee. See [`CommonFeeAlgo`]
    pub fee_algo: CommonFeeAlgo,

    /// Timestamp when the channel coordinator has proposed channel for the
    /// first time to the first peer. Used in calculating timeouts.
    ///
    /// If the timestamp in the future, the remote node must response with
    /// [`Error`] message containing errno code `BIFROST_ERR_FUTURE_TIMESTAMP`.
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Timeout in seconds from [`Self::timestamp`] to abandon channel if there
    /// is no reply from a peer to the coordinator - or no message on channel
    /// progress from the coordinator to any peer within x2 time.
    pub peer_timeout: u32,

    /// Timeout in seconds for waiting the funding transaction to be mined
    /// before abandoning channel. Calculated starting from the channel switch
    /// into [`ChannelState::Finalized`] state.
    pub funding_timeout: Option<u32>,
}

pub enum ChannelState {
    Proposed,
    Accepted,
    Finalized,
    Active,
    Reorg,
    Paused,
    Closing,
    Abandoned,
}

/// Data structure maintained by each node during channel creation phase
/// (before the funding transaction is mined or became a part of the most
/// recent parent channel state)
pub struct PreChannel {
    /// Channel id, constructed out of [`ChannelParams`] and
    /// [`Self::coordinator_node`]
    pub channel_id: ChannelId,
    pub coordinator_node: PublicKey,
    pub channel_params: ChannelParams,
    pub proposal: ChannelProposal<'_>,
    pub finalized_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request initiating channel creation workflow.
///
/// If a peer accepts the channel in the proposed – or updated – form, it MUST
/// reply with [`AcceptChannel`] message. If the channel is not accepted, the
/// peer must send [`super::Error`] message.
pub struct ProposeChannel {
    /// Parameters for the channel, defined by the channel coordinator.
    ///
    /// This parameters, together with the channel coordinator node public key,
    /// are used to construct `proposal_id` used in peer node replies and
    /// further communications during channel construction workflow.
    ///
    /// Peer nodes can't change channel parameters proposed by the coordinator;
    /// if they are not satisfied with them they must reply with appropriate
    /// [`Error`] message and cancel channel creation.
    pub params: ChannelParams,

    /// The latest version of a [`ChannelProposal`].
    ///
    /// *Channel coordinator* constructs first proposal; each peer has the
    /// right to update the channel proposal.
    pub proposal: ChannelProposal<'_>,

    pub pending: Vec<PublicKey>,
    pub accepted: BTreeMap<PublicKey, Signature>,
}

/// Response from a peer to a channel coordinator
pub struct AcceptChannel {
    pub channel_id: ChannelId,
    pub updated_proposal: ChannelProposal<'_>,
    pub signatures: BTreeMap<PublicKey, Signature>,
}

pub struct FinalizeChannel {
    pub channel_id: ChannelId,
    pub proposal: ChannelProposal<'_>,
}

pub struct MoveChannel {
    pub legacy_channel_id: legacy::ChannelId,
}

pub struct RemoveChannel {
    pub channel_id: ChannelId,
}

pub struct UpdateChannelStatus {
    pub channel_id: ChannelId,
    pub new_status: ChannelStatusUpdate,
    pub pending: Vec<PublicKey>,
    pub accepted: BTreeMap<PublicKey, Signature>,
}

pub enum ChannelStatusUpdate {
    Ready,

    /// Signals that the funding transaction has become invalid by either
    /// being excluded from the longest chain (for level-1 channels) or by
    /// being excluded from the most recent parent channel state (for other
    /// channels).
    Reorg,
    Pause,
}

pub struct UpgradeChannel {
    pub channel_id: ChannelId,
    pub protocol: ProtocolName,
    pub accepted: BTreeMap<PublicKey, Signature>,
}

pub struct DowngradeChannel {
    pub channel_id: ChannelId,
    pub protocol: ProtocolName,
    pub accepted: BTreeMap<PublicKey, Signature>,
}

pub struct CloseChannel {
    pub channel_id: ChannelId,
    pub closing_tx: Psbt,
    pub accepted: BTreeMap<PublicKey, Signature>,
}
