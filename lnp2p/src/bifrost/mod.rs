// LNP P2P library, plmeneting both legacy (BOLT) and Bifrost P2P messaging
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

//! # Bifrost transaction requirements
//!
//! Bifrost requires all off-chain transactions always have v2 and use
//! v1 witness P2TR outputs (or later witness versions). Transaction inputs,
//! aside from funding transaction, also must be v1 witness inputs spending
//! P2TR outputs (or above).
//!
//! For funding onchain transactions and funding outputs of channel level 1
//! this requirement is released to witness v0 or above. The reason for lower
//! requirement is the interoperability with the legacy lightning network,
//! allowing migration of existing channels opened in legacy network to
//! Bifrost.
//!
//!
//! # Channel coordination
//!
//! For channel operations we assume that any channel may be a multi-peer
//! channel. Thus, for channel updates it is required that all parties
//! cooperate and sign the latest version of updated channel transactions.
//! This is achieved by introducing concept of *channel coordinator*. Channel
//! coordinator is the lightning node that has originally proposed channel.
//! It is responsible for orchestrating message flow between all nodes which
//! are the parts of the channel and keeping them up-to-date. Also, the
//! channel coordinator is the only party required to have direct connections
//! with other channel participants – and each of channel participants is
//! required to be connected at least to the channel coordinator.
//!
//! If a multiple nested channels are present, for all higher-level channels
//! channel coordinator MUST be the same as channel coordinator for the base
//! (level 1) channel; the list of participants for the nested channels MUST be
//! a subset of the participants of the topmost level 1 channel.
//!
//!
//! # Channel workflows
//!
//! There are following workflows affecting channel status / existence. Each
//! of these workflows represent a set of P2P messages exchanged by channel
//! peers.
//!
//! - Channel creation
//! - Moving channel from legacy to Bifrost LN
//! - Removing channel from Bifrost to legacy LN
//! - Changing channel status (pausing etc)
//! - Upgrading channel to support more protocols
//! - Downgrading channel by removing specific protocol
//! - Cooperatively closing channel
//!
//! Workflow can be initiated only by a *channel coordinator*, and specific
//! P2P messages inside the workflow can be sent either from the *channel
//! coordinator* to a peer – or, in response, from a peer to the *channel
//! coordinator*.
//!
//! Normal channel operations are covered by application-specific business logic
//! and messages and are not part of any listed channel workflow. Unlike
//! workflows, they may be initiated by any of the channel peers sending message
//! to the channel coordinator, however whenever they involve other peers or
//! external channels, after being initiated they must be coordinated by the
//! channel coordinator.
//!
//! ## Channel creation workflow
//!
//! Considering generic case of multi-peer channel setup channel creation
//! workflow is organized with the following algorithm:
//!
//! 1. First, all parties agree on the structure of the *funding transaction*
//!    and overall transaction graph within the channel – simultaneously signing
//!    *refund transaction* (which, upon channel creation, will become first
//!    version of the channel *commitment transaction*). This is done using
//!    [`ProposeChannel`] requests sent by the *channel coordinator* to each of
//!    the peers, replying with either [`AcceptChannel`] (containing updated
//!    transaction graph with signed refund transaction) or [`Error`].
//!    peers must wait for `CHANNEL_CREATION_TIMEOUT` period and discard all
//!    provisional channel data from their memory.
//!
//! 2. Once the refund transaction is fully signed – implying that the
//!    transaction graph if agreed between participants – channel coordinator
//!    starts next phase, where the funding transaction gets fully signed.
//!    Coordinator sends [`FinalizeChannel`] message to each of the peers and
//!    collects signatures, publishing the final transaction either to bitcoin
//!    blockchain (for level 1 channels) or updating the state of the top-level
//!    channel (for nested channels above level 1). Peers track upper level
//!    channel or blockchain to detect funding transaction, and upon transaction
//!    mining starts operate channel in active mode, not requiring any other
//!    messages from the channel coordinator (NB: this differs from the legacy
//!    LN channel creation workflow).
//!  
//! 3. Replacing funding by fee (RBF): channel coordinator SHOULD initiate RBF
//!    subworkflow for level 1 channels if the funding transaction was not mined
//!    after reasonable amount of time, which should be less than
//!    [`ChannelParams::funding_timeout`]. With RGB subworkflow coordinator
//!    updates funding transaction – and propagates it with [`FinalizeChannel`]
//!    request, collecting new signatures (peers MUST reset their funding
//!    timeout counters).
//!
//! 4. Cancelling channel creation: if any of the peer nodes replied with
//!    [`Error`] on any of the channel construction requests within the channel
//!    creation workflow – or if the coordinator detected incorrect reply,
//!    channel coordinator MUST abandon channel creation – and MUST forward
//!    [`Error`] message to all other peers. A peer posting [`Error`] MUST
//!    provide a valid error code and a message explaining the cause of the
//!    error. The coordinator SHOULD also send [`Error`] message to peers if
//!    any of the stages of transaction construction workflow has stuck
//!    without a reply from a peer for over [`ChannelParams::peer_timeout`]
//!    time.
//!
//! 5. Timeouts: the coordinator SHOULD send [`Error`] message to peers if any
//!    of the peers at any stage of transaction construction workflow has stuck
//!    without a reply for over [`ChannelParams::peer_timeout`] time.
//!    The peers should abandon channel and clear all information about it from
//!    the memory regardless whether they have received [`Error`] message from
//!    the coordinator after [`ChannelParams::peer_timeout`]` * 2` time before
//!    `ChannelFinalized` – and if they has not received new
//!    [`FinalizeChannel`] request from the coordinator after
//!    [`ChannelParams::funding_timeout`] time (see pt 3 for RBF subworkflow).
//!
//! ```ignore
//! Channel coordinator                   Peer 1             Peer 2
//!         |                               |                  |
//! (enters ChannelProposed state)          |                  |
//!         |                               |                  |
//!         | --(1)- ProposeChannel ------> |                  |
//!         |                               |                  |
//!         | --(1)------------ ProposeChannel --------------> |
//!         |                               |                  |
//!         |                           (enter ChannelProposed state)
//!         |                               |                  |
//!         | <-(2)------------- AcceptChannel --------------- |
//!         |                               |                  |
//!         | <-(2)-- AcceptChannel ------- |                  |
//!         |                               |                  |
//!  (enters ChannelAccepted state)     (enter ChannelAccepted state)
//!         |                               |                  |
//!         | --(3)- FinalizeChannel -----> |                  |
//!         |                               |                  |
//!         | --(3)------------ FinalizeChannel -------------> |
//!         |                               |                  |
//!         | <-(4)-- FinalizeChannel ----- |                  |
//!         |                               |                  |
//!         | <-(4)------------- FinalizeChannel ------------- |
//!         |                               |                  |
//!  (enters ChannelFinalized state)    (enter ChannelFinalized state)
//!         |                               |                  |
//! (await funding transaction mining or entering the valid super-channel state)
//!         |                               |                  |
//!  (enters ChannelActive state)       (enter ChannelActive state)
//!         |                               |                  |
//! ```
//!
//! During channel construction workflow channels are identified by
//! [`ChannelId`], which is constructed as a tagged SHA-256 hash
//! (using `bifrost:channel-proposal` as tag) of the strict-serialized
//! [`ChannelParams`] data and coordinator node public key.
//!
//! [`Error`]: [struct@Error]

mod channel;
mod ctrl;
mod msg;
mod proposals;
mod types;

pub use channel::*;
pub use ctrl::*;
pub use msg::*;
pub use proposals::*;
pub use types::{
    AddressList, AnnouncedNodeAddr, ChannelId, ProtocolList, ProtocolName,
    ProtocolNameError,
};

use std::io;

use internet2::{CreateUnmarshaller, Payload, Unmarshall, Unmarshaller};
use lnpbp::bech32::Blob;
use strict_encoding::{self, StrictDecode, StrictEncode};

/// Default legacy Lightning port number
pub const LNP2P_BIFROST_PORT: u16 = 9999;

lazy_static! {
    pub static ref LNP2P_BIFROST_UNMARSHALLER: Unmarshaller<Messages> =
        Messages::create_unmarshaller();
}

#[derive(Clone, Debug, Display, Api)]
#[api(encoding = "strict")]
#[non_exhaustive]
#[display(inner)]
pub enum Messages {
    // Part I: Generic messages outside of channel operations (BOLT-1)
    // ===============================================================
    /// Once authentication is complete, the first message reveals the features
    /// supported or required by this node, even if this is a reconnection.
    #[api(type = 16)]
    Init(Init),

    /// For simplicity of diagnosis, it's often useful to tell a peer that
    /// something is incorrect.
    #[api(type = 17)]
    Error(Error),

    /// In order to allow for the existence of long-lived TCP connections, at
    /// times it may be required that both ends keep alive the TCP connection
    /// at the application level. Such messages also allow obfuscation of
    /// traffic patterns.
    #[api(type = 18)]
    Ping(Ping),

    /// The pong message is to be sent whenever a ping message is received. It
    /// serves as a reply and also serves to keep the connection alive, while
    /// explicitly notifying the other end that the receiver is still active.
    /// Within the received ping message, the sender will specify the number of
    /// bytes to be included within the data payload of the pong message.
    #[api(type = 19)]
    #[display("pong(...)")]
    Pong(Blob),

    #[api(type = 0x0020)]
    ProposeChannel(ProposeChannel),
    #[api(type = 0x0021)]
    AcceptChannel(AcceptChannel),
    #[api(type = 0x0022)]
    FinalizeChannel(FinalizeChannel),

    #[api(type = 0x0023)]
    MoveChannel(MoveChannel),
    #[api(type = 0x0024)]
    RemoveChannel(RemoveChannel),

    #[api(type = 0x0025)]
    UpdateChannelStatus(UpdateChannelStatus),

    #[api(type = 0x0026)]
    UpgradeChannel(UpgradeChannel),
    #[api(type = 0x0027)]
    DowngradeChannel(DowngradeChannel),

    #[api(type = 0x0028)]
    CloseChannel(CloseChannel),
}

impl StrictEncode for Messages {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Payload::from(self.clone()).strict_encode(e)
    }
}

impl StrictDecode for Messages {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let message =
            &*LNP2P_BIFROST_UNMARSHALLER.unmarshall(d).map_err(|err| {
                strict_encoding::Error::DataIntegrityError(format!(
                    "can't unmarshall Bifrost LNP2P message. Details: {}",
                    err
                ))
            })?;
        Ok(message.clone())
    }
}
