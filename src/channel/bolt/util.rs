// LNP/BP Core Library implementing LNPBP specifications & standards
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

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;

use internet2::presentation::sphinx::Hop;
use lnp2p::bolt::Messages;
use lnpbp::chain::AssetId;
use p2p::bolt::PaymentOnion;
use strict_encoding::{
    self, strict_deserialize, strict_serialize, StrictDecode, StrictEncode,
};

use super::{AnchorOutputs, BoltChannel, ChannelState, Error, Htlc};
use crate::channel::shared_ext::Bip96;
use crate::channel::tx_graph::TxRole;
use crate::channel::{self, Channel};
use crate::{extension, ChannelExtension};

/// Shorthand for representing asset - amount pairs
pub type AssetsBalance = BTreeMap<AssetId, u64>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display(Debug)]
pub enum BoltExt {
    /// The channel itself
    Channel = 0,

    /// Main channel constructor
    Bolt3 = 1,
    /// HTLC payments
    Htlc = 2,

    /// BOLT-9 feature: shutdown script
    ShutdownScript = 10,
    /// BOLT-9 feature: anchor
    AnchorOutputs = 11,

    /// The role of policy extension is to make sure that aggregate properties
    /// of the transaction (no of HTLCs, fees etc) does not violate channel
    /// policies – and adjust to these policies if needed
    ///
    /// NB: Policy must always be applied after other extenders
    Policy = 100,

    /// Deterministic transaction ordering
    Bip96 = 1000,
}

impl Default for BoltExt {
    fn default() -> Self {
        BoltExt::Channel
    }
}

impl From<BoltExt> for u16 {
    fn from(id: BoltExt) -> Self {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(
            &strict_serialize(&id)
                .expect("Enum in-memory strict encoding can't fail"),
        );
        u16::from_be_bytes(buf)
    }
}

impl TryFrom<u16> for BoltExt {
    type Error = strict_encoding::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        strict_deserialize(value.to_be_bytes())
    }
}

impl extension::Nomenclature for BoltExt {
    type State = ChannelState;
    type Error = Error;
    type PeerMessage = lnp2p::bolt::Messages;
    type UpdateMessage = ();
    type UpdateRequest = UpdateReq;
}

impl channel::Nomenclature for BoltExt {
    type Constructor = BoltChannel;

    #[inline]
    fn default_extenders() -> Vec<Box<dyn ChannelExtension<Self>>> {
        vec![Htlc::new()]
    }

    #[inline]
    fn default_modifiers() -> Vec<Box<dyn ChannelExtension<Self>>> {
        vec![Bip96::new()]
    }

    fn update_from_peer(
        channel: &mut Channel<Self>,
        message: &Messages,
    ) -> Result<(), Error> {
        #[allow(clippy::single_match)] // We'll add more code in the future
        match message {
            Messages::OpenChannel(open_channel) => {
                if open_channel.has_anchor_outputs() {
                    channel.add_extender(AnchorOutputs::new())
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum UpdateReq {
    PayBolt(Vec<Hop<PaymentOnion>>),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display(Debug)]
pub enum TxType {
    HtlcSuccess,
    HtlcTimeout,
    Unknown(u16),
}

impl From<TxType> for u16 {
    fn from(ty: TxType) -> Self {
        match ty {
            TxType::HtlcSuccess => 0x0,
            TxType::HtlcTimeout => 0x1,
            TxType::Unknown(x) => x,
        }
    }
}

impl From<u16> for TxType {
    fn from(ty: u16) -> Self {
        match ty {
            0x00 => TxType::HtlcSuccess,
            0x01 => TxType::HtlcTimeout,
            x => TxType::Unknown(x),
        }
    }
}

impl TxRole for TxType {}

/// Channel lifecycle: states of the channel state machine
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[repr(u8)]
pub enum Lifecycle {
    /// Channel is initialized, communications with the remote peer has not
    /// started yet
    #[display("INIT")]
    Initial,

    /// Sent or received `open_channel`
    #[display("PROPOSED")]
    Proposed,

    /// Sent or received `accept_channel`
    #[display("ACCEPTED")]
    Accepted,

    /// Producing signature for the refund transaction internally
    #[display("SIGNING")]
    Signing,

    /// Local party signed funding tx
    #[display("FUNDING")]
    Funding,

    /// Other peer signed funding tx
    #[display("SIGNED")]
    Signed,

    /// Funding tx is published but not mined
    #[display("FUNDED")]
    Funded,

    /// Funding tx mining confirmed by one peer
    #[display("LOCKED")]
    Locked,

    /// Both peers confirmed lock, channel active
    #[display("ACTIVE")]
    Active,

    /// Reestablishing connectivity
    #[display("REESTABLISHING")]
    Reestablishing,

    /// Shutdown proposed but not yet accepted
    #[display("SHUTDOWN")]
    Shutdown,

    /// Shutdown agreed, exchanging `closing_signed`
    #[display("CLOSING-{round}")]
    Closing { round: usize },

    /// Non-cooperative unilateral closing initialized from the self
    #[display("ABORTING")]
    Aborting,

    /// Reacting to an uncooperative channel close from remote
    #[display("PENALIZE")]
    Penalize,

    /// Channel non-operational and closed
    #[display("CLOSED")]
    Closed,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle::Initial
    }
}
