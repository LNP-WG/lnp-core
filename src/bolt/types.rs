// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
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

use lnpbp::chain::AssetId;
use strict_encoding::{
    self, strict_deserialize, strict_serialize, StrictDecode, StrictEncode,
};

use crate::bolt::constructors::Bolt3;
use crate::bolt::extenders::{AnchorOutputs, ShutdownScript};
use crate::bolt::modifiers::Bip96;
use crate::channel::{Channel, Error};
use crate::p2p::legacy::Messages;
use crate::{channel, extension, ChannelExtension, Extension};

/// Shorthand for representing asset - amount pairs
pub type AssetsBalance = BTreeMap<AssetId, u64>;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
pub enum ExtensionId {
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

impl Default for ExtensionId {
    fn default() -> Self {
        ExtensionId::Channel
    }
}

impl From<ExtensionId> for u16 {
    fn from(id: ExtensionId) -> Self {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(
            &strict_serialize(&id)
                .expect("Enum in-memory strict encoding can't fail"),
        );
        u16::from_be_bytes(buf)
    }
}

impl TryFrom<u16> for ExtensionId {
    type Error = strict_encoding::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        strict_deserialize(&value.to_be_bytes())
    }
}

impl extension::Nomenclature for ExtensionId {
    #[inline]
    fn default_constructor() -> Box<dyn ChannelExtension<Identity = Self>> {
        Bolt3::new()
    }

    #[inline]
    fn default_modifiers() -> Vec<Box<dyn ChannelExtension<Identity = Self>>> {
        vec![Bip96::new()]
    }

    fn update_from_peer(
        channel: &mut Channel<Self>,
        message: &Messages,
    ) -> Result<(), Error> {
        match message {
            Messages::OpenChannel(open_channel) => {
                if open_channel.shutdown_scriptpubkey.is_some() {
                    channel.add_extension(ShutdownScript::new());
                    // We will populate extension with parameters via
                    // `update_from_peer` call which will happen after the
                    // return from this function
                }
                if open_channel.has_anchor_outputs() {
                    channel.add_extension(AnchorOutputs::new())
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
#[non_exhaustive]
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

impl channel::TxRole for TxType {}

/// Channel lifecycle: states of the channel state machine
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[non_exhaustive]
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
