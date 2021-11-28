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

//! Transaction graph in its off-chain part is always tree, never DAG.
//!
//! Channels always start with a single funding input coming either from
//! a single on-chain funding or other channel transaction.
//!
//! More funding inputs can be add with on-chain mined transactions only when
//! channel becomes operational.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::schnorrsig::{PublicKey, Signature};
use bitcoin::{Amount, OutPoint, SigHashType, TxOut, Txid};
use wallet::scripts::Witness;

use crate::bifrost::ChannelId;

/// Flag for the transaction role in the channel.
pub type TxRole = u8;

/// Funding transaction flag value for [`TxRole`]
pub const LN_TX_ROLE_FUNDING: u8 = 0x00;
/// Refund transaction flag value for [`TxRole`]
pub const LN_TX_ROLE_REFUND: u8 = 0x02;
/// Commitment transaction flag value for [`TxRole`].
///
/// Equal to [`LN_TX_ROLE_REFUND`] since the first version of the commitment
/// transaction is a refund transaction.
pub const LN_TX_ROLE_COMMITMENT: u8 = 0x02;

/// Signature created by a single lightning node
pub struct NodeSignature(pub PublicKey, pub Signature);
/// Map of lightning node keys to their signatures over certain data
pub struct NodeSignatureMap(pub BTreeMap<PublicKey, Signature>);

/// External transaction output. Must always be a v0 witness or a above
pub struct ChannelInput {
    /// UTXO used for funding
    pub prev_outpoint: OutPoint,

    /// Sequence number to use in the input construction
    pub sequence_no: u32,

    /// Descriptor for the previous transaction output required to construct
    /// witness for the input. Always v0+ witness
    pub descriptor: SegwitDescriptor,

    /// Witness satisfying prevous transaction descriptor.
    ///
    /// Must be present only when the transaction is signed
    pub witness: Option<Witness>,
}

/// Information to construct external transaction output not used in the
/// channel.
pub struct ChannelOutput {
    /// We have to expose full descriptor in order to allow P2C tweaks
    pub output: Decriptor,

    /// P2C tweaks are used to construct DBC anchor, if needed.
    ///
    /// Used if RGB assets are added to the channel, or there is a need to
    /// create other forms of P2C tweaks compatible with deterministic bitcoin
    /// commitments (like timestamps).
    ///
    /// We do not expose the type of the tweak, to preserve the privacy of the
    /// data. The only information exposed is pseudonymous protocol ID which
    /// is required to construct DBC anchor data.
    ///
    /// This mechanism allows to add RGB to a newly created channel without the
    /// need to exchange all large consignment data – and without a need of a
    /// separate on-chain transaction later.
    pub p2c_tweaks: BTreeMap<ProtocolId, sha256::Hash>,

    /// Signature over all fields with node key to prove the originator
    pub signature: NodeSignature,
}

/// Information about the source of the funds for the channel funding
/// transaction.
///
/// Funding for a channel MUST either come from on-chain UTXO(s) – or from
/// some other existing channel.
pub enum ChannelFunding {
    /// Funds are coming from a set of on-chain UTXOs
    Blockchain(BTreeSet<ChannelInput>),

    /// Channel is funded by an output of some other existing channel, where
    /// all of the peers of the newly created channel already participate
    Channel {
        /// Channel id to take the funding from
        channel_id: ChannelId,

        /// Transaction id of the latest channel state that provides funds for
        /// this channel
        actual_state: Txid,

        /// List of outputs of the channel transaction from the `actual_state`
        /// field.
        ///
        /// Witnesses must satisfy spending requirements when the transaction
        /// is signed.
        funding: BTreeMap<u16, Option<TaprootWitness>>,
    },
}

/// A link is a transaction output plus a input for a off-chain (internal
/// channel) transaction spending that output.
pub struct ChannelLink {
    /// Amount allocated to the transaction outut and consumed by the child
    /// channel transaction
    pub amount: Amount,

    /// Template for the channel internal transaction spending the output.
    pub tx: Box<ChannelTx>,

    /// Miniscript-compatible taproot descriptor for the transaction output.
    ///
    /// We provide full descriptor to enable nodes to use custom keys. Still,
    /// the descriptor mod key values MUST match template defined for the
    /// gived [`TxRole`] from [`ChannelTx::children`] containing this link.
    pub descriptor: TaprootDescriptor,

    /// Sequence number to use in the child transaction input
    pub sequence_no: u32,

    /// Witness satisfying [`ChannelLink::descriptor`] (with included DBC tweak
    /// constructed out of [`ChannelLink::p2c_tweaks`]).
    pub witness: Option<TaprootWitness>,

    /// P2C tweaks are used to construct DBC anchor.
    ///
    /// For details, pls refer to [`ChannelOutput::p2c_tweaks`]
    pub p2c_tweaks: BTreeMap<ProtocolId, sha256::Hash>,
}

/// Information for constructing channel funding transaction
pub struct FundingTx {
    pub locktime: u32,
    pub funding: ChannelFunding,
    pub external_outputs: Vec<ChannelOutput>,
    pub channel_output: ChannelLink,
}

/// Template for constructing channel transaction of a certain type.
///
/// Channel transactions always have just a single input, spending a
/// parent transaction output. This is necessary due to a strict tree channel
/// structure requirement.
pub struct ChannelTx {
    pub locktime: u32,

    /// Outputs not spent in the current channel, which may be spent only by
    /// a future on-chain transactions upon channel closing.
    pub external_outputs: Vec<ChannelOutput>,

    /// Construction points for a child transaction spending outputs of this
    /// transaction.
    pub children: BTreeMap<TxRole, ChannelLink>,
}

pub trait ChannelGraph {
    fn tx_by_role(&self, role: TxChannelRole) -> RoleIter;
    fn iter(&self) -> ChannelIter;
    fn funding_tx(&self) -> &ChannelTx;
    fn refund_tx(&self) -> &ChannelTx;
}

pub struct ChannelProposal<'a>
where
    Self: 'a,
{
    channel: FundingTx,
    pub signatures: NodeSignatureMap, // signatures on the graph using node key
    index: Option<BTreeMap<TxRole, Vec<&'a ChannelTx>>>,
}
