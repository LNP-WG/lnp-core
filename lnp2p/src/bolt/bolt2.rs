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

use std::io;
use std::str::FromStr;

use amplify::flags::FlagVec;
use amplify::{DumbDefault, Slice32};
use bitcoin::hashes::sha256;
use bitcoin::Txid;
use bitcoin_scripts::hlc::{HashLock, HashPreimage};
use bitcoin_scripts::PubkeyScript;
use internet2::presentation::sphinx::Onion;
use internet2::tlv;
use secp256k1::ecdsa::Signature;
use secp256k1::{PublicKey, SecretKey};

use super::{ChannelId, TempChannelId};
use crate::bolt::PaymentOnion;

/// Total length of payment Sphinx package
pub const PAYMENT_SPHINX_LEN: usize = 1300;

/// Channel types are an explicit enumeration: for convenience of future
/// definitions they reuse even feature bits, but they are not an arbitrary
/// combination (they represent the persistent features which affect the channel
/// operation).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum ChannelType {
    /// no features (no bits set)
    #[display("basic")]
    Basic,

    /// option_static_remotekey (bit 12)
    #[display("static_remotekey")]
    StaticRemotekey,

    /// option_anchor_outputs and option_static_remotekey (bits 20 and 12)
    #[display("anchored")]
    AnchorOutputsStaticRemotekey,

    /// option_anchors_zero_fee_htlc_tx and option_static_remotekey (bits 22
    /// and 12)
    #[display("anchored_zero_fee")]
    AnchorsZeroFeeHtlcTxStaticRemotekey,
}

impl ChannelType {
    /// Detects whether channel has `option_static_remotekey` set
    #[inline]
    pub fn has_static_remotekey(self) -> bool {
        self != ChannelType::Basic
    }

    /// Detects whether channel has `option_anchor_outputs` set
    #[inline]
    pub fn has_anchor_outputs(self) -> bool {
        self == ChannelType::AnchorOutputsStaticRemotekey
    }

    /// Detects whether channel has `option_anchors_zero_fee_htlc_tx` set
    #[inline]
    pub fn has_anchors_zero_fee_htlc_tx(self) -> bool {
        self == ChannelType::AnchorsZeroFeeHtlcTxStaticRemotekey
    }

    /// Converts default channel type into `None` and non-default into
    /// `Some(ChannelType)`
    #[inline]
    pub fn into_option(self) -> Option<ChannelType> {
        match self {
            ChannelType::Basic => None,
            _ => Some(self),
        }
    }
}

/// Error parsing [`ChannelType`] from strings
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("unknown channel type name `{0}`")]
pub struct ChannelTypeParseError(String);

impl FromStr for ChannelType {
    type Err = ChannelTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "basic" => ChannelType::Basic,
            "static_remotekey" => ChannelType::StaticRemotekey,
            "anchored" => ChannelType::AnchorOutputsStaticRemotekey,
            "anchored_zero_fee" => {
                ChannelType::AnchorsZeroFeeHtlcTxStaticRemotekey
            }
            _ => return Err(ChannelTypeParseError(s.to_owned())),
        })
    }
}

impl Default for ChannelType {
    #[inline]
    fn default() -> Self {
        ChannelType::Basic
    }
}

impl lightning_encoding::LightningEncode for ChannelType {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        let mut flags = FlagVec::new();
        match self {
            ChannelType::Basic => {
                // no flags are used
            }
            ChannelType::StaticRemotekey => {
                flags.set(12);
            }
            ChannelType::AnchorOutputsStaticRemotekey => {
                flags.set(12);
                flags.set(20);
            }
            ChannelType::AnchorsZeroFeeHtlcTxStaticRemotekey => {
                flags.set(12);
                flags.set(22);
            }
        };

        // Workaround to avoid lightning encode by FlagVec, because it add plus
        // informations about length and does not working with lightning and
        // lnd.
        let buf = flags.as_inner();
        let mut buf = buf.to_owned();
        buf.sort();
        buf.reverse();
        e.write_all(&buf)?;

        Ok(buf.len() as usize)
    }
}

impl lightning_encoding::LightningDecode for ChannelType {
    fn lightning_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        // Workaround to avoid lightning decode by FlagVec, because it add plus
        // informations about length and does not working with lightning and
        // lnd.
        let mut buf = vec![];
        let _ = d.read_to_end(&mut buf);
        buf.sort();

        let mut flags = FlagVec::from_inner(buf);
        if flags.shrink() {
            return Err(lightning_encoding::Error::DataIntegrityError(s!(
                "non-minimal channel type encoding"
            )));
        } else if flags.as_inner() == &[] as &[u8] {
            return Ok(ChannelType::Basic);
        }

        let mut iter = flags.iter();
        match (iter.next(), iter.next(), iter.next()) {
            (Some(12), None, None) => Ok(ChannelType::StaticRemotekey),
            (Some(12), Some(20), None) => {
                Ok(ChannelType::AnchorOutputsStaticRemotekey)
            }
            (Some(12), Some(22), None) => {
                Ok(ChannelType::AnchorsZeroFeeHtlcTxStaticRemotekey)
            }
            _ => Err(lightning_encoding::Error::DataIntegrityError(s!(
                "invalid combination of channel type flags"
            ))),
        }
    }
}

/// This message contains information about a node and indicates its desire to
/// set up a new channel. This is the first step toward creating the funding
/// transaction and both versions of the commitment transaction.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
#[lightning_encoding(use_tlv)]
#[display(
    "open_channel({chain_hash}, {temporary_channel_id}, {funding_satoshis}, \
     {channel_flags}, ...)"
)]
pub struct OpenChannel {
    /// The genesis hash of the blockchain where the channel is to be opened
    pub chain_hash: Slice32,

    /// A temporary channel ID, until the funding outpoint is announced
    pub temporary_channel_id: TempChannelId,

    /// The channel value
    pub funding_satoshis: u64,

    /// The amount to push to the counter-party as part of the open, in
    /// millisatoshi
    pub push_msat: u64,

    /// The threshold below which outputs on transactions broadcast by sender
    /// will be omitted
    pub dust_limit_satoshis: u64,

    /// The maximum inbound HTLC value in flight towards sender, in
    /// millisatoshi
    pub max_htlc_value_in_flight_msat: u64,

    /// The minimum value unencumbered by HTLCs for the counterparty to keep
    /// in the channel
    pub channel_reserve_satoshis: u64,

    /// The minimum HTLC size incoming to sender, in milli-satoshi
    pub htlc_minimum_msat: u64,

    /// The fee rate per 1000-weight of sender generated transactions, until
    /// updated by update_fee
    pub feerate_per_kw: u32,

    /// The number of blocks which the counterparty will have to wait to claim
    /// on-chain funds if they broadcast a commitment transaction
    pub to_self_delay: u16,

    /// The maximum number of inbound HTLCs towards sender
    pub max_accepted_htlcs: u16,

    /// The sender's key controlling the funding transaction
    pub funding_pubkey: PublicKey,

    /// Used to derive a revocation key for transactions broadcast by
    /// counterparty
    pub revocation_basepoint: PublicKey,

    /// A payment key to sender for transactions broadcast by counterparty
    pub payment_point: PublicKey,

    /// Used to derive a payment key to sender for transactions broadcast by
    /// sender
    pub delayed_payment_basepoint: PublicKey,

    /// Used to derive an HTLC payment key to sender
    pub htlc_basepoint: PublicKey,

    /// The first to-be-broadcast-by-sender transaction's per commitment point
    pub first_per_commitment_point: PublicKey,

    /// Channel flags.
    ///
    /// Only the least-significant bit of channel_flags is currently defined:
    /// announce_channel. This indicates whether the initiator of the funding
    /// flow wishes to advertise this channel publicly to the network, as
    /// detailed within BOLT #7.
    pub channel_flags: u8,

    /// Optionally, a request to pre-set the to-sender output's scriptPubkey
    /// for when we collaboratively close
    #[lightning_encoding(tlv = 0)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 0))]
    pub shutdown_scriptpubkey: Option<PubkeyScript>,

    /// Channel types are an explicit enumeration: for convenience of future
    /// definitions they reuse even feature bits, but they are not an arbitrary
    /// combination (they represent the persistent features which affect the
    /// channel operation).
    #[lightning_encoding(tlv = 1)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 1))]
    pub channel_type: Option<ChannelType>,

    /// The rest of TLVs with unknown odd type ids
    #[lightning_encoding(unknown_tlvs)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(unknown_tlvs))]
    pub unknown_tlvs: tlv::Stream,
}

impl OpenChannel {
    /// Detects whether channel has `option_static_remotekey` set
    #[inline]
    pub fn has_static_remotekey(&self) -> bool {
        self.channel_type.unwrap_or_default().has_static_remotekey()
    }

    /// Detects whether channel has `option_anchor_outputs` set
    #[inline]
    pub fn has_anchor_outputs(&self) -> bool {
        self.channel_type.unwrap_or_default().has_anchor_outputs()
    }

    /// Detects whether channel has `option_anchors_zero_fee_htlc_tx` set
    #[inline]
    pub fn has_anchors_zero_fee_htlc_tx(&self) -> bool {
        self.channel_type
            .unwrap_or_default()
            .has_anchors_zero_fee_htlc_tx()
    }

    /// Detects whether channel should be announced
    #[inline]
    pub fn should_announce_channel(&self) -> bool {
        self.channel_flags & 0x01 == 0x01
    }
}

/// This message contains information about a node and indicates its acceptance
/// of the new channel. This is the second step toward creating the funding
/// transaction and both versions of the commitment transaction.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
#[lightning_encoding(use_tlv)]
#[display("accept_channel({temporary_channel_id}, ...)")]
pub struct AcceptChannel {
    /// A temporary channel ID, until the funding outpoint is announced
    pub temporary_channel_id: TempChannelId,

    /// The threshold below which outputs on transactions broadcast by sender
    /// will be omitted
    pub dust_limit_satoshis: u64,

    /// The maximum inbound HTLC value in flight towards sender, in
    /// milli-satoshi
    pub max_htlc_value_in_flight_msat: u64,

    /// The minimum value unencumbered by HTLCs for the counterparty to keep in
    /// the channel
    pub channel_reserve_satoshis: u64,

    /// The minimum HTLC size incoming to sender, in milli-satoshi
    pub htlc_minimum_msat: u64,

    /// Minimum depth of the funding transaction before the channel is
    /// considered open
    pub minimum_depth: u32,

    /// The number of blocks which the counterparty will have to wait to claim
    /// on-chain funds if they broadcast a commitment transaction
    pub to_self_delay: u16,

    /// The maximum number of inbound HTLCs towards sender
    pub max_accepted_htlcs: u16,

    /// The sender's key controlling the funding transaction
    pub funding_pubkey: PublicKey,

    /// Used to derive a revocation key for transactions broadcast by
    /// counterparty
    pub revocation_basepoint: PublicKey,

    /// A payment key to sender for transactions broadcast by counterparty
    pub payment_point: PublicKey,

    /// Used to derive a payment key to sender for transactions broadcast by
    /// sender
    pub delayed_payment_basepoint: PublicKey,

    /// Used to derive an HTLC payment key to sender for transactions broadcast
    /// by counterparty
    pub htlc_basepoint: PublicKey,

    /// The first to-be-broadcast-by-sender transaction's per commitment point
    pub first_per_commitment_point: PublicKey,

    /// Optionally, a request to pre-set the to-sender output's scriptPubkey
    /// for when we collaboratively close
    #[lightning_encoding(tlv = 0)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 0))]
    pub shutdown_scriptpubkey: Option<PubkeyScript>,

    /// Channel types are an explicit enumeration: for convenience of future
    /// definitions they reuse even feature bits, but they are not an arbitrary
    /// combination (they represent the persistent features which affect the
    /// channel operation).
    #[lightning_encoding(tlv = 1)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 1))]
    pub channel_type: Option<ChannelType>,

    /// The rest of TLVs with unknown odd type ids
    #[lightning_encoding(unknown_tlvs)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(unknown_tlvs))]
    pub unknown_tlvs: tlv::Stream,
}

impl AcceptChannel {
    /// Detects whether channel has `option_static_remotekey` set
    #[inline]
    pub fn has_static_remotekey(&self) -> bool {
        self.channel_type.unwrap_or_default().has_static_remotekey()
    }

    /// Detects whether channel has `option_anchor_outputs` set
    #[inline]
    pub fn has_anchor_outputs(&self) -> bool {
        self.channel_type.unwrap_or_default().has_anchor_outputs()
    }

    /// Detects whether channel has `option_anchors_zero_fee_htlc_tx` set
    #[inline]
    pub fn has_anchors_zero_fee_htlc_tx(&self) -> bool {
        self.channel_type
            .unwrap_or_default()
            .has_anchors_zero_fee_htlc_tx()
    }
}

/// This message describes the outpoint which the funder has created for the
/// initial commitment transactions. After receiving the peer's signature, via
/// `funding_signed`, it will broadcast the funding transaction.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
    "funding_created({temporary_channel_id}, \
     {funding_txid}:{funding_output_index}, ...signature)"
)]
pub struct FundingCreated {
    /// A temporary channel ID, until the funding is established
    pub temporary_channel_id: TempChannelId,

    /// The funding transaction ID
    pub funding_txid: Txid,

    /// The specific output index funding this channel
    pub funding_output_index: u16,

    /// The signature of the channel initiator (funder) on the funding
    /// transaction
    pub signature: Signature,
}

/// This message gives the funder the signature it needs for the first
/// commitment transaction, so it can broadcast the transaction knowing that
/// funds can be redeemed, if need be.
///
/// This message introduces the `channel_id` to identify the channel.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("funding_signed({channel_id}, ...signature)")]
pub struct FundingSigned {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The signature of the channel acceptor on the funding transaction
    pub signature: Signature,
}

/// This message indicates that the funding transaction has reached the
/// `minimum_depth` asked for in `accept_channel`. Once both nodes have sent
/// this, the channel enters normal operating mode.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("funding_locked({channel_id}, {next_per_commitment_point})")]
pub struct FundingLocked {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The per-commitment point of the second commitment transaction
    pub next_per_commitment_point: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("shutdown({channel_id}, {scriptpubkey})")]
pub struct Shutdown {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The destination of this peer's funds on closing.
    /// Must be in one of these forms: p2pkh, p2sh, p2wpkh, p2wsh.
    pub scriptpubkey: PubkeyScript,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("closing_signed({channel_id}, ...)")]
pub struct ClosingSigned {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The proposed total fee for the closing transaction
    pub fee_satoshis: u64,

    /// A signature on the closing transaction
    pub signature: Signature,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
#[lightning_encoding(use_tlv)]
#[display(
    "update_add_htlc({channel_id}, {htlc_id}, {amount_msat}, {payment_hash}, \
     ...)"
)]
pub struct UpdateAddHtlc {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The HTLC ID
    pub htlc_id: u64,

    /// The HTLC value in milli-satoshi
    pub amount_msat: u64,

    /// The payment hash, the pre-image of which controls HTLC redemption
    pub payment_hash: HashLock,

    /// The expiry height of the HTLC
    pub cltv_expiry: u32,

    /// An obfuscated list of hops and instructions for each hop along the
    /// path. It commits to the HTLC by setting the payment_hash as associated
    /// data, i.e. includes the payment_hash in the computation of HMACs. This
    /// prevents replay attacks that would reuse a previous
    /// onion_routing_packet with a different payment_hash.
    pub onion_routing_packet: Onion<PaymentOnion, PAYMENT_SPHINX_LEN>,

    /// The rest of TLVs with unknown odd type ids
    #[lightning_encoding(unknown_tlvs)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(unknown_tlvs))]
    pub unknown_tlvs: tlv::Stream,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("update_fullfill_htlc({channel_id}, {htlc_id}, ...preimages)")]
pub struct UpdateFulfillHtlc {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The HTLC ID
    pub htlc_id: u64,

    /// The pre-image of the payment hash, allowing HTLC redemption
    pub payment_preimage: HashPreimage,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("update_fail_htlc({channel_id}, {htlc_id}, ...reason)")]
pub struct UpdateFailHtlc {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The HTLC ID
    pub htlc_id: u64,

    /// The reason field is an opaque encrypted blob for the benefit of the
    /// original HTLC initiator, as defined in BOLT #4; however, there's a
    /// special malformed failure variant for the case where the peer couldn't
    /// parse it: in this case the current node instead takes action,
    /// encrypting it into a update_fail_htlc for relaying.
    pub reason: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("update_fail_malformed_htlc({channel_id}, {htlc_id}, ...onion)")]
pub struct UpdateFailMalformedHtlc {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The HTLC ID
    pub htlc_id: u64,

    /// SHA256 hash of onion data
    pub sha256_of_onion: sha256::Hash,

    /// The failure code
    pub failure_code: u16,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("commitment_signed({channel_id}, ...signatures)")]
pub struct CommitmentSigned {
    /// The channel ID
    pub channel_id: ChannelId,

    /// A signature on the commitment transaction
    pub signature: Signature,

    /// Signatures on the HTLC transactions
    pub htlc_signatures: Vec<Signature>,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display(
    "revoke_and_ack({channel_id}, {next_per_commitment_point}, \
     ...per_commitment_secret)"
)]
pub struct RevokeAndAck {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The secret corresponding to the per-commitment point
    pub per_commitment_secret: SecretKey,

    /// The next sender-broadcast commitment transaction's per-commitment point
    pub next_per_commitment_point: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("update_fee({channel_id}, {feerate_per_kw})")]
pub struct UpdateFee {
    /// The channel ID
    pub channel_id: ChannelId,

    /// Fee rate per 1000-weight of the transaction
    pub feerate_per_kw: u32,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("channel_reestablish({channel_id}, {next_commitment_number}, ...)")]
pub struct ChannelReestablish {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The next commitment number for the sender
    pub next_commitment_number: u64,

    /// The next commitment number for the recipient
    pub next_revocation_number: u64,

    /// Proof that the sender knows the per-commitment secret of a specific
    /// commitment transaction belonging to the recipient.
    ///
    /// We use [`Slice32`] here and not [`SecretKey`] since this value might be
    /// zero (indicating no previous per commitment secret was shared), which
    /// will result in serialization faiure for [`SecretKey`].
    pub your_last_per_commitment_secret: Slice32,

    /// The sender's per-commitment point for their current commitment
    /// transaction
    pub my_current_per_commitment_point: PublicKey,
}

impl DumbDefault for OpenChannel {
    fn dumb_default() -> Self {
        OpenChannel {
            chain_hash: none!(),
            temporary_channel_id: TempChannelId::dumb_default(),
            funding_satoshis: 0,
            push_msat: 0,
            dust_limit_satoshis: 0,
            max_htlc_value_in_flight_msat: 0,
            channel_reserve_satoshis: 0,
            htlc_minimum_msat: 0,
            feerate_per_kw: 0,
            to_self_delay: 0,
            max_accepted_htlcs: 0,
            funding_pubkey: dumb_pubkey!(),
            revocation_basepoint: dumb_pubkey!(),
            payment_point: dumb_pubkey!(),
            delayed_payment_basepoint: dumb_pubkey!(),
            htlc_basepoint: dumb_pubkey!(),
            first_per_commitment_point: dumb_pubkey!(),
            channel_flags: 0,
            shutdown_scriptpubkey: None,
            channel_type: None,
            unknown_tlvs: none!(),
        }
    }
}

impl DumbDefault for AcceptChannel {
    fn dumb_default() -> Self {
        AcceptChannel {
            temporary_channel_id: TempChannelId::dumb_default(),
            dust_limit_satoshis: 0,
            max_htlc_value_in_flight_msat: 0,
            channel_reserve_satoshis: 0,
            htlc_minimum_msat: 0,
            minimum_depth: 0,
            to_self_delay: 0,
            max_accepted_htlcs: 0,
            funding_pubkey: dumb_pubkey!(),
            revocation_basepoint: dumb_pubkey!(),
            payment_point: dumb_pubkey!(),
            delayed_payment_basepoint: dumb_pubkey!(),
            htlc_basepoint: dumb_pubkey!(),
            first_per_commitment_point: dumb_pubkey!(),
            shutdown_scriptpubkey: None,
            channel_type: none!(),
            unknown_tlvs: none!(),
        }
    }
}

#[cfg(test)]
mod test {
    use lightning_encoding::LightningDecode;

    use crate::bolt::Messages;

    #[test]
    fn real_clightning_open_channel() {
        // Real open_channel message sent by clightning
        let msg_recv = [
            0, 32, 6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235,
            91, 191, 40, 195, 79, 58, 94, 51, 42, 31, 199, 178, 183, 60, 241,
            136, 145, 15, 55, 163, 222, 247, 199, 217, 62, 176, 50, 239, 35, 1,
            82, 129, 198, 46, 117, 47, 78, 64, 130, 130, 167, 89, 107, 148,
            190, 121, 88, 127, 175, 82, 0, 0, 0, 0, 0, 1, 134, 160, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 34, 255, 255, 255, 255, 255, 255,
            255, 255, 0, 0, 0, 0, 0, 0, 3, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 253, 0, 6, 1, 227, 3, 33, 98, 70, 252, 48, 195, 103, 238, 233,
            231, 193, 79, 109, 137, 240, 0, 34, 234, 4, 191, 125, 249, 102, 44,
            137, 141, 152, 246, 118, 166, 205, 60, 3, 96, 241, 203, 115, 211,
            19, 224, 138, 23, 92, 68, 226, 196, 234, 61, 226, 143, 211, 90, 92,
            44, 147, 5, 89, 185, 117, 71, 57, 241, 139, 196, 28, 3, 252, 250,
            227, 188, 85, 7, 237, 113, 4, 18, 45, 7, 192, 165, 147, 18, 113,
            191, 216, 125, 175, 201, 118, 225, 63, 243, 29, 155, 194, 235, 167,
            20, 3, 12, 61, 69, 17, 92, 121, 215, 107, 192, 35, 192, 160, 214,
            235, 86, 202, 92, 206, 239, 201, 48, 28, 215, 9, 43, 255, 250, 80,
            32, 129, 98, 29, 3, 57, 9, 153, 179, 206, 248, 130, 112, 219, 32,
            69, 209, 220, 105, 18, 211, 2, 165, 247, 245, 245, 1, 170, 100,
            208, 34, 98, 123, 207, 130, 10, 66, 2, 21, 90, 74, 135, 143, 98,
            75, 173, 210, 81, 201, 99, 45, 76, 125, 176, 84, 187, 222, 90, 218,
            87, 5, 11, 119, 191, 75, 185, 108, 124, 8, 32, 1, 0, 0, 1, 2, 16,
            0,
        ];
        let msg = Messages::lightning_deserialize(&msg_recv);
        // println!("{:?}", msg);
        assert_eq!(true, msg.is_ok())
    }

    #[test]
    fn real_clightning_accept_message() {
        // Real accept_channel message sent by clightning
        let msg_recv = [
            0, 33, 117, 72, 156, 134, 70, 5, 93, 232, 6, 166, 206, 185, 243,
            33, 125, 57, 230, 233, 235, 59, 255, 0, 23, 127, 91, 135, 129, 43,
            74, 208, 254, 247, 0, 0, 0, 0, 0, 0, 2, 34, 255, 255, 255, 255,
            255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 3, 232, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 6, 1, 227, 3, 147, 217, 39, 113, 17, 182, 164,
            198, 126, 180, 51, 123, 215, 81, 65, 205, 222, 78, 101, 98, 199, 9,
            5, 82, 67, 253, 162, 180, 223, 72, 98, 66, 2, 128, 65, 61, 107,
            193, 243, 6, 121, 64, 101, 217, 132, 255, 102, 24, 104, 82, 231,
            85, 38, 41, 202, 139, 32, 111, 38, 234, 127, 68, 163, 60, 140, 2,
            39, 52, 86, 138, 94, 124, 142, 9, 235, 164, 16, 181, 217, 161, 26,
            12, 8, 130, 181, 137, 220, 99, 201, 127, 201, 112, 190, 163, 193,
            106, 156, 37, 2, 190, 147, 103, 247, 7, 229, 100, 68, 242, 62, 188,
            34, 207, 164, 62, 66, 28, 7, 175, 210, 8, 124, 194, 36, 83, 236,
            44, 127, 223, 168, 157, 68, 3, 14, 128, 103, 81, 154, 149, 202,
            159, 71, 124, 151, 73, 105, 239, 176, 47, 156, 129, 14, 188, 71,
            184, 153, 30, 177, 53, 89, 69, 99, 111, 56, 131, 3, 199, 31, 18,
            222, 84, 187, 107, 58, 128, 108, 91, 102, 62, 231, 232, 67, 121,
            29, 89, 1, 3, 82, 96, 15, 23, 248, 232, 249, 141, 149, 229, 70, 1,
            0,
        ];

        let msg = Messages::lightning_deserialize(&msg_recv);
        // println!("{:?}", msg);
        assert_eq!(true, msg.is_ok())
    }

    #[test]
    fn real_clightning_close_message() {
        // Real close_channel message sent by clightning
        let msg_recv = [
            0, 38, 240, 6, 9, 251, 176, 118, 10, 79, 144, 36, 249, 193, 225,
            103, 87, 223, 185, 26, 36, 177, 75, 202, 215, 227, 75, 79, 49, 101,
            79, 167, 93, 206, 0, 22, 0, 20, 42, 238, 172, 27, 222, 161, 61,
            181, 251, 208, 97, 79, 71, 255, 98, 8, 213, 205, 114, 94,
        ];
        let msg = Messages::lightning_deserialize(&msg_recv);
        // println!("{:?}", msg);
        assert_eq!(true, msg.is_ok())
    }
}
