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

use amplify::DumbDefault;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{PublicKey, Signature};
use bitcoin::Txid;
use internet2::tlv;
use lnpbp::chain::AssetId;
use wallet::hlc::{HashLock, HashPreimage};
use wallet::scripts::PubkeyScript;

use super::{ChannelId, OnionPacket, TempChannelId};

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
#[lightning_encoding(use_tlv)]
#[display("open_channel({chain_hash}, {temporary_channel_id}, {funding_satoshis}, {channel_flags}, ...)")]
pub struct OpenChannel {
    /// The genesis hash of the blockchain where the channel is to be opened
    pub chain_hash: AssetId,

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

    /// Channel flags
    pub channel_flags: u8,

    /// Optionally, a request to pre-set the to-sender output's scriptPubkey
    /// for when we collaboratively close
    #[lightning_encoding(tlv = 1)]
    #[network_encoding(tlv = 1)]
    pub shutdown_scriptpubkey: Option<PubkeyScript>,

    /// The rest of TLVs with unknown odd type ids
    #[lightning_encoding(unknown_tlvs)]
    #[network_encoding(unknown_tlvs)]
    pub unknown_tlvs: tlv::Stream,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
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
    #[network_encoding(tlv = 0)]
    pub shutdown_scriptpubkey: Option<PubkeyScript>,

    #[lightning_encoding(unknown_tlvs)]
    #[network_encoding(unknown_tlvs)]
    pub unknown_tlvs: tlv::Stream,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("funding_created({temporary_channel_id}, {funding_txid}:{funding_output_index}, ...signature)")]
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

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("funding_signed({channel_id}, ...signature)")]
pub struct FundingSigned {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The signature of the channel acceptor on the funding transaction
    pub signature: Signature,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("funding_locked({channel_id}, {next_per_commitment_point})")]
pub struct FundingLocked {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The per-commitment point of the second commitment transaction
    pub next_per_commitment_point: PublicKey,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("shutdown({channel_id}, {scriptpubkey})")]
pub struct Shutdown {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The destination of this peer's funds on closing.
    /// Must be in one of these forms: p2pkh, p2sh, p2wpkh, p2wsh.
    pub scriptpubkey: PubkeyScript,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
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

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
#[lightning_encoding(use_tlv)]
#[display("update_add_htlc({channel_id}, {htlc_id}, {amount_msat}, {payment_hash}, ...)")]
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
    pub onion_routing_packet: OnionPacket,

    /// RGB Extension: TLV
    #[lightning_encoding(tlv = 1)]
    #[network_encoding(tlv = 1)]
    pub asset_id: Option<AssetId>,

    /// The rest of TLVs with unknown odd type ids
    #[lightning_encoding(unknown_tlvs)]
    #[network_encoding(unknown_tlvs)]
    pub unknown_tlvs: tlv::Stream,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
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

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
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

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
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

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
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

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("revoke_and_ack({channel_id}, {next_per_commitment_point}, ...per_commitment_secret)")]
pub struct RevokeAndAck {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The secret corresponding to the per-commitment point
    pub per_commitment_secret: [u8; 32],

    /// The next sender-broadcast commitment transaction's per-commitment point
    pub next_per_commitment_point: PublicKey,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("update_fee({channel_id}, {feerate_per_kw})")]
pub struct UpdateFee {
    /// The channel ID
    pub channel_id: ChannelId,

    /// Fee rate per 1000-weight of the transaction
    pub feerate_per_kw: u32,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
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
    /// commitment transaction belonging to the recipient
    pub your_last_per_commitment_secret: [u8; 32],

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
            unknown_tlvs: none!(),
        }
    }
}
