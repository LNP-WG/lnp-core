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

use amplify::DumbDefault;
use bitcoin::blockdata::{opcodes::all::*, script};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};
use lnp2p::legacy::Messages;
use lnpbp::chain::AssetId;
use p2p::legacy::{ActiveChannelId, ChannelId, TempChannelId};
use wallet::lex_order::LexOrder;
use wallet::psbt::Psbt;
use wallet::scripts::{LockScript, PubkeyScript, WitnessScript};
use wallet::IntoPk;

use crate::bolt::channel::{CommonParams, PeerParams, Policy};
use crate::bolt::ExtensionId;
use crate::{channel, ChannelExtension, Extension};

#[derive(Copy, Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
pub struct Keyset {
    pub revocation_basepoint: PublicKey,
    pub payment_basepoint: PublicKey,
    pub delayed_payment_basepoint: PublicKey,
}

impl DumbDefault for Keyset {
    fn dumb_default() -> Self {
        Self {
            revocation_basepoint: dumb_pubkey!(),
            payment_basepoint: dumb_pubkey!(),
            delayed_payment_basepoint: dumb_pubkey!(),
        }
    }
}

/// The core of the lightning channel operating according to the Bolt3 standard.
/// This is "channel constructor" used by `Channel` structure and managing part
/// of the state which is not HTLC-related.
///
/// The type should not be constructed directly or used from outside of the
/// library, but it's made public for allowing channel state access.
#[derive(Getters, Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[getter(as_copy)]
pub struct Bolt3 {
    /// The chain_hash value denotes the exact blockchain that the opened
    /// channel will reside within. This is usually the genesis hash of the
    /// respective blockchain. The existence of the chain_hash allows nodes to
    /// open channels across many distinct blockchains as well as have channels
    /// within multiple blockchains opened to the same peer (if it supports the
    /// target chains).
    chain_hash: AssetId,

    /// Channel id used by the channel; first temporary and later final.
    ///
    /// The temporary_channel_id is used to identify this channel on a per-peer
    /// basis until the funding transaction is established, at which point it
    /// is replaced by the channel_id, which is derived from the funding
    /// transaction.
    active_channel_id: ActiveChannelId,

    /// Amount in millisatoshis
    local_amount: u64,

    /// Amount in millisatoshis
    remote_amount: u64,

    commitment_number: u64,

    obscuring_factor: u64,

    /// The policy for accepting remote node params
    policy: Policy,

    /// Common parapeters applying for both nodes
    common_params: CommonParams,

    /// Channel parameters required to be met by the remote node when operating
    /// towards the local one
    local_params: PeerParams,

    /// Channel parameters to be used towards the remote node
    remote_params: PeerParams,

    /// Set of locally-derived keys for creating channel transactions
    local_keys: Keyset,

    /// Set of remote-derived keys for creating channel transactions
    remote_keys: Keyset,

    /// Keeps information whether this node is the originator of the channel
    is_originator: bool,
}

impl Default for Bolt3 {
    fn default() -> Self {
        let is_originator = true;
        let dumb_keys = Keyset::dumb_default();
        let obscuring_factor = compute_obscuring_factor(
            is_originator,
            dumb_keys.payment_basepoint,
            dumb_keys.payment_basepoint,
        );
        Bolt3 {
            chain_hash: default!(),
            active_channel_id: ActiveChannelId::random(),
            local_amount: 0,
            remote_amount: 0,
            commitment_number: 0,
            obscuring_factor,
            policy: default!(),
            common_params: default!(),
            local_params: default!(),
            remote_params: default!(),
            local_keys: dumb_keys,
            remote_keys: dumb_keys,
            is_originator,
        }
    }
}

impl Bolt3 {
    /// Returns [`ChannelId`], if the channel already assigned it
    #[inline]
    pub fn channel_id(&self) -> Option<ChannelId> {
        self.active_channel_id.channel_id()
    }

    /// Before the channel is assigned a final [`ChannelId`] returns
    /// [`TempChannelId`], and `None` after
    #[inline]
    pub fn temp_channel_id(&self) -> Option<TempChannelId> {
        self.active_channel_id.temp_channel_id()
    }

    /// Sets channel policy
    #[inline]
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy
    }

    /// Sets common parameters for the chanel
    #[inline]
    pub fn set_common_params(&mut self, params: CommonParams) {
        self.common_params = params
    }

    /// Sets local parameters fro the channel
    #[inline]
    pub fn set_local_params(&mut self, params: PeerParams) {
        self.local_params = params
    }
}

impl channel::State for Bolt3 {}

impl Extension for Bolt3 {
    type Identity = ExtensionId;

    #[inline]
    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>> {
        Box::new(Bolt3::default())
    }

    fn identity(&self) -> Self::Identity {
        ExtensionId::Bolt3
    }

    fn update_from_peer(
        &mut self,
        message: &Messages,
    ) -> Result<(), channel::Error> {
        match message {
            Messages::OpenChannel(open_channel) => {
                self.is_originator = false;
                self.active_channel_id =
                    ActiveChannelId::from(open_channel.temporary_channel_id);
                self.local_amount = open_channel.funding_satoshis * 1000;
                self.remote_amount = open_channel.push_msat;

                // Policies
                self.remote_params =
                    self.policy.validate_inbound(open_channel)?;

                // Keys
                self.remote_keys.payment_basepoint = open_channel.payment_point;
                self.remote_keys.revocation_basepoint =
                    open_channel.revocation_basepoint;
                self.remote_keys.delayed_payment_basepoint =
                    open_channel.delayed_payment_basepoint;
            }
            Messages::AcceptChannel(accept_channel) => {
                self.remote_params = self
                    .policy
                    .confirm_outbound(self.local_params, accept_channel)?;

                // Keys
                self.remote_keys.payment_basepoint =
                    accept_channel.payment_point;
                self.remote_keys.revocation_basepoint =
                    accept_channel.revocation_basepoint;
                self.remote_keys.delayed_payment_basepoint =
                    accept_channel.delayed_payment_basepoint;
            }
            Messages::FundingCreated(funding_created) => {
                self.active_channel_id = ActiveChannelId::with(
                    funding_created.funding_txid,
                    funding_created.funding_output_index,
                );
            }
            Messages::FundingSigned(funding_signed) => {
                self.active_channel_id =
                    ActiveChannelId::from(funding_signed.channel_id);
            }
            Messages::FundingLocked(_) => {}
            Messages::Shutdown(_) => {}
            Messages::ClosingSigned(_) => {}
            Messages::UpdateAddHtlc(_message) => {
                /* TODO
                if message.amount_msat + total_htlc_value_in_flight_msat
                    > self.max_htlc_value_in_flight_msat
                {
                    return Err(channel::Error::Htlc(
                        "max HTLC inflight amount limit exceeded".to_string(),
                    ));
                }
                 */
            }
            Messages::UpdateFulfillHtlc(_) => {}
            Messages::UpdateFailHtlc(_) => {}
            Messages::UpdateFailMalformedHtlc(_) => {}
            Messages::CommitmentSigned(_) => {}
            Messages::RevokeAndAck(_) => {}
            Messages::ChannelReestablish(_) => {}
            _ => {}
        }
        Ok(())
    }

    fn extension_state(&self) -> Box<dyn channel::State> {
        Box::new(self.clone())
    }
}

impl ChannelExtension for Bolt3 {
    fn channel_state(&self) -> Box<dyn channel::State> {
        Box::new(self.clone())
    }

    fn apply(
        &mut self,
        tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error> {
        // The 48-bit commitment number is obscured by XOR with the lower
        // 48 bits of `obscuring_factor`
        let obscured_commitment = (self.commitment_number & 0xFFFFFF)
            ^ (self.obscuring_factor & 0xFFFFFF);
        let obscured_commitment = obscured_commitment as u32;
        let lock_time = (0x20u32 << 24) | obscured_commitment;
        let sequence = (0x80u32 << 24) | obscured_commitment;

        tx_graph.cmt_version = 2;
        tx_graph.cmt_locktime = lock_time;
        tx_graph.cmt_sequence = sequence;
        // We are doing counterparty's transaction!
        tx_graph.cmt_outs = vec![
            TxOut::ln_to_local(
                self.remote_amount,
                self.local_keys.revocation_basepoint,
                self.remote_keys.delayed_payment_basepoint,
                self.remote_params.to_self_delay,
            ),
            TxOut::ln_to_remote_v1(
                self.local_amount,
                self.local_keys.payment_basepoint,
            ),
        ];

        Ok(())
    }
}

pub trait ScriptGenerators {
    fn ln_funding(amount: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self;

    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;

    fn ln_to_remote_v1(amount: u64, remote_pubkey: PublicKey) -> Self;

    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self;
}

impl ScriptGenerators for LockScript {
    fn ln_funding(_: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self {
        let pk = vec![pubkey1.into_pk(), pubkey2.into_pk()].lex_ordered();

        script::Builder::new()
            .push_int(2)
            .push_key(&pk[0])
            .push_key(&pk[1])
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
            .into()
    }

    fn ln_to_local(
        _: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_IF)
            .push_key(&revocationpubkey.into_pk())
            .push_opcode(OP_ELSE)
            .push_int(to_self_delay as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&local_delayedpubkey.into_pk())
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script()
            .into()
    }

    fn ln_to_remote_v1(_: u64, _: PublicKey) -> Self {
        unimplemented!("LockScript can't be generated for to_remote v1 output")
    }

    fn ln_to_remote_v2(_: u64, remote_pubkey: PublicKey) -> Self {
        script::Builder::new()
            .push_key(&remote_pubkey.into_pk())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_int(1)
            .push_opcode(OP_CSV)
            .into_script()
            .into()
    }
}

impl ScriptGenerators for WitnessScript {
    #[inline]
    fn ln_funding(amount: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self {
        LockScript::ln_funding(amount, pubkey1, pubkey2).into()
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        LockScript::ln_to_local(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into()
    }

    #[inline]
    fn ln_to_remote_v1(_: u64, _: PublicKey) -> Self {
        unimplemented!(
            "WitnessScript can't be generated for to_remote v1 output"
        )
    }

    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self {
        LockScript::ln_to_remote_v2(amount, remote_pubkey).into()
    }
}

impl ScriptGenerators for PubkeyScript {
    #[inline]
    fn ln_funding(amount: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self {
        WitnessScript::ln_funding(amount, pubkey1, pubkey2).to_p2wsh()
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        WitnessScript::ln_to_local(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_to_remote_v1(_: u64, remote_pubkey: PublicKey) -> Self {
        remote_pubkey
            .into_pk()
            .wpubkey_hash()
            .expect("We just generated non-compressed key")
            .into()
    }

    #[inline]
    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self {
        WitnessScript::ln_to_remote_v2(amount, remote_pubkey).to_p2wsh()
    }
}

impl ScriptGenerators for TxOut {
    #[inline]
    fn ln_funding(amount: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_funding(amount, pubkey1, pubkey2)
                .into(),
        }
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_local(
                amount,
                revocationpubkey,
                local_delayedpubkey,
                to_self_delay,
            )
            .into(),
        }
    }

    #[inline]
    fn ln_to_remote_v1(amount: u64, remote_pubkey: PublicKey) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_remote_v1(amount, remote_pubkey)
                .into(),
        }
    }

    #[inline]
    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_remote_v2(amount, remote_pubkey)
                .into(),
        }
    }
}

fn compute_obscuring_factor(
    is_originator: bool,
    local_payment_basepoint: PublicKey,
    remote_payment_basepoint: PublicKey,
) -> u64 {
    use bitcoin::hashes::{sha256, Hash, HashEngine};

    let mut engine = sha256::Hash::engine();
    if is_originator {
        engine.input(&local_payment_basepoint.serialize());
        engine.input(&remote_payment_basepoint.serialize());
    } else {
        engine.input(&remote_payment_basepoint.serialize());
        engine.input(&local_payment_basepoint.serialize());
    }
    let obscuring_hash = sha256::Hash::from_engine(engine);

    let mut buf = [0u8; 8];
    buf.copy_from_slice(&obscuring_hash[24..]);
    u64::from_be_bytes(buf)
}

// TODO: Remove TxGenerators since they are not needed
pub trait TxGenerators {
    fn ln_cmt_base(
        local_amount: u64,
        remote_amount: u64,
        commitment_number: u64,
        obscuring_factor: u64,
        funding_outpoint: OutPoint,
        remote_pubkey: PublicKey,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;

    fn ln_closing(outpoint: OutPoint, txout: Vec<TxOut>) -> Self;
}

impl TxGenerators for Transaction {
    fn ln_cmt_base(
        local_amount: u64,
        remote_amount: u64,
        commitment_number: u64,
        obscuring_factor: u64,
        funding_outpoint: OutPoint,
        remote_pubkey: PublicKey,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        // The 48-bit commitment number is obscured by XOR with the lower
        // 48 bits of `obscuring_factor`
        let obscured_commitment =
            (commitment_number & 0xFFFFFF) ^ (obscuring_factor & 0xFFFFFF);
        let obscured_commitment = obscured_commitment as u32;
        let lock_time = (0x20u32 << 24) | obscured_commitment;
        let sequence = (0x80u32 << 24) | obscured_commitment;
        let tx = Transaction {
            version: 2,
            lock_time,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: none!(),
                sequence,
                witness: empty!(),
            }],
            output: vec![
                TxOut::ln_to_local(
                    local_amount,
                    revocationpubkey,
                    local_delayedpubkey,
                    to_self_delay,
                ),
                TxOut::ln_to_remote_v1(remote_amount, remote_pubkey),
            ],
        };
        tx.lex_ordered()
    }

    fn ln_closing(outpoint: OutPoint, txout: Vec<TxOut>) -> Self {
        Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: none!(),
                sequence: core::u32::MAX,
                witness: empty!(),
            }],
            output: txout,
        }
    }
}

impl TxGenerators for Psbt {
    fn ln_cmt_base(
        local_amount: u64,
        remote_amount: u64,
        commitment_number: u64,
        obscuring_factor: u64,
        funding_outpoint: OutPoint,
        remote_pubkey: PublicKey,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        Psbt::from_unsigned_tx(Transaction::ln_cmt_base(
            local_amount,
            remote_amount,
            commitment_number,
            obscuring_factor,
            funding_outpoint,
            remote_pubkey,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        ))
        .expect("Tx has empty sigs so PSBT creation does not faile")
    }

    fn ln_closing(outpoint: OutPoint, txout: Vec<TxOut>) -> Self {
        Psbt::from_unsigned_tx(Transaction::ln_closing(outpoint, txout))
            .expect("Tx has empty sigs so PSBT creation does not faile")
    }
}
