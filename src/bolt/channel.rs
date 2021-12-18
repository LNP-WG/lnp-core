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

use amplify::{DumbDefault, Slice32, Wrapper};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, OutPoint, TxOut, Txid};
use lnp2p::legacy::{
    AcceptChannel, ActiveChannelId, ChannelId, Messages, OpenChannel,
    TempChannelId,
};
use lnpbp::chain::Chain;
use secp256k1::{Secp256k1, Signature};
use wallet::lex_order::LexOrder;
use wallet::scripts::{LockScript, PubkeyScript, WitnessScript};
use wallet::{psbt, IntoPk};

use super::extensions::AnchorOutputs;
use super::policy::{CommonParams, PeerParams, Policy};
use super::{ExtensionId, Lifecycle, RemoteKeyset};
use crate::bolt::keyset::{LocalKeyset, LocalPubkey};
use crate::{channel, Channel, ChannelExtension, Extension};

/// Channel direction
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
pub enum Direction {
    /// Inbound channels accepted by the local node.
    ///
    /// Launched in response to received `accept_channel` messages
    #[display("inbound")]
    Inbound,

    /// Outbound channels proposed to a remote node.
    ///
    /// Created by sending `open_channel` message
    #[display("outbound")]
    Outbount,
}

impl Direction {
    /// Detects if the channel is inbound
    #[inline]
    pub fn is_inbound(self) -> bool {
        self == Direction::Inbound
    }

    /// Detects if the channel is outbound
    #[inline]
    pub fn is_outbound(self) -> bool {
        self == Direction::Outbount
    }
}

impl Channel<ExtensionId> {
    /// Constructs the new channel which will check the negotiation
    /// process against the provided policy and will use given parameters
    /// for constructing `open_channel` (for outbound channels) and
    /// `accept_channel` (for inbound channels) request sent to the remote node.
    pub fn with(
        temp_channel_id: TempChannelId,
        chain_hash: Slice32,
        policy: Policy,
        common_params: CommonParams,
        local_params: PeerParams,
        mut local_keys: LocalKeyset,
    ) -> Self {
        let mut channel = Self::default();

        let channel_type = common_params.channel_type;
        if channel_type.has_static_remotekey() {
            local_keys.static_remotekey = true;
        }
        if channel_type.has_anchor_outputs() {
            channel.add_extender(AnchorOutputs::new());
        }

        let core = channel.constructor_mut();
        core.set_temp_channel_id(temp_channel_id);
        core.set_chain_hash(chain_hash);
        core.set_policy(policy);
        core.set_common_params(common_params);
        core.set_local_params(local_params);
        core.set_local_keys(local_keys);

        channel
    }

    /// Sets channel policy.
    ///
    /// Can be used for changing the policy on the fly to enable accepting new
    /// `open_channel` - or follow-up `accept_channel` requests.
    #[inline]
    pub fn set_policy(&mut self, policy: Policy) {
        self.constructor_mut().set_policy(policy)
    }

    /// Sets common parameters for the chanel.
    ///
    /// Can be used for changing prospective channel parameters on the fly to
    /// enable accepting new `open_channel` - or follow-up `accept_channel`
    /// requests.
    #[inline]
    pub fn set_common_params(&mut self, params: CommonParams) {
        self.constructor_mut().set_common_params(params)
    }

    /// Sets local parameters for the channel.
    ///
    /// Can be used for changing prospective channel parameters on the fly to
    /// enable accepting new `open_channel` - or follow-up `accept_channel`
    /// requests.
    #[inline]
    pub fn set_local_params(&mut self, params: PeerParams) {
        self.constructor_mut().set_local_params(params)
    }

    /// Returns active channel id, covering both temporary and final channel ids
    #[inline]
    pub fn active_channel_id(&self) -> ActiveChannelId {
        self.constructor().active_channel_id()
    }

    /// Returns [`ChannelId`], if the channel already assigned it
    #[inline]
    pub fn channel_id(&self) -> Option<ChannelId> {
        self.active_channel_id().channel_id()
    }

    /// Before the channel is assigned a final [`ChannelId`] returns
    /// [`TempChannelId`], and `None` after
    #[inline]
    pub fn temp_channel_id(&self) -> Option<TempChannelId> {
        self.active_channel_id().temp_channel_id()
    }

    /// Composes `open_channel` message used for proposing channel opening to a
    /// remote peer. The message is composed basing on the local channel
    /// parameters set with [`Channel::with`] or [`Channel::set_local_params`]
    /// (see [`Bolt3::local_params`] for details on local parameters).
    ///
    /// Fails if the node is not in [`Lifecycle::Initial`] or
    /// [`Lifecycle::Reestablishing`] state.
    pub fn compose_open_channel(
        &mut self,
        funding_sat: u64,
        push_msat: u64,
        policy: Policy,
        common_params: CommonParams,
        local_params: PeerParams,
        local_keys: LocalKeyset,
    ) -> Result<OpenChannel, channel::Error> {
        self.constructor_mut().compose_open_channel(
            funding_sat,
            push_msat,
            policy,
            common_params,
            local_params,
            local_keys,
        )
    }

    /// Composes `accept_channel` message used for accepting channel opening
    /// from a remote peer. The message is composed basing on the local
    /// channel parameters set with [`Channel::with`] or
    /// [`Channel::set_local_params`] (see [`Bolt3::local_params`] for
    /// details on local parameters).
    ///
    /// Fails if the node is not in [`Lifecycle::Initial`] or
    /// [`Lifecycle::Reestablishing`] state.
    pub fn compose_accept_channel(
        &mut self,
    ) -> Result<AcceptChannel, channel::Error> {
        self.constructor_mut().compose_accept_channel()
    }

    /// Tries to identify bitcoin network which channel is based on. Returns
    /// `None` if the channel is using non-bitcoin chain.
    #[inline]
    pub fn network(&self) -> Option<Network> {
        let chain_hash = self.constructor().chain_hash();
        for chain in Chain::all_standard() {
            if chain.as_genesis_hash().as_inner() == chain_hash.as_inner() {
                return Network::try_from(chain).ok();
            }
        }
        None
    }

    #[inline]
    pub fn funding_output(&self) -> (TxOut, psbt::Output) {
        let funding = self.funding();
        let core = self.constructor();
        ScriptGenerators::ln_funding(
            funding.amount(),
            &core.local_keys().funding_pubkey,
            core.remote_keys().funding_pubkey,
        )
    }

    #[inline]
    pub fn feerate_per_kw(&self) -> u32 {
        let core = self.constructor();
        core.common_params().feerate_per_kw
    }

    #[inline]
    pub fn local_amount(&self) -> u64 {
        self.constructor().local_amount()
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
// TODO: Make it crate-private
pub struct Core {
    /// Current channel lifecycle stage
    #[getter(as_copy)]
    stage: Lifecycle,

    // TOO: Consider storing information about used chain at generic channel
    // level
    /// The chain_hash value denotes the exact blockchain that the opened
    /// channel will reside within. This is usually the genesis hash of the
    /// respective blockchain. The existence of the chain_hash allows nodes to
    /// open channels across many distinct blockchains as well as have channels
    /// within multiple blockchains opened to the same peer (if it supports the
    /// target chains).
    #[getter(as_copy)]
    chain_hash: Slice32,

    /// Channel id used by the channel; first temporary and later final.
    ///
    /// The temporary_channel_id is used to identify this channel on a per-peer
    /// basis until the funding transaction is established, at which point it
    /// is replaced by the channel_id, which is derived from the funding
    /// transaction.
    #[getter(as_copy)]
    active_channel_id: ActiveChannelId,

    /// Funding transaction outpoint spent by commitment transactions input
    #[getter(as_copy)]
    funding_outpoint: OutPoint,

    /// Amount in millisatoshis
    #[getter(as_copy)]
    local_amount: u64,

    /// Amount in millisatoshis
    #[getter(as_copy)]
    remote_amount: u64,

    #[getter(as_copy)]
    commitment_number: u64,

    #[getter(as_copy)]
    obscuring_factor: u64,

    commitment_sigs: Vec<Signature>,

    /// The policy for accepting remote node params
    #[getter(as_ref)]
    policy: Policy,

    /// Common parameters applying for both nodes
    #[getter(as_copy)]
    common_params: CommonParams,

    /// Channel parameters required to be met by the remote node when operating
    /// towards the local one
    #[getter(as_copy)]
    local_params: PeerParams,

    /// Channel parameters to be used towards the remote node
    #[getter(as_copy)]
    remote_params: PeerParams,

    /// Set of locally-derived keys for creating channel transactions
    local_keys: LocalKeyset,

    /// Set of remote-derived keys for creating channel transactions
    remote_keys: RemoteKeyset,

    remote_per_commitment_point: PublicKey,

    local_per_commitment_point: PublicKey,

    /// Keeps information about node directionality
    #[getter(as_copy)]
    direction: Direction,
}

impl Default for Core {
    fn default() -> Self {
        let direction = Direction::Outbount;
        let dumb_keys = RemoteKeyset::dumb_default();
        let obscuring_factor = compute_obscuring_factor(
            direction,
            dumb_keys.payment_basepoint,
            dumb_keys.payment_basepoint,
        );
        Core {
            stage: Lifecycle::Initial,
            chain_hash: default!(),
            active_channel_id: ActiveChannelId::random(),
            funding_outpoint: OutPoint::default(),
            local_amount: 0,
            remote_amount: 0,
            commitment_number: 0,
            obscuring_factor,
            commitment_sigs: vec![],
            policy: default!(),
            common_params: default!(),
            local_params: default!(),
            remote_params: default!(),
            local_keys: LocalKeyset::dumb_default(),
            remote_keys: dumb_keys,
            remote_per_commitment_point: dumb_pubkey!(),
            local_per_commitment_point: dumb_pubkey!(),
            direction,
        }
    }
}

impl Core {
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

    /// Assigns channel a temporary id
    #[inline]
    pub fn set_temp_channel_id(&mut self, temp_channel_id: TempChannelId) {
        self.active_channel_id = ActiveChannelId::Temporary(temp_channel_id)
    }

    /// Marks the channel as an inbound
    #[inline]
    pub fn set_inbound(&mut self) {
        self.direction = Direction::Inbound;
    }

    /// Marks the channel as an outbound
    #[inline]
    pub fn set_outbound(&mut self) {
        self.direction = Direction::Outbount;
    }

    /// Sets the channel chain hash
    #[inline]
    pub fn set_chain_hash(&mut self, chain_hash: Slice32) {
        self.chain_hash = chain_hash
    }

    /// Sets channel funding outpoint
    #[inline]
    pub fn set_funding(&mut self, funding_txid: Txid, funding_output: u16) {
        self.funding_outpoint =
            OutPoint::new(funding_txid, funding_output as u32)
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

    /// Sets local parameters for the channel
    #[inline]
    pub fn set_local_params(&mut self, params: PeerParams) {
        self.local_params = params
    }

    /// Sets local keys for the channel
    #[inline]
    pub fn set_local_keys(&mut self, keys: LocalKeyset) {
        self.local_keys = keys
    }

    /// Sets `static_remotekey` flag for the channel
    #[inline]
    pub fn set_static_remotekey(&mut self, static_remotekey: bool) {
        self.local_keys.static_remotekey = static_remotekey
    }
}

impl channel::State for Core {}

impl Extension for Core {
    type Identity = ExtensionId;

    #[inline]
    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>> {
        Box::new(Core::default())
    }

    fn identity(&self) -> Self::Identity {
        ExtensionId::Bolt3
    }

    fn update_from_peer(
        &mut self,
        message: &Messages,
    ) -> Result<(), channel::Error> {
        // TODO: Check lifecycle
        match message {
            Messages::OpenChannel(open_channel) => {
                self.stage = Lifecycle::Proposed;

                self.direction = Direction::Inbound;
                self.active_channel_id =
                    ActiveChannelId::from(open_channel.temporary_channel_id);
                self.local_amount = open_channel.funding_satoshis * 1000;
                self.remote_amount = open_channel.push_msat;

                // Policies
                self.remote_params =
                    self.policy.validate_inbound(open_channel)?;

                // TODO: Add channel checks and fail on:
                // 1) the `chain_hash` value is set to a hash of a chain that is
                //    unknown to the receiver;
                // 2) `push_msat` is greater than `funding_satoshis` * 1000;
                // 3) the funder's amount for the initial commitment transaction
                //    is not sufficient for full fee payment;
                // 4) both `to_local` and `to_remote` amounts for the initial
                //    commitment transaction are less than or equal to
                //    `channel_reserve_satoshis`;
                // 5) funding_satoshis is greater than or equal to 2^24 and the
                //    receiver does not support `option_support_large_channel`.

                // Keys
                self.remote_keys.funding_pubkey = open_channel.funding_pubkey;
                self.remote_keys.payment_basepoint = open_channel.payment_point;
                self.remote_keys.revocation_basepoint =
                    open_channel.revocation_basepoint;
                self.remote_keys.delayed_payment_basepoint =
                    open_channel.delayed_payment_basepoint;
                self.remote_keys.first_per_commitment_point =
                    open_channel.first_per_commitment_point;
                self.remote_per_commitment_point =
                    open_channel.first_per_commitment_point;
            }
            Messages::AcceptChannel(accept_channel) => {
                self.stage = Lifecycle::Accepted;

                self.remote_params = self
                    .policy
                    .confirm_outbound(self.local_params, accept_channel)?;

                // TODO: Add channel type and other checks
                // 1) the `temporary_channel_id` MUST be the same as the
                //    `temporary_channel_id` in the `open_channel`
                //    message;
                // 2) if `channel_type` is set, and `channel_type` was set in
                //    `open_channel`, and they are equal types;
                // 3) if the `channel_type` is not set it must had not been set
                //    in the `open_channel`.

                // Keys
                self.remote_keys.funding_pubkey = accept_channel.funding_pubkey;
                self.remote_keys.payment_basepoint =
                    accept_channel.payment_point;
                self.remote_keys.revocation_basepoint =
                    accept_channel.revocation_basepoint;
                self.remote_keys.delayed_payment_basepoint =
                    accept_channel.delayed_payment_basepoint;
                self.remote_keys.first_per_commitment_point =
                    accept_channel.first_per_commitment_point;
                self.remote_per_commitment_point =
                    accept_channel.first_per_commitment_point;
            }
            Messages::FundingCreated(funding_created) => {
                self.stage = Lifecycle::Funding;

                self.active_channel_id = ActiveChannelId::with(
                    funding_created.funding_txid,
                    funding_created.funding_output_index,
                );
            }
            Messages::FundingSigned(funding_signed) => {
                self.stage = Lifecycle::Funded;

                self.active_channel_id =
                    ActiveChannelId::from(funding_signed.channel_id);
                self.commitment_sigs.push(funding_signed.signature);
                // TODO: Verify signature agains transaction
            }
            Messages::FundingLocked(_) => {
                self.stage = Lifecycle::Locked; // TODO: or Active
            }
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

impl Core {
    fn compose_open_channel(
        &mut self,
        funding_sat: u64,
        push_msat: u64,
        policy: Policy,
        common_params: CommonParams,
        local_params: PeerParams,
        local_keyset: LocalKeyset,
    ) -> Result<OpenChannel, channel::Error> {
        if self.stage != Lifecycle::Initial
            && self.stage != Lifecycle::Reestablishing
        {
            return Err(channel::Error::LifecycleMismatch {
                current: self.stage,
                required: &[Lifecycle::Initial, Lifecycle::Reestablishing],
            });
        }

        self.direction = Direction::Outbount;
        self.policy = policy;
        self.common_params = common_params;
        self.local_params = local_params;
        self.local_keys = local_keyset.clone();

        Ok(OpenChannel {
            chain_hash: self.chain_hash(),
            temporary_channel_id: self.temp_channel_id().expect(
                "initial channel state must always have a temporary channel id",
            ),
            funding_satoshis: funding_sat,
            push_msat,
            dust_limit_satoshis: local_params.dust_limit_satoshis,
            max_htlc_value_in_flight_msat: local_params
                .max_htlc_value_in_flight_msat,
            channel_reserve_satoshis: local_params.channel_reserve_satoshis,
            htlc_minimum_msat: local_params.htlc_minimum_msat,
            feerate_per_kw: common_params.feerate_per_kw,
            to_self_delay: local_params.to_self_delay,
            max_accepted_htlcs: local_params.max_accepted_htlcs,
            funding_pubkey: local_keyset.funding_pubkey.key,
            revocation_basepoint: local_keyset.revocation_basepoint.key,
            payment_point: local_keyset.payment_basepoint.key,
            delayed_payment_basepoint: local_keyset
                .delayed_payment_basepoint
                .key,
            htlc_basepoint: local_keyset.htlc_basepoint.key,
            first_per_commitment_point: local_keyset
                .first_per_commitment_point
                .key,
            shutdown_scriptpubkey: local_keyset.shutdown_scriptpubkey.clone(),
            channel_flags: if common_params.announce_channel { 1 } else { 0 },
            channel_type: common_params.channel_type.into_option(),
            unknown_tlvs: none!(),
        })
    }

    fn compose_accept_channel(
        &mut self,
    ) -> Result<AcceptChannel, channel::Error> {
        if self.stage != Lifecycle::Initial
            && self.stage != Lifecycle::Reestablishing
        {
            return Err(channel::Error::LifecycleMismatch {
                current: self.stage,
                required: &[Lifecycle::Initial, Lifecycle::Reestablishing],
            });
        }

        Ok(AcceptChannel {
            temporary_channel_id: self.temp_channel_id().expect(
                "initial channel state must always have a temporary channel id",
            ),
            dust_limit_satoshis: self.local_params.dust_limit_satoshis,
            max_htlc_value_in_flight_msat: self
                .local_params
                .max_htlc_value_in_flight_msat,
            channel_reserve_satoshis: self
                .local_params
                .channel_reserve_satoshis,
            htlc_minimum_msat: self.local_params.htlc_minimum_msat,
            minimum_depth: self.policy.minimum_depth,
            to_self_delay: self.local_params.to_self_delay,
            max_accepted_htlcs: self.local_params.max_accepted_htlcs,
            funding_pubkey: self.local_keys.funding_pubkey.key,
            revocation_basepoint: self.local_keys.revocation_basepoint.key,
            payment_point: self.local_keys.payment_basepoint.key,
            delayed_payment_basepoint: self
                .local_keys
                .delayed_payment_basepoint
                .key,
            htlc_basepoint: self.local_keys.htlc_basepoint.key,
            first_per_commitment_point: self
                .local_keys
                .first_per_commitment_point
                .key,
            shutdown_scriptpubkey: self
                .local_keys
                .shutdown_scriptpubkey
                .clone(),
            channel_type: self.common_params.channel_type.into_option(),
            unknown_tlvs: none!(),
        })
    }

    fn revocationpubkey(&self) -> PublicKey {
        // TODO: Optimize and keep Secp256k1 on a permanent basis
        let secp = Secp256k1::verification_only();

        let mut tweaked_revocation_basepoint =
            self.remote_keys.revocation_basepoint;
        let mut engine = sha256::Hash::engine();
        engine.input(&self.remote_keys.revocation_basepoint.serialize());
        engine.input(&self.remote_per_commitment_point.serialize());
        let revocation_tweak = sha256::Hash::from_engine(engine);
        tweaked_revocation_basepoint
            .mul_assign(&secp, revocation_tweak.as_ref())
            .expect("negligible probability");

        let mut tweaked_per_commitment_point = self.remote_per_commitment_point;
        let mut engine = sha256::Hash::engine();
        engine.input(&self.remote_per_commitment_point.serialize());
        engine.input(&self.remote_keys.revocation_basepoint.serialize());
        let per_commitment_tweak = sha256::Hash::from_engine(engine);
        tweaked_per_commitment_point
            .mul_assign(&secp, per_commitment_tweak.as_ref())
            .expect("negligible probability");

        tweaked_revocation_basepoint
            .combine(&tweaked_per_commitment_point)
            .expect("negligible probability")
    }
}

impl ChannelExtension for Core {
    fn channel_state(&self) -> Box<dyn channel::State> {
        Box::new(self.clone())
    }

    fn apply(
        &self,
        tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error> {
        // The 48-bit commitment number is obscured by XOR with the lower
        // 48 bits of `obscuring_factor`
        let obscured_commitment = (self.commitment_number & 0xFFFFFF)
            ^ (self.obscuring_factor & 0xFFFFFF);
        let obscured_commitment = obscured_commitment as u32;
        let lock_time = (0x20u32 << 24) | obscured_commitment;
        let sequence = (0x80u32 << 24) | obscured_commitment;

        let revocationpubkey = self.revocationpubkey();

        tx_graph.cmt_version = 2;
        tx_graph.cmt_locktime = lock_time;
        tx_graph.cmt_sequence = sequence;
        // We are doing counterparty's transaction!
        tx_graph.cmt_outs = vec![
            ScriptGenerators::ln_to_local(
                self.remote_amount,
                // TODO: Generate proper revocation
                revocationpubkey,
                self.remote_keys.delayed_payment_basepoint,
                self.remote_params.to_self_delay,
            ),
            ScriptGenerators::ln_to_remote_v1(
                self.local_amount,
                self.local_keys.payment_basepoint.key,
            ),
        ];

        Ok(())
    }
}

pub trait ScriptGenerators {
    fn ln_funding(
        amount: u64,
        local_pubkey: &LocalPubkey,
        remote_pubkey: PublicKey,
    ) -> Self;

    /// NB: We use argument named `local_delayedpubkey`, but in fact the source
    /// for this key is the remote node key, since we generate a transaction
    /// which we will sign for the remote node.
    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;

    /// NB: We use argument named `remote_pubkey`, but in fact the source
    /// for this key is the local node key, since we generate a transaction
    /// which we will sign for the remote node.
    fn ln_to_remote_v1(amount: u64, remote_pubkey: PublicKey) -> Self;

    /// NB: We use argument named `remote_pubkey`, but in fact the source
    /// for this key is the local node key, since we generate a transaction
    /// which we will sign for the remote node.
    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self;
}

impl ScriptGenerators for LockScript {
    fn ln_funding(
        _: u64,
        local_pubkey: &LocalPubkey,
        remote_pubkey: PublicKey,
    ) -> Self {
        let pk = vec![local_pubkey.key.into_pk(), remote_pubkey.into_pk()]
            .lex_ordered();

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
    fn ln_funding(
        amount: u64,
        local_pubkey: &LocalPubkey,
        remote_pubkey: PublicKey,
    ) -> Self {
        LockScript::ln_funding(amount, local_pubkey, remote_pubkey).into()
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
    fn ln_funding(
        amount: u64,
        local_pubkey: &LocalPubkey,
        remote_pubkey: PublicKey,
    ) -> Self {
        WitnessScript::ln_funding(amount, local_pubkey, remote_pubkey)
            .to_p2wsh()
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

impl ScriptGenerators for (TxOut, psbt::Output) {
    #[inline]
    fn ln_funding(
        amount: u64,
        local_pubkey: &LocalPubkey,
        remote_pubkey: PublicKey,
    ) -> Self {
        let witness_script =
            WitnessScript::ln_funding(amount, local_pubkey, remote_pubkey)
                .into();
        let script_pubkey =
            PubkeyScript::ln_funding(amount, local_pubkey, remote_pubkey)
                .into();
        let txout = TxOut {
            value: amount,
            script_pubkey,
        };
        let output = psbt::Output {
            witness_script: Some(witness_script),
            bip32_derivation: bmap! {
                bitcoin::PublicKey::new(local_pubkey.key) => local_pubkey.source.clone()
            },
            ..Default::default()
        };
        (txout, output)
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        let witness_script = WitnessScript::ln_to_local(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into();
        let script_pubkey = PubkeyScript::ln_to_local(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into();
        let txout = TxOut {
            value: amount,
            script_pubkey,
        };
        let output = psbt::Output {
            witness_script: Some(witness_script),
            ..Default::default()
        };
        (txout, output)
    }

    #[inline]
    fn ln_to_remote_v1(amount: u64, remote_pubkey: PublicKey) -> Self {
        let txout = TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_remote_v1(amount, remote_pubkey)
                .into(),
        };
        (txout, psbt::Output::default())
    }

    #[inline]
    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self {
        let witness_script =
            WitnessScript::ln_to_remote_v2(amount, remote_pubkey).into();
        let script_pubkey =
            PubkeyScript::ln_to_remote_v2(amount, remote_pubkey).into();
        let txout = TxOut {
            value: amount,
            script_pubkey,
        };
        let output = psbt::Output {
            witness_script: Some(witness_script),
            ..Default::default()
        };
        (txout, output)
    }
}

fn compute_obscuring_factor(
    direction: Direction,
    local_payment_basepoint: PublicKey,
    remote_payment_basepoint: PublicKey,
) -> u64 {
    let mut engine = sha256::Hash::engine();
    if direction.is_inbound() {
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
