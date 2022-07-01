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
use bitcoin::{Network, TxOut};
use internet2::addr::NodeId;
use internet2::presentation::sphinx::{self, Hop, Onion, OnionPacket};
use lnp2p::bolt::{
    AcceptChannel, ActiveChannelId, ChannelId, Messages, OpenChannel,
    TempChannelId,
};
use lnpbp::chain::Chain;
use p2p::bolt::{
    ChannelReestablish, FundingLocked, PaymentOnion, UpdateAddHtlc,
};
use secp256k1::ecdsa::Signature;
use secp256k1::Secp256k1;
use strict_encoding::StrictDecode;
use wallet::hlc::HashLock;
use wallet::lex_order::LexOrder;
use wallet::psbt;
use wallet::psbt::Psbt;
use wallet::scripts::{LockScript, PubkeyScript, WitnessScript};

use super::keyset::{LocalKeyset, LocalPubkey, RemoteKeyset};
use super::policy::{CommonParams, PeerParams, Policy};
use super::{AnchorOutputs, BoltExt, ChannelState, Lifecycle};
use crate::channel::bolt::util::UpdateReq;
use crate::channel::bolt::PolicyError;
use crate::channel::funding::{self, Funding, PsbtLnpFunding};
use crate::channel::tx_graph::TxGraph;
use crate::extension::ChannelConstructor;
use crate::router::gossip::LocalChannelInfo;
use crate::{Channel, ChannelExtension, Extension};

// TODO: Use Box<dyn Error> for boxing extension- and channel-type-specific
//       errors.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// Error in channel funding: {0}
    #[from]
    Funding(funding::Error),

    /// Error reestablishing channel
    #[display(inner)]
    #[from]
    ChannelReestablish(ReestablishError),

    /// provided route can't be encoded into an onion packet. Details: {0}
    #[from]
    Route(sphinx::EncodeError),

    /// HTLC extension error
    // TODO: Expand into specific error types
    #[display(inner)]
    Htlc(String),

    /// Policy errors happening during channel negotiation
    #[from]
    #[display(inner)]
    Policy(PolicyError),

    /// channel is in a state {current} incompatible with the requested
    /// operation
    #[display(doc_comments)]
    LifecycleMismatch {
        current: Lifecycle,
        required: &'static [Lifecycle],
    },

    /// the channel does not have permanent channel_id assigned
    NoChanelId,

    /// the channel must have a temporary channel id and not be active for the
    /// operaiton
    NoTemporaryId,
}

/// Errors during channel re-establishment
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum ReestablishError {
    /// requested to re-establish channel, but the local channel has no
    /// channel_id set meaning that the funding transaction was not
    /// published; failing the channel
    NoPermanentId,

    /// local channel id {local} does not match to the one provided by
    /// the remote peer ({remote}) during the channel reestablishment
    ChannelIdMismatch { remote: ChannelId, local: ChannelId },
}

/// Channel direction
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
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

impl Channel<BoltExt> {
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

    /// Returns [`ChannelId`], if the channel already assigned it – or errors
    /// otherwise.
    #[inline]
    pub fn try_channel_id(&self) -> Result<ChannelId, Error> {
        self.channel_id().ok_or(Error::NoChanelId)
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
    ) -> Result<OpenChannel, Error> {
        self.set_funding_amount(funding_sat);
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
    pub fn compose_accept_channel(&mut self) -> Result<AcceptChannel, Error> {
        self.constructor_mut().compose_accept_channel()
    }

    #[inline]
    pub fn compose_funding_locked(&mut self) -> FundingLocked {
        self.constructor_mut().compose_funding_locked()
    }

    pub fn compose_reestablish_channel(
        &mut self,
        remote_channel_reestablish: &ChannelReestablish,
    ) -> Result<ChannelReestablish, Error> {
        self.constructor_mut()
            .compose_reestablish_channel(remote_channel_reestablish)
            .map_err(Error::from)
    }

    pub fn compose_add_update_htlc(
        &mut self,
        amount_msat: u64,
        payment_hash: HashLock,
        cltv_expiry: u32,
        route: Vec<Hop<PaymentOnion>>,
    ) -> Result<Messages, Error> {
        self.constructor_mut().compose_add_update_htlc(
            amount_msat,
            payment_hash,
            cltv_expiry,
            route,
        )
    }

    #[inline]
    pub fn chain_hash(&self) -> Slice32 {
        self.constructor().chain_hash()
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

    pub fn channel_info(&self, remote_node: NodeId) -> LocalChannelInfo {
        // TODO: Fill with the real data
        LocalChannelInfo {
            remote_node,
            channel_id: self
                .channel_id()
                .expect("channel id must be known at this stage"),
            short_channel_id: Default::default(),
            chain_hash: self.chain_hash(),
            inbound_capacity_msat: self.remote_amount_msat(),
            outboud_capacity_msat: self.local_amount_msat(),
            cltv_expiry: 0,
            htlc_minimum_msat: self
                .constructor()
                .local_params()
                .htlc_minimum_msat,
            htlc_maximum_msat: 0,
        }
    }

    #[inline]
    pub fn funding_pubkey(&self) -> PublicKey {
        self.constructor().local_keys().funding_pubkey.key
    }

    #[inline]
    pub fn funding_script_pubkey(&self) -> PubkeyScript {
        let funding = self.funding();
        let core = self.constructor();
        PubkeyScript::ln_funding(
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
    pub fn local_amount_msat(&self) -> u64 {
        self.constructor().local_amount_msat()
    }

    #[inline]
    pub fn remote_amount_msat(&self) -> u64 {
        self.constructor().remote_amount_msat()
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
pub struct BoltChannel {
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

    /// Amount in millisatoshis
    #[getter(as_copy)]
    local_amount_msat: u64,

    /// Amount in millisatoshis
    #[getter(as_copy)]
    remote_amount_msat: u64,

    #[getter(as_copy)]
    commitment_number: u64,

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

impl Default for BoltChannel {
    fn default() -> Self {
        let direction = Direction::Outbount;
        let dumb_keys = RemoteKeyset::dumb_default();
        BoltChannel {
            stage: Lifecycle::Initial,
            chain_hash: default!(),
            active_channel_id: ActiveChannelId::random(),
            local_amount_msat: 0,
            remote_amount_msat: 0,
            commitment_number: 0,
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

impl BoltChannel {
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

    /// Returns [`ChannelId`], if the channel already assigned it – or errors
    /// otherwise.
    #[inline]
    pub fn try_channel_id(&self) -> Result<ChannelId, Error> {
        self.channel_id().ok_or(Error::NoChanelId)
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

impl Extension<BoltExt> for BoltChannel {
    fn identity(&self) -> BoltExt {
        BoltExt::Bolt3
    }

    fn update_from_local(&mut self, _message: &()) -> Result<(), Error> {
        // Nothing to do here so far
        Ok(())
    }

    fn update_from_peer(&mut self, message: &Messages) -> Result<(), Error> {
        // TODO: Check lifecycle
        match message {
            Messages::OpenChannel(open_channel) => {
                self.stage = Lifecycle::Proposed;

                self.direction = Direction::Inbound;
                self.active_channel_id =
                    ActiveChannelId::from(open_channel.temporary_channel_id);
                self.remote_amount_msat = open_channel.funding_satoshis * 1000
                    - open_channel.push_msat;
                self.local_amount_msat = open_channel.push_msat;

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
                // TODO: Verify signature against transaction
            }
            Messages::FundingLocked(funding_locked) => {
                self.stage = Lifecycle::Locked; // TODO: or Active
                self.remote_per_commitment_point =
                    funding_locked.next_per_commitment_point;
            }
            Messages::Shutdown(_) => {}
            Messages::ClosingSigned(_) => {}
            Messages::UpdateAddHtlc(_message) => {
                /* TODO
                if message.amount_msat + total_htlc_value_in_flight_msat
                    > self.max_htlc_value_in_flight_msat
                {
                    return Err(Error::Htlc(
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

    fn load_state(&mut self, state: &ChannelState) {
        self.stage = state.stage;
        self.chain_hash = state.chain_hash;
        self.active_channel_id = state.active_channel_id;
        self.local_amount_msat = state.local_amount_msat;
        self.remote_amount_msat = state.remote_amount_msat;
        self.commitment_number = state.commitment_number;
        self.commitment_sigs = state.commitment_sigs.clone();
        self.policy = state.policy.clone();
        self.common_params = state.common_params;
        self.local_params = state.local_params;
        self.remote_params = state.remote_params;
        self.local_keys = state.local_keys.clone();
        self.remote_keys = state.remote_keys.clone();
        self.remote_per_commitment_point = state.remote_per_commitment_point;
        self.local_per_commitment_point = state.local_per_commitment_point;
        self.direction = state.direction;
    }

    fn store_state(&self, state: &mut ChannelState) {
        state.stage = self.stage;
        state.chain_hash = self.chain_hash;
        state.active_channel_id = self.active_channel_id;
        state.local_amount_msat = self.local_amount_msat;
        state.remote_amount_msat = self.remote_amount_msat;
        state.commitment_number = self.commitment_number;
        state.commitment_sigs = self.commitment_sigs.clone();
        state.policy = self.policy.clone();
        state.common_params = self.common_params;
        state.local_params = self.local_params;
        state.remote_params = self.remote_params;
        state.local_keys = self.local_keys.clone();
        state.remote_keys = self.remote_keys.clone();
        state.remote_per_commitment_point = self.remote_per_commitment_point;
        state.local_per_commitment_point = self.local_per_commitment_point;
        state.direction = self.direction;
    }
}

impl BoltChannel {
    fn commitment_fee(&self) -> u64 {
        724 * self.common_params.feerate_per_kw as u64 / 1000
    }

    fn obscured_commitment_number(&self) -> u64 {
        const LOWER_48_BITS: u64 = 0x00_00_FF_FF_FF_FF_FF_FF;

        let mut engine = sha256::Hash::engine();
        if self.direction.is_inbound() {
            engine.input(&self.remote_keys.payment_basepoint.serialize());
            engine.input(&self.local_keys.payment_basepoint.key.serialize());
        } else {
            engine.input(&self.local_keys.payment_basepoint.key.serialize());
            engine.input(&self.remote_keys.payment_basepoint.serialize());
        }
        let obscuring_hash = sha256::Hash::from_engine(engine);

        let mut buf = [0u8; 8];
        buf.copy_from_slice(&obscuring_hash[24..]);
        let obscuring_factor = u64::from_be_bytes(buf) & LOWER_48_BITS;

        // The 48-bit commitment number is obscured by XOR with the lower
        // 48 bits of `obscuring_factor`
        (self.commitment_number & LOWER_48_BITS) ^ obscuring_factor
    }

    fn compose_open_channel(
        &mut self,
        funding_sat: u64,
        push_msat: u64,
        policy: Policy,
        common_params: CommonParams,
        local_params: PeerParams,
        local_keyset: LocalKeyset,
    ) -> Result<OpenChannel, Error> {
        if self.stage != Lifecycle::Initial
            && self.stage != Lifecycle::Reestablishing
        {
            return Err(Error::LifecycleMismatch {
                current: self.stage,
                required: &[Lifecycle::Initial, Lifecycle::Reestablishing],
            });
        }

        self.direction = Direction::Outbount;
        self.policy = policy;
        self.common_params = common_params;
        self.local_params = local_params;
        self.local_keys = local_keyset.clone();
        self.local_amount_msat = funding_sat * 1000 - push_msat;
        self.remote_amount_msat = push_msat;
        self.local_per_commitment_point =
            local_keyset.first_per_commitment_point.key;

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
            first_per_commitment_point: self.local_per_commitment_point,
            shutdown_scriptpubkey: local_keyset.shutdown_scriptpubkey,
            channel_flags: if common_params.announce_channel { 1 } else { 0 },
            channel_type: common_params.channel_type.into_option(),
            unknown_tlvs: none!(),
        })
    }

    fn compose_accept_channel(&mut self) -> Result<AcceptChannel, Error> {
        if self.stage != Lifecycle::Initial
            && self.stage != Lifecycle::Reestablishing
        {
            return Err(Error::LifecycleMismatch {
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

    fn compose_reestablish_channel(
        &mut self,
        remote_channel_reestablish: &ChannelReestablish,
    ) -> Result<ChannelReestablish, ReestablishError> {
        let channel_id = if let Some(channel_id) = self.channel_id() {
            channel_id
        } else {
            return Err(ReestablishError::NoPermanentId);
        };

        if remote_channel_reestablish.channel_id != channel_id {
            return Err(ReestablishError::ChannelIdMismatch {
                remote: remote_channel_reestablish.channel_id,
                local: channel_id,
            });
        }

        // TODO: Check the rest of parameters to match local parameters

        Ok(ChannelReestablish {
            channel_id,
            next_commitment_number: remote_channel_reestablish
                .next_commitment_number,
            next_revocation_number: remote_channel_reestablish
                .next_revocation_number,
            // TODO: Set to the last per commitment secret we received, if any
            your_last_per_commitment_secret: Slice32::default(),
            my_current_per_commitment_point: self.local_per_commitment_point,
        })
    }

    fn compose_funding_locked(&mut self) -> FundingLocked {
        FundingLocked {
            channel_id: self
                .active_channel_id
                .channel_id()
                .expect("channel id must be known at FUNDING_LOCKED stage"),
            next_per_commitment_point: self.next_per_commitment_point(),
        }
    }

    pub fn compose_add_update_htlc(
        &mut self,
        amount_msat: u64,
        payment_hash: HashLock,
        cltv_expiry: u32,
        route: Vec<Hop<PaymentOnion>>,
    ) -> Result<Messages, Error> {
        // TODO: Optimize and keep Secp256k1 on a permanent basis
        let secp = Secp256k1::new();
        let onion_packet =
            OnionPacket::with(&secp, &route, payment_hash.as_ref())?;
        let mut message = Messages::UpdateAddHtlc(UpdateAddHtlc {
            channel_id: self.try_channel_id()?,
            htlc_id: 0,
            amount_msat,
            payment_hash,
            cltv_expiry,
            onion_routing_packet: Onion::Onion(onion_packet),
            unknown_tlvs: none!(),
        });
        self.state_change(&UpdateReq::PayBolt(route), &mut message)?;
        Ok(message)
    }

    fn next_per_commitment_point(&mut self) -> PublicKey {
        // TODO: Implement per commitment point switching
        self.local_per_commitment_point
    }

    fn remote_paymentpubkey(&self, as_remote_node: bool) -> PublicKey {
        // TODO: Optimize and keep Secp256k1 on a permanent basis
        let secp = Secp256k1::verification_only();

        let per_commitment_point = if as_remote_node {
            self.remote_per_commitment_point
        } else {
            self.local_per_commitment_point
        };
        let payment_basepoint = if as_remote_node {
            self.local_keys.payment_basepoint.key
        } else {
            self.remote_keys.payment_basepoint
        };

        let mut engine = sha256::Hash::engine();
        engine.input(&per_commitment_point.serialize());
        engine.input(&payment_basepoint.serialize());
        let tweak = sha256::Hash::from_engine(engine);

        let mut payment_pubkey = payment_basepoint;
        payment_pubkey
            .add_exp_assign(&secp, tweak.as_ref())
            .expect("negligible probability");
        payment_pubkey
    }

    fn local_delayedpubkey(&self, as_remote_node: bool) -> PublicKey {
        // TODO: Optimize and keep Secp256k1 on a permanent basis
        let secp = Secp256k1::verification_only();

        let per_commitment_point = if as_remote_node {
            self.local_per_commitment_point
        } else {
            self.remote_per_commitment_point
        };
        let delayed_payment_basepoint = if as_remote_node {
            self.remote_keys.delayed_payment_basepoint
        } else {
            self.local_keys.delayed_payment_basepoint.key
        };

        let mut engine = sha256::Hash::engine();
        engine.input(&per_commitment_point.serialize());
        engine.input(&delayed_payment_basepoint.serialize());
        let tweak = sha256::Hash::from_engine(engine);

        let mut delayed_pubkey = delayed_payment_basepoint;
        delayed_pubkey
            .add_exp_assign(&secp, tweak.as_ref())
            .expect("negligible probability");
        delayed_pubkey
    }

    fn remote_revocationpubkey(&self, as_remote_node: bool) -> PublicKey {
        // TODO: Optimize and keep Secp256k1 on a permanent basis
        let secp = Secp256k1::verification_only();

        let revocation_basepoint = if as_remote_node {
            self.local_keys.revocation_basepoint.key
        } else {
            self.remote_keys.revocation_basepoint
        };
        let per_commitment_point = if as_remote_node {
            self.remote_per_commitment_point
        } else {
            self.local_per_commitment_point
        };

        let mut tweaked_revocation_basepoint = revocation_basepoint;
        let mut engine = sha256::Hash::engine();
        engine.input(&revocation_basepoint.serialize());
        engine.input(&per_commitment_point.serialize());
        let revocation_tweak = sha256::Hash::from_engine(engine);
        tweaked_revocation_basepoint
            .mul_assign(&secp, revocation_tweak.as_ref())
            .expect("negligible probability");

        let mut tweaked_per_commitment_point = self.remote_per_commitment_point;
        let mut engine = sha256::Hash::engine();
        engine.input(&per_commitment_point.serialize());
        engine.input(&revocation_basepoint.serialize());
        let per_commitment_tweak = sha256::Hash::from_engine(engine);
        tweaked_per_commitment_point
            .mul_assign(&secp, per_commitment_tweak.as_ref())
            .expect("negligible probability");

        tweaked_revocation_basepoint
            .combine(&tweaked_per_commitment_point)
            .expect("negligible probability")
    }
}

impl ChannelExtension<BoltExt> for BoltChannel {
    #[inline]
    fn new() -> Box<dyn ChannelExtension<BoltExt>> {
        Box::new(BoltChannel::default())
    }

    fn build_graph(
        &self,
        tx_graph: &mut TxGraph,
        as_remote_node: bool,
    ) -> Result<(), Error> {
        let obscured_commitment = self.obscured_commitment_number();
        let lock_time =
            (0x20u32 << 24) | (obscured_commitment as u32 & 0x00_FF_FF_FF);
        let sequence = (0x80u32 << 24) | (obscured_commitment >> 24) as u32;

        let fee = self.commitment_fee();
        let (to_remote_fee, to_local_fee) =
            if self.direction == Direction::Outbount {
                (fee, 0)
            } else {
                (0, fee)
            };

        tx_graph.cmt_version = 2;
        tx_graph.cmt_locktime = lock_time;
        tx_graph.cmt_sequence = sequence;
        // We are doing counterparty's transaction!
        tx_graph.cmt_outs = Vec::with_capacity(2);

        let to_local_amount = if as_remote_node {
            self.remote_amount_msat
        } else {
            self.local_amount_msat
        };
        let to_remote_amount = if as_remote_node {
            self.local_amount_msat
        } else {
            self.remote_amount_msat
        };
        let to_self_delay = if as_remote_node {
            self.remote_params.to_self_delay
        } else {
            self.local_params.to_self_delay
        };
        if to_local_amount > 0 {
            tx_graph.cmt_outs.push(ScriptGenerators::ln_to_local(
                to_local_amount / 1000 - to_local_fee,
                self.remote_revocationpubkey(as_remote_node),
                self.local_delayedpubkey(as_remote_node),
                to_self_delay,
            ));
        }
        if to_remote_amount > 0 {
            tx_graph.cmt_outs.push(ScriptGenerators::ln_to_remote_v1(
                to_remote_amount / 1000 - to_remote_fee,
                self.remote_paymentpubkey(as_remote_node),
            ));
        }

        Ok(())
    }
}

impl ChannelConstructor<BoltExt> for BoltChannel {
    fn enrich_funding(
        &self,
        psbt: &mut Psbt,
        funding: &Funding,
    ) -> Result<(), Error> {
        let vout = psbt
            .channel_funding_output()
            .ok_or(funding::Error::NoFundingOutput)?;
        psbt.outputs[vout].witness_script = Some(
            WitnessScript::ln_funding(
                funding.amount(),
                &self.local_keys.funding_pubkey,
                self.remote_keys.funding_pubkey,
            )
            .into_inner(),
        );
        psbt.outputs[vout].bip32_derivation =
            self.local_keys.funding_pubkey.to_bip32_derivation_map();
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
        let pk = vec![
            local_pubkey.to_bitcoin_pk(),
            bitcoin::PublicKey::new(remote_pubkey),
        ]
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
            .push_key(&bitcoin::PublicKey::new(revocationpubkey))
            .push_opcode(OP_ELSE)
            .push_int(to_self_delay as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&bitcoin::PublicKey::new(local_delayedpubkey))
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
            .push_key(&bitcoin::PublicKey::new(remote_pubkey))
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
        bitcoin::PublicKey::new(remote_pubkey)
            .wpubkey_hash()
            .expect("We just generated non-compressed key")
            .into()
    }

    #[inline]
    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self {
        WitnessScript::ln_to_remote_v2(amount, remote_pubkey).to_p2wsh()
    }
}

impl ScriptGenerators for psbt::Output {
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
        let output = bitcoin::psbt::Output {
            witness_script: Some(witness_script),
            bip32_derivation: local_pubkey.to_bip32_derivation_map(),
            ..Default::default()
        };
        psbt::Output::with(0, output, txout)
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
        let output = bitcoin::psbt::Output {
            witness_script: Some(witness_script),
            ..Default::default()
        };
        psbt::Output::with(1, output, txout)
    }

    #[inline]
    fn ln_to_remote_v1(amount: u64, remote_pubkey: PublicKey) -> Self {
        let txout = TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_remote_v1(amount, remote_pubkey)
                .into(),
        };
        psbt::Output::new(2, txout)
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
        let output = bitcoin::psbt::Output {
            witness_script: Some(witness_script),
            ..Default::default()
        };
        psbt::Output::with(3, output, txout)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use amplify::hex::ToHex;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::{OutPoint, Script, Transaction, TxIn, Txid};
    use wallet::psbt::PsbtVersion;

    use super::*;
    use crate::channel::shared_ext::Bip96;

    macro_rules! pk {
        ($hex:expr) => {
            PublicKey::from_str($hex).unwrap()
        };
    }
    macro_rules! lk {
        ($pk:expr) => {
            LocalPubkey {
                key: $pk,
                ..LocalPubkey::dumb_default()
            }
        };
    }

    fn core_for_tests() -> BoltChannel {
        let local_payment_basepoint = pk!("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
        let remote_payment_basepoint = pk!("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");
        let mut core = BoltChannel::default();

        core.direction = Direction::Outbount;
        core.commitment_number = 42;
        core.local_keys.payment_basepoint = lk!(local_payment_basepoint);
        core.remote_keys.payment_basepoint = remote_payment_basepoint;
        core.local_params.to_self_delay = 144;
        core.local_params.dust_limit_satoshis = 546;

        core
    }

    fn tx_for_tests() -> Transaction {
        let local_funding_pubkey = pk!("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
        let remote_funding_pubkey = pk!("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");

        let output = psbt::Output::ln_funding(
            10000000,
            &LocalPubkey {
                key: local_funding_pubkey,
                ..LocalPubkey::dumb_default()
            },
            remote_funding_pubkey,
        );

        Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str(
                    "fd2105607605d2302994ffea703b09f66b6351816ee737a93e42a841ea20bbad"
                ).unwrap(), 0),
                script_sig: Script::from_str(
                    "48304502210090587b6201e166ad6af0227d3036a9454223d49a1f11839\
                    c1a362184340ef0240220577f7cd5cca78719405cbf1de7414ac027f023\
                    9ef6e214c90fcaab0454d84b3b012103535b32d5eb0a6ed0982a0479bba\
                    dc9868d9836f6ba94dd5a63be16d875069184"
                ).unwrap(),
                sequence: 4294967295,
                witness: empty!(),
            }],
            output: vec![
                TxOut {
                    value: output.amount,
                    script_pubkey: output.script,
                },
                TxOut {
                    value: 4989986080,
                    script_pubkey: Script::from_str("00143ca33c2e4446f4a305f23c80df8ad1afdcf652f9").unwrap()
                }
            ],
        }
    }

    #[test]
    fn bolt3_funding_witness_script() {
        let local_funding_pubkey = pk!("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
        let remote_funding_pubkey = pk!("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");
        let witness_script = WitnessScript::ln_funding(
            0,
            &LocalPubkey {
                key: local_funding_pubkey,
                ..LocalPubkey::dumb_default()
            },
            remote_funding_pubkey,
        );
        assert_eq!(
            witness_script.to_hex(),
            "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f\
            54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa\
            711c152ae"
        );
    }

    #[test]
    fn bolt3_obscured_commitment_no() {
        let core = core_for_tests();
        assert_eq!(0x2bb038521914 ^ 42, core.obscured_commitment_number());
    }

    #[test]
    fn bolt3_funding() {
        // let local_funding_privkey =
        // pk!("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901"
        // ); let local_privkey =
        // pk!("bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f27469449101"
        // );
        let tx = tx_for_tests();
        assert_eq!(tx.txid(), Txid::from_str("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap());
    }

    #[test]
    fn bolt3_commitment_tx() {
        let mut core = core_for_tests();

        core.direction = Direction::Outbount;
        core.local_amount_msat = 7000000000;
        core.remote_amount_msat = 3000000000;
        core.common_params.feerate_per_kw = 15000;

        // let local_funding_pubkey =
        // pk!("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"
        // ); let remote_funding_pubkey =
        // pk!("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"
        // ); let localpubkey =
        // pk!("030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7"
        // );
        let remotepubkey = pk!("0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b");
        let local_delayedpubkey = pk!("03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c");
        let local_revocation_pubkey = pk!("0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19");

        let mut funding_tx = tx_for_tests();
        funding_tx.input[0].script_sig = Script::default();
        let mut funding_psbt = Psbt::with(funding_tx, PsbtVersion::V0).unwrap();
        funding_psbt.set_channel_funding_output(0).unwrap();

        let mut channel =
            Channel::<BoltExt>::new(core.clone(), [], [Bip96::new()]);
        let psbt = channel.refund_tx(funding_psbt, true).unwrap();
        let mut tx = psbt.into_unsigned_tx();

        let mut testvec_tx: Transaction = bitcoin::consensus::deserialize(&Vec::from_hex(
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b\
            820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aab\
            ee14bb40fa3851ab2301de84311054a56a00000000002200204adb4e2f00643db396\
            dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022051b75c73\
            198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c41937\
            9c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c3836939014830450221\
            00f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e796802\
            2041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c001\
            475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f\
            54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa7\
            11c152ae3e195220"
        ).unwrap()).unwrap();
        // We can't produce proper input since we do not have funding PSBT
        testvec_tx.input[0].witness = empty!();
        tx.input[0].previous_output = testvec_tx.input[0].previous_output;
        // We need to manually re-generate outputs since we do not have test
        // basepoints and only final keys
        tx.output[1].script_pubkey = PubkeyScript::ln_to_local(
            0,
            local_revocation_pubkey,
            local_delayedpubkey,
            core.local_params.to_self_delay,
        )
        .into();
        tx.output[0].script_pubkey =
            PubkeyScript::ln_to_remote_v1(0, remotepubkey).into();

        assert_eq!(tx, testvec_tx);
    }

    #[test]
    fn bolt3_localkey_derivation() {
        let base_point = pk!("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
        let per_commitment_point = pk!("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
        let mut core = core_for_tests();
        core.remote_keys.payment_basepoint = base_point;
        core.local_per_commitment_point = per_commitment_point;
        assert_eq!(
            core.remote_paymentpubkey(false),
            pk!("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5")
        );

        core.local_keys.payment_basepoint = lk!(base_point);
        core.remote_per_commitment_point = per_commitment_point;
        assert_eq!(
            core.remote_paymentpubkey(true),
            pk!("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5")
        );

        core.local_keys.delayed_payment_basepoint = lk!(base_point);
        core.remote_per_commitment_point = per_commitment_point;
        assert_eq!(
            core.local_delayedpubkey(false),
            pk!("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5")
        );

        core.remote_keys.delayed_payment_basepoint = base_point;
        core.local_per_commitment_point = per_commitment_point;
        assert_eq!(
            core.local_delayedpubkey(true),
            pk!("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5")
        );
    }

    #[test]
    fn bolt3_revocationkey_derivation() {
        let base_point = pk!("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
        let per_commitment_point = pk!("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
        let mut core = core_for_tests();

        core.local_keys.revocation_basepoint = lk!(base_point);
        core.remote_per_commitment_point = per_commitment_point;
        assert_eq!(
            core.remote_revocationpubkey(true),
            pk!("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0")
        );

        core.remote_keys.revocation_basepoint = base_point;
        core.local_per_commitment_point = per_commitment_point;
        assert_eq!(
            core.remote_revocationpubkey(false),
            pk!("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0")
        );
    }
}
