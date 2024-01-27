// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020-2024 by
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

#[cfg(feature = "serde")]
use amplify::ToYamlString;
use amplify::{DumbDefault, Slice32};
use p2p::bolt::{ActiveChannelId, TempChannelId};
use secp256k1::ecdsa::Signature;
use secp256k1::PublicKey;

use super::{
    CommonParams, Direction, HtlcKnown, HtlcSecret, Lifecycle, LocalKeyset,
    PeerParams, Policy, RemoteKeyset,
};
use crate::channel::{Funding, State};

#[derive(Clone, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(ChannelState::to_yaml_string)
)]
pub struct ChannelState {
    pub funding: Funding,

    /// Current channel lifecycle stage
    pub stage: Lifecycle,

    // TOO: Consider storing information about used chain at generic channel
    // level
    /// The chain_hash value denotes the exact blockchain that the opened
    /// channel will reside within. This is usually the genesis hash of the
    /// respective blockchain. The existence of the chain_hash allows nodes to
    /// open channels across many distinct blockchains as well as have channels
    /// within multiple blockchains opened to the same peer (if it supports the
    /// target chains).
    pub chain_hash: Slice32,

    /// Channel id used by the channel; first temporary and later final.
    ///
    /// The temporary_channel_id is used to identify this channel on a per-peer
    /// basis until the funding transaction is established, at which point it
    /// is replaced by the channel_id, which is derived from the funding
    /// transaction.
    pub active_channel_id: ActiveChannelId,

    /// Amount in millisatoshis
    pub local_amount_msat: u64,

    /// Amount in millisatoshis
    pub remote_amount_msat: u64,

    pub commitment_number: u64,

    pub commitment_sigs: Vec<Signature>,

    /// The policy for accepting remote node params
    pub policy: Policy,

    /// Common parameters applying for both nodes
    pub common_params: CommonParams,

    /// Channel parameters required to be met by the remote node when operating
    /// towards the local one
    pub local_params: PeerParams,

    /// Channel parameters to be used towards the remote node
    pub remote_params: PeerParams,

    /// Set of locally-derived keys for creating channel transactions
    pub local_keys: LocalKeyset,

    /// Set of remote-derived keys for creating channel transactions
    pub remote_keys: RemoteKeyset,

    pub remote_per_commitment_point: PublicKey,

    pub local_per_commitment_point: PublicKey,

    /// Keeps information about node directionality
    pub direction: Direction,

    pub offered_htlcs: BTreeMap<u64, HtlcSecret>,
    pub received_htlcs: BTreeMap<u64, HtlcSecret>,
    pub resolved_htlcs: BTreeMap<u64, HtlcKnown>,
    pub last_received_htlc_id: u64,
    pub last_offered_htlc_id: u64,
}

impl State for ChannelState {
    fn to_funding(&self) -> Funding {
        self.funding.clone()
    }

    fn set_funding(&mut self, funding: &Funding) {
        self.funding = funding.clone()
    }
}

#[cfg(feature = "serde")]
impl ToYamlString for ChannelState {}

impl DumbDefault for ChannelState {
    fn dumb_default() -> Self {
        ChannelState {
            funding: Funding::new(),
            stage: Default::default(),
            chain_hash: Default::default(),
            active_channel_id: ActiveChannelId::Temporary(
                TempChannelId::dumb_default(),
            ),
            local_amount_msat: 0,
            remote_amount_msat: 0,
            commitment_number: 0,
            commitment_sigs: vec![],
            policy: Default::default(),
            common_params: Default::default(),
            local_params: Default::default(),
            remote_params: Default::default(),
            local_keys: LocalKeyset::dumb_default(),
            remote_keys: RemoteKeyset::dumb_default(),
            remote_per_commitment_point: dumb_pubkey!(),
            local_per_commitment_point: dumb_pubkey!(),
            direction: Direction::Inbound,
            offered_htlcs: none!(),
            received_htlcs: none!(),
            resolved_htlcs: none!(),
            last_received_htlc_id: 0,
            last_offered_htlc_id: 0,
        }
    }
}
