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

//! Routing extensions and data types

use std::collections::BTreeMap;

use internet2::presentation::sphinx::Hop;
use p2p::legacy::{
    ChannelAnnouncement, ChannelUpdate, Messages, PaymentOnion, PaymentRequest,
};
use secp256k1::PublicKey;

use crate::channel::bolt::ExtensionId;
use crate::channel::Error;
use crate::extension::Nomenclature;
use crate::{extension, ChannelExtension, Extension, RoutingExtension};

pub type ExtensionQueue<N> = BTreeMap<
    N,
    Box<
        dyn RoutingExtension<
            Identity = N,
            ChannelInfo = ChannelInfo,
            Payload = PaymentOnion,
        >,
    >,
>;

/// Information about channel used for route construction and re-broadcasting
/// gossip messages.
pub struct ChannelInfo {
    /// Node identities consituting channel
    pub nodes: (PublicKey, PublicKey),

    /// Information about each channel direction.
    ///
    /// The first tuple field corresponds to the direction from the first
    /// node id (see [`ChannelInfo::nodes`]) to the second one – and the second
    /// tuple field to the opposite direction.
    pub directions: (Option<ChannelUpdate>, Option<ChannelUpdate>),

    /// The channel capacity, known only for local channels - or if it can be
    /// deduced from on-chain data, if they are available
    pub capacity_sats: Option<u64>,

    /// Original channel announcement message from which we've got this
    /// information. Absent for manually added channels and may be absent for
    /// local channels.
    pub announcement: Option<ChannelAnnouncement>,
}

/// BOLT-7 gossip-based router
pub struct GossipRouter<N>
where
    N: extension::Nomenclature,
{
    channels: Vec<ChannelInfo>,
    extensions: ExtensionQueue<N>,
}

impl<N> Extension for GossipRouter<N>
where
    N: extension::Nomenclature,
{
    type Identity = ExtensionId;

    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>>
    where
        Self: Sized,
    {
        todo!()
    }

    fn identity(&self) -> Self::Identity {
        todo!()
    }

    fn update_from_peer(&mut self, message: &Messages) -> Result<(), Error> {
        todo!()
    }

    fn load_state(&mut self, state: &<Self::Identity as Nomenclature>::State) {
        todo!()
    }

    fn store_state(&self, state: &mut <Self::Identity as Nomenclature>::State) {
        todo!()
    }
}

impl<N> RoutingExtension for GossipRouter<N>
where
    N: extension::Nomenclature,
{
    type ChannelInfo = ChannelInfo;
    type Payload = PaymentOnion;

    fn improve_route(
        &mut self,
        payment: PaymentRequest,
        route: &mut Vec<Hop<Self::Payload>>,
        channels: &[Self::ChannelInfo],
    ) {
    }
}
