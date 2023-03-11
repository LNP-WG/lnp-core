// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2019 by
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
use internet2::presentation::sphinx::Hop;
use p2p::bolt::{
    ChannelId, HopRealm, Messages, PaymentOnion, PaymentRequest, ShortChannelId,
};
use strict_encoding::{strict_deserialize, strict_serialize};

use super::GossipChannelInfo;
use crate::router::gossip::LocalChannelInfo;
use crate::router::Router;
use crate::{extension, router, Extension, RouterExtension};

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum Error {}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
pub struct RouterState {
    remote_channels: Vec<GossipChannelInfo>,
    direct_channels: Vec<LocalChannelInfo>,
}

impl DumbDefault for RouterState {
    fn dumb_default() -> Self {
        RouterState::default()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display(Debug)]
pub enum GossipExt {
    MainRouter = 0,
    DirectRouter = 1,
    GossipRouter = 2,
}

impl Default for GossipExt {
    fn default() -> Self {
        GossipExt::MainRouter
    }
}

impl From<GossipExt> for u16 {
    fn from(id: GossipExt) -> Self {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(
            &strict_serialize(&id)
                .expect("Enum in-memory strict encoding can't fail"),
        );
        u16::from_be_bytes(buf)
    }
}

impl TryFrom<u16> for GossipExt {
    type Error = strict_encoding::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        strict_deserialize(value.to_be_bytes())
    }
}

impl extension::Nomenclature for GossipExt {
    type State = RouterState;
    type Error = Error;
    type PeerMessage = lnp2p::bolt::Messages;
    type UpdateMessage = UpdateMsg;
    type UpdateRequest = ();
}

impl router::Nomenclature for GossipExt {
    type HopPayload = PaymentOnion;

    fn default_extensions() -> Vec<Box<dyn RouterExtension<Self>>> {
        vec![
            Box::new(DirectRouter::default()) as Box<dyn RouterExtension<Self>>,
            Box::new(GossipRouter::default()) as Box<dyn RouterExtension<Self>>,
        ]
    }

    fn update_from_peer(
        _router: &mut Router<Self>,
        _message: &Messages,
    ) -> Result<(), Error> {
        // TODO: Add support for gossip queries by adding query extension if
        //       we are getting corresponding feature flag
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum UpdateMsg {
    DirectChannelAdd(LocalChannelInfo),
    DirectChannelRemove(ChannelId),
    DirectChannelUpdate {
        channel_id: ChannelId,
        local_amount_msat: u64,
        remote_amount_msat: u64,
    },
}

/// Router for direct channels (between this node and other nodes) for
/// bolt BOLT lightning channels
#[derive(Getters, Clone, PartialEq, Eq, Debug, Default)]
pub struct DirectRouter {
    channels: Vec<LocalChannelInfo>,
}

impl DirectRouter {
    fn add_direct_channel(
        &mut self,
        info: LocalChannelInfo,
    ) -> Option<LocalChannelInfo> {
        let prev_info = self.remove_direct_channel(info.channel_id);
        self.channels.push(info);
        prev_info
    }

    fn remove_direct_channel(
        &mut self,
        channel_id: ChannelId,
    ) -> Option<LocalChannelInfo> {
        if let Some((index, _)) = self
            .channels
            .iter()
            .enumerate()
            .find(|(_, info)| info.channel_id == channel_id)
        {
            Some(self.channels.remove(index))
        } else {
            None
        }
    }
}

impl Extension<GossipExt> for DirectRouter {
    fn identity(&self) -> GossipExt {
        GossipExt::DirectRouter
    }

    fn update_from_peer(&mut self, message: &Messages) -> Result<(), Error> {
        #[allow(clippy::match_single_binding)] // temporarily
        match message {
            /*
            Messages::FundingLocked(FundingLocked { channel_id, .. }) => {}
            Messages::ChannelReestablish(_) => {}
            Messages::ClosingSigned(_) => {}
            Messages::CommitmentSigned(_) => {}
            Messages::RevokeAndAck(_) => {}
             */
            _ => {} // Nothing to do here
        }

        Ok(())
    }

    fn update_from_local(&mut self, message: &UpdateMsg) -> Result<(), Error> {
        match message {
            UpdateMsg::DirectChannelAdd(info) => {
                self.add_direct_channel(*info);
            }
            UpdateMsg::DirectChannelRemove(channel_id) => {
                self.remove_direct_channel(*channel_id);
            }
            UpdateMsg::DirectChannelUpdate{ channel_id, local_amount_msat, remote_amount_msat } => {
                self.channels.iter_mut().for_each(|ch| {
                    if ch.channel_id == *channel_id {
                        ch.outbound_capacity_msat = *local_amount_msat;
                        ch.inbound_capacity_msat = *remote_amount_msat;
                    };
                });
            }
        }
        Ok(())
    }

    fn load_state(&mut self, state: &RouterState) {
        self.channels = state.direct_channels.clone();
    }

    fn store_state(&self, state: &mut RouterState) {
        state.direct_channels = self.channels.clone();
    }
}

impl RouterExtension<GossipExt> for DirectRouter {
    #[inline]
    fn new() -> Box<dyn RouterExtension<GossipExt>>
    where
        Self: Sized,
    {
        Box::new(DirectRouter::default())
    }

    fn build_route(
        &mut self,
        payment: PaymentRequest,
        route: &mut Vec<Hop<PaymentOnion>>,
    ) {
        if let Some(channel) = self
            .channels
            .iter()
            .find(|info| info.remote_node == payment.node_id)
        {
            if channel.outbound_capacity_msat < payment.amount_msat {
                return; // We do not have enough funds
            }

            *route = vec![Hop::with(payment.node_id, PaymentOnion {
                // TODO: Choose realm basing on the destination configuration
                realm: HopRealm::Legacy(ShortChannelId::default()),
                amt_to_forward: payment.amount_msat,
                outgoing_cltv_value: payment.min_final_cltv_expiry,
            })];
        }
    }
}

/// BOLT-7 gossip-based router
#[derive(Getters, Clone, PartialEq, Eq, Debug, Default)]
pub struct GossipRouter {
    channels: Vec<GossipChannelInfo>,
}

impl Extension<GossipExt> for GossipRouter {
    fn identity(&self) -> GossipExt {
        GossipExt::GossipRouter
    }

    fn update_from_local(&mut self, _message: &UpdateMsg) -> Result<(), Error> {
        // Nothing to do here so far
        Ok(())
    }

    fn update_from_peer(&mut self, message: &Messages) -> Result<(), Error> {
        match message {
            // TODO: Extract routing information from gossip messages
            Messages::UpdateFee(_) => {}
            Messages::ChannelAnnouncement(_) => {}
            Messages::ChannelUpdate(_) => {}
            _ => {}
        }
        Ok(())
    }

    fn load_state(&mut self, state: &RouterState) {
        self.channels = state.remote_channels.clone()
    }

    fn store_state(&self, state: &mut RouterState) {
        state.remote_channels = self.channels.clone()
    }
}

impl RouterExtension<GossipExt> for GossipRouter {
    #[inline]
    fn new() -> Box<dyn RouterExtension<GossipExt>>
    where
        Self: Sized,
    {
        Box::new(GossipRouter::default())
    }

    fn build_route(
        &mut self,
        _payment: PaymentRequest,
        _route: &mut Vec<Hop<PaymentOnion>>,
    ) {
        // TODO: Implement route computing
    }
}
