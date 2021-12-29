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
use p2p::legacy::{Messages, PaymentOnion, PaymentRequest};
use strict_encoding::{strict_deserialize, strict_serialize};

use super::GossipChannelInfo;
use crate::router::gossip::DirectChannelInfo;
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
    direct_channels: Vec<DirectChannelInfo>,
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
    DirectRouter = 1,
    GossipRouter = 2,
}

impl Default for GossipExt {
    fn default() -> Self {
        GossipExt::DirectRouter
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
        strict_deserialize(&value.to_be_bytes())
    }
}

impl extension::Nomenclature for GossipExt {
    type State = RouterState;
    type Error = Error;
}

impl router::Nomenclature for GossipExt {
    type HopPayload = PaymentOnion;

    fn default_extensions() -> Vec<Box<dyn RouterExtension<Identity = Self>>> {
        vec![
            Box::new(DirectRouter::default())
                as Box<dyn RouterExtension<Identity = Self>>,
            Box::new(GossipRouter::default())
                as Box<dyn RouterExtension<Identity = Self>>,
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

impl Router<GossipExt> {
    pub fn add_direct_channel(
        &'static mut self,
        info: DirectChannelInfo,
    ) -> Option<DirectChannelInfo> {
        let direct_router: &mut DirectRouter = self
            .extension_mut(GossipExt::DirectRouter)
            .expect("direct routed must be present in BOLT-compatible router");
        direct_router.add_direct_channel(info)
    }
}

/// Router for direct channels (between this node and other nodes) for
/// legacy BOLT lightning channels
#[derive(Getters, Clone, PartialEq, Eq, Debug, Default)]
pub struct DirectRouter {
    channels: Vec<DirectChannelInfo>,
}

impl DirectRouter {
    pub fn add_direct_channel(
        &mut self,
        info: DirectChannelInfo,
    ) -> Option<DirectChannelInfo> {
        let prev_info = if let Some((index, _)) = self
            .channels
            .iter()
            .enumerate()
            .find(|(index, c)| c.channel_id == info.channel_id)
        {
            Some(self.channels.remove(index))
        } else {
            None
        };
        self.channels.push(info);
        prev_info
    }
}

impl Extension for DirectRouter {
    type Identity = GossipExt;

    fn identity(&self) -> Self::Identity {
        GossipExt::DirectRouter
    }

    fn update_from_peer(&mut self, message: &Messages) -> Result<(), Error> {
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

    fn load_state(&mut self, state: &RouterState) {
        self.channels = state.direct_channels.clone();
    }

    fn store_state(&self, state: &mut RouterState) {
        state.direct_channels = self.channels.clone();
    }
}

impl RouterExtension for DirectRouter {
    #[inline]
    fn new() -> Box<dyn RouterExtension<Identity = Self::Identity>>
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
        todo!()
    }
}

/// BOLT-7 gossip-based router
#[derive(Getters, Clone, PartialEq, Eq, Debug, Default)]
pub struct GossipRouter {
    channels: Vec<GossipChannelInfo>,
}

impl Extension for GossipRouter {
    type Identity = GossipExt;

    fn identity(&self) -> Self::Identity {
        GossipExt::GossipRouter
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

impl RouterExtension for GossipRouter {
    #[inline]
    fn new() -> Box<dyn RouterExtension<Identity = Self::Identity>>
    where
        Self: Sized,
    {
        Box::new(GossipRouter::default())
    }

    fn build_route(
        &mut self,
        payment: PaymentRequest,
        route: &mut Vec<Hop<PaymentOnion>>,
    ) {
        todo!()
    }
}
