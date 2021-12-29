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

use internet2::presentation::sphinx::Hop;
use p2p::legacy::{Messages, PaymentOnion, PaymentRequest};
use strict_encoding::{strict_deserialize, strict_serialize};

use super::ChannelInfo;
use crate::router::Router;
use crate::{extension, router, Extension, RouterExtension};

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum Error {}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictEncode, StrictDecode)]
pub struct RouterState {
    channels: Vec<ChannelInfo>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display(Debug)]
pub enum RouterExt {
    Core,
}

impl extension::Nomenclature for RouterExt {
    type State = RouterState;
    type Error = Error;
}

impl Default for RouterExt {
    fn default() -> Self {
        RouterExt::Core
    }
}

impl From<RouterExt> for u16 {
    fn from(id: RouterExt) -> Self {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(
            &strict_serialize(&id)
                .expect("Enum in-memory strict encoding can't fail"),
        );
        u16::from_be_bytes(buf)
    }
}

impl TryFrom<u16> for RouterExt {
    type Error = strict_encoding::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        strict_deserialize(&value.to_be_bytes())
    }
}

impl router::Nomenclature for RouterExt {
    type HopPayload = PaymentOnion;

    fn update_from_peer(
        router: &mut Router<Self>,
        message: &Messages,
    ) -> Result<(), Error> {
        todo!()
    }
}

/// BOLT-7 gossip-based router
pub struct GossipRouter {
    pub channels: Vec<ChannelInfo>,
}

impl Extension for GossipRouter {
    type Identity = RouterExt;

    fn identity(&self) -> Self::Identity {
        todo!()
    }

    fn update_from_peer(&mut self, message: &Messages) -> Result<(), Error> {
        todo!()
    }

    fn load_state(&mut self, state: &RouterState) {
        todo!()
    }

    fn store_state(&self, state: &mut RouterState) {
        todo!()
    }
}

impl RouterExtension for GossipRouter {
    fn new() -> Box<dyn RouterExtension<Identity = Self::Identity>>
    where
        Self: Sized,
    {
        todo!()
    }

    fn build_route(
        &mut self,
        payment: PaymentRequest,
        route: &mut Vec<Hop<PaymentOnion>>,
    ) {
        todo!()
    }
}
