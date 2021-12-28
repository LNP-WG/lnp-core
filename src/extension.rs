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

use internet2::presentation::sphinx::{Hop, SphinxPayload};
use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use lnp2p::legacy::Messages;
use p2p::legacy::PaymentRequest;
use wallet::psbt::Psbt;

use super::{channel, Channel};
use crate::channel::State;
use crate::routing::ChannelInfo;
use crate::Funding;

/// Marker trait for creating extension nomenclatures, defining order in which
/// extensions are applied to the channel transaction structure.
///
/// Extension nomenclature is an enum with members convertible into `u16`
/// representation
pub trait Nomenclature
where
    Self: Clone
        + Copy
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + Debug
        + Display
        + Default
        + TryFrom<u16, Error = strict_encoding::Error>
        + Into<u16>,
{
    type Constructor: ChannelConstructor<Identity = Self>;
    type State: State;

    /// Returns set of default channel extenders
    fn default_extenders() -> Vec<Box<dyn ChannelExtension<Identity = Self>>> {
        Vec::default()
    }

    /// Returns set of default channel modifiers
    fn default_modifiers() -> Vec<Box<dyn ChannelExtension<Identity = Self>>> {
        Vec::default()
    }

    /// Updates channel extension structure from peer message. Processed before
    /// each of the registered extensions gets [`Extension::update_from_peer`]
    fn update_from_peer(
        channel: &mut Channel<Self>,
        message: &Messages,
    ) -> Result<(), channel::Error>;
}

pub trait Extension {
    type Identity: Nomenclature;

    /// Constructs boxed extension objects which can be insterted into channel
    /// extension pipeline
    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>>
    where
        Self: Sized;

    fn identity(&self) -> Self::Identity;

    /// Updates extension state from the data taken from the message received
    /// from the remote peer
    fn update_from_peer(
        &mut self,
        message: &Messages,
    ) -> Result<(), channel::Error>;

    fn load_state(&mut self, state: &<Self::Identity as Nomenclature>::State);

    fn store_state(&self, state: &mut <Self::Identity as Nomenclature>::State);
}

pub trait RoutingExtension: Extension {
    type ChannelInfo;
    type Payload: SphinxPayload;

    fn improve_route(
        &mut self,
        payment: PaymentRequest,
        route: &mut Vec<Hop<Self::Payload>>,
        channels: &[Self::ChannelInfo],
    );
}

pub trait GossipExtension: Extension {}

pub trait ChannelExtension: Extension {
    /// Applies state to the channel transaction graph
    fn build_graph(
        &self,
        tx_graph: &mut channel::TxGraph,
        remote: bool,
    ) -> Result<(), channel::Error>;
}

/// Channel constructor specific methods
pub trait ChannelConstructor: ChannelExtension + Default {
    fn enrich_funding(
        &self,
        psbt: &mut Psbt,
        funding: &Funding,
    ) -> Result<(), channel::Error>;
}
