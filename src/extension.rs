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

use amplify::DumbDefault;
use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use internet2::presentation::sphinx::Hop;
use lnp2p::legacy::Messages;
use p2p::legacy::PaymentRequest;
use wallet::psbt::Psbt;

use crate::channel::tx_graph::TxGraph;
use crate::channel::Funding;
use crate::{channel, router};

/// Marker trait for creating extension nomenclatures, defining order in which
/// extensions are called to process the data.
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
    type State: DumbDefault;
    type Error: std::error::Error;
}

pub trait Extension {
    // TODO: Refactor into generic parameter, not type alias. This should allow
    //       use of the same extension under multiple nomenclatures.
    type Identity: Nomenclature;

    fn identity(&self) -> Self::Identity;

    /// Updates extension state from the data taken from the message received
    /// from the remote peer
    fn update_from_peer(
        &mut self,
        message: &Messages,
    ) -> Result<(), <Self::Identity as Nomenclature>::Error>;

    fn load_state(&mut self, state: &<Self::Identity as Nomenclature>::State);
    fn store_state(&self, state: &mut <Self::Identity as Nomenclature>::State);
}

pub trait RouterExtension
where
    Self: Extension,
    <Self as Extension>::Identity: router::Nomenclature,
{
    /// Constructs boxed extension objects which can be inserted into router
    /// extension pipeline
    fn new() -> Box<dyn RouterExtension<Identity = Self::Identity>>
    where
        Self: Sized;

    fn build_route(
        &mut self,
        payment: PaymentRequest,
        route: &mut Vec<Hop<<<Self as Extension>::Identity as router::Nomenclature>::HopPayload>>,
    );
}

pub trait ChannelExtension
where
    Self: Extension,
    <Self as Extension>::Identity: channel::Nomenclature,
    <<Self as Extension>::Identity as Nomenclature>::State: channel::State,
{
    /// Constructs boxed extension objects which can be inserted into channel
    /// extension pipeline
    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>>
    where
        Self: Sized;

    /// Applies state to the channel transaction graph
    fn build_graph(
        &self,
        tx_graph: &mut TxGraph,
        remote: bool,
    ) -> Result<(), <<Self as Extension>::Identity as Nomenclature>::Error>;
}

/// Channel constructor specific methods
pub trait ChannelConstructor
where
    Self: ChannelExtension + Default,
    <Self as Extension>::Identity: channel::Nomenclature,
    <<Self as Extension>::Identity as Nomenclature>::State: channel::State,
{
    fn enrich_funding(
        &self,
        psbt: &mut Psbt,
        funding: &Funding,
    ) -> Result<(), <<Self as Extension>::Identity as Nomenclature>::Error>;
}
