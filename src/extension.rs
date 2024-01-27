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

use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use amplify::DumbDefault;
use internet2::presentation::sphinx::Hop;
use p2p::bolt::PaymentRequest;
use wallet::psbt::Psbt;

use crate::channel::tx_graph::TxGraph;
use crate::channel::Funding;
use crate::{channel, extension, router};

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
    type PeerMessage;
    type UpdateMessage;
    type UpdateRequest;
}

pub trait Extension<N: Nomenclature> {
    fn identity(&self) -> N;

    /// Perform a sate change and produce a message which should be communicated
    /// to peers notifying them about the state change
    #[allow(dead_code, unused_variables)]
    fn state_change(
        &mut self,
        request: &<N as extension::Nomenclature>::UpdateRequest,
        message: &mut <N as extension::Nomenclature>::PeerMessage,
    ) -> Result<(), <N as extension::Nomenclature>::Error> {
        // Do nothing by default
        Ok(())
    }

    /// Updates extension state from the data taken from the message received
    /// from the remote peer
    fn update_from_peer(
        &mut self,
        message: &<N as extension::Nomenclature>::PeerMessage,
    ) -> Result<(), <N as extension::Nomenclature>::Error>;

    /// Updates extension state from some local data
    fn update_from_local(
        &mut self,
        message: &<N as extension::Nomenclature>::UpdateMessage,
    ) -> Result<(), <N as extension::Nomenclature>::Error>;

    fn load_state(&mut self, state: &N::State);
    fn store_state(&self, state: &mut N::State);
}

pub trait RouterExtension<N>
where
    N: router::Nomenclature,
    Self: Extension<N>,
{
    /// Constructs boxed extension objects which can be inserted into router
    /// extension pipeline
    #[allow(clippy::new_ret_no_self)]
    fn new() -> Box<dyn RouterExtension<N>>
    where
        Self: Sized;

    fn build_route(
        &mut self,
        payment: PaymentRequest,
        route: &mut Vec<Hop<<N as router::Nomenclature>::HopPayload>>,
    );
}

pub trait ChannelExtension<N>
where
    N: channel::Nomenclature,
    N::State: channel::State,
    Self: Extension<N>,
{
    /// Constructs boxed extension objects which can be inserted into channel
    /// extension pipeline
    #[allow(clippy::new_ret_no_self)]
    fn new() -> Box<dyn ChannelExtension<N>>
    where
        Self: Sized;

    /// Applies state to the channel transaction graph
    fn build_graph(
        &self,
        tx_graph: &mut TxGraph,
        remote: bool,
    ) -> Result<(), <N as Nomenclature>::Error>;
}

/// Channel constructor specific methods
pub trait ChannelConstructor<N>
where
    N: channel::Nomenclature,
    N::State: channel::State,
    Self: ChannelExtension<N> + Default,
{
    fn enrich_funding(
        &self,
        psbt: &mut Psbt,
        funding: &Funding,
    ) -> Result<(), <N as Nomenclature>::Error>;
}
