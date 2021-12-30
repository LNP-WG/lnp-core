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

use std::any::Any;
use std::collections::BTreeMap;
use std::io::{Read, Write};

use amplify::DumbDefault;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use strict_encoding::{StrictDecode, StrictEncode};

use super::tx_graph::TxGraph;
use super::Funding;
use crate::channel::FundingError;
use crate::extension;
use crate::{ChannelConstructor, ChannelExtension, Extension};

/// Marker trait for creating channel extension nomenclatures, defining order in
/// which extensions are applied to the channel transaction structure.
///
/// Extension nomenclature is an enum with members convertible into `u16`
/// representation
pub trait Nomenclature: extension::Nomenclature
where
    <Self as extension::Nomenclature>::State: State,
{
    type Constructor: ChannelConstructor<Self>;

    /// Returns set of default channel extenders
    fn default_extenders() -> Vec<Box<dyn ChannelExtension<Self>>> {
        Vec::default()
    }

    /// Returns set of default channel modifiers
    fn default_modifiers() -> Vec<Box<dyn ChannelExtension<Self>>> {
        Vec::default()
    }

    /// Updates channel extension structure from peer message. Processed before
    /// each of the registered extensions gets [`Extension::update_from_peer`]
    fn update_from_peer(
        channel: &mut Channel<Self>,
        message: &Self::PeerMessage,
    ) -> Result<(), <Self as extension::Nomenclature>::Error>;
}

/// Trait for any data that can be used as a part of the channel state
pub trait State: StrictEncode + StrictDecode + DumbDefault {
    fn to_funding(&self) -> Funding;
    fn set_funding(&mut self, funding: &Funding);
}

pub type ExtensionQueue<N> = BTreeMap<N, Box<dyn ChannelExtension<N>>>;

/// Channel operates as a three sets of extensions, where each set is applied
/// to construct the transaction graph and the state in a strict order one after
/// other. The order of the extensions within each set is defined by the
/// concrete type implementing `extension::Nomenclature` marker trait, provided
/// as a type parameter `N`
#[derive(Getters)]
pub struct Channel<N>
where
    N: Nomenclature,
    N::State: State,
{
    /* TODO: Add channel graph cache.
             For this we need to track each state mutation and reset the cached data
    /// The most recent version of rendered [`TxGraph`] corresponding to the
    /// current channel state. Reset with each state update.
    #[getter(skip)]
    tx_graph: Option<TxGraph>,
     */
    /// This is a state that is shared / can be accessed by all channel
    /// extensions.
    ///
    /// It is not a part of the core extension since it must be always present
    /// in all channel types / under different channel cores
    funding: Funding,

    /// Constructor extensions constructs base transaction graph. There could
    /// be only a single extension of this type
    #[getter(as_mut)]
    constructor: N::Constructor,

    /// Extender extensions adds additional outputs to the transaction graph
    /// and the state data associated with these outputs, like HTLCs, PTLCs,
    /// anchored outputs, DLC-specific outs etc
    extenders: ExtensionQueue<N>,

    /// Modifier extensions do not change number of outputs, but may change
    /// their ordering or tweak individual inputs, outputs and public keys.
    /// These extensions may include: BIP96 lexicographic ordering, RGB, Liquid
    modifiers: ExtensionQueue<N>,
}

impl<N> Channel<N>
where
    N: 'static + Nomenclature,
    N::State: State,
{
    /// Constructs channel with all used extensions
    pub fn new(
        constructor: N::Constructor,
        extenders: impl IntoIterator<Item = Box<dyn ChannelExtension<N>>>,
        modifiers: impl IntoIterator<Item = Box<dyn ChannelExtension<N>>>,
    ) -> Self {
        Self {
            funding: Funding::new(),
            constructor,
            extenders: extenders.into_iter().fold(
                ExtensionQueue::<N>::new(),
                |mut queue, e| {
                    queue.insert(e.identity(), e);
                    queue
                },
            ),
            modifiers: modifiers.into_iter().fold(
                ExtensionQueue::<N>::new(),
                |mut queue, e| {
                    queue.insert(e.identity(), e);
                    queue
                },
            ),
        }
    }

    pub fn extension<E>(&'static self, id: N) -> Option<&E> {
        self.extenders
            .get(&id)
            .map(|ext| &*ext as &dyn Any)
            .and_then(|ext| ext.downcast_ref())
            .or_else(|| {
                self.modifiers
                    .get(&id)
                    .map(|ext| &*ext as &dyn Any)
                    .and_then(|ext| ext.downcast_ref())
            })
    }

    pub fn extension_mut<E>(&'static mut self, id: N) -> Option<&mut E> {
        self.extenders
            .get_mut(&id)
            .map(|ext| &mut *ext as &mut dyn Any)
            .and_then(|ext| ext.downcast_mut())
            .or_else(|| {
                self.modifiers
                    .get_mut(&id)
                    .map(|ext| &mut *ext as &mut dyn Any)
                    .and_then(|ext| ext.downcast_mut())
            })
    }

    /// Gets extender by extension identifier
    #[inline]
    pub fn extender(&self, id: N) -> Option<&Box<dyn ChannelExtension<N>>> {
        self.extenders.get(&id)
    }

    /// Gets modifier by extension identifier
    #[inline]
    pub fn modifier(&self, id: N) -> Option<&Box<dyn ChannelExtension<N>>> {
        self.modifiers.get(&id)
    }

    /// Gets mutable extender by extension identifier
    #[inline]
    pub fn extender_mut(
        &mut self,
        id: N,
    ) -> Option<&mut Box<dyn ChannelExtension<N>>> {
        self.extenders.get_mut(&id)
    }

    /// Gets mutable modifier by extension identifier
    #[inline]
    pub fn modifier_mut(
        &mut self,
        id: N,
    ) -> Option<&mut Box<dyn ChannelExtension<N>>> {
        self.modifiers.get_mut(&id)
    }

    /// Adds new extension to the channel.
    ///
    /// Will be effective onl upon next channel state update.
    #[inline]
    pub fn add_extender(&mut self, extension: Box<dyn ChannelExtension<N>>) {
        self.extenders.insert(extension.identity(), extension);
    }

    /// Adds new modifier to the channel.
    ///
    /// Will be effective onl upon next channel state update.
    #[inline]
    pub fn add_modifier(&mut self, modifier: Box<dyn ChannelExtension<N>>) {
        self.modifiers.insert(modifier.identity(), modifier);
    }

    /// Constructs current version of commitment transaction
    pub fn commitment_tx(
        &mut self,
        remote: bool,
    ) -> Result<Psbt, <N as extension::Nomenclature>::Error> {
        let mut tx_graph = TxGraph::from_funding(&self.funding);
        self.build_graph(&mut tx_graph, remote)?;
        Ok(tx_graph.render_cmt())
    }

    #[inline]
    pub fn set_funding_amount(&mut self, amount: u64) {
        self.funding = Funding::preliminary(amount)
    }
}

impl<N> Channel<N>
where
    N: 'static + Nomenclature,
    N::State: State,
    <N as extension::Nomenclature>::Error: From<FundingError>,
{
    /// Constructs the first commitment transaction (called "refund
    /// transaction") taking given funding outpoint.
    #[inline]
    pub fn refund_tx(
        &mut self,
        funding_psbt: Psbt,
        remote: bool,
    ) -> Result<Psbt, <N as extension::Nomenclature>::Error> {
        self.set_funding(funding_psbt)?;
        self.commitment_tx(remote)
    }

    #[inline]
    pub fn set_funding(
        &mut self,
        mut psbt: Psbt,
    ) -> Result<(), <N as extension::Nomenclature>::Error> {
        self.constructor.enrich_funding(&mut psbt, &self.funding)?;
        self.funding = Funding::with(psbt)?;
        Ok(())
    }
}

impl<N> Default for Channel<N>
where
    N: 'static + Nomenclature + Default,
    N::State: State,
{
    fn default() -> Self {
        Channel::new(
            N::Constructor::default(),
            N::default_extenders(),
            N::default_modifiers(),
        )
    }
}

impl<N> StrictEncode for Channel<N>
where
    N: 'static + Nomenclature,
    N::State: State,
{
    fn strict_encode<E: Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        let mut state = N::State::dumb_default();
        self.store_state(&mut state);
        state.strict_encode(e)
    }
}

impl<N> StrictDecode for Channel<N>
where
    N: 'static + Nomenclature,
    N::State: State,
{
    fn strict_decode<D: Read>(d: D) -> Result<Self, strict_encoding::Error> {
        let state = N::State::strict_decode(d)?;
        let mut channel = Channel::default();
        channel.load_state(&state);
        Ok(channel)
    }
}

/// Channel is the extension to itself :) so it receives the same input as any
/// other extension and just forwards it to them
impl<N> Extension<N> for Channel<N>
where
    N: 'static + Nomenclature,
    N::State: State,
{
    fn identity(&self) -> N {
        N::default()
    }

    fn update_from_peer(
        &mut self,
        message: &<N as extension::Nomenclature>::PeerMessage,
    ) -> Result<(), <N as extension::Nomenclature>::Error> {
        N::update_from_peer(self, message)?;
        self.constructor.update_from_peer(message)?;
        self.extenders
            .iter_mut()
            .try_for_each(|(_, e)| e.update_from_peer(message))?;
        self.modifiers
            .iter_mut()
            .try_for_each(|(_, e)| e.update_from_peer(message))?;
        Ok(())
    }

    fn load_state(&mut self, state: &N::State) {
        self.funding = state.to_funding();
        self.constructor.load_state(&state);
        for extension in self.extenders.values_mut() {
            extension.load_state(&state);
        }
        for extension in self.extenders.values_mut() {
            extension.load_state(&state);
        }
    }

    fn store_state(&self, state: &mut N::State) {
        state.set_funding(&self.funding);
        self.constructor.store_state(state);
        for extension in self.extenders.values() {
            extension.store_state(state);
        }
        for extension in self.extenders.values() {
            extension.store_state(state);
        }
    }
}

/// Channel is the extension to itself :) so it receives the same input as any
/// other extension and just forwards it to them. This is required for channel
/// composebility.
impl<N> ChannelExtension<N> for Channel<N>
where
    N: 'static + Nomenclature,
    N::State: State,
{
    #[inline]
    fn new() -> Box<dyn ChannelExtension<N>> {
        Box::new(Channel::default())
    }

    fn build_graph(
        &self,
        tx_graph: &mut TxGraph,
        as_remote_node: bool,
    ) -> Result<(), <N as extension::Nomenclature>::Error> {
        self.constructor.build_graph(tx_graph, as_remote_node)?;
        self.extenders
            .iter()
            .try_for_each(|(_, e)| e.build_graph(tx_graph, as_remote_node))?;
        self.modifiers
            .iter()
            .try_for_each(|(_, e)| e.build_graph(tx_graph, as_remote_node))?;
        Ok(())
    }
}

pub trait History {
    type State;
    type Error: std::error::Error;

    fn height(&self) -> usize;
    fn get(&self, height: usize) -> Result<Self::State, Self::Error>;
    fn top(&self) -> Result<Self::State, Self::Error>;
    fn bottom(&self) -> Result<Self::State, Self::Error>;
    fn dig(&self) -> Result<Self::State, Self::Error>;
    fn push(&mut self, state: Self::State) -> Result<&mut Self, Self::Error>;
}
