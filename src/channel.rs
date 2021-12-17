// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
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
use std::fmt::Debug;
use std::hash::Hash;

use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{Transaction, TxIn, TxOut};
use lnp2p::legacy::Messages;

use super::extension::{self, ChannelExtension, Extension};
use crate::bolt::{Lifecycle, PolicyError};
use crate::{funding, Funding};

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// Error in channel funding: {0}
    #[from]
    Funding(funding::Error),

    /// Extension-specific error: {0}
    Extension(String),

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
}

/// Marker trait for any data that can be used as a part of the channel state
pub trait State {}

// Allow empty state
impl State for () {}

/// Channel state is a sum of the state from all its extensions
pub type IntegralState<N> = BTreeMap<N, Box<dyn State>>;
impl<N> State for IntegralState<N> where N: extension::Nomenclature {}

pub type ExtensionQueue<N> =
    BTreeMap<N, Box<dyn ChannelExtension<Identity = N>>>;

/// Channel operates as a three sets of extensions, where each set is applied
/// to construct the transaction graph and the state in a strict order one after
/// other. The order of the extensions within each set is defined by the
/// concrete type implementing `extension::Nomenclature` marker trait, provided
/// as a type parameter `N`
#[derive(Getters)]
pub struct Channel<N>
where
    N: extension::Nomenclature,
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
    N: 'static + extension::Nomenclature,
{
    /// Constructs channel with all used extensions
    pub fn new(
        constructor: N::Constructor,
        extenders: impl IntoIterator<Item = Box<dyn ChannelExtension<Identity = N>>>,
        modifiers: impl IntoIterator<Item = Box<dyn ChannelExtension<Identity = N>>>,
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

    /// Gets extender by extension identifier
    #[inline]
    pub fn extender(
        &self,
        id: N,
    ) -> Option<&Box<dyn ChannelExtension<Identity = N>>> {
        self.extenders.get(&id)
    }

    /// Gets modifier by extension identifier
    #[inline]
    pub fn modifier(
        &self,
        id: N,
    ) -> Option<&Box<dyn ChannelExtension<Identity = N>>> {
        self.modifiers.get(&id)
    }

    /// Gets mutable extender by extension identifier
    #[inline]
    pub fn extender_mut(
        &mut self,
        id: N,
    ) -> Option<&mut Box<dyn ChannelExtension<Identity = N>>> {
        self.extenders.get_mut(&id)
    }

    /// Gets mutable modifier by extension identifier
    #[inline]
    pub fn modifier_mut(
        &mut self,
        id: N,
    ) -> Option<&mut Box<dyn ChannelExtension<Identity = N>>> {
        self.modifiers.get_mut(&id)
    }

    /// Adds new extension to the channel.
    ///
    /// Will be effective onl upon next channel state update.
    #[inline]
    pub fn add_extender(
        &mut self,
        extension: Box<dyn ChannelExtension<Identity = N>>,
    ) {
        self.extenders.insert(extension.identity(), extension);
    }

    /// Adds new modifier to the channel.
    ///
    /// Will be effective onl upon next channel state update.
    #[inline]
    pub fn add_modifier(
        &mut self,
        modifier: Box<dyn ChannelExtension<Identity = N>>,
    ) {
        self.modifiers.insert(modifier.identity(), modifier);
    }

    // Move to TxGraph
    /// Constructs current version of commitment transaction
    pub fn commitment_tx(&mut self) -> Result<Psbt, Error> {
        let mut tx_graph = TxGraph::from_funding(&self.funding);
        self.apply(&mut tx_graph)?;
        Ok(tx_graph.render_cmt())
    }

    /// Constructs the first commitment transaction (called "refund
    /// transaction") taking given funding outpoint.
    #[inline]
    pub fn refund_tx(&mut self, funding_psbt: Psbt) -> Result<Psbt, Error> {
        self.set_funding(funding_psbt)?;
        self.commitment_tx()
    }

    #[inline]
    pub fn set_funding(&mut self, psbt: Psbt) -> Result<(), Error> {
        self.funding = Funding::with(psbt)?;
        Ok(())
    }
}

impl<N> Default for Channel<N>
where
    N: 'static + extension::Nomenclature + Default,
{
    fn default() -> Self {
        Channel::new(
            N::Constructor::default(),
            N::default_extenders(),
            N::default_modifiers(),
        )
    }
}

/// Channel is the extension to itself :) so it receives the same input as any
/// other extension and just forwards it to them
impl<N> Extension for Channel<N>
where
    N: 'static + extension::Nomenclature,
{
    type Identity = N;

    #[inline]
    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>> {
        Box::new(Channel::default())
    }

    fn identity(&self) -> Self::Identity {
        N::default()
    }

    fn update_from_peer(&mut self, message: &Messages) -> Result<(), Error> {
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

    fn extension_state(&self) -> Box<dyn State> {
        let mut data = IntegralState::<N>::new();
        data.insert(
            self.constructor.identity(),
            self.constructor.extension_state(),
        );
        self.extenders.iter().for_each(|(id, e)| {
            data.insert(*id, e.extension_state());
        });
        self.modifiers.iter().for_each(|(id, e)| {
            data.insert(*id, e.extension_state());
        });
        Box::new(data)
    }
}

/// Channel is the extension to itself :) so it receives the same input as any
/// other extension and just forwards it to them. This is required for channel
/// composebility.
impl<N> ChannelExtension for Channel<N>
where
    N: 'static + extension::Nomenclature,
{
    fn channel_state(&self) -> Box<dyn State> {
        let mut data = IntegralState::<N>::new();
        data.insert(
            self.constructor.identity(),
            self.constructor.extension_state(),
        );
        self.extenders.iter().for_each(|(id, e)| {
            data.insert(*id, e.extension_state());
        });
        self.modifiers.iter().for_each(|(id, e)| {
            data.insert(*id, e.extension_state());
        });
        Box::new(data)
    }

    fn apply(&self, tx_graph: &mut TxGraph) -> Result<(), Error> {
        self.constructor.apply(tx_graph)?;
        self.extenders
            .iter()
            .try_for_each(|(_, e)| e.apply(tx_graph))?;
        self.modifiers
            .iter()
            .try_for_each(|(_, e)| e.apply(tx_graph))?;
        Ok(())
    }
}

pub trait TxRole: Clone + From<u16> + Into<u16> {}
pub trait TxIndex: Clone + From<u64> + Into<u64> {}

impl TxRole for u16 {}
impl TxIndex for u64 {}

#[derive(Getters, Clone, PartialEq)]
pub struct TxGraph<'channel> {
    /// Read-only data for extensions on the number of channel parties
    funding: &'channel Funding,
    pub cmt_version: i32,
    pub cmt_locktime: u32,
    pub cmt_sequence: u32,
    pub cmt_outs: Vec<TxOut>,
    graph: BTreeMap<u16, BTreeMap<u64, Psbt>>,
}

impl<'channel> TxGraph<'channel>
where
    Self: 'channel,
{
    pub fn from_funding(funding: &'channel Funding) -> TxGraph<'channel> {
        TxGraph {
            funding,
            // TODO: Check that we have commitment version set correctly
            cmt_version: 0,
            cmt_locktime: 0,
            cmt_sequence: 0,
            cmt_outs: vec![],
            graph: bmap! {},
        }
    }

    pub fn tx<R, I>(&self, role: R, index: I) -> Option<&Psbt>
    where
        R: TxRole,
        I: TxIndex,
    {
        self.graph
            .get(&role.into())
            .and_then(|v| v.get(&index.into()))
    }

    pub fn tx_mut<R, I>(&mut self, role: R, index: I) -> Option<&mut Psbt>
    where
        R: TxRole,
        I: TxIndex,
    {
        self.graph
            .get_mut(&role.into())
            .and_then(|v| v.get_mut(&index.into()))
    }

    pub fn insert_tx<R, I>(
        &mut self,
        role: R,
        index: I,
        psbt: Psbt,
    ) -> Option<Psbt>
    where
        R: TxRole,
        I: TxIndex,
    {
        self.graph
            .entry(role.into())
            .or_insert(empty!())
            .insert(index.into(), psbt)
    }

    pub fn len(&self) -> usize {
        self.graph
            .iter()
            .fold(0usize, |sum, (_, map)| sum + map.len())
    }

    pub fn last_index<R>(&self, role: R) -> usize
    where
        R: TxRole,
    {
        match self.graph.get(&role.into()) {
            Some(map) => map.len(),
            None => 0usize,
        }
    }

    pub fn render(&self) -> Vec<Psbt> {
        let mut txes = Vec::with_capacity(self.len());
        let cmt_tx = self.render_cmt();
        txes.push(cmt_tx);
        txes.extend(self.graph.values().flat_map(|v| v.values().cloned()));
        txes
    }

    pub fn render_cmt(&self) -> Psbt {
        let cmt_tx = Transaction {
            version: self.cmt_version,
            lock_time: self.cmt_locktime,
            input: vec![TxIn {
                previous_output: self.funding.outpoint(),
                script_sig: empty!(),
                sequence: self.cmt_sequence,
                witness: empty!(),
            }],
            output: self.cmt_outs.clone(),
        };
        Psbt::from_unsigned_tx(cmt_tx).expect(
            "PSBT construction fails only if script_sig and witness are not \
             empty; which is not the case here",
        )
    }

    pub fn iter(&self) -> GraphIter {
        GraphIter::with(self)
    }

    pub fn vec_mut(&mut self) -> Vec<(u16, u64, &mut Psbt)> {
        let vec = self
            .graph
            .iter_mut()
            .flat_map(|(role, map)| {
                map.iter_mut().map(move |(index, tx)| (*role, *index, tx))
            })
            .collect::<Vec<_>>();
        vec
    }
}

pub struct GraphIter<'iter, 'channel> {
    graph: &'iter TxGraph<'channel>,
    curr_role: u16,
    curr_index: u64,
}

impl<'iter, 'channel> GraphIter<'iter, 'channel> {
    fn with(graph: &'iter TxGraph<'channel>) -> Self {
        Self {
            graph,
            curr_role: 0,
            curr_index: 0,
        }
    }
}

impl<'iter, 'channel> Iterator for GraphIter<'iter, 'channel> {
    type Item = (u16, u64, &'iter Psbt);

    fn next(&mut self) -> Option<Self::Item> {
        let tx = self.graph.tx(self.curr_role, self.curr_index).or_else(|| {
            self.curr_role += 1;
            self.curr_index = 0;
            self.graph.tx(self.curr_role, self.curr_index)
        });
        self.curr_index += 1;
        tx.map(|tx| (self.curr_role, self.curr_index, tx))
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
