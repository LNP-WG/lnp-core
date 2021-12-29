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

use amplify::DumbDefault;
use std::any::Any;
use std::collections::BTreeMap;
use std::io::{Read, Write};

use internet2::presentation::sphinx::{Hop, SphinxPayload};
use p2p::legacy::{Messages, PaymentRequest};
use strict_encoding::{StrictDecode, StrictEncode};

use crate::{extension, Extension, RouterExtension};

pub type ExtensionQueue<N> =
    BTreeMap<N, Box<dyn RouterExtension<Identity = N>>>;

/// Marker trait for creating routing extension nomenclatures, defining order in
/// which extensions are called to construct the route.
///
/// Extension nomenclature is an enum with members convertible into `u16`
/// representation
pub trait Nomenclature
where
    Self: extension::Nomenclature,
{
    type HopPayload: SphinxPayload;

    fn default_extensions() -> Vec<Box<dyn RouterExtension<Identity = Self>>>;

    /// Updates router extension structure from peer message. Processed before
    /// each of the registered extensions gets [`Extension::update_from_peer`]
    fn update_from_peer(
        router: &mut Router<Self>,
        message: &Messages,
    ) -> Result<(), <Self as extension::Nomenclature>::Error>;
}

/// Generic router consisting of a queue of routing extensions, implementing
/// specific router logic
pub struct Router<N>
where
    N: Nomenclature,
{
    extensions: ExtensionQueue<N>,
}

impl<N> Router<N>
where
    N: Nomenclature,
{
    /// Constructs router with all used extensions
    pub fn new(
        extensions: impl IntoIterator<Item = Box<dyn RouterExtension<Identity = N>>>,
    ) -> Self {
        Self {
            extensions: extensions.into_iter().fold(
                ExtensionQueue::<N>::new(),
                |mut queue, e| {
                    queue.insert(e.identity(), e);
                    queue
                },
            ),
        }
    }

    /// Gets extension reference by extension identifier
    pub fn extension<E>(&'static self, id: N) -> Option<&E> {
        self.extensions
            .get(&id)
            .map(|ext| &*ext as &dyn Any)
            .and_then(|ext| ext.downcast_ref())
    }

    /// Gets mutable extension reference by extension identifier
    pub fn extension_mut<E>(&'static mut self, id: N) -> Option<&mut E> {
        self.extensions
            .get_mut(&id)
            .map(|ext| &mut *ext as &mut dyn Any)
            .and_then(|ext| ext.downcast_mut())
    }

    /// Adds new extension to the channel.
    ///
    /// Will be effective onl upon next channel state update.
    #[inline]
    pub fn add_extender(
        &mut self,
        extension: Box<dyn RouterExtension<Identity = N>>,
    ) {
        self.extensions.insert(extension.identity(), extension);
    }
}

impl<N> Default for Router<N>
where
    N: 'static + Nomenclature + Default,
{
    fn default() -> Self {
        Router::new(N::default_extensions())
    }
}

impl<N> StrictEncode for Router<N>
where
    N: 'static + Nomenclature,
    N::State: StrictEncode,
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

impl<N> StrictDecode for Router<N>
where
    N: 'static + Nomenclature,
    N::State: StrictDecode,
{
    fn strict_decode<D: Read>(d: D) -> Result<Self, strict_encoding::Error> {
        let state = N::State::strict_decode(d)?;
        let mut router = Router::default();
        router.load_state(&state);
        Ok(router)
    }
}

impl<N> Extension for Router<N>
where
    N: extension::Nomenclature + Nomenclature,
{
    type Identity = N;

    #[inline]
    fn identity(&self) -> Self::Identity {
        N::default()
    }

    fn update_from_peer(
        &mut self,
        message: &Messages,
    ) -> Result<(), <N as extension::Nomenclature>::Error> {
        N::update_from_peer(self, message)?;
        self.extensions
            .iter_mut()
            .try_for_each(|(_, e)| e.update_from_peer(message))?;
        Ok(())
    }

    fn load_state(
        &mut self,
        state: &<Self::Identity as extension::Nomenclature>::State,
    ) {
        for extension in self.extensions.values_mut() {
            extension.load_state(&state);
        }
    }

    fn store_state(
        &self,
        state: &mut <Self::Identity as extension::Nomenclature>::State,
    ) {
        for extension in self.extensions.values() {
            extension.store_state(state);
        }
    }
}

impl<N> RouterExtension for Router<N>
where
    N: Nomenclature + 'static,
{
    fn new() -> Box<dyn RouterExtension<Identity = Self::Identity>>
    where
        Self: Sized,
    {
        Box::new(Router::default())
    }

    fn build_route(
        &mut self,
        payment: PaymentRequest,
        route: &mut Vec<Hop<N::HopPayload>>,
    ) {
        for extension in self.extensions.values_mut() {
            extension.build_route(payment, route);
        }
    }
}
