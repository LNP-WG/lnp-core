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

use internet2::presentation::sphinx::{Hop, SphinxPayload};
use p2p::legacy::{Messages, PaymentRequest};

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

impl<N> Router<N> where N: Nomenclature {}

impl<N> Extension for Router<N>
where
    N: extension::Nomenclature + Nomenclature,
{
    type Identity = N;

    fn identity(&self) -> Self::Identity {
        todo!()
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
    N: Nomenclature,
{
    fn new() -> Box<dyn RouterExtension<Identity = Self::Identity>>
    where
        Self: Sized,
    {
        todo!()
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
