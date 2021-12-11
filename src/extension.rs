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

use lnp2p::legacy::Messages;
use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use super::channel;
use crate::channel::Channel;

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
    /// Returns default constructor
    fn default_constructor() -> Box<dyn ChannelExtension<Identity = Self>>;

    /// Returns set of default channel extenders
    fn default_extenders() -> Vec<Box<dyn ChannelExtension<Identity = Self>>> {
        Vec::default()
    }

    /// Returns set of default channel modifiers
    fn default_modifiers() -> Vec<Box<dyn ChannelExtension<Identity = Self>>> {
        Vec::default()
    }

    /// Updates core channel structure from peer message. Processed before each
    /// of the registered extensions gets [`Extension::update_from_peer`]
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

    /// Returns extension state for persistence & backups
    ///
    /// These are extension configuration data, like the data that are the part
    /// of the channel parameters negotiatied between peeers or preconfigured
    /// parameters from the configuration file
    fn extension_state(&self) -> Box<dyn channel::State>;
}

pub trait RoutingExtension: Extension {}

pub trait GossipExtension: Extension {}

pub trait ChannelExtension: Extension {
    /// Returns channel state for persistence & backups.
    ///
    /// These are channel-specific data generated from channel operations,
    /// including client-validated data
    fn channel_state(&self) -> Box<dyn channel::State>;

    /// Applies state to the channel transaction graph
    fn apply(
        &mut self,
        tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error>;
}
