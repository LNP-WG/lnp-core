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

use p2p::legacy::Messages;

use crate::bolt::ExtensionId;
use crate::{channel, ChannelExtension, Extension};

#[derive(Debug, Default)]
pub struct AnchorOutputs;

impl Extension for AnchorOutputs {
    type Identity = ExtensionId;

    #[inline]
    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>>
    where
        Self: Sized,
    {
        Box::new(AnchorOutputs::default())
    }

    #[inline]
    fn identity(&self) -> Self::Identity {
        ExtensionId::AnchorOutputs
    }

    #[inline]
    fn update_from_peer(&mut self, _: &Messages) -> Result<(), channel::Error> {
        // TODO: Implement
        Ok(())
    }

    #[inline]
    fn extension_state(&self) -> Box<dyn channel::State> {
        Box::new(())
    }
}

impl ChannelExtension for AnchorOutputs {
    #[inline]
    fn channel_state(&self) -> Box<dyn channel::State> {
        Box::new(())
    }

    #[inline]
    fn apply(
        &self,
        _tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error> {
        todo!("implement anchor outputs")
    }
}
