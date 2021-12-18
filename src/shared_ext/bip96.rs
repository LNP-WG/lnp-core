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

use lnp2p::legacy::Messages;
use wallet::lex_order::LexOrder;

use crate::bolt::ExtensionId;
use crate::{channel, ChannelExtension, Extension};

#[derive(Debug, Default)]
pub struct Bip96;

impl Extension for Bip96 {
    type Identity = ExtensionId;

    #[inline]
    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>>
    where
        Self: Sized,
    {
        Box::new(Bip96::default())
    }

    #[inline]
    fn identity(&self) -> Self::Identity {
        ExtensionId::Bip96
    }

    #[inline]
    fn update_from_peer(&mut self, _: &Messages) -> Result<(), channel::Error> {
        // Nothing to do here: peers can't tell us anything that will be related
        // to the stateless lexicographic output ordering. So ignoring their
        // messages all together
        Ok(())
    }

    #[inline]
    fn extension_state(&self) -> Box<dyn channel::State> {
        Box::new(())
    }
}

impl ChannelExtension for Bip96 {
    #[inline]
    fn channel_state(&self) -> Box<dyn channel::State> {
        Box::new(())
    }

    #[inline]
    fn apply(
        &self,
        tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error> {
        tx_graph.cmt_outs.lex_order();
        tx_graph
            .vec_mut()
            .into_iter()
            .for_each(|(_, _, tx)| tx.lex_order());
        Ok(())
    }
}
