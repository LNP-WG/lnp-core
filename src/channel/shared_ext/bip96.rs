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

use crate::channel::bolt::{BoltExt, ChannelState, Error};
use crate::channel::tx_graph::TxGraph;
use crate::{channel, extension, ChannelExtension, Extension};

#[derive(Debug, Default)]
pub struct Bip96;

impl Extension<BoltExt> for Bip96 {
    #[inline]
    fn identity(&self) -> BoltExt {
        BoltExt::Bip96
    }

    fn update_from_local(&mut self, _message: &()) -> Result<(), Error> {
        // Nothing to do here so far
        Ok(())
    }

    #[inline]
    fn update_from_peer(&mut self, _: &Messages) -> Result<(), Error> {
        // Nothing to do here: peers can't tell us anything that will be related
        // to the stateless lexicographic output ordering. So ignoring their
        // messages all together
        Ok(())
    }

    fn load_state(&mut self, _state: &ChannelState) {
        // Nothing to do here
    }

    fn store_state(&self, _state: &mut ChannelState) {
        // Nothing to do here
    }
}

impl<N> ChannelExtension<N> for Bip96
where
    Self: Extension<N>,
    N: channel::Nomenclature,
    N::State: channel::State,
{
    #[inline]
    fn new() -> Box<dyn ChannelExtension<N>>
    where
        Self: Sized,
    {
        Box::new(Bip96::default())
    }

    #[inline]
    fn build_graph(
        &self,
        tx_graph: &mut TxGraph,
        _as_remote_node: bool,
    ) -> Result<(), <N as extension::Nomenclature>::Error> {
        tx_graph.cmt_outs.lex_order();
        tx_graph
            .vec_mut()
            .into_iter()
            .for_each(|(_, _, tx)| tx.lex_order());
        Ok(())
    }
}
