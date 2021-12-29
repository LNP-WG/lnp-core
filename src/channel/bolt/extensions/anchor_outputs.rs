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

use crate::channel::bolt::{BoltExt, ChannelState, Error};
use crate::channel::tx_graph::TxGraph;
use crate::{ChannelExtension, Extension};

#[derive(Debug, Default)]
pub struct AnchorOutputs;

impl Extension<BoltExt> for AnchorOutputs {
    #[inline]
    fn identity(&self) -> BoltExt {
        BoltExt::AnchorOutputs
    }

    #[inline]
    fn update_from_peer(&mut self, _: &Messages) -> Result<(), Error> {
        // TODO: Implement
        Ok(())
    }

    fn load_state(&mut self, _state: &ChannelState) {
        // Nothing to do here
    }

    fn store_state(&self, _state: &mut ChannelState) {
        // Nothing to do here
    }
}

impl ChannelExtension<BoltExt> for AnchorOutputs {
    #[inline]
    fn new() -> Box<dyn ChannelExtension<BoltExt>>
    where
        Self: Sized,
    {
        Box::new(AnchorOutputs::default())
    }

    #[inline]
    fn build_graph(
        &self,
        _tx_graph: &mut TxGraph,
        _as_remote_node: bool,
    ) -> Result<(), Error> {
        todo!("implement anchor outputs")
    }
}
