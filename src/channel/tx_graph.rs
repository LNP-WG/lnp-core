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

//! The module must be used only by libraries providing new channel types and
//! not by the final LN node implementations.

use std::collections::BTreeMap;

use bitcoin::{Transaction, TxIn, TxOut};
use wallet::psbt::{self, Psbt};

use crate::channel::Funding;

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
    pub cmt_outs: Vec<(TxOut, psbt::Output)>,
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
            .or_insert_with(Default::default)
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
        let outputs = self
            .cmt_outs
            .clone()
            .into_iter()
            .map(|(txout, _)| txout)
            .collect();
        let cmt_tx = Transaction {
            version: self.cmt_version,
            lock_time: self.cmt_locktime,
            input: vec![TxIn {
                previous_output: self.funding.outpoint(),
                script_sig: empty!(),
                sequence: self.cmt_sequence,
                witness: empty!(),
            }],
            output: outputs,
        };
        let mut psbt = Psbt::from_unsigned_tx(cmt_tx).expect(
            "PSBT construction fails only if script_sig and witness are not \
             empty; which is not the case here",
        );
        let funding_psbt = self.funding.psbt();
        let funding_output = self.funding.output() as usize;
        psbt.inputs[0].witness_utxo = Some(
            funding_psbt.global.unsigned_tx.output[funding_output].clone(),
        );
        psbt.inputs[0].witness_script =
            funding_psbt.outputs[funding_output].witness_script.clone();
        psbt.inputs[0].bip32_derivation = funding_psbt.outputs[funding_output]
            .bip32_derivation
            .clone();
        for (index, output) in psbt.outputs.iter_mut().enumerate() {
            *output = self.cmt_outs[index].1.clone();
        }
        psbt
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
