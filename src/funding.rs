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

use bitcoin::util::psbt::raw::ProprietaryKey;
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use wallet::psbt;
use wallet::psbt::Psbt;

pub const PSBT_LNP_PROPRIETARY_PREFIX: &[u8] = b"LNP";
pub const PSBT_OUT_LNP_CHANNEL_FUNDING: u8 = 0x01;

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum Error {
    /// no funding output found in the funding transaction. The funding output
    /// must be marked with proprietary key having "LNP" prefix and 0x01
    /// subtype.
    NoFundingOutput,

    /// funding transaction does not contain output #{0} specified as a
    /// funding outpoint
    WrongOutput(u16),
}

/// Information about channel funding
#[derive(Getters, Clone, PartialEq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Funding {
    /// PSBT containing full information about the funding of the channel in a
    /// structured way.
    ///
    /// Channel is always funded with a single input, that is why we need a
    /// single PSBT. If channel needs to receive more funds, it will require a
    /// new funding transaction to be created, spending previous funding
    /// transaction output.
    psbt: Psbt,

    // Cached information extracted from PSBT, which is the master data source
    #[getter(as_copy)]
    txid: Txid,

    #[getter(as_copy)]
    output: u16,

    #[getter(as_copy)]
    amount: u64,

    #[getter(as_copy)]
    signing_parties: u8,

    #[getter(as_copy)]
    signing_threshold: u8,
}

impl Funding {
    /// Constructs empty funding information. Can be used only during initial
    /// channel setup.
    #[inline]
    pub(super) fn new() -> Funding {
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut {
                value: 0,
                script_pubkey: Default::default(),
            }],
        })
        .expect("dumb manual PSBT creation");
        psbt.outputs[0]
            .proprietary
            .insert(lnp_out_channel_funding_key(), vec![]);
        Funding::with(psbt).expect("dumb manual PSBT creation")
    }

    #[inline]
    pub fn with(psbt: Psbt) -> Result<Funding, Error> {
        psbt.extract_channel_funding()
    }

    #[inline]
    pub fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid, self.output as u32)
    }
}

fn lnp_out_channel_funding_key() -> ProprietaryKey {
    ProprietaryKey {
        prefix: PSBT_LNP_PROPRIETARY_PREFIX.to_vec(),
        subtype: PSBT_OUT_LNP_CHANNEL_FUNDING,
        key: vec![],
    }
}

fn psbt_funding_output_info(
    psbt: &Psbt,
) -> Result<(u16, &psbt::Output, &TxOut), Error> {
    let funding_key = lnp_out_channel_funding_key();
    psbt.outputs
        .iter()
        .zip(&psbt.global.unsigned_tx.output)
        .enumerate()
        .find(|(_, (output, _))| output.proprietary.get(&funding_key).is_some())
        .ok_or(Error::NoFundingOutput)
        .map(|(vout, (out, txout))| (vout as u16, out, txout))
}

pub trait PsbtLnpFunding {
    fn set_channel_funding_output(&mut self, vout: u16) -> Result<(), Error>;
    fn channel_funding_outpoint(&self) -> Result<OutPoint, Error>;
    fn extract_channel_funding(self) -> Result<Funding, Error>;
}

impl PsbtLnpFunding for Psbt {
    fn set_channel_funding_output(&mut self, vout: u16) -> Result<(), Error> {
        self.outputs
            .get_mut(vout as usize)
            .map(|out| {
                out.proprietary
                    .insert(lnp_out_channel_funding_key(), vec![]);
            })
            .ok_or(Error::WrongOutput(vout))
    }

    fn channel_funding_outpoint(&self) -> Result<OutPoint, Error> {
        let (vout, _, _) = psbt_funding_output_info(&self)?;
        Ok(OutPoint::new(self.global.unsigned_tx.txid(), vout as u32))
    }

    fn extract_channel_funding(self) -> Result<Funding, Error> {
        let (vout, _out, txout) = psbt_funding_output_info(&self)?;
        let amount = txout.value;
        let txid = self.global.unsigned_tx.txid();
        // TODO: Parse number of signing parties and signing threshold from
        //       witness script attached to the funding output
        Ok(Funding {
            psbt: self,
            txid,
            output: vout as u16,
            amount,
            signing_parties: 2,
            signing_threshold: 2,
        })
    }
}
