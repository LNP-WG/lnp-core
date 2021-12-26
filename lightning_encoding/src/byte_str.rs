// Network encoding for lightning network peer protocol data types
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

use std::io;
use std::ops::Deref;

use super::{Error, LightningDecode, LightningEncode};

impl LightningEncode for &[u8] {
    fn lightning_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let mut len = self.len();
        // We handle oversize problems at the level of `usize` value
        // serializaton
        len += len.lightning_encode(&mut e)?;
        e.write_all(self)?;
        Ok(len)
    }
}

impl<const LEN: usize> LightningEncode for [u8; LEN] {
    fn lightning_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(self)?;
        Ok(self.len())
    }
}

impl<const LEN: usize> LightningDecode for [u8; LEN] {
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut ret = [0u8; LEN];
        d.read_exact(&mut ret)?;
        Ok(ret)
    }
}

impl LightningEncode for Box<[u8]> {
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.deref().lightning_encode(e)
    }
}

impl LightningDecode for Box<[u8]> {
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::lightning_decode(&mut d)?;
        let mut ret = vec![0u8; len];
        d.read_exact(&mut ret)?;
        Ok(ret.into_boxed_slice())
    }
}

impl LightningEncode for &str {
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_bytes().lightning_encode(e)
    }
}

impl LightningEncode for String {
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_bytes().lightning_encode(e)
    }
}

impl LightningDecode for String {
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(String::from_utf8_lossy(&Vec::<u8>::lightning_decode(d)?)
            .to_string())
    }
}
