// Network encoding for lightning network peer protocol data types
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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io;

use super::{Error, LightningDecode, LightningEncode};

impl<T> LightningEncode for Option<T>
where
    T: LightningEncode,
{
    fn lightning_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(1 + match self {
            None => e.write(&[0u8])?,
            Some(val) => {
                e.write(&[1u8])?;
                val.lightning_encode(&mut e)?
            }
        })
    }
}

impl<T> LightningDecode for Option<T>
where
    T: LightningDecode,
{
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut flag = [0u8; 1];
        d.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(None),
            1 => Ok(Some(T::lightning_decode(&mut d)?)),
            _ => Err(Error::DataIntegrityError(s!("wrong optional encoding"))),
        }
    }
}

impl<T> LightningEncode for Vec<T>
where
    T: LightningEncode,
{
    fn lightning_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len().lightning_encode(&mut e)?;
        self.iter()
            .try_fold(len, |len, item| Ok(len + item.lightning_encode(&mut e)?))
    }
}

impl<T> LightningDecode for Vec<T>
where
    T: LightningDecode,
{
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let count = usize::lightning_decode(&mut d)?;
        let mut vec = Vec::with_capacity(count);
        for _ in 0..count {
            vec.push(T::lightning_decode(&mut d)?)
        }
        Ok(vec)
    }
}

impl<T> LightningEncode for HashSet<T>
where
    T: LightningEncode,
{
    fn lightning_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len().lightning_encode(&mut e)?;
        self.iter()
            .try_fold(len, |len, item| Ok(len + item.lightning_encode(&mut e)?))
    }
}

impl<T> LightningDecode for HashSet<T>
where
    T: LightningDecode + Eq + std::hash::Hash,
{
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let count = usize::lightning_decode(&mut d)?;
        let mut set = HashSet::with_capacity(count);
        for _ in 0..count {
            set.insert(T::lightning_decode(&mut d)?);
        }
        Ok(set)
    }
}

impl<K, V> LightningEncode for HashMap<K, V>
where
    K: LightningEncode,
    V: LightningEncode,
{
    fn lightning_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len().lightning_encode(&mut e)?;
        self.iter().try_fold(len, |len, (k, v)| {
            Ok(len
                + k.lightning_encode(&mut e)?
                + v.lightning_encode(&mut e)?)
        })
    }
}

impl<K, V> LightningDecode for HashMap<K, V>
where
    K: LightningDecode + Eq + std::hash::Hash,
    V: LightningDecode,
{
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let count = usize::lightning_decode(&mut d)?;
        let mut set = HashMap::with_capacity(count);
        for _ in 0..count {
            set.insert(
                K::lightning_decode(&mut d)?,
                V::lightning_decode(&mut d)?,
            );
        }
        Ok(set)
    }
}

impl<T> LightningEncode for BTreeSet<T>
where
    T: LightningEncode,
{
    fn lightning_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len().lightning_encode(&mut e)?;
        self.iter()
            .try_fold(len, |len, item| Ok(len + item.lightning_encode(&mut e)?))
    }
}

impl<T> LightningDecode for BTreeSet<T>
where
    T: LightningDecode + Ord,
{
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let count = usize::lightning_decode(&mut d)?;
        let mut set = BTreeSet::new();
        for _ in 0..count {
            set.insert(T::lightning_decode(&mut d)?);
        }
        Ok(set)
    }
}

impl<K, V> LightningEncode for BTreeMap<K, V>
where
    K: LightningEncode,
    V: LightningEncode,
{
    fn lightning_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len().lightning_encode(&mut e)?;
        self.iter().try_fold(len, |len, (k, v)| {
            Ok(len
                + k.lightning_encode(&mut e)?
                + v.lightning_encode(&mut e)?)
        })
    }
}

impl<K, V> LightningDecode for BTreeMap<K, V>
where
    K: LightningDecode + Ord,
    V: LightningDecode,
{
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let count = usize::lightning_decode(&mut d)?;
        let mut set = BTreeMap::new();
        for _ in 0..count {
            set.insert(
                K::lightning_decode(&mut d)?,
                V::lightning_decode(&mut d)?,
            );
        }
        Ok(set)
    }
}
