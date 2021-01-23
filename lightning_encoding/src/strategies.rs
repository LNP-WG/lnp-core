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

use std::io;
use strict_encoding::{self, StrictDecode, StrictEncode};

use crate::BigSize;
use crate::{Error, LightningDecode, LightningEncode};

// Defining strategies:
pub struct AsStrict;
pub struct AsBigSize;
pub struct AsBitcoinHash;
pub struct AsWrapped;

pub trait Strategy {
    type Strategy;
}

impl<T> LightningEncode for T
where
    T: Strategy + Clone,
    amplify::Holder<T, <T as Strategy>::Strategy>: LightningEncode,
{
    #[inline]
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, io::Error> {
        amplify::Holder::new(self.clone()).lightning_encode(e)
    }
}

impl<T> LightningDecode for T
where
    T: Strategy,
    amplify::Holder<T, <T as Strategy>::Strategy>: LightningDecode,
{
    #[inline]
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(amplify::Holder::lightning_decode(d)?.into_inner())
    }
}

impl<T> LightningEncode for amplify::Holder<T, AsStrict>
where
    T: StrictEncode,
{
    #[inline]
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, io::Error> {
        self.as_inner().strict_encode(e).map_err(|err| match err {
            strict_encoding::Error::Io(io_err) => io_err.into(),
            _ => io::Error::from(io::ErrorKind::InvalidData),
        })
    }
}

impl<T> LightningDecode for amplify::Holder<T, AsStrict>
where
    T: StrictDecode,
{
    #[inline]
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(T::strict_decode(d)?))
    }
}

impl<T> LightningEncode for amplify::Holder<T, AsBitcoinHash>
where
    T: bitcoin::hashes::Hash + strict_encoding::StrictEncode,
{
    #[inline]
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, io::Error> {
        self.as_inner().strict_encode(e).map_err(|err| match err {
            strict_encoding::Error::Io(io_err) => io_err.into(),
            _ => io::Error::from(io::ErrorKind::InvalidData),
        })
    }
}

impl<T> LightningDecode for amplify::Holder<T, AsBitcoinHash>
where
    T: bitcoin::hashes::Hash + strict_encoding::StrictDecode,
{
    #[inline]
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(T::strict_decode(d).map_err(|err| {
            Error::DataIntegrityError(err.to_string())
        })?))
    }
}

impl<T> LightningEncode for amplify::Holder<T, AsWrapped>
where
    T: amplify::Wrapper,
    T::Inner: LightningEncode,
{
    #[inline]
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, io::Error> {
        self.as_inner().as_inner().lightning_encode(e)
    }
}

impl<T> LightningDecode for amplify::Holder<T, AsWrapped>
where
    T: amplify::Wrapper,
    T::Inner: LightningDecode,
{
    #[inline]
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(T::from_inner(T::Inner::lightning_decode(d)?)))
    }
}

impl<T> LightningDecode for amplify::Holder<T, AsBigSize>
where
    T: From<BigSize>,
{
    #[inline]
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(T::from(BigSize::lightning_decode(d)?)))
    }
}

impl<T> LightningEncode for amplify::Holder<T, AsBigSize>
where
    T: Into<BigSize>,
    T: Copy,
{
    #[inline]
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, io::Error> {
        (*self.as_inner()).into().lightning_encode(e)
    }
}

impl From<strict_encoding::Error> for Error {
    #[inline]
    fn from(err: strict_encoding::Error) -> Self {
        match err {
            strict_encoding::Error::Io(io_err) => Error::Io(io_err),
            strict_encoding::Error::DataNotEntirelyConsumed => {
                Error::DataNotEntirelyConsumed
            }
            strict_encoding::Error::DataIntegrityError(msg) => {
                Error::DataIntegrityError(msg)
            }
            other => Error::DataIntegrityError(other.to_string()),
        }
    }
}
