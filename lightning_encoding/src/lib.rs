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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]

#[cfg(feature = "derive")]
#[allow(unused_imports)]
#[macro_use]
extern crate lightning_encoding_derive as derive;
pub use derive::{LightningDecode, LightningEncode};

#[allow(unused_imports)]
#[macro_use]
extern crate amplify;

mod big_size;
mod bitcoin;
mod byte_str;
mod collections;
mod error;
// mod net; - no need in encoding network addresses for lightning p2p protocol
mod primitives;
pub mod strategies;

// -----------------------------------------------------------------------------
use std::io;

pub use big_size::BigSize;
pub use error::Error;
pub use strategies::Strategy;
pub use strict_encoding::TlvError;

/// Lightning-network specific encoding as defined in BOLT-1, 2, 3...
pub trait LightningEncode {
    /// Encode with the given [`std::io::Write`] instance; must return result
    /// with either amount of bytes encoded – or implementation-specific
    /// error type.
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, Error>;

    /// Serializes data as a byte array using
    /// [`LightningEncode::lightning_encode`] function.
    fn lightning_serialize(&self) -> Result<Vec<u8>, Error> {
        let mut encoder = vec![];
        self.lightning_encode(&mut encoder)?;
        Ok(encoder)
    }
}

/// Lightning-network specific encoding as defined in BOLT-1, 2, 3...
pub trait LightningDecode
where
    Self: Sized,
{
    /// Decode with the given [`std::io::Read`] instance; must either
    /// construct an instance or return implementation-specific error type.
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error>;

    /// Tries to deserialize byte array into the current type using
    /// [`LightningDecode::lightning_decode`] function.
    fn lightning_deserialize(data: impl AsRef<[u8]>) -> Result<Self, Error> {
        let mut decoder = io::Cursor::new(data.as_ref());
        let rv = Self::lightning_decode(&mut decoder)?;
        let consumed = decoder.position() as usize;

        // Fail if data are not consumed entirely.
        if consumed == data.as_ref().len() {
            Ok(rv)
        } else {
            Err(Error::DataNotEntirelyConsumed)
        }
    }
}

/// Convenience method for strict encoding of data structures implementing
/// [`LightningEncode`] into a byte vector.
pub fn lightning_serialize<T>(data: &T) -> Result<Vec<u8>, Error>
where
    T: LightningEncode,
{
    data.lightning_serialize()
}

/// Convenience method for strict decoding of data structures implementing
/// [`LightningDecode`] from any byt data source.
pub fn lightning_deserialize<T>(data: impl AsRef<[u8]>) -> Result<T, Error>
where
    T: LightningDecode,
{
    T::lightning_deserialize(data)
}
