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
#[macro_use]
extern crate amplify_derive;

mod big_size;
mod bitcoin;
mod byte_str;
mod collections;
mod error;
// mod net; - no need in encoding network addresses for lightning p2p protocol
mod primitives;
pub mod strategies;

pub use big_size::BigSize;
pub use error::Error;
pub use strategies::Strategy;

// -----------------------------------------------------------------------------

use std::io;

/// Lightning-network specific encoding as defined in BOLT-1, 2, 3...
pub trait LightningEncode {
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, io::Error>;
    fn lightning_serialize(&self) -> Vec<u8> {
        let mut encoder = vec![];
        self.lightning_encode(&mut encoder)
            .expect("Memory encoders can't fail");
        encoder
    }
}

/// Lightning-network specific encoding as defined in BOLT-1, 2, 3...
pub trait LightningDecode
where
    Self: Sized,
{
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error>;
    fn lightning_deserialize(data: &impl AsRef<[u8]>) -> Result<Self, Error> {
        let mut decoder = io::Cursor::new(data);
        let rv = Self::lightning_decode(&mut decoder)?;
        let consumed = decoder.position() as usize;

        // Fail if data are not consumed entirely.
        if consumed == data.as_ref().len() {
            Ok(rv)
        } else {
            Err(Error::DataNotEntirelyConsumed)?
        }
    }
}

pub fn lightning_serialize<T>(data: &T) -> Vec<u8>
where
    T: LightningEncode,
{
    data.lightning_serialize()
}

pub fn lightning_deserialize<T>(data: &impl AsRef<[u8]>) -> Result<T, Error>
where
    T: LightningDecode,
{
    T::lightning_deserialize(data)
}
