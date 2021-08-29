// Derive macros for lightning network peer protocol encodings
//
// Written in 2020-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

#![allow(dead_code)]

#[macro_use]
extern crate amplify_derive;

use lightning_encoding::{LightningDecode, LightningEncode};

#[derive(LightningEncode, LightningDecode)]
struct Me(u8);

#[derive(LightningEncode, LightningDecode)]
#[lightning_encoding(crate = lightning_encoding)]
struct One {
    a: Vec<u8>,
}

#[derive(LightningEncode, LightningDecode)]
struct Heap(Box<[u8]>);

#[derive(LightningEncode, LightningDecode)]
#[lightning_encoding(crate = lightning_encoding)]
enum Hi {
    /// Docstring
    First(u8),
    Second(Heap),
    Third,
    Fourth {
        heap: Heap,
    },
    Seventh,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[repr(u8)]
#[derive(LightningEncode, LightningDecode)]
pub enum ContractType {
    #[display("singlesig")]
    SingleSig,

    #[display("multisig")]
    MultiSig,

    #[display("script")]
    Script,
}

#[derive(LightningEncode, LightningDecode)]
#[lightning_encoding(by_order)]
#[repr(u8)]
enum ByOrder {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
}

#[derive(LightningEncode, LightningDecode)]
#[lightning_encoding(by_value)]
#[repr(u8)]
enum ByValue {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
}

// All variants have custom values apart from the first one, which should has
// value = 1
#[derive(LightningEncode, LightningDecode)]
#[lightning_encoding(by_value)]
#[repr(u8)]
enum CustomValues {
    Bit8 = 1,

    #[lightning_encoding(value = 11)]
    Bit16 = 2,

    #[lightning_encoding(value = 12)]
    Bit32 = 4,

    #[lightning_encoding(value = 13)]
    Bit64 = 8,
}

#[derive(LightningEncode, LightningDecode)]
#[lightning_encoding(by_order, repr = u16)]
#[repr(u16)]
enum U16 {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
}

#[derive(LightningEncode, LightningDecode)]
struct Skipping {
    pub data: Vec<u8>,

    // This will initialize the field upon decoding with Option::default()
    // value
    #[lightning_encoding(skip)]
    pub ephemeral: Option<bool>,
}

#[derive(LightningEncode, LightningDecode)]
enum CustomErr<Err>
where
    Err: std::error::Error + LightningEncode + LightningDecode,
{
    Other(Err),
}

fn main() {
    assert_eq!(ByValue::Bit64.lightning_serialize().unwrap(), vec![8])
}
