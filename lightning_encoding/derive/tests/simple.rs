// Derive macros for lightning network peer protocol encodings
//
// Written in 2020-2022 by
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

// TODO: Implement lightning encoding derive test harness like in
//       strict_encoding_derive

#[macro_use]
extern crate lightning_encoding_derive;

use internet2::tlv;

#[derive(LightningEncode, LightningDecode)]
struct Me(u8);

#[derive(LightningEncode, LightningDecode)]
#[lightning_encoding(use_tlv)]
struct One {
    field_a: Vec<u8>,

    #[lightning_encoding(tlv = 1)]
    tlv_int: Option<u16>,

    #[lightning_encoding(tlv = 2)]
    tlv_int2: Option<u16>,

    #[lightning_encoding(unknown_tlvs)]
    rest_of_tlvs: tlv::Stream,
}

#[derive(LightningEncode, LightningDecode)]
struct Heap(Box<[u8]>);

#[derive(LightningEncode, LightningDecode)]
struct You {
    //    a: (),
    b: Vec<u8>,
}

#[derive(LightningEncode, LightningDecode)]
struct Other {
    //    a: (),
    b: u8,
}
