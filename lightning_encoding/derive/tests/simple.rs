#[allow(dead_code)]
#[macro_use]
extern crate lightning_encoding_derive;

use ::core::marker::PhantomData;

#[derive(LightningEncode, LightningDecode)]
struct Me(u8);

#[derive(LightningEncode, LightningDecode)]
struct One {
    a: Vec<u8>,
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

//#[derive(LightningEncode, LightningDecode)]
enum Hi<T> {
    /// Docstring
    First(u8),
    Second(Heap),
    Third,
    Fourth {
        other: Other,
    },
    Fifth(PhantomData<T>),
    Seventh,
}

//#[derive(LightningEncode, LightningDecode)]
enum CustomErr<E: std::error::Error> {
    Other(E),
}

fn main() {}
