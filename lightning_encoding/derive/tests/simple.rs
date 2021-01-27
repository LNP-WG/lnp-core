#[allow(dead_code)]
#[macro_use]
extern crate lightning_encoding_derive;

#[derive(LightningEncode, LightningDecode)]
struct Me(u8);

#[derive(LightningEncode, LightningDecode)]
struct One {
    a: Vec<u8>,

    #[tlv(type = 1)]
    b: Option<u16>,

    #[tlv(unknown)]
    c: usize,
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

fn main() {}
