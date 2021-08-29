mod _inet {
    use super::*;
    use inet2_addr::{InetAddr, InetSocketAddr, InetSocketAddrExt};

    impl Strategy for InetAddr {
        type Strategy = strategies::AsStrict;
    }

    impl Strategy for InetSocketAddr {
        type Strategy = strategies::AsStrict;
    }

    impl Strategy for InetSocketAddrExt {
        type Strategy = strategies::AsStrict;
    }
}

#[cfg(feature = "lnpbp")]
mod _lnpbp {
    use super::*;
    use lnpbp::chain::AssetId;

    impl Strategy for AssetId {
        type Strategy = strategies::AsBitcoinHash;
    }

    // TODO: Remove after proper TLV implementation
    impl LightningEncode for Option<AssetId> {
        fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            match self {
                Some(id) => id.lightning_encode(e),
                None => Ok(0),
            }
        }
    }

    impl LightningDecode for Option<AssetId> {
        fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            AssetId::lightning_decode(d).map(|id| Some(id)).or(Ok(None))
        }
    }
}

#[cfg(feature = "rgb")]
mod _rgb {
    use super::*;
    use rgb::{Consignment, Schema, Transition};

    impl Strategy for Consignment {
        type Strategy = strategies::AsStrict;
    }

    impl Strategy for Transition {
        type Strategy = strategies::AsStrict;
    }

    impl Strategy for Schema {
        type Strategy = strategies::AsWrapped;
    }
}
