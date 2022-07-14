// LNP P2P library, plmeneting both bolt (BOLT) and Bifrost P2P messaging
// system for Lightning network protocol (LNP)
//
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

use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::io::{Read, Write};

use amplify::Wrapper;
use bitcoin::hashes::Hash;
use internet2::tlv;
use lightning_encoding::{LightningDecode, LightningEncode};
use lnpbp::chain::AssetId;

use super::{ChannelId, InitFeatures};

/// List of the assets for parsing as a TLV field type 1 inside [`Init`]
/// message.
#[derive(Wrapper, Clone, Eq, PartialEq, Default, Debug, From)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
pub struct AssetList(HashSet<AssetId>);

impl LightningEncode for AssetList {
    fn lightning_encode<E: Write>(
        &self,
        mut e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        self.0.iter().try_fold(0usize, |len, asset| {
            Ok(len + asset.lightning_encode(&mut e)?)
        })
    }
}

impl LightningDecode for AssetList {
    fn lightning_decode<D: Read>(
        mut d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        let mut vec = Vec::with_capacity(32);
        let len = d.read_to_end(&mut vec)?;
        if len % 32 != 0 {
            return Err(lightning_encoding::Error::DataIntegrityError(
                format!(
                    "Init/networks length {} is not proportional to 32 bytes",
                    len
                ),
            ));
        }
        let assets = vec
            .chunks(32)
            .into_iter()
            .map(AssetId::from_slice)
            .collect::<Result<HashSet<AssetId>, _>>()
            .expect("AssetId must be always constructable from 32-byte slice");
        Ok(AssetList(assets))
    }
}

/// Once authentication is complete, the first message reveals the features
/// supported or required by this node, even if this is a reconnection.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-init-message>
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
#[lightning_encoding(use_tlv)]
#[display("init({global_features}, {local_features})")]
#[display("init({global_features}, {local_features}, {assets:#?})")]
pub struct Init {
    pub global_features: InitFeatures,
    pub local_features: InitFeatures,

    #[lightning_encoding(tlv = 1)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 1))]
    pub assets: AssetList,

    #[lightning_encoding(unknown_tlvs)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(unknown_tlvs))]
    pub unknown_tlvs: tlv::Stream,
}

/// In order to allow for the existence of long-lived TCP connections, at
/// times it may be required that both ends keep alive the TCP connection
/// at the application level. Such messages also allow obfuscation of
/// traffic patterns.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-ping-and-pong-messages>
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
#[display("ping({pong_size})")]
pub struct Ping {
    pub pong_size: u16,
    pub ignored: Vec<u8>,
}

/// For simplicity of diagnosis, it's often useful to tell a peer that something
/// is incorrect.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-error-message>
#[derive(Clone, PartialEq, Eq, Debug, Error, LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
pub struct Error {
    /// The channel is referred to by channel_id, unless channel_id is 0 (i.e.
    /// all bytes are 0), in which case it refers to all channels.
    pub channel_id: ChannelId,

    /// Any specific error details, either as string or binary data
    pub data: Vec<u8>,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Error")?;
        if self.channel_id.is_wildcard() {
            f.write_str(" on all channels")?;
        } else {
            write!(f, " on channel {}", self.channel_id)?;
        }
        // NB: if data is not composed solely of printable ASCII characters (For
        // reference: the printable character set includes byte values 32
        // through 126, inclusive) SHOULD NOT print out data verbatim.
        if let Ok(msg) = String::from_utf8(self.data.clone()) {
            write!(f, ": {}", msg)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use amplify::hex::FromHex;
    use internet2::TypedEnum;
    use lightning_encoding::LightningDecode;

    use super::*;
    use crate::bolt::Messages;

    #[test]
    fn bolt1_testvec() {
        let init_msg = Messages::Init(Init {
            global_features: none!(),
            local_features: none!(),
            assets: none!(),
            unknown_tlvs: none!(),
        });
        assert_eq!(
            init_msg.serialize(),
            Vec::<u8>::from_hex("001000000000").unwrap()
        );
    }

    #[test]
    fn real_clightning_testvec() {
        // Real init message sent by c-lightning
        let init_recv = [
            // msg type
            0u8, 16, //
            // global features - 2 bytes
            0, 2, 34, 0, //
            // local features - 3 bytes
            0, 3, 2, 170, 162, //
            // TLV type = 1 (networks / assets)
            1, //
            // len
            32, //
            // network value
            111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99,
            247, 79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0,
            0, 0,
        ];
        let msg = Messages::lightning_deserialize(init_recv).unwrap();
        println!("{}", msg);
    }
}
