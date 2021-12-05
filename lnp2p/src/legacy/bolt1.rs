// LNP P2P library, plmeneting both legacy (BOLT) and Bifrost P2P messaging
// system for Lightning network protocol (LNP)
//
// Written in 2020-2021 by
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

use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Display, Formatter};

use lnpbp::chain::AssetId;

use super::{ChannelId, InitFeatures};

/// Once authentication is complete, the first message reveals the features
/// supported or required by this node, even if this is a reconnection.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-init-message>
#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
#[lightning_encoding(use_tlv)]
#[display("init({global_features}, {local_features}, {assets:#?})")]
pub struct Init {
    pub global_features: InitFeatures,
    pub local_features: InitFeatures,
    #[lightning_encoding(tlv = 1)]
    pub assets: HashSet<AssetId>,
    #[lightning_encoding(unknown_tlvs)]
    pub unknown_tlvs: BTreeMap<usize, Box<[u8]>>,
}

/// In order to allow for the existence of long-lived TCP connections, at
/// times it may be required that both ends keep alive the TCP connection
/// at the application level. Such messages also allow obfuscation of
/// traffic patterns.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-ping-and-pong-messages>
#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
#[display("ping({pong_size})")]
pub struct Ping {
    pub ignored: Vec<u8>,
    pub pong_size: u16,
}

/// For simplicity of diagnosis, it's often useful to tell a peer that something
/// is incorrect.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-error-message>
#[derive(Clone, PartialEq, Debug, Error, LightningEncode, LightningDecode)]
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
    use super::*;
    use crate::legacy::Messages;
    use amplify::hex::FromHex;
    use internet2::TypedEnum;

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
            Vec::<u8>::from_hex("00100000000000").unwrap()
        );
    }
}
