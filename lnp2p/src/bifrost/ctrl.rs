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

use super::{ChannelId, ProtocolList};

/// Once authentication is complete, the first message reveals the features
/// supported or required by this node, even if this is a reconnection.
#[derive(
    Clone, PartialEq, Eq, Debug, Display, NetworkEncode, NetworkDecode,
)]
#[network_encoding(use_tlv)]
#[display("init({protocols}, {assets:#?})")]
pub struct Init {
    pub protocols: ProtocolList,
    pub assets: HashSet<AssetId>,
    #[network_encoding(unknown_tlvs)]
    pub unknown_tlvs: BTreeMap<usize, Box<[u8]>>,
}

/// In order to allow for the existence of long-lived TCP connections, at
/// times it may be required that both ends keep alive the TCP connection
/// at the application level. Such messages also allow obfuscation of
/// traffic patterns.
#[derive(
    Clone, PartialEq, Eq, Debug, Display, NetworkEncode, NetworkDecode,
)]
#[display("ping({pong_size})")]
pub struct Ping {
    pub ignored: Vec<u8>,
    pub pong_size: u16,
}

/// For simplicity of diagnosis, it's often useful to tell a peer that something
/// is incorrect.
#[derive(Clone, PartialEq, Debug, Error, NetworkEncode, NetworkDecode)]
#[network_encoding(use_tlv)]
pub struct Error {
    pub channel_id: Option<ChannelId>,
    pub errno: u64,
    pub message: Option<String>,
    /// Any additiona error details
    #[network_encoding(unknown_tlvs)]
    pub unknown_tlvs: BTreeMap<usize, Box<[u8]>>,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Error #{}", self.errno)?;
        if let Some(channel_id) = self.channel_id {
            write!(f, " on channel {}", channel_id)?;
        }
        // NB: if data is not composed solely of printable ASCII characters (For
        // reference: the printable character set includes byte values 32
        // through 126, inclusive) SHOULD NOT print out data verbatim.
        if let Some(ref msg) = self.message {
            write!(f, ": {}", msg)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bifrost::Messages;
    use amplify::hex::FromHex;
    use internet2::TypedEnum;

    #[test]
    fn bolt1_testvec() {
        let init_msg = Messages::Init(Init {
            protocols: none!(),
            assets: none!(),
            unknown_tlvs: none!(),
        });
        assert_eq!(
            init_msg.serialize(),
            Vec::<u8>::from_hex("1000000000000000").unwrap()
        );
    }
}
