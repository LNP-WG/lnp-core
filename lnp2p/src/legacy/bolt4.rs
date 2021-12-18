// LNP P2P library, plmeneting both legacy (BOLT) and Bifrost P2P messaging
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

use amplify::DumbDefault;
use bitcoin::hashes::{sha256, Hmac};

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[display("onion_packet(v{version}, to: {public_key}, ...)")]
pub struct OnionPacket {
    pub version: u8,
    pub public_key: bitcoin::secp256k1::PublicKey,
    pub hop_data: Vec<u8>, //[u8; 20 * 65],
    pub hmac: Hmac<sha256::Hash>,
}

impl DumbDefault for OnionPacket {
    fn dumb_default() -> Self {
        OnionPacket {
            version: 0,
            public_key: dumb_pubkey!(),
            hop_data: empty!(),
            hmac: zero!(),
        }
    }
}
