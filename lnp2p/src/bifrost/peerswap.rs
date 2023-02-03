// LNP P2P library, plmeneting both bolt (BOLT) and Bifrost P2P messaging
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

use amplify::{Display, Slice32};
use bitcoin::hashes::{sha256, sha256t};
use bitcoin::Txid;
use lnpbp::chain::AssetId;
use secp256k1::{PublicKey, SecretKey};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};

use crate::bolt;

pub const PROTOCOL_VERSION: u16 = 1;
pub const BIFROST_APP_PEERSWAP: u16 = 0x8008;

// SHA256("bifrost:swap")
const SWAP_ID_MIDSTATE: [u8; 32] = [
    0x4e, 0x2e, 0x6e, 0xb2, 0xa3, 0xda, 0x16, 0xbc, 0x03, 0xe3, 0x38, 0x30,
    0xb3, 0xfa, 0xae, 0x6f, 0xe2, 0x76, 0x00, 0x1b, 0x2e, 0x79, 0xf1, 0x8f,
    0xd3, 0x8c, 0x43, 0xdc, 0x79, 0xfb, 0x99, 0xdd,
];

/// Tag used for [`SwapId`] hash type
pub struct SwapIdTag;

impl sha256t::Tag for SwapIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(SWAP_ID_MIDSTATE);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    Default,
    Wrapper,
    From,
    NetworkEncode,
    NetworkDecode
)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex, BorrowSlice)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SwapId(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

impl SwapId {
    #[inline]
    pub fn random() -> Self {
        SwapId::from(Slice32::random())
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    NetworkEncode,
    NetworkDecode
)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
#[network_encoding(use_tlv)]
pub struct SwapInRequestMsg {
    pub protocol_version: u64,
    pub swap_id: SwapId,
    pub asset: Option<AssetId>,
    pub network: String,
    pub scid: bolt::ChannelId,
    pub amount: u64,
    pub pubkey: PublicKey,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ValidationError {
    /// Network and asset has different value.
    NetworkMismatch,

    /// Unknown Network {0}
    UnknownNetwork(String),
}

impl SwapInRequestMsg {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let _network_ok = {
            match self.network.as_str() {
                "mainnet" => Ok(()),
                "testnet" => Ok(()),
                "testnet3" => Ok(()),
                "signet" => Ok(()),
                "regtest" => Ok(()),
                x => Err(ValidationError::UnknownNetwork(x.to_string())),
            }
        }?;

        Ok(())
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    NetworkEncode,
    NetworkDecode
)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
#[network_encoding(use_tlv)]
pub struct SwapInAgreementMsg {
    pub protocol_version: u64,
    pub swap_id: SwapId,
    pub pubkey: PublicKey,
    pub premium: u64,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Debug,
    Display,
    NetworkEncode,
    NetworkDecode
)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
#[network_encoding(use_tlv)]
pub struct SwapOutRequestMsg {
    pub protocol_version: u64,
    pub swap_id: SwapId,
    pub asset: Option<AssetId>,
    pub network: String,
    pub scid: bolt::ChannelId,
    pub amount: u64,
    pub pubkey: PublicKey,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Debug,
    Display,
    NetworkEncode,
    NetworkDecode
)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
#[network_encoding(use_tlv)]
pub struct SwapOutAgreementMsg {
    pub protocol_version: u64,
    pub swap_id: SwapId,
    pub pubkey: PublicKey,
    pub payreq: String,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Debug,
    Display,
    NetworkEncode,
    NetworkDecode
)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
#[network_encoding(use_tlv)]
pub struct OpeningTxBroadcastedMsg {
    pub swap_id: SwapId,
    pub payreq: String,
    pub tx_id: Txid,
    pub script_out: u64,
    pub blinding_key: SecretKey,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Debug,
    Display,
    NetworkEncode,
    NetworkDecode
)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
#[network_encoding(use_tlv)]
pub struct CancelMsg {
    pub swap_id: SwapId,
    pub message: String,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Debug,
    Display,
    NetworkEncode,
    NetworkDecode
)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
#[network_encoding(use_tlv)]
pub struct CoopCloseMsg {
    pub swap_id: SwapId,
    pub message: String,
    pub privkey: SecretKey,
}
