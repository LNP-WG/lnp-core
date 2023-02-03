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

use std::borrow::Borrow;
use std::fmt::{self, Display, Formatter};
use std::io::{Read, Write};
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::bech32::{self, FromBase32, ToBase32};
use bitcoin::hashes::{sha256, sha256t, Hash, HashEngine};
use bitcoin::secp256k1::XOnlyPublicKey;
use strict_encoding::net::{
    AddrFormat, DecodeError, RawAddr, Transport, Uniform, UniformAddr, ADDR_LEN,
};
use strict_encoding::{self, StrictDecode, StrictEncode};

use crate::bifrost::ChannelParams;

// SHA256("bifrost:channel")
const CHANNEL_ID_MIDSTATE: [u8; 32] = [
    0, 79, 153, 191, 3, 7, 224, 35, 234, 47, 114, 213, 138, 22, 15, 17, 27,
    122, 131, 124, 85, 22, 92, 114, 24, 218, 119, 230, 233, 173, 106, 218,
];

/// Bech32m prefix for channel id encoding
pub const CHANNEL_BECH32_HRP: &str = "lnch";

/// Tag used for [`ChannelId`] hash type
pub struct ChannelIdTag;

impl sha256t::Tag for ChannelIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(CHANNEL_ID_MIDSTATE);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// A channel identifier
///
/// Represents commitment to the channel parameters and channel coordinator
/// node; any two distinct channels are guaranteed (with SHA256 collision
/// resistance level) to have a distinct channel ids.
#[derive(
    Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From
)]
#[wrapper(Debug, LowerHex, BorrowSlice)]
#[wrapper(Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ChannelId(sha256t::Hash<ChannelIdTag>);

impl ChannelId {
    /// Computes ChannelId from the provided data
    pub fn with(
        params: ChannelParams,
        node_pubkey: XOnlyPublicKey,
    ) -> ChannelId {
        let mut engine = ChannelId::engine();
        params
            .strict_encode(&mut engine)
            .expect("memory encoding of channel parameters");
        engine.input(&node_pubkey.serialize());
        ChannelId::from_engine(engine)
    }

    /// Constructs library id from a binary representation of the hash data
    #[inline]
    pub fn from_bytes(array: [u8; ChannelId::LEN]) -> ChannelId {
        ChannelId(sha256t::Hash::<ChannelIdTag>::from_inner(array))
    }

    /// Returns fixed-size array of inner representation of the library id
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_inner()
    }
}

impl Hash for ChannelId {
    type Engine = <sha256t::Hash<ChannelIdTag> as Hash>::Engine;
    type Inner = <sha256t::Hash<ChannelIdTag> as Hash>::Inner;

    const LEN: usize = 32;
    const DISPLAY_BACKWARD: bool = false;

    #[inline]
    fn engine() -> Self::Engine {
        sha256t::Hash::<ChannelIdTag>::engine()
    }

    #[inline]
    fn from_engine(e: Self::Engine) -> Self {
        Self(sha256t::Hash::from_engine(e))
    }

    #[inline]
    fn from_slice(sl: &[u8]) -> Result<Self, bitcoin::hashes::Error> {
        Ok(Self(sha256t::Hash::from_slice(sl)?))
    }

    #[inline]
    fn into_inner(self) -> Self::Inner {
        self.0.into_inner()
    }

    #[inline]
    fn as_inner(&self) -> &Self::Inner {
        self.0.as_inner()
    }

    #[inline]
    fn from_inner(inner: Self::Inner) -> Self {
        Self(sha256t::Hash::from_inner(inner))
    }

    fn all_zeros() -> Self {
        Self(sha256t::Hash::all_zeros())
    }
}

impl strict_encoding::Strategy for ChannelId {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

/// Error parsing [`ChannelId`] bech32m representation
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[display(doc_comments)]
pub enum ChannelIdError {
    /// Error reported by bech32 library
    #[display(inner)]
    #[from]
    Bech32(bech32::Error),

    /// ChannelId must start with `lnch1` and not `{0}`
    InvalidHrp(String),

    /// ChannelId must be encoded with Bech32m variant and not Bech32
    InvalidVariant,

    /// ChannelId data must have length of 32 bytes
    #[from]
    InvalidLength(bitcoin::hashes::Error),
}

impl ::std::error::Error for ChannelIdError {
    fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
        match self {
            ChannelIdError::Bech32(err) => Some(err),
            ChannelIdError::InvalidLength(err) => Some(err),
            ChannelIdError::InvalidHrp(_) | ChannelIdError::InvalidVariant => {
                None
            }
        }
    }
}

impl Display for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes: &[u8] = self.borrow();
        let s = bech32::encode(
            CHANNEL_BECH32_HRP,
            bytes.to_base32(),
            bech32::Variant::Bech32m,
        )
        .map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

impl FromStr for ChannelId {
    type Err = ChannelIdError;

    fn from_str(s: &str) -> Result<Self, ChannelIdError> {
        let (hrp, b32, variant) = bech32::decode(s)?;
        if hrp != CHANNEL_BECH32_HRP {
            return Err(ChannelIdError::InvalidHrp(hrp));
        }
        if variant != bech32::Variant::Bech32m {
            return Err(ChannelIdError::InvalidVariant);
        }
        let data = Vec::<u8>::from_base32(&b32)?;
        ChannelId::from_slice(&data).map_err(ChannelIdError::from)
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Display, Debug, Error)]
#[display(doc_comments)]
/// incorrect naming for protocol {_0}: protocol name in Bifrost can contain
/// only ASCII alphanumeric characters and dashes
pub struct ProtocolNameError(pub String);

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, From
)]
pub struct ProtocolList(Vec<ProtocolName>);

impl IntoIterator for ProtocolList {
    type Item = ProtocolName;
    type IntoIter = std::vec::IntoIter<ProtocolName>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ProtocolList {
    type Item = &'a ProtocolName;
    type IntoIter = std::slice::Iter<'a, ProtocolName>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<ProtocolName> for ProtocolList {
    fn from_iter<T: IntoIterator<Item = ProtocolName>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl ProtocolList {
    pub fn new(protocol: impl Into<ProtocolName>) -> Self {
        Self(vec![protocol.into()])
    }

    pub fn with<I>(list: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<ProtocolName>,
    {
        Self(list.into_iter().map(I::Item::into).collect())
    }

    pub fn add(&mut self, protocol: impl Into<ProtocolName>) {
        self.0.push(protocol.into())
    }

    pub fn extend<I>(&mut self, list: I)
    where
        I: IntoIterator,
        I::Item: Into<ProtocolName>,
    {
        for protocol in list {
            self.add(protocol)
        }
    }

    #[inline]
    pub fn iter(&self) -> std::slice::Iter<ProtocolName> {
        self.0.iter()
    }
}

impl Display for ProtocolList {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut len = self.0.len();
        for protocol in self {
            Display::fmt(protocol, f)?;
            len -= 1;
            if len > 0 {
                f.write_str(" ")?;
            }
        }
        Ok(())
    }
}

impl FromStr for ProtocolList {
    type Err = ProtocolNameError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split(' ')
            .filter(|s| !s.is_empty())
            .map(ProtocolName::from_str)
            .collect()
    }
}

impl StrictEncode for ProtocolList {
    #[inline]
    fn strict_encode<E: Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        self.to_string().strict_encode(e)
    }
}

impl StrictDecode for ProtocolList {
    #[inline]
    fn strict_decode<D: Read>(d: D) -> Result<Self, strict_encoding::Error> {
        let s = String::strict_decode(d)?;
        Self::from_str(&s).map_err(|_| {
            strict_encoding::Error::DataIntegrityError(format!(
                "invalid Bifrost protocol list value `{}`",
                s
            ))
        })
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From
)]
#[derive(NetworkEncode, NetworkDecode)]
#[display(inner)]
pub struct ProtocolName(String);

impl FromStr for ProtocolName {
    type Err = ProtocolNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.chars().any(|ch| {
            ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '-'
        }) {
            Ok(ProtocolName(s.to_owned()))
        } else {
            Err(ProtocolNameError(s.to_owned()))
        }
    }
}

#[derive(Clone, Debug, From, PartialEq, Eq, Hash, PartialOrd, Ord, Copy)]
pub enum AnnouncedNodeAddr {
    /// An IPv4 address/port on which the peer is listening.
    IpV4 {
        /// The 4-byte IPv4 address
        addr: [u8; 4],
        /// The port on which the node is listening
        port: u16,
    },
    /// An IPv6 address/port on which the peer is listening.
    IpV6 {
        /// The 16-byte IPv6 address
        addr: [u8; 16],
        /// The port on which the node is listening
        port: u16,
    },
    /// A modern Tor onion address/port on which the peer is listening.
    /// To create the human-readable "hostname", concatenate ed25519_pubkey,
    /// checksum, and version, wrap as base32 and append ".onion".
    OnionV3 {
        /// The ed25519 long-term public key of the peer
        ed25519_pubkey: [u8; 32],
    },
}

impl Uniform for AnnouncedNodeAddr {
    fn addr_format(&self) -> AddrFormat {
        match self {
            AnnouncedNodeAddr::IpV4 { .. } => AddrFormat::IpV4,
            AnnouncedNodeAddr::IpV6 { .. } => AddrFormat::IpV6,
            AnnouncedNodeAddr::OnionV3 { .. } => AddrFormat::OnionV3,
        }
    }

    fn addr(&self) -> RawAddr {
        match self {
            AnnouncedNodeAddr::IpV4 { addr, .. } => {
                let mut ip = [0u8; ADDR_LEN];
                ip[29..].copy_from_slice(addr);
                ip
            }

            AnnouncedNodeAddr::IpV6 { addr, .. } => {
                let mut ip = [0u8; ADDR_LEN];
                ip[17..].copy_from_slice(addr);
                ip
            }

            AnnouncedNodeAddr::OnionV3 { ed25519_pubkey, .. } => {
                let mut ip = [0u8; ADDR_LEN];
                ip[1..].copy_from_slice(ed25519_pubkey);
                ip
            }
        }
    }

    fn port(&self) -> Option<u16> {
        match self {
            // How to remove these unused variables?
            AnnouncedNodeAddr::IpV4 { port, .. } => Some(*port),
            AnnouncedNodeAddr::IpV6 { port, .. } => Some(*port),
            AnnouncedNodeAddr::OnionV3 { .. } => None,
        }
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        Some(Transport::Tcp)
    }

    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        match addr.addr_format() {
            AddrFormat::IpV4 => {
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&addr.addr[29..]);
                Ok(AnnouncedNodeAddr::IpV4 {
                    addr: ip,
                    port: match addr.port {
                        Some(p) => p,
                        _ => return Err(DecodeError::InsufficientData),
                    },
                })
            }

            AddrFormat::IpV6 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&addr.addr[17..]);
                Ok(AnnouncedNodeAddr::IpV6 {
                    addr: ip,
                    port: match addr.port {
                        Some(p) => p,
                        _ => return Err(DecodeError::InsufficientData),
                    },
                })
            }

            AddrFormat::OnionV3 => {
                let mut ip = [0u8; 32];
                ip.copy_from_slice(&addr.addr[1..]);
                Ok(AnnouncedNodeAddr::OnionV3 { ed25519_pubkey: ip })
            }

            _ => Err(DecodeError::InvalidAddr),
        }
    }

    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        AnnouncedNodeAddr::from_uniform_addr_lossy(addr)
    }
}

impl strict_encoding::Strategy for AnnouncedNodeAddr {
    type Strategy = strict_encoding::strategies::UsingUniformAddr;
}

#[derive(Wrapper, Clone, Debug, Display, Hash, Default, From, PartialEq, Eq)]
#[derive(NetworkEncode, NetworkDecode)]
#[display(Debug)]
pub struct AddressList(Vec<AnnouncedNodeAddr>);

#[cfg(test)]
mod test {
    use bitcoin::hashes::hex::FromHex;

    use super::*;

    #[test]
    fn test_address_encodings() {
        // Test vectors taken from https://github.com/rust-bitcoin/rust-lightning/blob/main/lightning/src/ln/msgs.rs
        let ipv4 = AnnouncedNodeAddr::IpV4 {
            addr: [255, 254, 253, 252],
            port: 9735,
        };

        let ipv6 = AnnouncedNodeAddr::IpV6 {
            addr: [
                255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244,
                243, 242, 241, 240,
            ],
            port: 9735,
        };

        let onion_v3 = AnnouncedNodeAddr::OnionV3 {
            ed25519_pubkey: [
                255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244,
                243, 242, 241, 240, 239, 238, 237, 236, 235, 234, 233, 232,
                231, 230, 229, 228, 227, 226, 225, 224,
            ],
        };

        let ipv4_target = Vec::<u8>::from_hex("000000000000000000000000000000000000000000000000000000000000fffefdfc260701").unwrap();
        let ipv6_target =
            Vec::<u8>::from_hex("010000000000000000000000000000000000fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0260701")
                .unwrap();
        let onionv3_target = Vec::<u8>::from_hex("0300fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0000001").unwrap();

        // Check strict encoding/decoding
        let ipv4_encoded = ipv4.strict_serialize().unwrap();
        let ipv6_encoded = ipv6.strict_serialize().unwrap();
        let onionv3_encoded = onion_v3.strict_serialize().unwrap();

        let ipv4_decoded =
            AnnouncedNodeAddr::strict_deserialize(&ipv4_target).unwrap();
        let ipv6_decoded =
            AnnouncedNodeAddr::strict_deserialize(&ipv6_target).unwrap();
        let onionv3_decoded =
            AnnouncedNodeAddr::strict_deserialize(&onionv3_target).unwrap();

        assert_eq!(ipv4, ipv4_decoded);
        assert_eq!(ipv6, ipv6_decoded);
        assert_eq!(onion_v3, onionv3_decoded);

        assert_eq!(ipv4_encoded, ipv4_target);
        assert_eq!(ipv6_encoded, ipv6_target);
        assert_eq!(onionv3_encoded, onionv3_target);

        // Check Uniform encoding/decoding
        let uniform_ipv4 = ipv4.to_uniform_addr();
        let uniform_ipv6 = ipv6.to_uniform_addr();
        let uniform_onionv3 = onion_v3.to_uniform_addr();

        let uniform_ipv4_decoded =
            AnnouncedNodeAddr::from_uniform_addr(uniform_ipv4).unwrap();
        let uniform_ipv6_decoded =
            AnnouncedNodeAddr::from_uniform_addr(uniform_ipv6).unwrap();
        let uniform_onionv3_decoded =
            AnnouncedNodeAddr::from_uniform_addr(uniform_onionv3).unwrap();

        // IPV4, IPV6 and OnionV2 should match
        assert_eq!(ipv4, uniform_ipv4_decoded);
        assert_eq!(ipv6, uniform_ipv6_decoded);

        // OnionV3 will have None as checksum and version
        let uniform_v3_target = AnnouncedNodeAddr::OnionV3 {
            ed25519_pubkey: [
                255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244,
                243, 242, 241, 240, 239, 238, 237, 236, 235, 234, 233, 232,
                231, 230, 229, 228, 227, 226, 225, 224,
            ],
        };
        assert_eq!(uniform_v3_target, uniform_onionv3_decoded);

        // AddressList encoding/decoding
        let address_list = AddressList(vec![ipv4, ipv6, onion_v3]);
        let address_list_target = Vec::<u8>::from_hex(
            "0300000000000000000000000000000000000000000000000000000000000000\
            fffefdfc260701010000000000000000000000000000000000fffefdfcfbfaf9f8f\
            7f6f5f4f3f2f1f02607010300fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedeceb\
            eae9e8e7e6e5e4e3e2e1e0000001").unwrap();

        let address_list_encoded = address_list.strict_serialize().unwrap();

        assert_eq!(address_list_encoded, address_list_target)
    }
}
