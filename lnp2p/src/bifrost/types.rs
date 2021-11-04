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

#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::fmt::{self, Display, Formatter};
use std::io::{Read, Write};
use std::str::FromStr;

use amplify::hex::{self, FromHex};
use amplify::{Slice32, Wrapper};
use bitcoin::OutPoint;
use strict_encoding::net::{
    AddrFormat, DecodeError, RawAddr, Transport, Uniform, UniformAddr, ADDR_LEN,
};
use strict_encoding::{self, StrictDecode, StrictEncode};

/// Bifrost lightning network channel id: 256-bit number representing funding
/// txid plus 32-bit funding output number
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
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
    From,
    StrictEncode,
    StrictDecode,
)]
#[display(inner)]
#[wrapper(FromStr)]
pub struct ChannelId(OutPoint);

impl ChannelId {
    /// Constructs channel if from a funding outpoint value
    #[inline]
    pub fn with(funding_outpoint: OutPoint) -> Self {
        ChannelId(funding_outpoint)
    }
}

/// Lightning network Bifrost temporary channel id, representing ID of the
/// initial channel smart contract proposal (CSCP)
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct TempChannelId(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

impl FromHex for TempChannelId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where
        I: Iterator<Item = Result<u8, hex::Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Display, Debug, Error)]
#[display(doc_comments)]
/// incorrect naminng for protocol {0}: protocol name in Bifrost can contain
/// only ASCII alphanumeric characters and dashes
pub struct ProtocolNameError(pub String);

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, From,
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
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<ProtocolName> {
        self.0.iter()
    }
}

impl Display for ProtocolList {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let iter = self.iter();
        for protocol in iter {
            Display::fmt(protocol, f)?;
            if iter.take(1).count() == 0 {
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
            .into_iter()
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
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From,
)]
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
        /// The checksum of the pubkey and version, as included in the onion
        /// address
        // Optional values taken here to be compatible with Uniform encoding
        checksum: Option<u16>,
        /// The version byte, as defined by the Tor Onion v3 spec.
        version: Option<u8>,
        /// The port on which the node is listening
        port: u16,
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
            AnnouncedNodeAddr::IpV4 { port, .. } => Some(port.clone()),
            AnnouncedNodeAddr::IpV6 { port, .. } => Some(port.clone()),
            AnnouncedNodeAddr::OnionV3 { port, .. } => Some(port.clone()),
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
                Ok(AnnouncedNodeAddr::OnionV3 {
                    ed25519_pubkey: ip,
                    // Converting from Uniform encoding will always lead these
                    // values to be None
                    checksum: None,
                    version: None,
                    port: match addr.port {
                        Some(p) => p,
                        _ => return Err(DecodeError::InsufficientData),
                    },
                })
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

#[derive(
    Wrapper,
    Clone,
    Debug,
    Display,
    Hash,
    Default,
    From,
    PartialEq,
    Eq,
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
pub struct AddressList(Vec<AnnouncedNodeAddr>);

#[cfg(test)]
mod test {
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
            checksum: Some(32),
            version: Some(16),
            port: 9735,
        };

        let ipv4_target = Vec::<u8>::from_hex("01fffefdfc2607").unwrap();
        let ipv6_target =
            Vec::<u8>::from_hex("02fffefdfcfbfaf9f8f7f6f5f4f3f2f1f02607")
                .unwrap();
        let onionv3_target = Vec::<u8>::from_hex("04fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607").unwrap();

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
            checksum: None,
            version: None,
            port: 9735,
        };
        assert_eq!(uniform_v3_target, uniform_onionv3_decoded);

        // AddressList encoding/decoding
        let address_list = AddressList(vec![ipv4, ipv6, onion_v3]);
        let address_list_target = Vec::<u8>::from_hex("000401fffefdfc260702fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0260703fffefdfcfbfaf9f8f7f6260704fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607").unwrap();

        let address_list_encoded = address_list.strict_serialize().unwrap();

        assert_eq!(address_list_encoded, address_list_target)
    }
}
