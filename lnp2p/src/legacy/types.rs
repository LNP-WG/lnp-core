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
use std::io;
use std::str::FromStr;

use amplify::hex::{self, FromHex};
use amplify::{Display, DumbDefault, Slice32, Wrapper};
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use chrono::{DateTime, Local, TimeZone, Utc};
use lightning_encoding::{LightningDecode, LightningEncode};
use std::ops::{Add, Sub};

#[cfg(feature = "strict_encoding")]
use strict_encoding::net::{
    AddrFormat, DecodeError, RawAddr, Transport, Uniform, UniformAddr, ADDR_LEN,
};
#[cfg(feature = "strict_encoding")]
use strict_encoding::{self, StrictDecode, StrictEncode};

/// Legacy lightning network channel id: 256-bit number representing funding
/// txid XOR'ed with 32-bit funding output number
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
    LightningEncode,
    LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct ChannelId(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

impl FromHex for ChannelId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where
        I: Iterator<Item = Result<u8, hex::Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl ChannelId {
    pub fn with(funding_outpoint: OutPoint) -> Self {
        let mut slice = funding_outpoint.txid.into_inner();
        let vout = funding_outpoint.vout.to_be_bytes();
        slice[30] ^= vout[0];
        slice[31] ^= vout[1];
        ChannelId::from_inner(Slice32::from_inner(slice))
    }

    /// With some lightning messages (like error) channel id consisting of all
    /// zeros has a special meaning of "applicable to all opened channels". This
    /// function allow to detect this kind of [`ChannelId`]
    pub fn is_wildcard(&self) -> bool {
        self.to_inner().to_inner() == [0u8; 32]
    }
}

/// Lightning network temporary channel Id
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
    LightningEncode,
    LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct TempChannelId(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

impl From<TempChannelId> for ChannelId {
    fn from(temp: TempChannelId) -> Self {
        Self(temp.into_inner())
    }
}

impl From<ChannelId> for TempChannelId {
    fn from(id: ChannelId) -> Self {
        Self(id.into_inner())
    }
}

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

impl TempChannelId {
    pub fn random() -> Self {
        TempChannelId::from_inner(Slice32::random())
    }
}

impl DumbDefault for TempChannelId {
    fn dumb_default() -> Self {
        Self(Default::default())
    }
}

#[derive(Wrapper, Clone, Debug, From, PartialEq, Eq)]
pub struct NodeColor([u8; 3]);

impl NodeColor {
    fn encode<E: io::Write>(&self, mut e: E) -> Result<usize, io::Error> {
        let len = e.write(self.as_inner())?;
        Ok(len)
    }

    fn decode<D: io::Read>(mut d: D) -> Result<Self, io::Error> {
        let mut buf = [0u8; 3];
        d.read_exact(&mut buf)?;
        Ok(Self::from_inner(buf))
    }
}

impl LightningEncode for NodeColor {
    #[inline]
    fn lightning_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        self.encode(e).map_err(lightning_encoding::Error::from)
    }
}

impl LightningDecode for NodeColor {
    #[inline]
    fn lightning_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        Self::decode(d).map_err(lightning_encoding::Error::from)
    }
}

#[cfg(feature = "strict_encoding")]
impl StrictEncode for NodeColor {
    #[inline]
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        self.encode(e).map_err(strict_encoding::Error::from)
    }
}

#[cfg(feature = "strict_encoding")]
impl StrictDecode for NodeColor {
    #[inline]
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Self::decode(d).map_err(strict_encoding::Error::from)
    }
}

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
    LightningEncode,
    LightningDecode,
)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct Alias(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

/// Lightning network short channel Id as per BOLT7
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
    From,
    Getters,
)]
#[display("{block_height}x{tx_index}x{output_index}")]
pub struct ShortChannelId {
    block_height: u32,
    tx_index: u32,
    output_index: u16,
}

impl ShortChannelId {
    pub fn new(
        block_height: u32,
        tx_index: u32,
        output_index: u16,
    ) -> Option<Self> {
        if block_height > 2 << 23 || tx_index > 2 << 23 {
            return None;
        } else {
            return Some(Self {
                block_height: block_height,
                tx_index: tx_index,
                output_index: output_index,
            });
        }
    }
}

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
pub enum ShortChannelIdParseError {
    /// Wrong block height data
    WrongBlockHeight,
    /// Wrong transaction index number
    WrongTxIndex,
    /// Wrong output index number
    WrongOutputIndex,
    /// too many short channel id components; expected three (block height,
    /// tx index and output index)
    ExessiveComponents,
}

impl FromStr for ShortChannelId {
    type Err = ShortChannelIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('x');
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some(block_height), Some(tx_index), Some(output_index), None) => {
                Ok(ShortChannelId {
                    block_height: block_height.parse().map_err(|_| {
                        ShortChannelIdParseError::WrongBlockHeight
                    })?,
                    tx_index: tx_index
                        .parse()
                        .map_err(|_| ShortChannelIdParseError::WrongTxIndex)?,
                    output_index: output_index.parse().map_err(|_| {
                        ShortChannelIdParseError::WrongOutputIndex
                    })?,
                })
            }
            _ => Err(ShortChannelIdParseError::ExessiveComponents),
        }
    }
}

#[cfg(feature = "strict_encoding")]
impl StrictEncode for ShortChannelId {
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        let mut len = 0;

        // representing block height as 3 bytes
        let block_height: [u8; 3] = [
            (self.block_height >> 16 & 0xFF) as u8,
            (self.block_height >> 8 & 0xFF) as u8,
            (self.block_height & 0xFF) as u8,
        ];
        len += e.write(&block_height[..])?;

        // representing transaction index as 3 bytes
        let tx_index: [u8; 3] = [
            (self.tx_index >> 16 & 0xFF) as u8,
            (self.tx_index >> 8 & 0xFF) as u8,
            (self.tx_index & 0xFF) as u8,
        ];
        len += e.write(&tx_index[..])?;

        // represents output index as 2 bytes
        let output_index: [u8; 2] = [
            (self.output_index >> 8 & 0xFF) as u8,
            (self.output_index & 0xFF) as u8,
        ];
        len += e.write(&output_index[..])?;

        Ok(len)
    }
}

#[cfg(feature = "strict_encoding")]
impl StrictDecode for ShortChannelId {
    fn strict_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        // read the block height
        let mut block_height_bytes = [0u8; 3];
        d.read_exact(&mut block_height_bytes[..])?;

        let block_height = ((block_height_bytes[0] as u32) << 16)
            + ((block_height_bytes[1] as u32) << 8)
            + (block_height_bytes[2] as u32);

        // read the transaction index
        let mut transaction_index_bytes = [0u8; 3];
        d.read_exact(&mut transaction_index_bytes[..])?;

        let transaction_index = ((transaction_index_bytes[0] as u32) << 16)
            + ((transaction_index_bytes[1] as u32) << 8)
            + (transaction_index_bytes[2] as u32);

        // read the output index
        let mut output_index = [0u8; 2];
        d.read_exact(&mut output_index[..])?;

        let output_index =
            ((output_index[0] as u16) << 8) + (output_index[1] as u16);

        Ok(Self {
            block_height: block_height,
            tx_index: transaction_index,
            output_index: output_index,
        })
    }
}

impl lightning_encoding::Strategy for ShortChannelId {
    type Strategy = lightning_encoding::strategies::AsStrict;
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
    /// An old-style Tor onion address/port on which the peer is listening.
    OnionV2 {
        /// The bytes (usually encoded in base32 with ".onion" appended)
        addr: [u8; 10],
        /// The port on which the node is listening
        port: u16,
    },
    /// A new-style Tor onion address/port on which the peer is listening.
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

impl AnnouncedNodeAddr {
    fn into_u8(&self) -> u8 {
        match self {
            &AnnouncedNodeAddr::IpV4 { .. } => 1,
            &AnnouncedNodeAddr::IpV6 { .. } => 2,
            &AnnouncedNodeAddr::OnionV2 { .. } => 3,
            &AnnouncedNodeAddr::OnionV3 { .. } => 4,
        }
    }
}

#[cfg(feature = "strict_encoding")]
impl Uniform for AnnouncedNodeAddr {
    fn addr_format(&self) -> AddrFormat {
        match self {
            AnnouncedNodeAddr::IpV4 { .. } => AddrFormat::IpV4,
            AnnouncedNodeAddr::IpV6 { .. } => AddrFormat::IpV6,
            AnnouncedNodeAddr::OnionV2 { .. } => AddrFormat::OnionV2,
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

            AnnouncedNodeAddr::OnionV2 { addr, .. } => {
                let mut ip = [0u8; ADDR_LEN];
                ip[23..].copy_from_slice(addr);
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
            AnnouncedNodeAddr::OnionV2 { port, .. } => Some(port.clone()),
            AnnouncedNodeAddr::OnionV3 { port, .. } => Some(port.clone()),
        }
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
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

            AddrFormat::OnionV2 => {
                let mut ip = [0u8; 10];
                ip.copy_from_slice(&addr.addr[23..]);
                Ok(AnnouncedNodeAddr::OnionV2 {
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

impl LightningEncode for AnnouncedNodeAddr {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        let mut len = 0;

        match self {
            AnnouncedNodeAddr::IpV4 { addr, port } => {
                len += e.write(&self.into_u8().to_be_bytes()[..])?;
                len += e.write(&addr[..])?;
                len += e.write(&port.to_be_bytes()[..])?;
                Ok(len)
            }
            AnnouncedNodeAddr::IpV6 { addr, port } => {
                let mut len = 0;
                len += e.write(&self.into_u8().to_be_bytes()[..])?;
                len += e.write(&addr[..])?;
                len += e.write(&port.to_be_bytes()[..])?;

                Ok(len)
            }
            AnnouncedNodeAddr::OnionV2 { addr, port } => {
                let mut len = 0;
                len += e.write(&self.into_u8().to_be_bytes()[..])?;
                len += e.write(&addr[..])?;
                len += e.write(&port.to_be_bytes()[..])?;

                Ok(len)
            }

            AnnouncedNodeAddr::OnionV3 {
                ed25519_pubkey,
                checksum,
                version,
                port,
            } => {
                let mut len = 0;
                len += e.write(&self.into_u8().to_be_bytes()[..])?;
                len += e.write(&ed25519_pubkey[..])?;
                if let Some(checksum) = checksum {
                    len += e.write(&checksum.to_be_bytes()[..])?;
                } else {
                    return Err(std::io::ErrorKind::InvalidData.into());
                };
                if let Some(version) = version {
                    len += e.write(&version.to_be_bytes()[..])?;
                } else {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                len += e.write(&port.to_be_bytes()[..])?;

                Ok(len)
            }
        }
    }
}

impl LightningDecode for AnnouncedNodeAddr {
    fn lightning_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        let mut type_byte = [0u8; 1];
        d.read_exact(&mut type_byte)?;
        let type_byte = u8::from_be_bytes(type_byte);

        match type_byte {
            1u8 => {
                let mut addr = [0u8; 4];
                let mut port = [0u8; 2];
                d.read_exact(&mut addr[..])?;
                d.read_exact(&mut port[..])?;
                let port = u16::from_be_bytes(port);

                Ok(AnnouncedNodeAddr::IpV4 {
                    addr: addr,
                    port: port,
                })
            }

            2u8 => {
                let mut addr = [0u8; 16];
                let mut port = [0u8; 2];
                d.read_exact(&mut addr[..])?;
                d.read_exact(&mut port[..])?;
                let port = u16::from_be_bytes(port);

                Ok(AnnouncedNodeAddr::IpV6 {
                    addr: addr,
                    port: port,
                })
            }

            3u8 => {
                let mut addr = [0u8; 10];
                let mut port = [0u8; 2];
                d.read_exact(&mut addr[..])?;
                d.read_exact(&mut port[..])?;
                let port = u16::from_be_bytes(port);

                Ok(AnnouncedNodeAddr::OnionV2 {
                    addr: addr,
                    port: port,
                })
            }

            4u8 => {
                let mut ed2559_pubkey = [0u8; 32];
                let mut checksum = [0u8; 2];
                let mut version = [0u8; 1];
                let mut port = [0u8; 2];
                d.read_exact(&mut ed2559_pubkey[..])?;
                d.read_exact(&mut checksum[..])?;
                d.read_exact(&mut version[..])?;
                d.read_exact(&mut port[..])?;
                let checksum = u16::from_be_bytes(checksum);
                let version = u8::from_be_bytes(version);
                let port = u16::from_be_bytes(port);

                Ok(AnnouncedNodeAddr::OnionV3 {
                    ed25519_pubkey: ed2559_pubkey,
                    checksum: Some(checksum),
                    version: Some(version),
                    port: port,
                })
            }

            _ => Err(lightning_encoding::Error::DataIntegrityError(s!(
                "Wrong Network Address Format"
            ))),
        }
    }
}

impl strict_encoding::Strategy for AnnouncedNodeAddr {
    type Strategy = strict_encoding::strategies::UsingUniformAddr;
}
#[derive(
    Wrapper, Clone, Debug, Display, Hash, Default, From, PartialEq, Eq,
)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[display(Debug)]
pub struct AddressList(Vec<AnnouncedNodeAddr>);

impl LightningEncode for AddressList {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        let mut written = 0;
        let len = self.0.len() as u16;
        written += e.write(&len.to_be_bytes()[..])?;
        for addr in &self.0 {
            written += addr.lightning_encode(&mut e)?;
        }
        Ok(written)
    }
}

impl LightningDecode for AddressList {
    fn lightning_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        let mut len_bytes = [0u8; 2];
        d.read_exact(&mut len_bytes)?;
        let len = u16::from_be_bytes(len_bytes) as usize;
        let mut data = Vec::<AnnouncedNodeAddr>::with_capacity(len);
        for _ in 0..len {
            data.push(AnnouncedNodeAddr::lightning_decode(&mut d)?);
        }
        Ok(AddressList(data))
    }
}

#[derive(
    Display, Copy, Clone, Debug, PartialEq, Hash, Eq, PartialOrd, Ord, Wrapper,
)]
#[display("{0} sec")]
pub struct Timestamp(u32);

impl<T> From<DateTime<T>> for Timestamp
where
    T: TimeZone,
{
    fn from(dt: DateTime<T>) -> Timestamp {
        Timestamp(dt.timestamp() as u32)
    }
}

impl From<u32> for Timestamp {
    fn from(seconds: u32) -> Timestamp {
        Timestamp(seconds)
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Timestamp(Utc::now().timestamp() as u32)
    }
}

impl From<Timestamp> for DateTime<Utc> {
    fn from(ts: Timestamp) -> DateTime<Utc> {
        Utc.timestamp(ts.0 as i64, 0)
    }
}

impl From<Timestamp> for DateTime<Local> {
    fn from(ts: Timestamp) -> DateTime<Local> {
        Local.timestamp(ts.0 as i64, 0)
    }
}

impl Timestamp {
    pub fn checked_add(self, rhs: Timestamp) -> Option<Timestamp> {
        self.0.checked_add(rhs.0).map(Timestamp)
    }

    pub fn checked_sub(self, rhs: Timestamp) -> Option<Timestamp> {
        self.0.checked_sub(rhs.0).map(Timestamp)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hashes::hex::FromHex;
    use lightning_encoding::{LightningDecode, LightningEncode};

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

        let onion_v2 = AnnouncedNodeAddr::OnionV2 {
            addr: [255, 254, 253, 252, 251, 250, 249, 248, 247, 246],
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
        let onionv2_target =
            Vec::<u8>::from_hex("03fffefdfcfbfaf9f8f7f62607").unwrap();
        let onionv3_target = Vec::<u8>::from_hex("04fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607").unwrap();

        // Check strict encoding/decoding
        let ipv4_encoded = ipv4.lightning_serialize().unwrap();
        let ipv6_encoded = ipv6.lightning_serialize().unwrap();
        let onionv2_encoded = onion_v2.lightning_serialize().unwrap();
        let onionv3_encoded = onion_v3.lightning_serialize().unwrap();

        let ipv4_decoded =
            AnnouncedNodeAddr::lightning_deserialize(&ipv4_target).unwrap();
        let ipv6_decoded =
            AnnouncedNodeAddr::lightning_deserialize(&ipv6_target).unwrap();
        let onionv2_decoded =
            AnnouncedNodeAddr::lightning_deserialize(&onionv2_target).unwrap();
        let onionv3_decoded =
            AnnouncedNodeAddr::lightning_deserialize(&onionv3_target).unwrap();

        assert_eq!(ipv4, ipv4_decoded);
        assert_eq!(ipv6, ipv6_decoded);
        assert_eq!(onion_v2, onionv2_decoded);
        assert_eq!(onion_v3, onionv3_decoded);

        assert_eq!(ipv4_encoded, ipv4_target);
        assert_eq!(ipv6_encoded, ipv6_target);
        assert_eq!(onionv2_encoded, onionv2_target);
        assert_eq!(onionv3_encoded, onionv3_target);

        // Check Uniform encoding/decoding
        let uniform_ipv4 = ipv4.to_uniform_addr();
        let uniform_ipv6 = ipv6.to_uniform_addr();
        let uniform_onionv2 = onion_v2.to_uniform_addr();
        let uniform_onionv3 = onion_v3.to_uniform_addr();

        let uniform_ipv4_decoded =
            AnnouncedNodeAddr::from_uniform_addr(uniform_ipv4).unwrap();
        let uniform_ipv6_decoded =
            AnnouncedNodeAddr::from_uniform_addr(uniform_ipv6).unwrap();
        let uniform_onionv2_decoded =
            AnnouncedNodeAddr::from_uniform_addr(uniform_onionv2).unwrap();
        let uniform_onionv3_decoded =
            AnnouncedNodeAddr::from_uniform_addr(uniform_onionv3).unwrap();

        // IPV4, IPV6 and OnionV2 should match
        assert_eq!(ipv4, uniform_ipv4_decoded);
        assert_eq!(ipv6, uniform_ipv6_decoded);
        assert_eq!(onion_v2, uniform_onionv2_decoded);

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
        let address_list = AddressList(vec![ipv4, ipv6, onion_v2, onion_v3]);
        let address_list_target = Vec::<u8>::from_hex("000401fffefdfc260702fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0260703fffefdfcfbfaf9f8f7f6260704fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607").unwrap();

        let address_list_encoded = address_list.lightning_serialize().unwrap();

        assert_eq!(address_list_encoded, address_list_target)
    }
}
