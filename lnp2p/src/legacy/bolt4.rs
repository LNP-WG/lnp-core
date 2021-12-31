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

//! Lightning payment data as they are decrypted from Sphinx onion packet

use std::io;

use amplify::Wrapper;
use internet2::presentation::sphinx::SphinxPayload;
use internet2::tlv;
use lightning_encoding::{BigSize, LightningDecode, LightningEncode};
use wallet::hlc::HashPreimage;

use crate::legacy::ShortChannelId;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
pub struct PaymentOnion {
    pub realm: HopRealm,
    pub amt_to_forward: u64,
    pub outgoing_cltv_value: u32,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
pub enum HopRealm {
    Legacy(ShortChannelId),
    TlvIntermediary(ShortChannelId),
    TlvReceiver(Option<PaymentData>),
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(LightningEncode, LightningDecode)]
#[cfg_attr(feature = "strict_encoding", derive(NetworkEncode, NetworkDecode))]
pub struct PaymentData {
    pub payment_secret: HashPreimage,
    pub total_msat: u64,
}

// For internal use to simplify Tlv encoding/decoding implementation
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(LightningEncode, LightningDecode)]
#[lightning_encoding(use_tlv)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(NetworkEncode, NetworkDecode),
    network_encoding(use_tlv)
)]
struct TlvPayment {
    #[lightning_encoding(tlv = 2)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 2))]
    amt_to_forward: Option<u64>,

    #[lightning_encoding(tlv = 4)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 4))]
    outgoing_cltv_value: Option<u32>,

    #[lightning_encoding(tlv = 6)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 6))]
    short_channel_id: Option<ShortChannelId>,

    #[lightning_encoding(tlv = 8)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(tlv = 8))]
    payment_data: Option<PaymentData>,

    #[lightning_encoding(unknown_tlvs)]
    #[cfg_attr(feature = "strict_encoding", network_encoding(unknown_tlvs))]
    unknown: tlv::Stream,
}

impl LightningEncode for PaymentOnion {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        let tlv = match self.realm {
            HopRealm::Legacy(short_channel_id) => {
                0u8.lightning_encode(&mut e)?;
                short_channel_id.lightning_encode(&mut e)?;
                self.amt_to_forward.lightning_encode(&mut e)?;
                self.outgoing_cltv_value.lightning_encode(&mut e)?;
                e.write_all(&[0u8; 12])?;
                return Ok(33);
            }
            HopRealm::TlvIntermediary(short_channel_id) => TlvPayment {
                amt_to_forward: Some(self.amt_to_forward),
                outgoing_cltv_value: Some(self.outgoing_cltv_value),
                short_channel_id: Some(short_channel_id),
                payment_data: None,
                unknown: none!(),
            },
            HopRealm::TlvReceiver(payment_data) => TlvPayment {
                amt_to_forward: Some(self.amt_to_forward),
                outgoing_cltv_value: Some(self.outgoing_cltv_value),
                short_channel_id: None,
                payment_data,
                unknown: none!(),
            },
        };
        let stream = tlv.lightning_serialize()?;
        BigSize::from(stream.len()).lightning_encode(&mut e)?;
        e.write_all(&stream)?;
        Ok(stream.len())
    }
}

impl LightningDecode for PaymentOnion {
    fn lightning_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        let len = BigSize::lightning_decode(&mut d)?;
        match len.into_inner() {
            0 => {
                let onion = PaymentOnion {
                    realm: HopRealm::Legacy(ShortChannelId::lightning_decode(
                        &mut d,
                    )?),
                    amt_to_forward: LightningDecode::lightning_decode(&mut d)?,
                    outgoing_cltv_value: LightningDecode::lightning_decode(
                        &mut d,
                    )?,
                };
                let mut padding = [0u8; 12];
                d.read_exact(&mut padding)?;
                Ok(onion)
            }
            // A single 0x01 byte for length is reserved for future use to
            // signal a different payload format. This is safe since no TLV
            // value can ever be shorter than 2 bytes. In this case the hop_
            // payload_length MUST be defined in the future specification making
            // use of this length.
            1 => Err(lightning_encoding::Error::DataIntegrityError(s!(
                "payment onion with reserved realm=0x01"
            ))),
            len => {
                let tlv = TlvPayment::lightning_decode(d.take(len))?;
                match (
                    tlv.amt_to_forward,
                    tlv.outgoing_cltv_value,
                    tlv.short_channel_id,
                    tlv.payment_data,
                ) {
                    (None, _, _, _) => {
                        Err(lightning_encoding::Error::DataIntegrityError(s!(
                            "payment onion must contain amt_to_forward"
                        )))
                    }
                    (_, None, _, _) => {
                        Err(lightning_encoding::Error::DataIntegrityError(s!(
                            "payment onion must contain outgoing_cltv_value"
                        )))
                    }
                    (Some(_), Some(_), Some(_), Some(_)) => {
                        Err(lightning_encoding::Error::DataIntegrityError(s!(
                            "payment onion must not contain both \
                             short_channel_id and payment_data"
                        )))
                    }
                    (
                        Some(amt_to_forward),
                        Some(outgoing_cltv_value),
                        Some(short_channel_id),
                        None,
                    ) => Ok(PaymentOnion {
                        realm: HopRealm::TlvIntermediary(short_channel_id),
                        amt_to_forward,
                        outgoing_cltv_value,
                    }),
                    (
                        Some(amt_to_forward),
                        Some(outgoing_cltv_value),
                        None,
                        payment_data,
                    ) => Ok(PaymentOnion {
                        realm: HopRealm::TlvReceiver(payment_data),
                        amt_to_forward,
                        outgoing_cltv_value,
                    }),
                }
            }
        }
    }
}

impl SphinxPayload for PaymentOnion {
    type DecodeError = lightning_encoding::Error;

    fn serialized_len(&self) -> usize {
        match self.realm {
            HopRealm::Legacy(_) => 33,
            HopRealm::TlvIntermediary(_) => 27,
            HopRealm::TlvReceiver(None) => 27 - 10,
            HopRealm::TlvReceiver(Some(_)) => 27 + 32,
        }
    }

    #[inline]
    fn encode(&self, writer: impl io::Write) -> Result<usize, io::Error> {
        self.lightning_encode(writer).map_err(|err| match err {
            lightning_encoding::Error::Io(err) => err.into(),
            _ => unreachable!(),
        })
    }

    #[inline]
    fn decode(reader: impl io::Read) -> Result<Self, Self::DecodeError>
    where
        Self: Sized,
    {
        PaymentOnion::lightning_decode(reader)
    }
}
