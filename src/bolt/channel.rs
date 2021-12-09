// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
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
#[cfg(feature = "serde")]
use amplify::ToYamlString;
use std::fmt::Debug;

use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use lnp2p::legacy::{AcceptChannel, OpenChannel};
use secp256k1::{Secp256k1, Signing};
use wallet::hd::HardenedIndex;
use wallet::scripts::PubkeyScript;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    Error,
    StrictEncode,
    StrictDecode,
)]
#[display(doc_comments)]
/// Errors from
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#requirements-1>
pub enum NegotiationError {
    // TODO: Add other errors from validation parts of open_channel message
    /// minimum depth requested by the remote peer is unreasonably large ({0});
    /// rejecting the channel according to BOLT-2
    UnreasonableMinDepth(u32),

    /// channel_reserve_satoshis ({0}) is less than dust_limit_satoshis ({1})
    /// within the open_channel message; rejecting the channel according to
    /// BOLT-2
    LocalDustExceedsRemoteReserve(u64, u64),

    /// channel_reserve_satoshis from the open_channel message ({0}) is less
    /// than dust_limit_satoshis ({1}; rejecting the channel according to
    /// BOLT-2
    RemoteDustExceedsLocalReserve(u64, u64),
}

#[derive(
    Clone, Copy, PartialEq, Eq, Debug, Default, StrictEncode, StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(Params::to_yaml_string)
)]
pub struct Params {
    pub funding_satoshis: u64,
    pub push_msat: u64,
    pub dust_limit_satoshis: u64,
    pub max_htlc_value_in_flight_msat: u64,
    pub channel_reserve_satoshis: u64,
    pub htlc_minimum_msat: u64,
    pub feerate_per_kw: u32,
    pub minimum_depth: u32,
    pub to_self_delay: u16,
    pub max_accepted_htlcs: u16,
    pub channel_flags: u8,
}

#[cfg(feature = "serde")]
impl ToYamlString for Params {}

impl Params {
    pub fn with(open_channel: &OpenChannel) -> Result<Self, NegotiationError> {
        // TODO: Validate parameters according to BOLT-2 open_channel validation
        //       requirements
        Ok(Self {
            funding_satoshis: open_channel.funding_satoshis,
            push_msat: open_channel.push_msat,
            dust_limit_satoshis: open_channel.dust_limit_satoshis,
            max_htlc_value_in_flight_msat: open_channel
                .max_htlc_value_in_flight_msat,
            channel_reserve_satoshis: open_channel.channel_reserve_satoshis,
            htlc_minimum_msat: open_channel.htlc_minimum_msat,
            feerate_per_kw: open_channel.feerate_per_kw,
            minimum_depth: 0,
            to_self_delay: 0,
            max_accepted_htlcs: open_channel.max_accepted_htlcs,
            channel_flags: open_channel.channel_flags,
        })
    }

    pub fn updated(
        &self,
        accept_channel: &AcceptChannel,
        depth_upper_bound: Option<u32>,
    ) -> Result<Self, NegotiationError> {
        // The temporary_channel_id MUST be the same as the temporary_channel_id
        // in the open_channel message.

        // if minimum_depth is unreasonably large:
        //
        //     MAY reject the channel.
        if let Some(depth_upper_bound) = depth_upper_bound {
            if accept_channel.minimum_depth > depth_upper_bound {
                return Err(NegotiationError::UnreasonableMinDepth(
                    accept_channel.minimum_depth,
                ));
            }
        }

        // if channel_reserve_satoshis is less than dust_limit_satoshis within
        // the open_channel message:
        //
        //     MUST reject the channel.
        if accept_channel.channel_reserve_satoshis < self.dust_limit_satoshis {
            return Err(NegotiationError::LocalDustExceedsRemoteReserve(
                accept_channel.channel_reserve_satoshis,
                self.dust_limit_satoshis,
            ));
        }

        // if channel_reserve_satoshis from the open_channel message is less
        // than dust_limit_satoshis:
        //
        //     MUST reject the channel.
        if self.dust_limit_satoshis < accept_channel.channel_reserve_satoshis {
            return Err(NegotiationError::RemoteDustExceedsLocalReserve(
                self.channel_reserve_satoshis,
                accept_channel.dust_limit_satoshis,
            ));
        }

        // Other fields have the same requirements as their counterparts in
        // open_channel.
        Ok(Self {
            dust_limit_satoshis: accept_channel.dust_limit_satoshis,
            max_htlc_value_in_flight_msat: accept_channel
                .max_htlc_value_in_flight_msat,
            channel_reserve_satoshis: accept_channel.channel_reserve_satoshis,
            htlc_minimum_msat: accept_channel.htlc_minimum_msat,
            minimum_depth: accept_channel.minimum_depth,
            to_self_delay: accept_channel.to_self_delay,
            max_accepted_htlcs: accept_channel.max_accepted_htlcs,
            ..*self
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(Keyset::to_yaml_string)
)]
pub struct Keyset {
    pub funding_pubkey: PublicKey,
    pub revocation_basepoint: PublicKey,
    pub payment_basepoint: PublicKey,
    pub delayed_payment_basepoint: PublicKey,
    pub htlc_basepoint: PublicKey,
    pub first_per_commitment_point: PublicKey,
    pub shutdown_scriptpubkey: Option<PubkeyScript>,
}

#[cfg(feature = "serde")]
impl ToYamlString for Keyset {}

impl From<&OpenChannel> for Keyset {
    fn from(msg: &OpenChannel) -> Self {
        Self {
            funding_pubkey: msg.funding_pubkey,
            revocation_basepoint: msg.revocation_basepoint,
            payment_basepoint: msg.payment_point,
            delayed_payment_basepoint: msg.delayed_payment_basepoint,
            htlc_basepoint: msg.htlc_basepoint,
            first_per_commitment_point: msg.first_per_commitment_point,
            shutdown_scriptpubkey: msg.shutdown_scriptpubkey.clone(),
        }
    }
}

impl From<&AcceptChannel> for Keyset {
    fn from(msg: &AcceptChannel) -> Self {
        Self {
            funding_pubkey: msg.funding_pubkey,
            revocation_basepoint: msg.revocation_basepoint,
            payment_basepoint: msg.payment_point,
            delayed_payment_basepoint: msg.delayed_payment_basepoint,
            htlc_basepoint: msg.htlc_basepoint,
            first_per_commitment_point: msg.first_per_commitment_point,
            shutdown_scriptpubkey: msg.shutdown_scriptpubkey.clone(),
        }
    }
}

impl DumbDefault for Keyset {
    fn dumb_default() -> Self {
        Self {
            funding_pubkey: dumb_pubkey!(),
            revocation_basepoint: dumb_pubkey!(),
            payment_basepoint: dumb_pubkey!(),
            delayed_payment_basepoint: dumb_pubkey!(),
            htlc_basepoint: dumb_pubkey!(),
            first_per_commitment_point: dumb_pubkey!(),
            shutdown_scriptpubkey: None,
        }
    }
}

impl Keyset {
    /// Derives keyset from a *channel extended key* using LNPBP-46 standard
    pub fn with<C: Signing>(
        secp: &Secp256k1<C>,
        funding_pubkey: PublicKey,
        channel_xpriv: ExtendedPrivKey,
    ) -> Self {
        let keys = [1u16, 2, 3, 4, 5]
            .into_iter()
            .map(HardenedIndex::from)
            .map(ChildNumber::from)
            .map(|index| [index])
            .map(|path| {
                channel_xpriv
                    .derive_priv(&secp, &path)
                    .expect("negligible probability")
                    .private_key
                    .key
            })
            .map(|seckey| PublicKey::from_secret_key(&secp, &seckey))
            .collect::<Vec<_>>();

        Self {
            funding_pubkey,
            revocation_basepoint: keys[2],
            payment_basepoint: keys[0],
            delayed_payment_basepoint: keys[1],
            htlc_basepoint: keys[5],
            first_per_commitment_point: keys[4],
            shutdown_scriptpubkey: None,
        }
    }
}
