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
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use lnp2p::legacy::{AcceptChannel, OpenChannel};
use p2p::legacy::{ActiveChannelId, ChannelId, TempChannelId};
use secp256k1::{Secp256k1, Signing};
use std::any::Any;
use std::fmt::Debug;
use wallet::hd::HardenedIndex;
use wallet::scripts::PubkeyScript;

use crate::bolt::{Bolt3, ExtensionId};
use crate::channel::Channel;

/// Limit for the maximum number of the accepted HTLCs towards some node
pub const MAX_ACCEPTED_HTLC_LIMIT: u16 = 483;

#[display(doc_comments)]
/// Errors from
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#requirements-1>
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
pub enum NegotiationError {
    // TODO: Add other errors from validation parts of open_channel message
    /// minimum depth requested by the remote peer is unreasonably large ({0});
    /// rejecting the channel according to BOLT-2
    UnreasonableMinDepth(u32),

    /// `channel_reserve_satoshis` ({channel_reserve}) is less than
    /// dust_limit_satoshis ({dust_limit}) within the `open_channel`
    /// message; rejecting the channel according to BOLT-2
    LocalDustExceedsRemoteReserve {
        channel_reserve: u64,
        dust_limit: u64,
    },

    /// `channel_reserve_satoshis` from the open_channel message
    /// ({channel_reserve}) is less than `dust_limit_satoshis`
    /// ({dust_limit}; rejecting the channel according to BOLT-2
    RemoteDustExceedsLocalReserve {
        channel_reserve: u64,
        dust_limit: u64,
    },
}

impl Channel<ExtensionId> {
    /// Returns BOLT-3 channel representation
    #[inline]
    fn as_bolt3(&self) -> &Bolt3 {
        let any = &*self.constructor() as &dyn Any;
        any.downcast_ref()
            .expect("BOLT channel uses non-BOLT-3 constructor")
    }

    /// Returns active channel id, covering both temporary and final channel ids
    #[inline]
    pub fn active_channel_id(&self) -> ActiveChannelId {
        self.as_bolt3().active_channel_id()
    }

    /// Returns [`ChannelId`], if the channel already assigned it
    #[inline]
    pub fn channel_id(&self) -> Option<ChannelId> {
        self.active_channel_id().channel_id()
    }

    /// Before the channel is assigned a final [`ChannelId`] returns
    /// [`TempChannelId`], and `None` after
    #[inline]
    pub fn temp_channel_id(&self) -> Option<TempChannelId> {
        self.active_channel_id().temp_channel_id()
    }
}

/// Structure containing part of the channel state which must follow specific
/// policies and be accepted or validated basing on those policies and
/// additional protocol-level requirements.
///
/// Should be instantiated directly as a [`Bolt3::policy`] and
/// [`Bolt3::local_params`] objects first by deserializing from the node
/// configuration persistent storage and/or command line parameters via
/// [`Channel::constructor()`]
/// [`::as_bolt3()`](Channel::as_bolt3)[`.set_policy()`](Bolt3::set_policy) and
/// [`.set_local_params()`](Bolt3::set_local_params).
///
/// Later, when creating new channels, it should be copied from the local
/// channel defaults object and updated / checked against local policies upon
/// receiving `accept_channel` reply by setting [`Bolt3::remote_params`] to a
/// value returned from
/// [`Bolt3::local_params`][`.accept_remote`](Params::accept_remote) method.
///
/// Upon receiving `open_channel` message from the remote node must validate the
/// proposed parameters against local policy with
/// [`Bolt3::policy`][`.validate`](Params::validate) method and assign the
/// return value to [`Bolt3::remote_params`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(Params::to_yaml_string)
)]
pub struct Params {
    /// The threshold below which outputs on transactions broadcast by sender
    /// will be omitted
    pub dust_limit_satoshis: u64,

    /// Minimum depth of the funding transaction before the channel is
    /// considered open
    pub minimum_depth: u32,

    /// The number of blocks which the counterparty will have to wait to claim
    /// on-chain funds if they broadcast a commitment transaction
    pub to_self_delay: u16,

    /// The maximum inbound HTLC value in flight towards sender, in
    /// milli-satoshi
    pub max_htlc_value_in_flight_msat: u64,

    /// The minimum value unencumbered by HTLCs for the counterparty to keep in
    /// the channel
    pub channel_reserve_satoshis: u64,

    /// The maximum number of inbound HTLCs towards sender
    pub max_accepted_htlcs: u16,

    /// indicates the initial fee rate in satoshi per 1000-weight (i.e. 1/4 the
    /// more normally-used 'satoshi per 1000 vbytes') that this side will pay
    /// for commitment and HTLC transactions, as described in BOLT #3 (this can
    /// be adjusted later with an update_fee message).
    pub feerate_per_kw: u32,
}

#[cfg(feature = "serde")]
impl ToYamlString for Params {}

impl DumbDefault for Params {
    fn dumb_default() -> Self {
        Params {
            dust_limit_satoshis: 0,
            minimum_depth: 0,
            to_self_delay: 0,
            max_htlc_value_in_flight_msat: 0,
            channel_reserve_satoshis: 0,
            max_accepted_htlcs: 0,
            feerate_per_kw: 0,
        }
    }
}

impl Params {
    pub fn validate(
        self,
        open_channel: &OpenChannel,
        /// Range the fee value may differ from a locally set fee policy,
        /// in percents (from 1 to 100)
        fee_range: u8,
    ) -> Result<Params, NegotiationError> {
        // if `to_self_delay` is unreasonably large.
        if open_channel.to_self_delay > self.to_self_delay {
            return Err(NegotiationError::ToSelfDelayUnreasonablyLarge {
                proposed: open_channel.to_self_delay,
                policy: self.to_self_delay,
            });
        }

        // if `max_accepted_htlcs` is greater than 483.
        if open_channel.max_accepted_htlcs > MAX_ACCEPTED_HTLC_LIMIT {
            return Err(NegotiationError::MaxAcceptedHtlcLimitExceeded(
                open_channel.max_accepted_htlcs,
            ));
        }

        // if we consider `feerate_per_kw` too small for timely processing or
        // unreasonably large.
        let fee_from = self.feerate_per_kw * fee_range / 100;
        let fee_to = self.feerate_per_kw * fee_range / 100;
        if !(fee_from..fee_to).contains(&open_channel.feerate_per_kw) {
            return Err(NegotiationError::FeeRateUnreasonable {
                proposed: open_channel.feerate_per_kw,
                lowest_accepted: fee_from,
                highest_accepted: fee_from,
            });
        }

        Ok(Params {
            dust_limit_satoshis: open_channel.dust_limit_satoshis,
            max_htlc_value_in_flight_msat: open_channel
                .max_htlc_value_in_flight_msat,
            channel_reserve_satoshis: open_channel.channel_reserve_satoshis,
            feerate_per_kw: open_channel.feerate_per_kw,
            minimum_depth: self.minimum_depth,
            to_self_delay: open_channel.to_self_delay,
            max_accepted_htlcs: open_channel.max_accepted_htlcs,
        })
    }

    pub fn accept_remote(
        self,
        accept_channel: &AcceptChannel,
        depth_upper_bound: u32,
    ) -> Result<Params, NegotiationError> {
        // The temporary_channel_id MUST be the same as the temporary_channel_id
        // in the open_channel message.

        // if `minimum_depth` is unreasonably large:
        //
        //     MAY reject the channel.
        if accept_channel.minimum_depth > depth_upper_bound {
            return Err(NegotiationError::UnreasonableMinDepth(
                accept_channel.minimum_depth,
            ));
        }

        // if `channel_reserve_satoshis` is less than `dust_limit_satoshis`
        // within the open_channel message:
        //
        //     MUST reject the channel.
        if accept_channel.channel_reserve_satoshis < self.dust_limit_satoshis {
            return Err(NegotiationError::LocalDustExceedsRemoteReserve {
                channel_reserve: accept_channel.channel_reserve_satoshis,
                dust_limit: self.dust_limit_satoshis,
            });
        }

        // if `channel_reserve_satoshis` from the open_channel message is less
        // than `dust_limit_satoshis`:
        //
        //     MUST reject the channel.
        if self.channel_reserve_satoshis < accept_channel.dust_limit_satoshis {
            return Err(NegotiationError::RemoteDustExceedsLocalReserve {
                channel_reserve: self.channel_reserve_satoshis,
                dust_limit: accept_channel.dust_limit_satoshis,
            });
        }

        // TODO: Other fields have the same requirements as their counterparts
        //       in `open_channel`.
        Ok(Params {
            dust_limit_satoshis: accept_channel.dust_limit_satoshis,
            max_htlc_value_in_flight_msat: accept_channel
                .max_htlc_value_in_flight_msat,
            channel_reserve_satoshis: accept_channel.channel_reserve_satoshis,
            minimum_depth: accept_channel.minimum_depth,
            to_self_delay: accept_channel.to_self_delay,
            max_accepted_htlcs: accept_channel.max_accepted_htlcs,
            feerate_per_kw: self.feerate_per_kw,
        })
    }
}

/// Set of keys used by the core of the channel (in fact, [`Bolt3`]). It does
/// not include HTLC basepoint which is managed separately by
/// [`self::htlc::Htlc`] extension.
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(Keyset::to_yaml_string)
)]
pub struct Keyset {
    /// Public key used in the funding outpoint multisig
    pub funding_pubkey: PublicKey,
    /// Base point for deriving keys used for penalty spending paths
    pub revocation_basepoint: PublicKey,
    /// Base point for deriving keys in `to_remote`
    pub payment_basepoint: PublicKey,
    /// Base point for deriving keys in `to_local` time-locked spending paths
    pub delayed_payment_basepoint: PublicKey,
    /// Base point for deriving keys used for penalty spending paths
    pub first_per_commitment_point: PublicKey,
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
            first_per_commitment_point: msg.first_per_commitment_point,
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
            first_per_commitment_point: msg.first_per_commitment_point,
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
            first_per_commitment_point: dumb_pubkey!(),
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
            first_per_commitment_point: keys[4],
        }
    }
}
