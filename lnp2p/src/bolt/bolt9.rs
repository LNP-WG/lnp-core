// LNP P2P library, plmeneting both bolt (BOLT) and Bifrost P2P messaging
// system for Lightning network protocol (LNP)
//
// Written in 2020-2024 by
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

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io;
use std::str::FromStr;

use amplify::flags::FlagVec;
use lightning_encoding::{self, LightningDecode, LightningEncode};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};

/// Feature-flags-related errors
#[derive(
    Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Debug, Display, Error,
    From
)]
#[display(doc_comments)]
pub enum Error {
    #[from]
    /// feature flags inconsistency: {0}
    FeaturesInconsistency(NoRequiredFeatureError),

    /// unknown even feature flag with number {0}
    UnknownEvenFeature(u16),
}

/// Errors from internal features inconsistency happening when a feature is
/// present, but it's required feature is not specified
#[derive(
    Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum NoRequiredFeatureError {
    /// `gossip_queries_eq` feature requires `gossip_queries` feature
    GossipQueries,

    /// `payment_secret` feature requires `var_option_optin` feature
    VarOptionOptin,

    /// `basic_mpp` feature requires `payment_secret` feature
    PaymentSecret,

    /// `option_anchor_outputs` feature requires `option_static_remotekey`
    /// feature
    OptionStaticRemotekey,
}

/// Some features don't make sense on a per-channels or per-node basis, so each
/// feature defines how it is presented in those contexts. Some features may be
/// required for opening a channel, but not a requirement for use of the
/// channel, so the presentation of those features depends on the feature
/// itself.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md#bolt-9-assigned-feature-flags>
pub trait FeatureContext:
    Display
    + Debug
    + Copy
    + Clone
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Hash
    + Default
{
}

/// Type representing `init` message feature context.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Default
)]
#[display("I", alt = "init")]
pub struct InitContext;
impl FeatureContext for InitContext {}

/// Type representing `node_announcement` message feature context.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Default
)]
#[display("N", alt = "node_announcement")]
pub struct NodeAnnouncementContext;
impl FeatureContext for NodeAnnouncementContext {}

/// Type representing `channel_announcement` message feature context.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Default
)]
#[display("C", alt = "channel_announcement")]
pub struct ChannelAnnouncementContext;
impl FeatureContext for ChannelAnnouncementContext {}

/// Type representing BOLT-11 invoice feature context.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Default
)]
#[display("9", alt = "bolt11")]
pub struct Bolt11Context;
impl FeatureContext for Bolt11Context {}

/// Specific named feature flags
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[non_exhaustive]
#[repr(u16)]
pub enum Feature {
    /// Requires or supports extra `channel_reestablish` fields
    #[display("option_data_loss_protect", alt = "0/1")]
    OptionDataLossProtect = 0,

    /// Sending node needs a complete routing information dump
    #[display("initial_routing_sync", alt = "3")]
    InitialRoutingSync = 2,

    /// Commits to a shutdown scriptpubkey when opening channel
    #[display("option_data_loss_protect", alt = "4/5")]
    OptionUpfrontShutdownScript = 4,

    /// More sophisticated gossip control
    #[display("gossip_queries", alt = "6/7")]
    GossipQueries = 6,

    /// Requires/supports variable-length routing onion payloads
    #[display("var_onion_optin", alt = "8/9")]
    VarOnionOptin = 8,

    /// Gossip queries can include additional information
    #[display("gossip_queries_ex", alt = "10/11")]
    GossipQueriesEx = 10,

    /// Static key for remote output
    #[display("option_static_remotekey", alt = "12/13")]
    OptionStaticRemotekey = 12,

    /// Node supports `payment_secret` field
    #[display("payment_secret", alt = "14/15")]
    PaymentSecret = 14,

    /// Node can receive basic multi-part payments
    #[display("basic_mpp", alt = "16/17")]
    BasicMpp = 16,

    /// Can create large channels
    #[display("option_support_large_channel", alt = "18/19")]
    OptionSupportLargeChannel = 18,

    /// Anchor outputs
    #[display("option_anchor_outputs", alt = "20/21")]
    OptionAnchorOutputs = 20,

    /// Anchor commitment type with zero fee HTLC transactions
    #[display("option_anchors_zero_fee_htlc_tx", alt = "22/23")]
    OptionAnchorZeroFeeHtlcTx = 22,

    /// Future segwit versions allowed in shutdown
    #[display("option_shutdown_anysegwit", alt = "26/27")]
    OptionShutdownAnySegwit = 26,

    /// Node supports the channel_type field in open/accept
    #[display("option_channel_type", alt = "44/45")]
    OptionChannelType = 44,

    /// Supply channel aliases for routing
    #[display("option_scid_alias", alt = "46/47")]
    OptionScidAlias = 46,

    /// Payment metadata in tlv record
    #[display("option_payment_metadata", alt = "48/49")]
    OptionPaymentMetadata = 48,

    /// Understands zeroconf channel types
    #[display("option_zeroconf", alt = "50/51")]
    OptionZeroConf = 50,
    // NB: When adding new feature INCLUDE it into Feature::all
}

impl Feature {
    pub fn all() -> &'static [Feature] {
        &[
            Feature::OptionDataLossProtect,
            Feature::InitialRoutingSync,
            Feature::OptionUpfrontShutdownScript,
            Feature::GossipQueries,
            Feature::VarOnionOptin,
            Feature::GossipQueriesEx,
            Feature::OptionStaticRemotekey,
            Feature::PaymentSecret,
            Feature::BasicMpp,
            Feature::OptionSupportLargeChannel,
            Feature::OptionAnchorOutputs,
            Feature::OptionAnchorZeroFeeHtlcTx,
            Feature::OptionShutdownAnySegwit,
            Feature::OptionChannelType,
            Feature::OptionScidAlias,
            Feature::OptionPaymentMetadata,
            Feature::OptionZeroConf,
        ]
    }

    /// Returns number of bit that is set by the flag
    ///
    /// # Arguments
    /// `required`: which type of flag bit should be returned:
    /// - `false` for even (non-required) bit variant
    /// - `true` for odd (required) bit variant
    ///
    /// # Returns
    /// Bit number in feature vector if the feature is allowed for the provided
    /// `required` condition; `None` otherwise.
    pub fn bit(self, required: bool) -> Option<u16> {
        if self == Feature::InitialRoutingSync && required {
            return None;
        }
        Some(self as u16 + !required as u16)
    }
}

/// Error reporting unrecognized feature name
#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display("the provided feature name is not known: {0}")]
pub struct UnknownFeatureError(pub String);

impl FromStr for Feature {
    type Err = UnknownFeatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let feature = match s {
            s if s == Feature::OptionDataLossProtect.to_string() => {
                Feature::OptionDataLossProtect
            }
            s if s == Feature::InitialRoutingSync.to_string() => {
                Feature::InitialRoutingSync
            }
            s if s == Feature::OptionUpfrontShutdownScript.to_string() => {
                Feature::OptionUpfrontShutdownScript
            }
            s if s == Feature::GossipQueries.to_string() => {
                Feature::GossipQueries
            }
            s if s == Feature::VarOnionOptin.to_string() => {
                Feature::VarOnionOptin
            }
            s if s == Feature::GossipQueriesEx.to_string() => {
                Feature::GossipQueriesEx
            }
            s if s == Feature::OptionStaticRemotekey.to_string() => {
                Feature::OptionStaticRemotekey
            }
            s if s == Feature::PaymentSecret.to_string() => {
                Feature::PaymentSecret
            }
            s if s == Feature::BasicMpp.to_string() => Feature::BasicMpp,
            s if s == Feature::OptionSupportLargeChannel.to_string() => {
                Feature::OptionSupportLargeChannel
            }
            s if s == Feature::OptionAnchorOutputs.to_string() => {
                Feature::OptionAnchorOutputs
            }
            s if s == Feature::OptionAnchorZeroFeeHtlcTx.to_string() => {
                Feature::OptionAnchorZeroFeeHtlcTx
            }
            s if s == Feature::OptionShutdownAnySegwit.to_string() => {
                Feature::OptionShutdownAnySegwit
            }
            s if s == Feature::OptionChannelType.to_string() => {
                Feature::OptionChannelType
            }
            s if s == Feature::OptionScidAlias.to_string() => {
                Feature::OptionScidAlias
            }
            s if s == Feature::OptionPaymentMetadata.to_string() => {
                Feature::OptionPaymentMetadata
            }
            s if s == Feature::OptionZeroConf.to_string() => {
                Feature::OptionZeroConf
            }
            other => return Err(UnknownFeatureError(other.to_owned())),
        };
        Ok(feature)
    }
}

/// Features provided in the `init` message and announced with
/// `node_announcement`.
///
/// Flags are numbered from the least-significant bit, at bit 0 (i.e. 0x1, an
/// even bit). They are generally assigned in pairs so that features can be
/// introduced as optional (odd bits) and later upgraded to be compulsory (even
/// bits), which will be refused by outdated nodes: see BOLT #1: The init
/// Message.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md>
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct InitFeatures {
    /// Requires or supports extra `channel_reestablish` fields
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_data_loss_protect: Option<bool>,

    /// Sending node needs a complete routing information dump
    pub initial_routing_sync: bool,

    /// Commits to a shutdown scriptpubkey when opening channel
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_upfront_shutdown_script: Option<bool>,

    /// More sophisticated gossip control
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub gossip_queries: Option<bool>,

    /// Requires/supports variable-length routing onion payloads
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub var_onion_optin: Option<bool>,

    /// Gossip queries can include additional information
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub gossip_queries_ex: Option<bool>,

    /// Static key for remote output
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_static_remotekey: Option<bool>,

    /// Node supports `payment_secret` field
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub payment_secret: Option<bool>,

    /// Node can receive basic multi-part payments
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub basic_mpp: Option<bool>,

    /// Can create large channels
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_support_large_channel: Option<bool>,

    /// Anchor outputs
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_anchor_outputs: Option<bool>,

    /// Anchor commitment type with zero fee HTLC transactions
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_anchors_zero_fee_htlc_tx: Option<bool>,

    /// Future segwit versions allowed in shutdown
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_shutdown_anysegwit: Option<bool>,

    /// Node supports the channel_type field in open/accept
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_channel_type: Option<bool>,

    /// Supply channel aliases for routing
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_scid_alias: Option<bool>,

    /// Payment metadata in tlv record
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_payment_metadata: Option<bool>,

    /// Understands zeroconf channel types
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub option_zeroconf: Option<bool>,

    /// Rest of feature flags which are unknown to the current implementation
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    pub unknown: FlagVec,
}

impl Display for InitFeatures {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for (feature, required) in self.known_set_features() {
            Display::fmt(&feature, f)?;
            if !required {
                f.write_str("?")?;
            }
            f.write_str(", ")?;
        }
        Ok(())
    }
}

// TODO: Re-org into a trait
impl InitFeatures {
    /// Measures minimally-encoded byte length for the feature vector
    pub fn byte_len(&self) -> u16 {
        let max_known = Feature::all()
            .iter()
            .map(|f| f.bit(false).or_else(|| f.bit(true)).unwrap_or(0))
            .max()
            .unwrap_or(0);
        let max_unknown = Iterator::max(self.unknown.iter()).unwrap_or(0);
        max_known.max(max_unknown)
    }

    pub fn check(&self) -> Result<(), Error> {
        self.check_consistency()?;
        self.check_unknown_even()
    }

    pub fn check_consistency(&self) -> Result<(), NoRequiredFeatureError> {
        if self.gossip_queries_ex.is_some() && self.gossip_queries.is_none() {
            return Err(NoRequiredFeatureError::GossipQueries);
        }
        if self.payment_secret.is_some() && self.var_onion_optin.is_none() {
            return Err(NoRequiredFeatureError::VarOptionOptin);
        }
        if self.basic_mpp.is_some() && self.payment_secret.is_none() {
            return Err(NoRequiredFeatureError::PaymentSecret);
        }
        if self.option_anchor_outputs.is_some()
            && self.option_static_remotekey.is_none()
        {
            return Err(NoRequiredFeatureError::OptionStaticRemotekey);
        }
        Ok(())
    }

    pub fn check_unknown_even(&self) -> Result<(), Error> {
        if let Some(flag) = self.unknown.iter().find(|flag| flag % 2 == 0) {
            return Err(Error::UnknownEvenFeature(flag));
        }
        Ok(())
    }

    pub fn known_set_features(&self) -> BTreeMap<Feature, bool> {
        let mut map = bmap! {};
        if let Some(required) = self.option_data_loss_protect {
            map.insert(Feature::OptionDataLossProtect, required);
        }
        if self.initial_routing_sync {
            map.insert(Feature::InitialRoutingSync, false);
        }
        if let Some(required) = self.option_upfront_shutdown_script {
            map.insert(Feature::OptionUpfrontShutdownScript, required);
        }
        if let Some(required) = self.gossip_queries {
            map.insert(Feature::GossipQueries, required);
        }
        if let Some(required) = self.var_onion_optin {
            map.insert(Feature::VarOnionOptin, required);
        }
        if let Some(required) = self.gossip_queries_ex {
            map.insert(Feature::GossipQueriesEx, required);
        }
        if let Some(required) = self.option_static_remotekey {
            map.insert(Feature::OptionStaticRemotekey, required);
        }
        if let Some(required) = self.payment_secret {
            map.insert(Feature::PaymentSecret, required);
        }
        if let Some(required) = self.basic_mpp {
            map.insert(Feature::BasicMpp, required);
        }
        if let Some(required) = self.option_support_large_channel {
            map.insert(Feature::OptionSupportLargeChannel, required);
        }
        if let Some(required) = self.option_anchor_outputs {
            map.insert(Feature::OptionAnchorOutputs, required);
        }
        if let Some(required) = self.option_anchors_zero_fee_htlc_tx {
            map.insert(Feature::OptionAnchorZeroFeeHtlcTx, required);
        }
        if let Some(required) = self.option_shutdown_anysegwit {
            map.insert(Feature::OptionShutdownAnySegwit, required);
        }
        if let Some(required) = self.option_channel_type {
            map.insert(Feature::OptionChannelType, required);
        }
        if let Some(required) = self.option_scid_alias {
            map.insert(Feature::OptionScidAlias, required);
        }
        if let Some(required) = self.option_payment_metadata {
            map.insert(Feature::OptionPaymentMetadata, required);
        }
        if let Some(required) = self.option_zeroconf {
            map.insert(Feature::OptionZeroConf, required);
        }
        map
    }
}

impl TryFrom<FlagVec> for InitFeatures {
    type Error = Error;

    fn try_from(flags: FlagVec) -> Result<Self, Self::Error> {
        let requirements = |feature: Feature| -> Option<bool> {
            if let Some(true) = feature.bit(false).map(|bit| flags.is_set(bit))
            {
                Some(false)
            } else if let Some(true) =
                feature.bit(true).map(|bit| flags.is_set(bit))
            {
                Some(true)
            } else {
                None
            }
        };

        let mut parsed = InitFeatures {
            option_data_loss_protect: requirements(
                Feature::OptionDataLossProtect,
            ),
            initial_routing_sync: flags.is_set(3),
            option_upfront_shutdown_script: requirements(
                Feature::OptionUpfrontShutdownScript,
            ),
            gossip_queries: requirements(Feature::GossipQueries),
            var_onion_optin: requirements(Feature::VarOnionOptin),
            gossip_queries_ex: requirements(Feature::GossipQueriesEx),
            option_static_remotekey: requirements(
                Feature::OptionStaticRemotekey,
            ),
            payment_secret: requirements(Feature::PaymentSecret),
            basic_mpp: requirements(Feature::BasicMpp),
            option_support_large_channel: requirements(
                Feature::OptionSupportLargeChannel,
            ),
            option_anchor_outputs: requirements(Feature::OptionAnchorOutputs),
            option_anchors_zero_fee_htlc_tx: requirements(
                Feature::OptionAnchorZeroFeeHtlcTx,
            ),
            option_shutdown_anysegwit: requirements(
                Feature::OptionShutdownAnySegwit,
            ),
            option_channel_type: requirements(Feature::OptionChannelType),
            option_scid_alias: requirements(Feature::OptionScidAlias),
            option_payment_metadata: requirements(
                Feature::OptionPaymentMetadata,
            ),
            option_zeroconf: requirements(Feature::OptionZeroConf),
            unknown: none!(),
        };

        parsed.unknown = flags ^ parsed.clone().into();
        parsed.unknown.shrink();

        parsed.check()?;

        Ok(parsed)
    }
}

impl From<InitFeatures> for FlagVec {
    fn from(features: InitFeatures) -> Self {
        let flags = features.unknown.shrunk();
        features.known_set_features().into_iter().fold(
            flags,
            |mut flags, (feature, required)| {
                flags.set(feature.bit(required).expect(
                    "InitFeatures feature flag specification is broken",
                ));
                flags
            },
        )
    }
}

impl LightningEncode for InitFeatures {
    fn lightning_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        FlagVec::from(self.clone()).lightning_encode(e)

        /* Previous implementation:
        let len = self.byte_len();
        let mut vec = vec![len];

        let set_bit = |bit: u16| {
            let byte_no = len - bit / 8 - 1;
            let bit_no = bit % 8;
            vec[byte_no] |= 1 << bit_no;
        };

        for (feature, required) in self.known_set_features() {
            let bit = feature
                .bit(required)
                .expect("feature with unknown bit is set in feature vector");
            if !bit {
                continue;
            }
            set_bit(bit)
        }
        for bit in &self.unknown {
            set_bit(bit)
        }
        vec.lightning_encode(e)
         */
    }
}

impl LightningDecode for InitFeatures {
    fn lightning_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        let flag_vec = FlagVec::lightning_decode(d)?;
        InitFeatures::try_from(flag_vec).map_err(|e| {
            lightning_encoding::Error::DataIntegrityError(e.to_string())
        })
    }
}

#[cfg(feature = "strict_encoding")]
impl strict_encoding::StrictEncode for InitFeatures {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        FlagVec::from(self.clone()).strict_encode(e)
    }
}

#[cfg(feature = "strict_encoding")]
impl strict_encoding::StrictDecode for InitFeatures {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let vec = FlagVec::strict_decode(d)?;
        InitFeatures::try_from(vec).map_err(|e| {
            strict_encoding::Error::DataIntegrityError(e.to_string())
        })
    }
}

/// Features negotiated during channel creation and announced with
/// `channel_announcement`.
///
/// NB: Current BOLT-1 does not define any specific channel features.
///
/// Flags are numbered from the least-significant bit, at bit 0 (i.e. 0x1, an
/// even bit). They are generally assigned in pairs so that features can be
/// introduced as optional (odd bits) and later upgraded to be compulsory (even
/// bits), which will be refused by outdated nodes.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md>
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct ChannelFeatures {}

impl TryFrom<FlagVec> for ChannelFeatures {
    type Error = Error;

    fn try_from(_: FlagVec) -> Result<Self, Self::Error> {
        Ok(ChannelFeatures {})
    }
}

impl From<ChannelFeatures> for FlagVec {
    fn from(_: ChannelFeatures) -> Self {
        FlagVec::default()
    }
}

impl LightningEncode for ChannelFeatures {
    fn lightning_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        FlagVec::from(*self).lightning_encode(e)

        /* Previous implementation:
        let len = self.byte_len();
        let mut vec = vec![len];

        let set_bit = |bit: u16| {
            let byte_no = len - bit / 8 - 1;
            let bit_no = bit % 8;
            vec[byte_no] |= 1 << bit_no;
        };

        for (feature, required) in self.known_set_features() {
            let bit = feature
                .bit(required)
                .expect("feature with unknown bit is set in feature vector");
            if !bit {
                continue;
            }
            set_bit(bit)
        }
        for bit in &self.unknown {
            set_bit(bit)
        }
        vec.lightning_encode(e)
         */
    }
}

impl LightningDecode for ChannelFeatures {
    fn lightning_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        let flag_vec = FlagVec::lightning_decode(d)?;
        ChannelFeatures::try_from(flag_vec).map_err(|e| {
            lightning_encoding::Error::DataIntegrityError(e.to_string())
        })
    }
}

#[cfg(feature = "strict_encoding")]
impl strict_encoding::StrictEncode for ChannelFeatures {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        FlagVec::from(*self).strict_encode(e)
    }
}

#[cfg(feature = "strict_encoding")]
impl strict_encoding::StrictDecode for ChannelFeatures {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let vec = FlagVec::strict_decode(d)?;
        ChannelFeatures::try_from(vec).map_err(|e| {
            strict_encoding::Error::DataIntegrityError(e.to_string())
        })
    }
}
