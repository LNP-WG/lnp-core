// LNP/BP Core Library implementing LNPBP specifications & standards
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

use std::collections::BTreeMap;

use amplify::DumbDefault;
#[cfg(feature = "serde")]
use amplify::ToYamlString;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, KeySource};
use bitcoin_scripts::PubkeyScript;
use p2p::bolt::{AcceptChannel, ChannelType, OpenChannel};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use wallet::hd::HardenedIndex;

/// Key + information about its derivation
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(LocalPubkey::to_yaml_string)
)]
pub struct LocalPubkey {
    pub key: PublicKey,
    pub source: KeySource,
}

impl LocalPubkey {
    #[inline]
    pub fn to_bip32_derivation_map(&self) -> BTreeMap<PublicKey, KeySource> {
        bmap! { self.key => self.source.clone() }
    }

    #[inline]
    pub fn to_bitcoin_pk(&self) -> bitcoin::PublicKey {
        bitcoin::PublicKey::new(self.key)
    }
}

/// Set of keys used by the core of the channel. It does not include HTLC
/// basepoint which is managed separately by [`super::Htlc`] extension.
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(LocalKeyset::to_yaml_string)
)]
pub struct LocalKeyset {
    /// Public key used in the funding outpoint multisig
    pub funding_pubkey: LocalPubkey,
    /// Base point for deriving keys used for penalty spending paths
    pub revocation_basepoint: LocalPubkey,
    /// Base point for deriving keys in `to_remote`
    pub payment_basepoint: LocalPubkey,
    /// Base point for deriving keys in `to_local` time-locked spending paths
    pub delayed_payment_basepoint: LocalPubkey,
    /// Base point for deriving HTLC-related keys
    pub htlc_basepoint: LocalPubkey,
    /// Commitment point to be used for the first commitment transaction
    pub first_per_commitment_point: LocalPubkey,
    /// Private Key of the commitment point to be used `revoke_and_ack` message
    pub first_per_commitment_secret: Option<SecretKey>,
    /// Allows the sending node to commit to where funds will go on mutual
    /// close, which the remote node should enforce even if a node is
    /// compromised later.
    pub shutdown_scriptpubkey: Option<PubkeyScript>,
    /// If `option_static_remotekey` or `option_anchors` is negotiated, the
    /// remotepubkey is simply the remote node's payment_basepoint, otherwise
    /// it is calculated as above using the remote node's payment_basepoint.
    pub static_remotekey: bool,
}

/// Set of keys used by the core of the channel. It does not include HTLC
/// basepoint which is managed separately by [`super::Htlc`] extension.
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(RemoteKeyset::to_yaml_string)
)]
pub struct RemoteKeyset {
    /// Public key used in the funding outpoint multisig
    pub funding_pubkey: PublicKey,
    /// Base point for deriving keys used for penalty spending paths
    pub revocation_basepoint: PublicKey,
    /// Base point for deriving keys in `to_remote`
    pub payment_basepoint: PublicKey,
    /// Base point for deriving keys in `to_local` time-locked spending paths
    pub delayed_payment_basepoint: PublicKey,
    /// Base point for deriving HTLC-related keys
    pub htlc_basepoint: PublicKey,
    /// Base point for deriving keys used for penalty spending paths
    pub first_per_commitment_point: PublicKey,
    /// Allows the sending node to commit to where funds will go on mutual
    /// close, which the remote node should enforce even if a node is
    /// compromised later.
    pub shutdown_scriptpubkey: Option<PubkeyScript>,
    /// If `option_static_remotekey` or `option_anchors` is negotiated, the
    /// remotepubkey is simply the remote node's payment_basepoint, otherwise
    /// it is calculated as above using the remote node's payment_basepoint.
    pub static_remotekey: bool,
}

#[cfg(feature = "serde")]
impl ToYamlString for LocalPubkey {}

#[cfg(feature = "serde")]
impl ToYamlString for LocalKeyset {}

#[cfg(feature = "serde")]
impl ToYamlString for RemoteKeyset {}

impl From<&OpenChannel> for RemoteKeyset {
    fn from(open_channel: &OpenChannel) -> Self {
        Self {
            funding_pubkey: open_channel.funding_pubkey,
            revocation_basepoint: open_channel.revocation_basepoint,
            payment_basepoint: open_channel.payment_point,
            delayed_payment_basepoint: open_channel.delayed_payment_basepoint,
            htlc_basepoint: open_channel.htlc_basepoint,
            first_per_commitment_point: open_channel.first_per_commitment_point,
            shutdown_scriptpubkey: open_channel.shutdown_scriptpubkey.clone(),
            static_remotekey: false,
        }
    }
}

impl From<&AcceptChannel> for RemoteKeyset {
    fn from(accept_channel: &AcceptChannel) -> Self {
        Self {
            funding_pubkey: accept_channel.funding_pubkey,
            revocation_basepoint: accept_channel.revocation_basepoint,
            payment_basepoint: accept_channel.payment_point,
            delayed_payment_basepoint: accept_channel.delayed_payment_basepoint,
            htlc_basepoint: accept_channel.htlc_basepoint,
            first_per_commitment_point: accept_channel
                .first_per_commitment_point,
            shutdown_scriptpubkey: accept_channel.shutdown_scriptpubkey.clone(),
            static_remotekey: accept_channel
                .channel_type
                .map(ChannelType::has_static_remotekey)
                .unwrap_or_default(),
        }
    }
}

impl DumbDefault for LocalPubkey {
    fn dumb_default() -> Self {
        LocalPubkey {
            key: dumb_pubkey!(),
            source: KeySource::default(),
        }
    }
}

impl DumbDefault for LocalKeyset {
    fn dumb_default() -> Self {
        Self {
            funding_pubkey: DumbDefault::dumb_default(),
            revocation_basepoint: DumbDefault::dumb_default(),
            payment_basepoint: DumbDefault::dumb_default(),
            delayed_payment_basepoint: DumbDefault::dumb_default(),
            htlc_basepoint: DumbDefault::dumb_default(),
            first_per_commitment_secret: None,
            first_per_commitment_point: DumbDefault::dumb_default(),
            shutdown_scriptpubkey: None,
            static_remotekey: false,
        }
    }
}

impl DumbDefault for RemoteKeyset {
    fn dumb_default() -> Self {
        Self {
            funding_pubkey: dumb_pubkey!(),
            revocation_basepoint: dumb_pubkey!(),
            payment_basepoint: dumb_pubkey!(),
            delayed_payment_basepoint: dumb_pubkey!(),
            htlc_basepoint: dumb_pubkey!(),
            first_per_commitment_point: dumb_pubkey!(),
            shutdown_scriptpubkey: None,
            static_remotekey: false,
        }
    }
}

impl LocalKeyset {
    /// Derives keyset from a *channel extended key* using LNPBP-46 standard
    pub fn with<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        channel_source: KeySource,
        channel_xpriv: ExtendedPrivKey,
        shutdown_scriptpubkey: Option<PubkeyScript>,
    ) -> Self {
        let fingerpint = channel_source.0;

        let secrets = (0u16..=6)
            .into_iter()
            .map(HardenedIndex::from)
            .map(ChildNumber::from)
            .map(|index| [index])
            .map(|path| {
                channel_xpriv
                    .derive_priv(secp, &path)
                    .expect("negligible probability")
                    .private_key
            })
            .collect::<Vec<_>>();

        let keys = (0u16..=6)
            .into_iter()
            .map(HardenedIndex::from)
            .map(ChildNumber::from)
            .map(|index| [index])
            .map(|path| {
                let derivation_path = channel_source.1.clone().extend(path);
                let seckey = channel_xpriv
                    .derive_priv(secp, &path)
                    .expect("negligible probability")
                    .private_key;
                LocalPubkey {
                    key: PublicKey::from_secret_key(secp, &seckey),
                    source: (fingerpint, derivation_path),
                }
            })
            .collect::<Vec<_>>();

        Self {
            funding_pubkey: keys[0].clone(),
            revocation_basepoint: keys[3].clone(),
            payment_basepoint: keys[1].clone(),
            delayed_payment_basepoint: keys[2].clone(),
            htlc_basepoint: keys[5].clone(),
            first_per_commitment_point: keys[4].clone(),
            first_per_commitment_secret: Some(secrets[4].clone()),
            shutdown_scriptpubkey,
            static_remotekey: false,
        }
    }
}
