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

use amplify::{DumbDefault, ToYamlString};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use p2p::legacy::{AcceptChannel, ChannelType, OpenChannel};
use secp256k1::{PublicKey, Secp256k1};
use wallet::hd::HardenedIndex;
use wallet::scripts::{Category, PubkeyScript, ToPubkeyScript};

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
impl ToYamlString for Keyset {}

impl From<&OpenChannel> for Keyset {
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

impl From<&AcceptChannel> for Keyset {
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
            static_remotekey: false,
        }
    }
}

impl Keyset {
    /// Derives keyset from a *channel extended key* using LNPBP-46 standard
    pub fn with<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        channel_xpriv: ExtendedPrivKey,
        commit_to_shutdown_scriptpubkey: bool,
    ) -> Self {
        let keys = (0u16..=7)
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
            funding_pubkey: keys[0],
            revocation_basepoint: keys[2],
            payment_basepoint: keys[0],
            delayed_payment_basepoint: keys[1],
            htlc_basepoint: keys[5],
            first_per_commitment_point: keys[4],
            shutdown_scriptpubkey: if commit_to_shutdown_scriptpubkey {
                Some(keys[7].to_pubkey_script(Category::SegWit))
            } else {
                None
            },
            static_remotekey: false,
        }
    }
}
