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

use bitcoin::secp256k1::PublicKey;
use wallet::hlc::HashLock;

/// Payment request as it may be extracted from BOLT-11 invoice and used for
/// route construction.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("pay {amount_msat} msat to {node_id} locked by {payment_hash}")]
pub struct PaymentRequest {
    /// Amount to pay
    pub amount_msat: u64,

    /// The hash lock for the payment
    pub payment_hash: HashLock,

    /// Destination node id
    pub node_id: PublicKey,

    /// Minimal CLTV expiry that should be used at the destination.
    ///
    /// The actual CLTV used in the offered HTLC may be larger due to
    /// `cltv_delay`s on a route.
    pub min_final_cltv_expiry: u32,
}
