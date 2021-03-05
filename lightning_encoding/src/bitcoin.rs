// Network encoding for lightning network peer protocol data types
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

use bitcoin::{hashes, secp256k1};

use super::{strategies, Strategy};

// TODO: Verify byte order for lightnin encoded types

impl Strategy for hashes::ripemd160::Hash {
    type Strategy = strategies::AsBitcoinHash;
}

impl Strategy for hashes::hash160::Hash {
    type Strategy = strategies::AsBitcoinHash;
}

impl Strategy for hashes::sha256::Hash {
    type Strategy = strategies::AsBitcoinHash;
}

impl Strategy for hashes::sha256d::Hash {
    type Strategy = strategies::AsBitcoinHash;
}

impl<T> Strategy for hashes::sha256t::Hash<T>
where
    T: hashes::sha256t::Tag,
{
    type Strategy = strategies::AsBitcoinHash;
}

impl<T> Strategy for hashes::hmac::Hmac<T>
where
    T: hashes::Hash,
{
    type Strategy = strategies::AsBitcoinHash;
}

impl Strategy for bitcoin::Txid {
    type Strategy = strategies::AsBitcoinHash;
}

impl Strategy for bitcoin::OutPoint {
    type Strategy = strategies::AsStrict;
}

impl Strategy for bitcoin::Script {
    // NB: Existing BOLTs define script length as u16, not BigSize, so we
    // can use this trick for now
    // TODO: Actually we can't. We need big endian encoding, while strict is
    //       little endian
    type Strategy = strategies::AsStrict;
}

impl Strategy for bitcoin::PublicKey {
    type Strategy = strategies::AsStrict;
}

impl Strategy for secp256k1::PublicKey {
    type Strategy = strategies::AsStrict;
}

impl Strategy for secp256k1::Signature {
    type Strategy = strategies::AsStrict;
}

impl Strategy for wallet::features::FlagVec {
    type Strategy = strategies::AsStrict;
}

impl Strategy for wallet::Slice32 {
    type Strategy = strategies::AsStrict;
}

impl Strategy for wallet::HashLock {
    type Strategy = strategies::AsStrict;
}

impl Strategy for wallet::HashPreimage {
    type Strategy = strategies::AsStrict;
}
