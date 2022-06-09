// LNP P2P library, plmeneting both bolt (BOLT) and Bifrost P2P messaging
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

/// Message specific to a particular Bifrost application (Layer 3).
pub struct Message {
    /// Application identifier.
    ///
    /// Range up to `0..=0x8000` is reserved for applications registered as
    /// LNPBP standards. Range `0x8001-0xFFFF` (custom user range) can be used
    /// by any application without registration.
    ///
    /// It is strongly advised to use random numbers from custom user range;
    /// for instance by taking first two bytes of the SHA256 hash of the
    /// application name or developer domain name and do a binary OR operation
    /// with `0x8000`.
    pub application: u16,

    /// Application-defined message type
    pub message_type: u16,

    /// Real message data
    pub message_data: Box<[u8]>,
}
