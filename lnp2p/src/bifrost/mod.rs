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

mod channel;
mod ctrl;
mod types;

pub use channel::*;
pub use ctrl::*;
pub use types::{
    AddressList, AnnouncedNodeAddr, ChannelId, ProtocolList, ProtocolName,
    ProtocolNameError, TempChannelId,
};

use std::io;

use internet2::{CreateUnmarshaller, Payload, Unmarshall, Unmarshaller};
use strict_encoding::{self, StrictDecode, StrictEncode};

/// Default legacy Lightning port number
pub const LNP2P_BIFROST_PORT: u16 = 9999;

lazy_static! {
    pub static ref LNP2P_BIFROST_UNMARSHALLER: Unmarshaller<Messages> =
        Messages::create_unmarshaller();
}

#[derive(Clone, Debug, Display, Api)]
#[api(encoding = "strict")]
#[non_exhaustive]
#[display(inner)]
pub enum Messages {
    // Part I: Generic messages outside of channel operations (BOLT-1)
    // ===============================================================
    /// Once authentication is complete, the first message reveals the features
    /// supported or required by this node, even if this is a reconnection.
    #[api(type = 16)]
    Init(Init),

    /// For simplicity of diagnosis, it's often useful to tell a peer that
    /// something is incorrect.
    #[api(type = 17)]
    Error(Error),

    /// In order to allow for the existence of long-lived TCP connections, at
    /// times it may be required that both ends keep alive the TCP connection
    /// at the application level. Such messages also allow obfuscation of
    /// traffic patterns.
    #[api(type = 18)]
    Ping(Ping),

    /// The pong message is to be sent whenever a ping message is received. It
    /// serves as a reply and also serves to keep the connection alive, while
    /// explicitly notifying the other end that the receiver is still active.
    /// Within the received ping message, the sender will specify the number of
    /// bytes to be included within the data payload of the pong message.
    #[api(type = 19)]
    #[display("pong(...)")]
    Pong(Vec<u8>),
}

impl StrictEncode for Messages {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Payload::from(self.clone()).strict_encode(e)
    }
}

impl StrictDecode for Messages {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let message = &*LNP2P_BIFROST_UNMARSHALLER
            .unmarshall(&Vec::<u8>::strict_decode(d)?)
            .map_err(|_| {
                strict_encoding::Error::DataIntegrityError(s!(
                    "can't unmarshall Bifrost message"
                ))
            })?;
        Ok(message.clone())
    }
}
