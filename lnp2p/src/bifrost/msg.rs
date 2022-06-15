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

use std::io;

use strict_encoding::{StrictDecode, StrictEncode};

pub const BIFROST_MSG_APP_STORM: u16 = 0x0001;
pub const BIFROST_MSG_APP_VENDOR_MASK: u16 = 0x8000;

/// Bifrost message application
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum MsgApp {
    /// Storm: storage and messaging over the lightning.
    #[display("storm")]
    Storm,

    /// Future applications. Numbers are reserved for LNPBP standardized apps.
    #[display("future({0:#06})")]
    Future(u16),

    /// Vendor-specific applications which does not standardized by LNP/BP
    /// Standards Association.
    #[display("vendor({0:#06})")]
    Vendor(u16),
}

impl MsgApp {
    pub fn app_code(self) -> u16 {
        match self {
            MsgApp::Storm => BIFROST_MSG_APP_STORM,
            MsgApp::Future(app) => app,
            MsgApp::Vendor(vendor) => vendor,
        }
    }
}

impl StrictEncode for MsgApp {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        self.app_code().strict_encode(e)
    }
}

impl StrictDecode for MsgApp {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        u16::strict_decode(d).map(MsgApp::from)
    }
}

impl From<MsgApp> for u16 {
    fn from(app: MsgApp) -> Self {
        app.app_code()
    }
}

impl From<u16> for MsgApp {
    fn from(code: u16) -> Self {
        match code {
            BIFROST_MSG_APP_STORM => MsgApp::Storm,
            vendor if vendor & BIFROST_MSG_APP_VENDOR_MASK > 0 => {
                MsgApp::Vendor(vendor)
            }
            future => MsgApp::Future(future),
        }
    }
}

/// Application-specific message payload.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display("{message_type:#08X}, ...")]
pub struct MsgPayload {
    /// Application-defined message type
    pub message_type: u16,

    /// Real message data
    pub message_data: Box<[u8]>,
}

/// Message specific to a particular Bifrost application (Layer 3).
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[display("msg({application}, {payload})")]
pub struct Msg {
    /// Application identifier.
    ///
    /// Range up to `0..0x8000` is reserved for applications registered as
    /// LNPBP standards. Range `0x8000-0xFFFF` (custom user range) can be used
    /// by any application without registration.
    ///
    /// It is strongly advised to use random numbers from custom user range;
    /// for instance by taking first two bytes of the SHA256 hash of the
    /// application name or developer domain name and do a binary OR operation
    /// with `0x8000`.
    pub application: MsgApp,

    /// Application-specific message payload.
    pub payload: MsgPayload,
}
