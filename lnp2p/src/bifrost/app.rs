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

pub const BIFROST_APP_STORM: u16 = 0x0001;
pub const BIFROST_APP_VENDOR_MASK: u16 = 0x8000;

/// Bifrost application identifier.
///
/// Range up to `0..0x8000` is reserved for applications registered as
/// LNPBP standards. Range `0x8000-0xFFFF` (custom user range) can be used
/// by any application without registration.
///
/// It is strongly advised to use random numbers from custom user range;
/// for instance by taking first two bytes of the SHA256 hash of the
/// application name or developer domain name and do a binary OR operation
/// with `0x8000`.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum BifrostApp {
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

impl BifrostApp {
    pub fn app_code(self) -> u16 {
        match self {
            BifrostApp::Storm => BIFROST_APP_STORM,
            BifrostApp::Future(app) => app,
            BifrostApp::Vendor(vendor) => vendor,
        }
    }
}

impl StrictEncode for BifrostApp {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        self.app_code().strict_encode(e)
    }
}

impl StrictDecode for BifrostApp {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        u16::strict_decode(d).map(BifrostApp::from)
    }
}

impl From<BifrostApp> for u16 {
    fn from(app: BifrostApp) -> Self {
        app.app_code()
    }
}

impl From<u16> for BifrostApp {
    fn from(code: u16) -> Self {
        match code {
            BIFROST_APP_STORM => BifrostApp::Storm,
            vendor if vendor & BIFROST_APP_VENDOR_MASK > 0 => {
                BifrostApp::Vendor(vendor)
            }
            future => BifrostApp::Future(future),
        }
    }
}
