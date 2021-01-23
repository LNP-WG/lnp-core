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

use crate::{strategies, Strategy};

use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};

impl Strategy for IpAddr {
    type Strategy = strategies::AsStrict;
}

impl Strategy for Ipv4Addr {
    type Strategy = strategies::AsStrict;
}

impl Strategy for Ipv6Addr {
    type Strategy = strategies::AsStrict;
}

impl Strategy for SocketAddr {
    type Strategy = strategies::AsStrict;
}

impl Strategy for SocketAddrV4 {
    type Strategy = strategies::AsStrict;
}

impl Strategy for SocketAddrV6 {
    type Strategy = strategies::AsStrict;
}
