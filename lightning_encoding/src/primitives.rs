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

use super::{strategies, Strategy};

impl Strategy for u8 {
    type Strategy = strategies::AsBigSize;
}

impl Strategy for u16 {
    type Strategy = strategies::AsBigSize;
}

impl Strategy for u32 {
    type Strategy = strategies::AsBigSize;
}

impl Strategy for u64 {
    type Strategy = strategies::AsBigSize;
}

impl Strategy for usize {
    type Strategy = strategies::AsBigSize;
}

impl Strategy for amplify::flags::FlagVec {
    type Strategy = strategies::AsStrict;
}

impl Strategy for amplify::Slice32 {
    type Strategy = strategies::AsStrict;
}
