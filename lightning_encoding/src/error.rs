// Network encoding for lightning network peer protocol data types
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

use amplify::IoError;
use strict_encoding::TlvError;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// I/O error
    #[from(std::io::Error)]
    #[from(std::io::ErrorKind)]
    #[display(inner)]
    Io(IoError),

    /// decoded BigSize is not canonical
    BigSizeNotCanonical,

    /// unexpected EOF while decoding BigSize value
    BigSizeEof,

    /// Indicates absence of BigSize value. Used in TLV stream reading
    #[display("unexpected EOF while decoding BigSize value")]
    BigSizeNoValue,

    /// not all provided data were consumed during decoding process
    DataNotEntirelyConsumed,

    /// Custom type-specific error
    #[display(inner)]
    DataIntegrityError(String),

    /// TLV encoding error
    #[from]
    #[display(inner)]
    Tlv(TlvError),

    /// unsupported value `{0}` for enum `{0}` encountered during decode
    /// operation
    EnumValueNotKnown(&'static str, usize),

    /// data size {0} exceeds maximum allowed for the lightning message
    TooLargeData(usize),
}
