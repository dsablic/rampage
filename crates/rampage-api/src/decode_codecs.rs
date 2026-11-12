//! The codecs `decode_file_range` and `probe_compression` name, and their explicit parameters.

use rampage_decode::{Decoder, FlagOrder, Lz4Block, Lzss, Lzss4k, OffsetMode, ReferenceLayout};
use serde::Serialize;

use crate::ApiError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, schemars::JsonSchema)]
pub enum ContentCodec {
    /// The classic 4 KiB ring variant; only `initial_write_offset` and `dictionary_fill` vary.
    #[serde(rename = "lzss-4k")]
    Lzss4k,
    /// LZSS with every variant parameter explicit in `lzss`.
    #[serde(rename = "lzss")]
    Lzss,
    /// The LZ4 block format (no frame header).
    #[serde(rename = "lz4-block")]
    Lz4Block,
}

impl std::str::FromStr for ContentCodec {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lzss-4k" => Ok(Self::Lzss4k),
            "lzss" => Ok(Self::Lzss),
            "lz4-block" => Ok(Self::Lz4Block),
            _ => Err("unsupported decoder; select lzss-4k, lzss or lz4-block explicitly".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LzssFlagOrder {
    /// The least-significant flag bit describes the first token.
    LsbFirst,
    MsbFirst,
}

/// How a reference's two bytes `b0 b1` split into an offset of `window_bits` bits and a length of the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LzssReferenceLayout {
    /// Offset is `b0` plus the high bits of `b1` above it; length is the low bits of `b1`.
    SplitByte,
    /// Little-endian 16-bit word, offset in the low bits.
    Le16OffsetLow,
    /// Little-endian 16-bit word, length in the low bits.
    Le16LengthLow,
    /// Big-endian 16-bit word, offset in the low bits.
    Be16OffsetLow,
    /// Big-endian 16-bit word, length in the low bits.
    Be16LengthLow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LzssOffsetMode {
    /// Absolute position in a ring of 2^window_bits bytes, filled with `dictionary_fill` and written from
    /// `initial_write_offset`.
    RingPosition,
    /// Distance back from the next output byte.
    Distance,
    /// Distance back minus one.
    DistanceMinusOne,
}

/// Every LZSS variant parameter, explicit. Flag bytes carry eight tokens; literals are one byte; references are
/// two bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LzssParameters {
    /// Offset bits, 10..=13 (a 1, 2, 4 or 8 KiB window); the length field has the other 16 - window_bits bits.
    #[schemars(range(min = 10, max = 13))]
    pub window_bits: u8,
    /// Added to the length field, 2 or 3.
    #[schemars(range(min = 2, max = 3))]
    pub min_match: u8,
    pub flag_order: LzssFlagOrder,
    /// The flag bit value, 0 or 1, that means a literal.
    #[schemars(range(min = 0, max = 1))]
    pub literal_bit: u8,
    pub reference_layout: LzssReferenceLayout,
    pub offset_mode: LzssOffsetMode,
}

impl LzssParameters {
    pub(crate) fn provider(self, initial_write_offset: u16, dictionary_fill: u8) -> Lzss {
        Lzss {
            window_bits: self.window_bits,
            min_match: self.min_match,
            flag_order: match self.flag_order {
                LzssFlagOrder::LsbFirst => FlagOrder::LsbFirst,
                LzssFlagOrder::MsbFirst => FlagOrder::MsbFirst,
            },
            literal_flag: self.literal_bit == 1,
            layout: match self.reference_layout {
                LzssReferenceLayout::SplitByte => ReferenceLayout::SplitByte,
                LzssReferenceLayout::Le16OffsetLow => ReferenceLayout::Le16OffsetLow,
                LzssReferenceLayout::Le16LengthLow => ReferenceLayout::Le16LengthLow,
                LzssReferenceLayout::Be16OffsetLow => ReferenceLayout::Be16OffsetLow,
                LzssReferenceLayout::Be16LengthLow => ReferenceLayout::Be16LengthLow,
            },
            offset_mode: match self.offset_mode {
                LzssOffsetMode::RingPosition => OffsetMode::RingPosition,
                LzssOffsetMode::Distance => OffsetMode::Distance,
                LzssOffsetMode::DistanceMinusOne => OffsetMode::DistanceMinusOne,
            },
            initial_write_offset,
            dictionary_fill,
        }
    }

    pub(crate) fn from_provider(lzss: &Lzss) -> Self {
        Self {
            window_bits: lzss.window_bits,
            min_match: lzss.min_match,
            flag_order: match lzss.flag_order {
                FlagOrder::LsbFirst => LzssFlagOrder::LsbFirst,
                FlagOrder::MsbFirst => LzssFlagOrder::MsbFirst,
            },
            literal_bit: u8::from(lzss.literal_flag),
            reference_layout: match lzss.layout {
                ReferenceLayout::SplitByte => LzssReferenceLayout::SplitByte,
                ReferenceLayout::Le16OffsetLow => LzssReferenceLayout::Le16OffsetLow,
                ReferenceLayout::Le16LengthLow => LzssReferenceLayout::Le16LengthLow,
                ReferenceLayout::Be16OffsetLow => LzssReferenceLayout::Be16OffsetLow,
                ReferenceLayout::Be16LengthLow => LzssReferenceLayout::Be16LengthLow,
            },
            offset_mode: match lzss.offset_mode {
                OffsetMode::RingPosition => LzssOffsetMode::RingPosition,
                OffsetMode::Distance => LzssOffsetMode::Distance,
                OffsetMode::DistanceMinusOne => LzssOffsetMode::DistanceMinusOne,
            },
        }
    }
}

/// The ring start a codec uses when none is supplied: 4078 (0xfee) for `lzss-4k`, zero otherwise.
pub fn default_initial_write_offset(codec: ContentCodec) -> u16 {
    if codec == ContentCodec::Lzss4k { 4078 } else { 0 }
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

/// The provider for a codec and its parameters, refusing parameters that do not belong to it.
pub(crate) fn provider(
    codec: ContentCodec,
    lzss: Option<LzssParameters>,
    initial_write_offset: u16,
    dictionary_fill: u8,
) -> Result<Box<dyn Decoder>, ApiError> {
    Ok(match (codec, lzss) {
        (ContentCodec::Lzss4k, None) => {
            if initial_write_offset >= 4096 {
                return Err(invalid("LZSS initial_write_offset must be 0..4095"));
            }
            Box::new(Lzss4k { initial_write_offset, dictionary_fill })
        }
        (ContentCodec::Lzss, Some(parameters)) => {
            let provider = parameters.provider(initial_write_offset, dictionary_fill);
            if !provider.is_valid() {
                return Err(invalid(
                    "invalid lzss parameters: window_bits 10..=13, min_match 2..=3, literal_bit 0..=1, \
                     initial_write_offset below the window, and initial_write_offset and dictionary_fill zero \
                     unless offset_mode is ring_position",
                ));
            }
            Box::new(provider)
        }
        (ContentCodec::Lz4Block, None) if initial_write_offset == 0 && dictionary_fill == 0 => Box::new(Lz4Block),
        (ContentCodec::Lz4Block, None) => {
            return Err(invalid("lz4-block takes no initial_write_offset or dictionary_fill"));
        }
        (ContentCodec::Lzss, None) => return Err(invalid("codec lzss needs explicit lzss parameters")),
        (_, Some(_)) => return Err(invalid("lzss parameters apply only to codec lzss")),
    })
}

pub(crate) fn dictionary_size(codec: ContentCodec, lzss: Option<LzssParameters>) -> usize {
    match (codec, lzss) {
        (ContentCodec::Lzss, Some(parameters)) => 1 << parameters.window_bits,
        (ContentCodec::Lz4Block, _) => 65536,
        _ => 4096,
    }
}

pub(crate) fn variant_limitation(codec: ContentCodec) -> &'static str {
    match codec {
        ContentCodec::Lzss4k => {
            "Explicit lzss-4k variant: 4096-byte ring, LSB-first flags, 1=literal, 12-bit offset and length nibble+3."
        }
        ContentCodec::Lzss => "Explicit lzss variant: every parameter is in the receipt's lzss object.",
        ContentCodec::Lz4Block => "LZ4 block format: no frame, checksum or external dictionary; 64 KiB distances.",
    }
}
