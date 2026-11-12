use rampage_decode::encode;
use rampage_decode::probe::{FLAG_ORDERS, LAYOUTS, MIN_MATCHES, WINDOW_BITS};
use rampage_decode::{DecodeError, DecodeOptions, Decoder, Lz4Block, Lzss, Lzss4k, OffsetMode, ScanEnd};

fn options(expected: usize) -> DecodeOptions {
    DecodeOptions {
        expected_output_size: expected,
        max_output_size: 1 << 20,
        max_expansion_ratio: 1024,
        max_steps: 1 << 24,
    }
}

fn every_variant() -> impl Iterator<Item = Lzss> {
    let mut all = Vec::new();
    for window_bits in WINDOW_BITS {
        for min_match in MIN_MATCHES {
            for flag_order in FLAG_ORDERS {
                for literal_flag in [true, false] {
                    for layout in LAYOUTS {
                        for (offset_mode, start, fill) in [
                            (OffsetMode::Distance, 0, 0),
                            (OffsetMode::DistanceMinusOne, 0, 0),
                            (OffsetMode::RingPosition, (1u16 << window_bits) - 18, 0x20),
                            (OffsetMode::RingPosition, 7, 0),
                        ] {
                            all.push(Lzss {
                                window_bits,
                                min_match,
                                flag_order,
                                literal_flag,
                                layout,
                                offset_mode,
                                initial_write_offset: start,
                                dictionary_fill: fill,
                            });
                        }
                    }
                }
            }
        }
    }
    all.into_iter()
}

#[test]
fn every_lzss_variant_round_trips_through_the_reference_encoder() {
    let mut data = encode::synthetic_firmware(3000, 12);
    data.extend([0x20; 40]);
    for lzss in every_variant() {
        let stream = encode::lzss(&lzss, &data);
        let decoded = lzss.decode(&stream, &options(data.len()), &mut || false).unwrap();
        assert_eq!(decoded.bytes, data, "{lzss:?}");
        assert_eq!(decoded.consumed, stream.len(), "{lzss:?}");
        assert_eq!(lzss.measure(&stream, data.len()), (Some(stream.len()), lzss.measure(&stream, data.len()).1));
    }
}

#[test]
fn classic_variant_is_the_lzss_4k_provider() {
    let data = encode::synthetic_firmware(5000, 3);
    let stream = encode::lzss(&Lzss::classic_4k(4078, 0), &data);
    let decoded = Lzss4k { initial_write_offset: 4078, dictionary_fill: 0 }
        .decode(&stream, &options(data.len()), &mut || false)
        .unwrap();
    assert_eq!(decoded.bytes, data);
}

#[test]
fn distance_references_before_the_output_start_are_invalid_not_zero_filled() {
    let lzss = Lzss { offset_mode: OffsetMode::Distance, initial_write_offset: 0, ..Lzss::classic_4k(0, 0) };
    // One literal, then a reference two bytes back: past the output start.
    let stream = [0b01, b'A', 2, 0];
    assert_eq!(lzss.decode(&stream, &options(4), &mut || false), Err(DecodeError::InvalidReference));
    let scan = lzss.decode_available(&stream, 100, 1000, &mut || false).unwrap();
    assert_eq!((scan.bytes, scan.consumed, scan.end), (b"A".to_vec(), 2, ScanEnd::InvalidToken));
    let invalid = Lzss { window_bits: 14, ..lzss };
    assert_eq!(invalid.decode(&[], &options(0), &mut || false), Err(DecodeError::InvalidParameters));
    let ring_fill_on_distance = Lzss { dictionary_fill: 1, ..lzss };
    assert!(!ring_fill_on_distance.is_valid());
}

#[test]
fn available_decoding_stops_on_token_boundaries_and_names_why() {
    let lzss = Lzss::classic_4k(4078, 0);
    let data = encode::synthetic_firmware(2000, 4);
    let stream = encode::lzss(&lzss, &data);
    let whole = lzss.decode_available(&stream, usize::MAX, u64::MAX, &mut || false).unwrap();
    assert_eq!((whole.bytes.len(), whole.end), (data.len(), ScanEnd::InputExhausted));
    let cut = lzss.decode_available(&stream[..stream.len() - 1], usize::MAX, u64::MAX, &mut || false).unwrap();
    assert!(cut.consumed < stream.len() - 1 || cut.end == ScanEnd::InputExhausted);
    assert!(data.starts_with(&cut.bytes));
    let capped = lzss.decode_available(&stream, 100, u64::MAX, &mut || false).unwrap();
    assert!(capped.bytes.len() <= 100 && capped.end == ScanEnd::OutputLimit);
    assert_eq!(lzss.decode_available(&stream, usize::MAX, 10, &mut || false), Err(DecodeError::WorkLimitExceeded));
}

#[test]
fn lz4_blocks_round_trip_and_bad_distances_or_truncation_refuse() {
    for data in [encode::synthetic_firmware(9000, 5), vec![7; 300], b"short".to_vec()] {
        let stream = encode::lz4_block(&data);
        let decoded = Lz4Block.decode(&stream, &options(data.len()), &mut || false).unwrap();
        assert_eq!((decoded.bytes, decoded.consumed), (data.clone(), stream.len()));
        let scan = Lz4Block.decode_available(&stream, usize::MAX, u64::MAX, &mut || false).unwrap();
        assert_eq!((scan.bytes.len(), scan.end), (data.len(), ScanEnd::InputExhausted));
    }
    // One literal 'A', then a match at distance 2: past the output start.
    let bad = [0x10, b'A', 2, 0];
    assert_eq!(Lz4Block.decode(&bad, &options(6), &mut || false), Err(DecodeError::InvalidReference));
    assert_eq!(Lz4Block.decode(&[0x50, b'A'], &options(5), &mut || false), Err(DecodeError::TruncatedInput));
    assert_eq!(Lz4Block.id(), "lz4-block");
}
