use rampage_decode::Lzss;
use rampage_decode::encode::{self, Random};

use crate::FileLayoutRequest;
use crate::file_layout::{LayoutParameters, layout};

/// A component: load-address word, payload length, decoded length, then a checksum word, then the payload.
fn component(load: u32, payload: &[u8], decoded: usize, checksum: Option<u32>) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(load.to_le_bytes());
    bytes.extend((payload.len() as u32).to_le_bytes());
    bytes.extend((decoded as u32).to_le_bytes());
    bytes.extend(checksum.unwrap_or(0x1234_5678).to_le_bytes());
    bytes.extend(payload);
    bytes
}

fn sum(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)))
}

fn hints(bytes: &[u8]) -> Vec<crate::file_layout::LayoutHint> {
    let parameters = LayoutParameters::from_request(&FileLayoutRequest::default()).unwrap();
    layout(bytes, 0x100, bytes.len() as u64 + 0x100, true, &parameters)
        .hints
        .into_iter()
        .filter(|hint| hint.kind == "compressed_component_candidate")
        .collect()
}

#[test]
fn chained_checksummed_components_after_a_loader_are_reported_with_extents_and_decoded_sizes() {
    let first = encode::synthetic_firmware(24 << 10, 1);
    let second = encode::synthetic_firmware(9000, 2);
    let classic = Lzss::classic_4k(4078, 0);
    let (packed1, packed2) = (encode::lzss(&classic, &first), encode::lzss(&classic, &second));
    // A small plain loader, padding, then two components back to back and erased flash.
    let mut image = encode::synthetic_firmware(3000, 9);
    image.extend([0xff; 96]);
    let first_header = image.len();
    image.extend(component(0x2000_0000, &packed1, first.len(), Some(sum(&packed1))));
    let second_header = image.len();
    image.extend(component(0x2001_0000, &packed2, second.len(), Some(sum(&packed2))));
    image.extend([0xff; 512]);

    let found = hints(&image);
    assert_eq!(found.len(), 2, "{found:#?}");
    for (hint, header, packed, decoded) in
        [(&found[0], first_header, &packed1, first.len()), (&found[1], second_header, &packed2, second.len())]
    {
        let container = hint.container.as_ref().unwrap();
        assert_eq!(container.payload_offset, 0x100 + header as u64 + 16);
        assert_eq!(container.payload_length, packed.len() as u64);
        assert_eq!(container.size_field.offset, 0x100 + header as u64 + 4);
        assert_eq!(container.checksum_field.unwrap().kind, "byte_sum32", "{container:#?} {:#x}", sum(packed));
        assert_eq!(container.checksum_field.unwrap().offset, 0x100 + header as u64 + 12);
        assert!(container.decoded_size_candidates.iter().any(|word| word.value as usize == decoded));
        assert!(container.checks_passed.contains(&"checksum_verified_over_payload"));
        assert!(hint.evidence[0].starts_with("header-checked compressed-component candidate"));
    }
    assert_eq!(found[1].container.as_ref().unwrap().payload_end, "fill_run");
}

#[test]
fn crc32_and_big_endian_headers_verify_without_a_fill_boundary_check() {
    let payload = encode::lzss(&Lzss::classic_4k(4078, 0), &encode::synthetic_firmware(6000, 4));
    let mut crc = flate2::Crc::new();
    crc.update(&payload);
    let mut image = vec![0xff; 128];
    image.extend(0x0800_4000u32.to_be_bytes());
    image.extend((payload.len() as u32).to_be_bytes());
    image.extend(crc.sum().to_be_bytes());
    image.extend(&payload);
    image.extend(encode::synthetic_firmware(2000, 5));
    let found = hints(&image);
    assert_eq!(found.len(), 1, "{found:#?}");
    let container = found[0].container.as_ref().unwrap();
    assert_eq!((container.byte_order, container.checksum_field.unwrap().kind), ("big", "crc32"));
    assert_eq!(container.payload_end, "none");
}

#[test]
fn unchecked_code_random_data_and_wrong_sums_give_no_candidate() {
    let mut code = encode::synthetic_firmware(200 << 10, 6);
    code.extend([0xff; 256]);
    code.extend(Random(3).bytes(64 << 10));
    code.extend([0; 256]);
    assert!(hints(&code).is_empty());

    // A size that fits and a packed payload, but a wrong checksum, no decoded-size word and no boundary.
    let payload = Random(4).bytes(5000);
    let mut image = vec![0xff; 128];
    image.extend([0; 4]);
    image.extend((payload.len() as u32).to_le_bytes());
    image.extend([1, 0, 0, 0]);
    image.extend((sum(&payload) ^ 1).to_le_bytes());
    image.extend(&payload);
    image.extend(encode::synthetic_firmware(4000, 8));
    assert!(hints(&image).is_empty(), "{:#?}", hints(&image));
}
