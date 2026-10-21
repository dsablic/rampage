use std::ffi::{CStr, CString};

use crate::sleigh_decode::SleighDecoder;
use crate::{DataOrganization, FFI_LOCK, abi, context};

#[test]
fn exact_pilot_native_organizations_after_memimage_space_isolation() {
    for (profile, compiler, code_name, highest, word_size, bytes) in [
        ("TI_MSP430:LE:16:default", "default", "RAM", 0xffff, 1, &[0x30, 0x41][..]),
        ("avr8:LE:16:default", "gcc", "code", 0x1ffff, 2, &[0x08, 0x95][..]),
    ] {
        let started = std::time::Instant::now();
        let decoder = SleighDecoder::open(profile).unwrap();
        let metadata = decoder.metadata();
        let code = metadata.spaces.iter().find(|space| space.id == metadata.code_space).unwrap();
        assert_eq!(code.name, code_name);
        assert_eq!(code.kind, 1);
        assert_eq!(code.address_size, 2);
        assert_eq!(code.word_size, word_size);
        assert_eq!(code.highest, highest);
        assert_eq!(metadata.alignment_bytes, 2);
        assert!(metadata.required_parallel_helper.is_none());
        let context = context::require_verified_bundled_native_context().unwrap();
        let specification_before = rampage_arch::hex::bytes(&context.manifest_sha256());
        let home = CString::new(context.home().as_os_str().as_encoded_bytes()).unwrap();
        let language = format!("{profile}:{compiler}");
        let language_c = CString::new(language.as_str()).unwrap();
        let bases = [0x1000_u64];
        let pointers = [bytes.as_ptr()];
        let lengths = [bytes.len()];
        let sizes = [bytes.len() as u64];
        let yes = [1_u8];
        let no = [0_u8];
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let before = context::begin_native_attempt(context.home());
        // SAFETY: verified exact IDs and one owned RX code mapping; all arrays live through the copying call.
        let handle = unsafe {
            crate::rampage_decomp_open(
                home.as_ptr(),
                language_c.as_ptr(),
                1,
                bases.as_ptr(),
                pointers.as_ptr(),
                lengths.as_ptr(),
                sizes.as_ptr(),
                yes.as_ptr(),
                yes.as_ptr(),
                no.as_ptr(),
            )
        };
        context::finish_native_attempt(before);
        assert!(!handle.is_null(), "{language}: native allocation failed");
        // SAFETY: the live handle's native error string is copied before closing under the same lock.
        let error = unsafe { crate::rampage_decomp_error(handle) };
        let error = (!error.is_null()).then(|| unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned());
        let mut widths = [0_i32; 3];
        if error.is_none() {
            let [pointer, int, long] = &mut widths;
            // SAFETY: native initialization succeeded; these three scalar outputs are live and distinct.
            unsafe {
                crate::rampage_decomp_data_organization(handle, pointer, int, long);
            }
        }
        // SAFETY: this test uniquely owns the handle and closes it exactly once while holding FFI_LOCK.
        unsafe { crate::rampage_decomp_close(handle) };
        assert!(error.is_none(), "{language}: {error:?}");
        let after = context::require_verified_bundled_native_context_locked().unwrap();
        let specification_after = rampage_arch::hex::bytes(&after.manifest_sha256());
        assert_eq!(specification_before, specification_after);
        let actual = abi::checked_data_organization(widths).unwrap();
        println!(
            "PILOT_NATIVE_DATA_ORGANIZATION {}",
            serde_json::json!({
                "language_requested": language,
                "organization_source": "native TypeFactory through rampage_decomp_data_organization",
                "actual": actual,
                "decoder_code_space_metadata": code,
                "owned_code_base_byte": "0x1000",
                "owned_code_hex": rampage_arch::hex::bytes(bytes),
                "specification_manifest_before": specification_before,
                "specification_manifest_after": specification_after,
                "verified_native_context_after": true,
                "elapsed_milliseconds": started.elapsed().as_millis(),
                "target_execution": false,
                "public_raw_c_admission": false,
                "full_abi_claim": false,
            })
        );
        assert_eq!(actual, DataOrganization { pointer: 2, int: 2, long: 4 }, "{language}");
        assert_eq!(abi::c_data_organization(&language), Some(actual));
        abi::validate_data_organization(None, &language, actual).unwrap();
    }
}
