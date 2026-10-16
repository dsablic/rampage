//! Deliberately hostile acceptance fixture, not the real triage workflow.
//! A fresh import-free instance owns one invocation. Only a scalar selector is retained.
//! Leading JSON whitespace selects tab: run loop, LF: output loop, CR: memory growth,
//! space: oversized advertised output, space+LF: malformed output. An object selects the fixed control.

#[cfg(target_arch = "wasm32")]
mod probe {
    use std::sync::atomic::{AtomicU8, Ordering};

    wit_bindgen::generate!({
        path: "../../wit",
        world: "triage-plugin",
    });

    struct Component;

    static SELECTOR: AtomicU8 = AtomicU8::new(0);
    const CONTROL: &[u8] = br#"{"schemaVersion":1,"outcome":{"status":"failure","code":"invalid_input"}}"#;

    fn consume_cpu() -> ! {
        loop {
            std::hint::spin_loop();
        }
    }

    impl exports::rampage::workflow::triage::Guest for Component {
        fn run(input: Vec<u8>) -> u32 {
            let selector = if input.starts_with(b" \n") { b'!' } else { input.first().copied().unwrap_or(0) };
            SELECTOR.store(selector, Ordering::Relaxed);
            match selector {
                b'\t' => consume_cpu(),
                b'\r' => {
                    // The increment alone exceeds 64 MiB, regardless of the initial memory size.
                    let previous_pages = core::arch::wasm32::memory_grow::<0>(1025);
                    if previous_pages == usize::MAX {
                        core::arch::wasm32::unreachable();
                    }
                    CONTROL.len() as u32
                }
                b' ' => u32::MAX,
                b'!' => 1,
                _ => CONTROL.len() as u32,
            }
        }

        fn output(offset: u32) -> (u64, u64, u64, u64) {
            match SELECTOR.load(Ordering::Relaxed) {
                b'\n' => consume_cpu(),
                // OutputTooLarge, rather than Trap, proves the host never calls this export.
                b' ' => core::arch::wasm32::unreachable(),
                b'!' => return (u64::from(b'{'), 0, 0, 0),
                _ => {}
            }
            let mut words = [0u64; 4];
            for (index, byte) in CONTROL.iter().skip(offset as usize).take(32).enumerate() {
                words[index / 8] |= u64::from(*byte) << ((index % 8) * 8);
            }
            (words[0], words[1], words[2], words[3])
        }
    }

    export!(Component);
}
