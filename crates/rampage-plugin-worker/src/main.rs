#![forbid(unsafe_code)]

fn main() {
    if rampage_decompiler::worker::serve_binary_stdio_checkpointed(rampage_plugin::serve_stdio_checkpointed).is_err() {
        eprintln!("rampage-plugin-worker: worker lifecycle failure");
        std::process::exit(1);
    }
}
