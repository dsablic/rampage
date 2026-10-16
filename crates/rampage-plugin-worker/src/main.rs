#![forbid(unsafe_code)]

fn main() {
    if rampage_decompiler::worker::serve_binary_stdio(rampage_plugin::serve_stdio).is_err() {
        eprintln!("rampage-plugin-worker: worker lifecycle failure");
        std::process::exit(1);
    }
}
