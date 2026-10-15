fn main() {
    if let Err(error) = rampage_decompiler::worker::serve_worker_stdio() {
        eprintln!("rampage-worker: {error}");
        std::process::exit(1);
    }
}
