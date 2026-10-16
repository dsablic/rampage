use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

fn componentize(input: &Path, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(input)?;
    if !file.metadata()?.is_file() {
        return Err("input must be a regular owned core-Wasm build artifact".into());
    }
    let mut bytes = Vec::new();
    file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 8 * 1024 * 1024 || !bytes.starts_with(b"\0asm\x01\0\0\0") {
        return Err("expected a core-Wasm module within the eight-MiB build limit".into());
    }
    let component = wit_component::ComponentEncoder::default().module(&bytes)?.validate(true).encode()?;
    if component.len() > 8 * 1024 * 1024 {
        return Err("encoded component exceeds the eight-MiB build limit".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(output)?;
    file.write_all(&component)?;
    file.sync_all()?;
    Ok(())
}

fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 3 {
        eprintln!("usage: rampage-componentize OWNED-CORE.wasm NEW-COMPONENT.wasm");
        std::process::exit(2);
    }
    if let Err(error) = componentize(Path::new(&arguments[1]), Path::new(&arguments[2])) {
        eprintln!("componentize: {error}");
        std::process::exit(1);
    }
}
