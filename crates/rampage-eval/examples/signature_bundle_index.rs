use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use rampage_signatures::SignatureDb;

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    profiles: PathBuf,
    #[arg(long)]
    asset: String,
    #[arg(long)]
    output: PathBuf,
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!("{}: expected a regular file of at most {limit} bytes", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err("input changed length while reading".into());
    }
    Ok(bytes)
}

fn run(arguments: Arguments) -> Result<(), String> {
    let database = read(&arguments.database, 64 * 1024 * 1024)?;
    let profiles = read(&arguments.profiles, 128 * 1024)?;
    let profiles = std::str::from_utf8(&profiles).map_err(|error| error.to_string())?;
    let index = SignatureDb::bundled_index(&database, &arguments.asset, profiles).map_err(|error| error.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&arguments.output)
        .map_err(|error| format!("{}: {error}", arguments.output.display()))?;
    output.write_all(index.as_bytes()).and_then(|()| output.sync_all()).map_err(|error| error.to_string())
}

fn main() -> std::process::ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("signature bundle index: {error}");
            std::process::ExitCode::from(2)
        }
    }
}
