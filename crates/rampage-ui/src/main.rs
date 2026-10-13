//! `rampage-ui [FILE] [--arch ARCH] [--image-offset OFFSET [--image-length LENGTH]] [--pack DIR]...`: the desktop
//! UI.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rampage_api::Packs;
use rampage_arch::Arch;
use rampage_loaders::ImageAt;

#[derive(Parser)]
#[command(name = "rampage-ui", version, about = "The rampage desktop UI")]
struct Args {
    /// The binary to open
    file: Option<PathBuf>,
    /// Architecture slice to load from a universal binary
    #[arg(long, value_parser = |text: &str| text.parse::<Arch>())]
    arch: Option<Arch>,
    /// Open the executable embedded at this file offset (hex 0x... or decimal), such as one the Carve window lists
    #[arg(long, value_parser = rampage_api::parse_file_offset, requires = "file")]
    image_offset: Option<u64>,
    /// With --image-offset, the embedded image's length in bytes; defaults to the extent its header tables give
    #[arg(long, value_parser = rampage_api::parse_file_offset, requires = "image_offset")]
    image_length: Option<u64>,
    /// A data pack directory (holding rampage-pack.toml) layered over the bundled heuristic databases; repeatable,
    /// earlier packs take precedence. Directories in RAMPAGE_PACKS (a path list) load after these
    #[arg(long = "pack", value_name = "DIR")]
    packs: Vec<PathBuf>,
}

fn main() -> eframe::Result {
    let args = Args::parse();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1440.0, 900.0]).with_title("rampage"),
        ..Default::default()
    };
    eframe::run_native(
        "rampage",
        options,
        Box::new(move |creation| {
            let packs = Arc::new(Packs::lazy_with_env(&args.packs));
            let mut app = rampage_ui::App::default().with_packs(packs);
            if let Some(file) = args.file {
                let image = args.image_offset.map(|offset| ImageAt::new(offset, args.image_length));
                app.open_at(&creation.egui_ctx, file, args.arch, image);
            }
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_repeat_in_order_and_image_options_need_a_file() {
        let args = Args::try_parse_from(["rampage-ui", "--pack", "a", "bin", "--pack", "b"]).unwrap();
        assert_eq!(args.packs, [PathBuf::from("a"), PathBuf::from("b")]);
        assert_eq!(args.file, Some(PathBuf::from("bin")));
        let args = Args::try_parse_from(["rampage-ui", "bin", "--image-offset", "0x1000", "--image-length", "64"]);
        let args = args.unwrap();
        assert_eq!((args.image_offset, args.image_length), (Some(0x1000), Some(64)));
        assert!(Args::try_parse_from(["rampage-ui", "--image-offset", "0x1000"]).is_err());
        assert!(Args::try_parse_from(["rampage-ui", "bin", "--image-length", "64"]).is_err());
    }
}
