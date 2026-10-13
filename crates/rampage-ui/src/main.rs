//! `rampage-ui [FILE] [--arch ARCH] [--image-offset OFFSET [--image-length LENGTH]]`: the desktop UI.

use std::path::PathBuf;

use clap::Parser;
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
            let mut app = rampage_ui::App::default();
            if let Some(file) = args.file {
                let image = args.image_offset.map(|offset| ImageAt::new(offset, args.image_length));
                app.open_at(&creation.egui_ctx, file, args.arch, image);
            }
            Ok(Box::new(app))
        }),
    )
}
