//! `rampage-ui [FILE] [--arch ARCH]`: the desktop UI.

use std::path::PathBuf;

use clap::Parser;
use rampage_arch::Arch;

#[derive(Parser)]
#[command(name = "rampage-ui", version, about = "The rampage desktop UI")]
struct Args {
    /// The binary to open
    file: Option<PathBuf>,
    /// Architecture slice to load from a universal binary
    #[arg(long, value_parser = |text: &str| text.parse::<Arch>())]
    arch: Option<Arch>,
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
                app.open(&creation.egui_ctx, file, args.arch);
            }
            Ok(Box::new(app))
        }),
    )
}
