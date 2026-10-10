//! `rampage-ui [file] [--arch ARCH]`: the desktop UI.

use std::path::PathBuf;

fn main() -> eframe::Result {
    let mut path = None;
    let mut arch = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--arch" => arch = args.next().and_then(|value| value.parse().ok()),
            _ => path = Some(PathBuf::from(arg)),
        }
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1440.0, 900.0]).with_title("rampage"),
        ..Default::default()
    };
    eframe::run_native(
        "rampage",
        options,
        Box::new(move |creation| {
            let mut app = rampage_ui::App::default();
            if let Some(path) = path {
                app.open(&creation.egui_ctx, path, arch);
            }
            Ok(Box::new(app))
        }),
    )
}
