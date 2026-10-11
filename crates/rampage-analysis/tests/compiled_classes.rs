//! Compiles a small polymorphic C++ program at test time and checks that language metadata recovers the class
//! name from its vtable symbol. Skips cleanly when a C++ compiler is unavailable, and compiles to the host
//! target so the produced binary is one rampage-loaders can open on the machine running the test.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_analysis::language;
use rampage_loaders::Binary;

const SOURCE: &str = r#"
struct Shape {
    virtual int area();
    virtual ~Shape() {}
};
int Shape::area() { return 0; }
int main() {
    Shape shape;
    return shape.area();
}
"#;

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn compiler_available() -> bool {
    Command::new("clang++").arg("--version").output().map(|out| out.status.success()).unwrap_or(false)
}

#[test]
fn recovers_class_name_from_a_compiled_vtable() {
    if !compiler_available() {
        eprintln!("clang++ unavailable; skipping compiled class-name test");
        return;
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let unique = format!("rampage-class-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let guard = TempDir(dir.clone());
    let source = dir.join("shape.cpp");
    let binary_path = dir.join("shape");
    std::fs::write(&source, SOURCE).expect("write source");

    // A key function defined out of line makes this translation unit emit Shape's vtable symbol.
    let compiled = Command::new("clang++").arg(&source).arg("-o").arg(&binary_path).output();
    let Ok(output) = compiled else {
        eprintln!("clang++ failed to run; skipping");
        return;
    };
    if !output.status.success() {
        eprintln!("clang++ could not link the sample; skipping: {}", String::from_utf8_lossy(&output.stderr));
        return;
    }

    let binary = Binary::open(&binary_path).expect("open compiled binary");
    let metadata = language::metadata(&binary);
    let shape = metadata
        .symbols
        .iter()
        .find(|symbol| symbol.category == "vtable" && symbol.class_name.as_deref() == Some("Shape"));
    assert!(
        shape.is_some(),
        "expected a vtable with class_name Shape; vtables: {:?}",
        metadata
            .symbols
            .iter()
            .filter(|symbol| symbol.category == "vtable")
            .map(|symbol| (&symbol.display, &symbol.class_name))
            .collect::<Vec<_>>()
    );
    drop(guard);
}
