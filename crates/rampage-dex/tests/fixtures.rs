//! The committed Android fixtures (tests/fixtures/android) hold what the test-side writers produce. With
//! RAMPAGE_WRITE_ANDROID_FIXTURES=1 the test writes them instead (see tests/fixtures/build-android.sh).
//!
//! The APK is compared member by member after inflation, not byte for byte: deflate output depends on the
//! compression backend Cargo's feature unification picks for flate2.

use std::path::{Path, PathBuf};

use rampage_dex::testkit::{sample_apk, sample_classes, write_dex};
use rampage_unpack::{At, Limits, read_entries};

fn android(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/android").join(name)
}

fn members(path: &Path) -> Vec<(String, Vec<u8>)> {
    let selected = read_entries(path, At::default(), &[], Limits::default(), &mut |_| true).unwrap();
    selected.contents.into_iter().map(|(index, bytes)| (selected.entries[index].path.clone(), bytes)).collect()
}

fn local_paths(bytes: &[u8]) -> bool {
    bytes.windows(7).any(|window| window == b"/Users/" || window.starts_with(b"/home/"))
}

#[test]
fn committed_fixtures_match_the_writers() {
    let library = std::fs::read(android("libnative-arm64.so")).unwrap();
    let dex = write_dex(&sample_classes(), 35);
    let apk = sample_apk(Some(&library));
    if std::env::var_os("RAMPAGE_WRITE_ANDROID_FIXTURES").is_some() {
        std::fs::write(android("recorder.dex"), &dex).unwrap();
        std::fs::write(android("recorder.apk"), &apk).unwrap();
    }
    let committed = std::fs::read(android("recorder.dex")).unwrap();
    assert!(committed == dex, "recorder.dex differs from the writer's output; see tests/fixtures/build-android.sh");
    let generated = std::env::temp_dir().join(format!("rampage-dex-fixture-{}.apk", std::process::id()));
    std::fs::write(&generated, &apk).unwrap();
    let expected = members(&generated);
    std::fs::remove_file(&generated).unwrap();
    assert!(members(&android("recorder.apk")) == expected, "recorder.apk members differ from the writers' output");
    for name in ["recorder.dex", "recorder.apk", "libnative-arm64.so"] {
        assert!(!local_paths(&std::fs::read(android(name)).unwrap()), "{name} holds a local path");
    }
}
