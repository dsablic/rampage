//! Code facts: string users, calls, capture APIs and reachability on the sample classes.

use rampage_dex::Dex;
use rampage_dex::scan::{capture_uses, index, reachable};
use rampage_dex::testkit::{BOOT_RECEIVER_CLASS, CAPTURE_CLASS, SAMPLE_URL, sample_classes, write_dex};

#[test]
fn strings_calls_captures_and_reachability() {
    let dex = Dex::parse(write_dex(&sample_classes(), 35)).unwrap();
    let code = index(&dex);
    let url = (0..dex.header.strings.count).find(|&index| dex.string_text(index) == SAMPLE_URL).unwrap();
    assert_eq!(code.string_users[&url], [format!("{CAPTURE_CLASS}->start()V")]);
    let uses = capture_uses(&code.calls);
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].medium, "microphone");
    assert_eq!(uses[0].permissions, ["android.permission.RECORD_AUDIO"]);
    let entries = code.class_methods[BOOT_RECEIVER_CLASS].clone();
    let reached = reachable(&code.calls, &entries, 1000);
    assert!(reached.contains_key(&format!("{CAPTURE_CLASS}->start()V")));
    assert!(reachable(&code.calls, &entries, 1).len() <= 2);
}
