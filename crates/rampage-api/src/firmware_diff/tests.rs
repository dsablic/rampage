use serde_json::json;

use super::*;

#[test]
fn halving_cuts_inner_lists_before_the_component_list() {
    let mut value = json!({
        "summary": ["a", "b", "c"],
        "components": [{"code": {"changed": [1, 2, 3, 4, 5, 6]}}, {"code": {"changed": [1]}}],
    });
    assert!(halve_longest(&mut value));
    assert_eq!(value["components"][0]["code"]["changed"], json!([1, 2, 3]));
    assert_eq!(value["summary"].as_array().unwrap().len(), 3);
    while halve_longest(&mut value) {}
    assert_eq!(value["components"].as_array().unwrap().len(), 1);
}
