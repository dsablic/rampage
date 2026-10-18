use super::{DEFAULT_PAGE, IdentifyArgs, MAX_RESULT_CHARS};
use crate::signatures::SignatureApplication;
use crate::{ApiError, Project};
use serde_json::{Value, json};

pub(super) fn identify_page(project: &Project, args: IdentifyArgs) -> Result<Value, ApiError> {
    let limit = args.limit.unwrap_or(DEFAULT_PAGE);
    if !(1..=256).contains(&limit) {
        return Err(ApiError::Invalid("limit must be in 1..=256; no names written".to_owned()));
    }
    let user = match &args.database {
        Some(path) => Some(crate::load_signature_database(std::path::Path::new(path), project.binary.arch)?),
        None => None,
    };
    let fuzzy =
        match (&args.fuzzy_database, &args.fuzzy_request) {
            (Some(database), Some(request)) if !args.no_bundled => Some(
                serde_json::to_value(project.suggest_fuzzy_signature_files(
                    std::path::Path::new(database),
                    std::path::Path::new(request),
                    user.as_ref(),
                )?)
                .map_err(|error| ApiError::Invalid(format!("cannot serialize fuzzy suggestions: {error}")))?,
            ),
            (None, None) => None,
            _ => return Err(ApiError::Invalid(
                "fuzzy queries need both fuzzy_database and fuzzy_request and cannot use no_bundled; no names written"
                    .to_owned(),
            )),
        };
    let mut receipt = Value::Null;
    let application =
        project.identify_functions_with_preflight(user.as_ref(), !args.no_bundled, args.apply, |planned| {
            // Reserve the largest possible applied count before the first rename. Only this numeric field
            // changes afterwards; all detail rows and warnings come from this same plan.
            let max_applied = if args.apply { planned.matched } else { 0 };
            receipt = signature_page_with_fuzzy(
                planned,
                fuzzy.as_ref(),
                args.apply,
                max_applied,
                args.offset.unwrap_or(0),
                limit,
            )?;
            Ok(())
        })?;
    receipt["applied"] = json!(application.applied);
    Ok(receipt)
}

#[cfg(test)]
fn signature_page(
    application: &SignatureApplication,
    apply: bool,
    applied: usize,
    offset: usize,
    limit: usize,
) -> Result<Value, ApiError> {
    signature_page_with_fuzzy(application, None, apply, applied, offset, limit)
}

fn signature_page_with_fuzzy(
    application: &SignatureApplication,
    fuzzy: Option<&Value>,
    apply: bool,
    applied: usize,
    offset: usize,
    limit: usize,
) -> Result<Value, ApiError> {
    let matches_total = application.matches.len();
    let warnings_total = application.warnings.len();
    let fuzzy_rows = fuzzy.and_then(|value| value["suggestions"].as_array());
    let fuzzy_total = fuzzy_rows.map_or(0, Vec::len);
    let details_total = matches_total + warnings_total + fuzzy_total;
    let start = offset.min(details_total);
    let end = start.saturating_add(limit).min(details_total);
    let mut receipt = json!({
        "matched": application.matched,
        "applied": applied,
        "totals_scope": "whole_result",
        "apply_requested": apply,
        "apply_scope": "whole_result",
        "matches": [],
        "warnings": [],
        "warnings_total": warnings_total,
        "details_total": details_total,
        "offset": offset,
        "limit": limit,
        "returned": 0,
        "matches_omitted": matches_total,
        "warnings_omitted": warnings_total,
        "details_omitted": details_total,
        "more": start < details_total,
        "next_offset": if start < details_total { json!(start) } else { Value::Null },
        "byte_capped": start < end,
    });
    if let Some(fuzzy) = fuzzy {
        let mut metadata = fuzzy.clone();
        metadata["suggestions"] = json!([]);
        metadata["suggestions_total"] = json!(fuzzy_total);
        metadata["suggestions_omitted"] = json!(fuzzy_total);
        metadata["candidates_total"] = json!(
            fuzzy_rows
                .into_iter()
                .flatten()
                .map(|row| { row["report"]["candidates"].as_array().map_or(0, Vec::len) })
                .sum::<usize>()
        );
        receipt["fuzzy"] = metadata;
    }
    if receipt.to_string().len() > MAX_RESULT_CHARS {
        return Err(too_large());
    }
    for index in start..end {
        let mut candidate = receipt.clone();
        let row = if index < matches_total {
            serde_json::to_value(&application.matches[index])
                .map_err(|error| ApiError::Invalid(format!("cannot serialize signature match: {error}")))?
        } else if index < matches_total + warnings_total {
            json!(&application.warnings[index - matches_total])
        } else {
            fuzzy_rows.expect("fuzzy detail rows")[index - matches_total - warnings_total].clone()
        };
        if index < matches_total {
            candidate["matches"].as_array_mut().expect("match array").push(row);
        } else if index < matches_total + warnings_total {
            candidate["warnings"].as_array_mut().expect("warning array").push(row);
        } else {
            candidate["fuzzy"]["suggestions"].as_array_mut().expect("fuzzy array").push(row);
        }
        let next = index + 1;
        let returned = next - start;
        candidate["returned"] = json!(returned);
        candidate["matches_omitted"] = json!(matches_total - candidate["matches"].as_array().unwrap().len());
        candidate["warnings_omitted"] = json!(warnings_total - candidate["warnings"].as_array().unwrap().len());
        if fuzzy.is_some() {
            candidate["fuzzy"]["suggestions_omitted"] =
                json!(fuzzy_total - candidate["fuzzy"]["suggestions"].as_array().unwrap().len());
        }
        candidate["details_omitted"] = json!(details_total - returned);
        candidate["more"] = json!(next < details_total);
        candidate["next_offset"] = if next < details_total { json!(next) } else { Value::Null };
        candidate["byte_capped"] = json!(next < end);
        if candidate.to_string().len() > MAX_RESULT_CHARS {
            if index == start {
                return Err(too_large());
            }
            break;
        }
        receipt = candidate;
    }
    Ok(receipt)
}

fn too_large() -> ApiError {
    ApiError::Invalid(
        "signature page header or first complete row exceeds 60000 JSON bytes; no names written".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::SignatureMatch;

    fn application(names: &[&str], warnings: &[&str]) -> SignatureApplication {
        SignatureApplication {
            matched: names.len(),
            applied: 0,
            matches: names
                .iter()
                .enumerate()
                .map(|(index, name)| SignatureMatch {
                    address: 0x1000 + index as u64 * 16,
                    name: (*name).to_owned(),
                    unnamed: true,
                    source: "user database".to_owned(),
                })
                .collect(),
            warnings: warnings.iter().map(|text| (*text).to_owned()).collect(),
        }
    }

    #[test]
    fn warnings_continue_after_matches_without_losing_totals() {
        let planned = application(&["one", "two", "three"], &["first warning", "second warning"]);
        let first = signature_page(&planned, true, 3, 0, 2).unwrap();
        let second = signature_page(&planned, true, 3, 2, 2).unwrap();
        let third = signature_page(&planned, true, 3, 4, 2).unwrap();
        assert_eq!(first["next_offset"], 2);
        assert_eq!(second["matches"][0]["name"], "three");
        assert_eq!(second["warnings"], json!(["first warning"]));
        assert_eq!(second["next_offset"], 4);
        assert_eq!(third["warnings"], json!(["second warning"]));
        assert_eq!(third["next_offset"], Value::Null);
        for page in [first, second, third, signature_page(&planned, true, 3, usize::MAX, 2).unwrap()] {
            assert_eq!(page["matched"], 3);
            assert_eq!(page["applied"], 3);
            assert_eq!(page["details_total"], 5);
            assert_eq!(page["warnings_total"], 2);
        }
    }

    #[test]
    fn fuzzy_pages_keep_secondary_totals_separate_and_budget_before_apply() {
        let planned = application(&["exact"], &["pack warning"]);
        let fuzzy = json!({
            "read_only":true,
            "warnings":[],
            "suggestions":[
                {"address":"0x2000","report":{"candidates":[{"name":"candidate"}]}},
                {"address":"0x3000","report":{"candidates":[]}}
            ]
        });
        let first = signature_page_with_fuzzy(&planned, Some(&fuzzy), true, 1, 0, 2).unwrap();
        let next = signature_page_with_fuzzy(&planned, Some(&fuzzy), true, 1, 2, 1).unwrap();
        let last = signature_page_with_fuzzy(&planned, Some(&fuzzy), true, 1, 3, 1).unwrap();
        assert_eq!(first["fuzzy"]["suggestions"], json!([]));
        assert_eq!(next["fuzzy"]["suggestions"][0]["address"], "0x2000");
        assert_eq!(last["fuzzy"]["suggestions"][0]["address"], "0x3000");
        for page in [first, next, last] {
            assert_eq!(page["matched"], 1);
            assert_eq!(page["applied"], 1);
            assert_eq!(page["details_total"], 4);
            assert_eq!(page["fuzzy"]["suggestions_total"], 2);
            assert_eq!(page["fuzzy"]["candidates_total"], 1);
        }
        let mut huge = fuzzy;
        huge["suggestions"][0]["report"]["candidates"][0]["name"] = json!("x".repeat(MAX_RESULT_CHARS));
        assert!(signature_page_with_fuzzy(&planned, Some(&huge), true, 1, 2, 1).is_err());
    }

    #[test]
    fn exact_json_budget_keeps_complete_unicode_and_escaped_rows() {
        let large = "\"\\\n雪".repeat(4000);
        let planned = application(&[&large, &large, &large], &["warning"]);
        let page = signature_page(&planned, true, usize::MAX, 0, 256).unwrap();
        assert!(page.to_string().len() <= MAX_RESULT_CHARS);
        assert_eq!(page["matches"].as_array().unwrap().len(), 1);
        assert_eq!(page["matches"][0]["name"], large);
        assert_eq!(page["byte_capped"], true);
        assert_eq!(page["next_offset"], 1);
        assert_eq!(page["applied"], json!(usize::MAX));
        let parsed: Value = serde_json::from_str(&page.to_string()).unwrap();
        assert_eq!(parsed, page);
    }

    #[test]
    fn exact_header_and_next_offset_digits_are_budgeted() {
        let mut planned = application(&[""], &["warning"]);
        let base = signature_page(&planned, true, 999, 0, 1).unwrap().to_string().len();
        planned.matches[0].name = "a".repeat(MAX_RESULT_CHARS - base);
        let page = signature_page(&planned, true, 999, 0, 1).unwrap();
        assert_eq!(page.to_string().len(), MAX_RESULT_CHARS);
        assert_eq!(page["next_offset"], 1);
        planned.matches[0].name.push('a');
        assert!(signature_page(&planned, true, 999, 0, 1).is_err());
        assert!(signature_page(&application(&[], &[&"雪".repeat(30_000)]), false, 0, 0, 1).is_err());
    }

    #[test]
    fn receipt_preflight_rejection_leaves_every_name_unchanged() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/bin/musl-static-x86_64.elf");
        let project = crate::Session::default().open(&path, None).unwrap();
        let before = project.identify_functions(None, true, false).unwrap();
        assert!(before.matches.iter().filter(|row| row.unnamed).count() > 1);
        let names: Vec<_> = before.matches.iter().map(|row| project.function_name(row.address)).collect();
        let mut called = 0;
        let result = project.identify_functions_with_preflight(None, true, true, |planned| {
            called += 1;
            assert_eq!(planned.matched, before.matched);
            assert_eq!(planned.applied, 0);
            let oversized = application(&[&"x".repeat(MAX_RESULT_CHARS)], &[]);
            signature_page(&oversized, true, planned.matched, 0, 1).map(|_| ())
        });
        assert!(result.is_err());
        assert_eq!(called, 1);
        let after: Vec<_> = before.matches.iter().map(|row| project.function_name(row.address)).collect();
        assert_eq!(after, names);
    }
}
