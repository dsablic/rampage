use serde_json::{Value, json};

use super::MAX_RESULT_CHARS;
use crate::{ApiError, Project, SearchRequest};

pub(crate) fn page(project: &Project, request: &SearchRequest) -> Result<Value, ApiError> {
    let report = project.search(&request.resolve(project)?)?;
    let available = report.total.min(report.budget.limits.results);
    let mut receipt = serde_json::to_value(&report)
        .map_err(|error| ApiError::Invalid(format!("cannot serialize search report: {error}")))?;
    receipt["hits"] = json!([]);
    receipt["available_hits"] = json!(available);
    receipt["unavailable_observed_hits"] = json!(report.total.saturating_sub(available));
    receipt["totals_scope"] = json!("whole_scan");
    receipt["continuation_scope"] = json!("observed_hit_rows_not_scan_resume");
    update_page(&mut receipt, report.offset, report.total, available, false);
    if receipt.to_string().len() > MAX_RESULT_CHARS {
        return Err(too_large());
    }
    for (index, row) in report.hits.iter().enumerate() {
        let mut candidate = receipt.clone();
        candidate["hits"].as_array_mut().expect("search hit array").push(
            serde_json::to_value(row)
                .map_err(|error| ApiError::Invalid(format!("cannot serialize search hit: {error}")))?,
        );
        update_page(&mut candidate, report.offset, report.total, available, index + 1 < report.hits.len());
        if candidate.to_string().len() > MAX_RESULT_CHARS {
            if index == 0 {
                return Err(too_large());
            }
            receipt["byte_capped"] = json!(true);
            break;
        }
        receipt = candidate;
    }
    Ok(receipt)
}

fn update_page(receipt: &mut Value, offset: usize, total: usize, available: usize, byte_capped: bool) {
    let returned = receipt["hits"].as_array().expect("search hit array").len();
    let next = offset.saturating_add(returned);
    let more = next < available;
    receipt["returned"] = json!(returned);
    receipt["hits_omitted"] = json!(total.saturating_sub(returned));
    receipt["available_hits_omitted"] = json!(available.saturating_sub(returned));
    receipt["more"] = json!(more);
    receipt["next_offset"] = if more { json!(next) } else { Value::Null };
    receipt["byte_capped"] = json!(byte_capped);
}

fn too_large() -> ApiError {
    ApiError::Invalid("search page header or first complete hit exceeds 60000 JSON bytes; no strings cut".to_owned())
}
