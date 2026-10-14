use crate::ApiError;
use rampage_decompiler::worker::WorkerOperation;

pub(super) fn plan(
    project: &crate::Project,
    annotations: &crate::annotations::Annotations,
) -> Result<Vec<WorkerOperation>, ApiError> {
    use crate::debug_layout_import::{self, LayoutBundle};
    debug_layout_import::validate_replay_source(project, annotations)?;
    let layouts = debug_layout_import::stored_layouts(annotations)?;
    let image = if layouts.is_empty() {
        None
    } else {
        Some(rampage_arch::hex::bytes(&debug_layout_import::image_digest(project)?))
    };
    let specifications =
        if layouts.is_empty() { None } else { Some(debug_layout_import::current_specification_digest()?) };
    let mut operations = Vec::new();
    let mut assertions = Vec::new();
    let mut name_work = 0usize;
    for text in annotations.types().values() {
        if let Some(bundle) = LayoutBundle::decode(text)? {
            if image.as_deref() != Some(bundle.image.as_str()) {
                return Err(ApiError::Invalid("layout bundle belongs to a different selected image".to_owned()));
            }
            if specifications.as_deref() != Some(bundle.specifications.as_str()) {
                return Err(ApiError::Invalid(
                    "layout bundle requires a different embedded specification manifest".to_owned(),
                ));
            }
            for stored in bundle.layouts {
                operations.push(WorkerOperation::ParseTypes {
                    declarations: debug_layout_import::declaration(&stored.layout),
                });
                assertions.push(WorkerOperation::AssertPlainStructLayout {
                    layout: stored.layout,
                    expected_context: Some(bundle.specifications.clone()),
                });
            }
            continue;
        }
        validate(text)?;
        if !layouts.is_empty() {
            name_work += text.len();
            if name_work > 1024 * 1024 || debug_layout_import::words(text).any(|word| layouts.contains_key(word)) {
                return Err(ApiError::Invalid("manual type input conflicts with an assertion-backed type".to_owned()));
            }
        }
        for declaration in declarations(text)? {
            if declaration
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|word| word == "extern")
            {
                return Err(ApiError::Invalid("type input cannot contain function signatures".to_owned()));
            }
            operations.push(WorkerOperation::ParseTypes { declarations: declaration.to_owned() });
        }
    }
    operations.extend(assertions);
    for (&address, declaration) in annotations.globals() {
        validate(declaration)?;
        reject_late_type_definitions(declaration, &layouts)?;
        operations.push(WorkerOperation::Global { address, declaration: declaration.clone() });
    }
    for (&address, declaration) in annotations.signatures() {
        let declaration = debug_layout_import::signature(declaration, &layouts)?;
        validate(declaration)?;
        reject_late_type_definitions(declaration, &layouts)?;
        let indirect = project.binary.import_slot(address).is_some();
        if !indirect {
            operations.push(WorkerOperation::Symbol { address, name: project.function_name_in(annotations, address) });
        }
        operations.push(WorkerOperation::Prototype { address, indirect, declaration: declaration.to_owned() });
        if indirect {
            for stub in super::symbols::stub_targets(project, address) {
                operations.push(WorkerOperation::Prototype {
                    address: stub,
                    indirect: false,
                    declaration: declaration.to_owned(),
                });
            }
        }
    }
    Ok(operations)
}

fn reject_late_type_definitions(
    text: &str,
    layouts: &std::collections::BTreeMap<String, String>,
) -> Result<(), ApiError> {
    if (text.contains(['{', '}']) || crate::debug_layout_import::words(text).any(|word| word == "typedef"))
        && crate::debug_layout_import::words(text).any(|word| layouts.contains_key(word))
    {
        return Err(ApiError::Invalid(
            "globals and signatures cannot redefine types after layout assertions".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate(text: &str) -> Result<(), ApiError> {
    if text.len() > 65536 || text.contains(['#', '"', '\'', '/']) || text.starts_with('!') {
        return Err(ApiError::Invalid("declaration is too large or contains unsupported syntax".to_owned()));
    }
    let mut at = 0;
    while let Some(start) = text[at..].find('[') {
        let start = at + start + 1;
        let end = text[start..]
            .find(']')
            .map(|end| start + end)
            .ok_or_else(|| ApiError::Invalid("unterminated array bound".to_owned()))?;
        let bound = text[start..end].trim();
        if bound.len() > 1 && bound.starts_with('0') {
            return Err(ApiError::Invalid("array bounds cannot have leading zeros".to_owned()));
        }
        bound
            .parse::<u32>()
            .ok()
            .filter(|&count| count > 0 && count <= 65536)
            .ok_or_else(|| ApiError::Invalid("array bounds require a decimal integer in 1..65536".to_owned()))?;
        at = end + 1;
    }
    Ok(())
}

pub(super) fn declarations(text: &str) -> Result<Vec<&str>, ApiError> {
    let mut depth = 0usize;
    let mut start = 0;
    let mut declarations = Vec::new();
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => depth = depth.checked_sub(1).ok_or_else(|| ApiError::Invalid("unmatched type brace".to_owned()))?,
            b';' if depth == 0 => {
                let declaration = text[start..=index].trim();
                if !declaration.is_empty() {
                    declarations.push(declaration);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    if depth != 0 || !text[start..].trim().is_empty() {
        return Err(ApiError::Invalid("type declarations require balanced braces and final semicolons".to_owned()));
    }
    Ok(declarations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::annotations::{Annotations, Field};
    use crate::debug_layout_import::{LayoutBundle, image_digest, seal_signature};
    use rampage_decompiler::layout::{
        LayoutField, LayoutOrganization, LayoutScalar, LayoutType, PlainStructLayout, ScalarKind,
    };

    #[test]
    fn every_plan_asserts_layouts_after_types_and_before_dependent_prototypes() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
        let project = crate::Project::new(rampage_loaders::Binary::open(path).unwrap());
        let address = project.resolve("debug_mix").unwrap();
        let layout = PlainStructLayout {
            name: "ordered_record".to_owned(),
            size: 4,
            alignment: 4,
            organization: LayoutOrganization {
                pointer_size: 8,
                int_size: 4,
                long_size: 8,
                scalar_alignments: [1, 2, 4, 8],
            },
            fields: vec![LayoutField {
                name: "value".to_owned(),
                offset: 0,
                size: 4,
                ty: LayoutType::Scalar {
                    scalar: LayoutScalar {
                        name: "int4".to_owned(),
                        kind: ScalarKind::SignedInteger,
                        size: 4,
                        alignment: 4,
                    },
                },
            }],
        };
        let text = LayoutBundle::encode(&image_digest(&project).unwrap(), &[layout]).unwrap();
        let bundle = LayoutBundle::decode(&text).unwrap().unwrap();
        let signature = seal_signature("int4 debug_mix(ordered_record *record);", &[&bundle.layouts[0]]).unwrap();
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Types, address, Some(text)).unwrap();
        annotations.set(Field::Signature, address, Some(signature)).unwrap();
        for _ in 0..2 {
            let operations = plan(&project, &annotations).unwrap();
            let types = operations.iter().position(|op| matches!(op, WorkerOperation::ParseTypes { .. })).unwrap();
            let assertion =
                operations.iter().position(|op| matches!(op, WorkerOperation::AssertPlainStructLayout { .. })).unwrap();
            let prototype = operations.iter().position(|op| matches!(op, WorkerOperation::Prototype { .. })).unwrap();
            assert!(types < assertion && assertion < prototype);
        }
        annotations
            .set(Field::Global, 0, Some("struct ordered_record { uint8 changed; } variable;".to_owned()))
            .unwrap();
        assert!(plan(&project, &annotations).is_err());
    }
}
