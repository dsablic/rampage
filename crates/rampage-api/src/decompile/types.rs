use crate::ApiError;
use rampage_decompiler::worker::WorkerOperation;

pub(super) fn plan(
    project: &crate::Project,
    annotations: &crate::annotations::Annotations,
) -> Result<Vec<WorkerOperation>, ApiError> {
    let mut operations = Vec::new();
    for text in annotations.types().values() {
        validate(text)?;
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
    for (&address, declaration) in annotations.globals() {
        validate(declaration)?;
        operations.push(WorkerOperation::Global { address, declaration: declaration.clone() });
    }
    for (&address, declaration) in annotations.signatures() {
        validate(declaration)?;
        let indirect = project.binary.import_slot(address).is_some();
        if !indirect {
            operations.push(WorkerOperation::Symbol { address, name: project.function_name_in(annotations, address) });
        }
        operations.push(WorkerOperation::Prototype { address, indirect, declaration: declaration.clone() });
        if indirect {
            for stub in super::symbols::stub_targets(project, address) {
                operations.push(WorkerOperation::Prototype {
                    address: stub,
                    indirect: false,
                    declaration: declaration.clone(),
                });
            }
        }
    }
    Ok(operations)
}

pub(super) fn validate(text: &str) -> Result<(), ApiError> {
    if text.len() > 65536 || text.contains(['#', '"', '\'', '/']) {
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
