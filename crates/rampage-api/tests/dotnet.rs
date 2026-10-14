use std::path::PathBuf;

use rampage_api::{ApiError, DetectionConfidence, DotNetIlQuery, DotNetList, DotNetQuery, ReportLimits, Session};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

const ASSEMBLY: &str = "Microsoft.Bcl.HashCode.dll";

struct EventImage(PathBuf);

impl Drop for EventImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn event_image() -> EventImage {
    let mut strings = vec![0];
    let mut name = |text: &str| {
        let index = strings.len() as u16;
        strings.extend_from_slice(text.as_bytes());
        strings.push(0);
        index
    };
    let namespace = name("Demo");
    let owner = name("Publisher");
    let idle = name("Idle");
    let handler = name("Handler");
    let bind = name("Bind");
    let unbind = name("Unbind");
    let changed = name("Changed");
    let broken = name("Broken");

    let present = [(0x01, 1u32), (0x02, 2), (0x06, 2), (0x12, 1), (0x14, 2), (0x18, 2)];
    let valid = present.iter().fold(0u64, |mask, &(table, _)| mask | (1 << table));
    let mut tables = vec![0, 0, 0, 0, 2, 0, 0, 1];
    tables.extend_from_slice(&valid.to_le_bytes());
    tables.extend_from_slice(&0u64.to_le_bytes());
    for &(_, rows) in &present {
        tables.extend_from_slice(&rows.to_le_bytes());
    }
    let mut narrow = |columns: &[u16]| {
        for value in columns {
            tables.extend_from_slice(&value.to_le_bytes());
        }
    };
    narrow(&[0, handler, namespace]);
    // Narrow columns split the TypeDef flags and MethodDef RVA into their two 16-bit halves.
    narrow(&[1, 0, owner, namespace, 0, 1, 1]);
    narrow(&[1, 0, idle, namespace, 0, 1, 3]);
    narrow(&[0, 0, 0, 0x16, bind, 1, 1]);
    narrow(&[0, 0, 0, 0x16, unbind, 1, 1]);
    narrow(&[1, 1]);
    narrow(&[0x0200, changed, 5]);
    narrow(&[0x0400, broken, 3]);
    narrow(&[8, 1, 2]);
    narrow(&[16, 2, 2]);

    let blobs = [0, 3, 0, 0, 1];
    let streams: [(&str, &[u8]); 3] = [("#~", &tables), ("#Strings", &strings), ("#Blob", &blobs)];
    let version = b"v4.0.30319\0\0";
    let mut root = Vec::new();
    root.extend_from_slice(&0x424A_5342u32.to_le_bytes());
    root.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0, 0]);
    root.extend_from_slice(&(version.len() as u32).to_le_bytes());
    root.extend_from_slice(version);
    root.extend_from_slice(&[0, 0, 3, 0]);
    let mut offset =
        root.len() + streams.iter().map(|(name, _)| 8 + (name.len() + 1).next_multiple_of(4)).sum::<usize>();
    for (name, data) in streams {
        root.extend_from_slice(&(offset as u32).to_le_bytes());
        root.extend_from_slice(&(data.len() as u32).to_le_bytes());
        root.extend_from_slice(name.as_bytes());
        root.push(0);
        while !root.len().is_multiple_of(4) {
            root.push(0);
        }
        offset += data.len().next_multiple_of(4);
    }
    for (_, data) in streams {
        root.extend_from_slice(data);
        while !root.len().is_multiple_of(4) {
            root.push(0);
        }
    }
    let mut image = std::fs::read(fixture(ASSEMBLY)).unwrap();
    let metadata = rampage_loaders::dotnet::parse_image(&image).unwrap().unwrap();
    let start = image.windows(4).position(|bytes| bytes == b"BSJB").unwrap();
    assert!(root.len() <= metadata.cli.metadata_size as usize);
    image[start..start + root.len()].copy_from_slice(&root);
    let path = std::env::temp_dir().join(format!("rampage-api-dotnet-events-{}.dll", std::process::id()));
    let scratch = EventImage(path);
    std::fs::write(&scratch.0, image).unwrap();
    scratch
}

fn resource_image(declared: u32, cut: usize) -> Vec<u8> {
    let strings = b"\0Alpha\0Beta\0Part.netmodule\0OtherAssembly\0";
    let present = [(0x23, 1u32), (0x26, 1), (0x28, declared)];
    let valid = present.iter().fold(0u64, |mask, &(table, _)| mask | (1 << table));
    let mut tables = vec![0, 0, 0, 0, 2, 0, 0, 1];
    tables.extend_from_slice(&valid.to_le_bytes());
    tables.extend_from_slice(&0u64.to_le_bytes());
    for &(_, rows) in &present {
        tables.extend_from_slice(&rows.to_le_bytes());
    }
    for value in [1u16, 2, 3, 4, 0, 0, 0, 27, 0, 0] {
        tables.extend_from_slice(&value.to_le_bytes());
    }
    tables.extend_from_slice(&1u32.to_le_bytes());
    tables.extend_from_slice(&12u16.to_le_bytes());
    tables.extend_from_slice(&0u16.to_le_bytes());
    for (offset, flags, name, implementation) in
        [(0u32, 1u32, 1u16, 0u16), (4, 2, 7, 4), (8, 1, 1, 5), (0, 1, 0xffff, 3)]
    {
        tables.extend_from_slice(&offset.to_le_bytes());
        tables.extend_from_slice(&flags.to_le_bytes());
        tables.extend_from_slice(&name.to_le_bytes());
        tables.extend_from_slice(&implementation.to_le_bytes());
    }
    tables.truncate(tables.len() - cut);
    let streams: [(&str, &[u8]); 2] = [("#~", &tables), ("#Strings", strings)];
    let version = b"v4.0.30319\0\0";
    let mut root = Vec::new();
    root.extend_from_slice(&0x424A_5342u32.to_le_bytes());
    root.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0, 0]);
    root.extend_from_slice(&(version.len() as u32).to_le_bytes());
    root.extend_from_slice(version);
    root.extend_from_slice(&[0, 0, 2, 0]);
    let mut offset =
        root.len() + streams.iter().map(|(name, _)| 8 + (name.len() + 1).next_multiple_of(4)).sum::<usize>();
    for (name, data) in streams {
        root.extend_from_slice(&(offset as u32).to_le_bytes());
        root.extend_from_slice(&(data.len() as u32).to_le_bytes());
        root.extend_from_slice(name.as_bytes());
        root.push(0);
        while !root.len().is_multiple_of(4) {
            root.push(0);
        }
        offset += data.len().next_multiple_of(4);
    }
    for (_, data) in streams {
        root.extend_from_slice(data);
        while !root.len().is_multiple_of(4) {
            root.push(0);
        }
    }
    let mut image = std::fs::read(fixture(ASSEMBLY)).unwrap();
    let metadata = rampage_loaders::dotnet::parse_image(&image).unwrap().unwrap();
    let start = image.windows(4).position(|bytes| bytes == b"BSJB").unwrap();
    assert!(root.len() <= metadata.cli.metadata_size as usize);
    image[start..start + root.len()].copy_from_slice(&root);
    image
}

fn resource_project(declared: u32, cut: usize) -> rampage_api::Project {
    let image = resource_image(declared, cut);
    let path =
        std::env::temp_dir().join(format!("rampage-api-dotnet-resources-{}-{declared}-{cut}.dll", std::process::id()));
    let scratch = EventImage(path);
    std::fs::write(&scratch.0, image).unwrap();
    rampage_api::Project::new(rampage_loaders::Binary::open(&scratch.0).unwrap())
}

fn boxed_attribute_image() -> Vec<u8> {
    let mut strings = vec![0];
    let mut name = |text: &str| {
        let index = strings.len() as u16;
        strings.extend_from_slice(text.as_bytes());
        strings.push(0);
        index
    };
    let attribute = name("BoxedAttribute");
    let namespace = name("Demo");
    let ctor = name(".ctor");
    let enum_name = name("Enum");
    let system = name("System");
    let mode = name("Mode");
    let value_field = name("value__");
    let all = name("All");
    let alias = name("Alias");
    let mscorlib = name("mscorlib");
    let mut value = vec![1, 0, 0x08, 42, 0, 0, 0, 2, 0, 0, 0, 0x0E, 2, b'4', b'2'];
    value.extend([0x1D, 0x08, 2, 0, 0, 0]);
    value.extend((-2i32).to_le_bytes());
    value.extend(7i32.to_le_bytes());
    value.extend([2, 0, 0x54, 0x51, 5]);
    value.extend(b"Value");
    value.extend([0x50, 11]);
    value.extend(b"Demo.Target");
    value.extend([0x53, 0x1D, 0x51, 5]);
    value.extend(b"Items");
    value.extend([2, 0, 0, 0, 0x0E, 0xFF, 0x02, 1]);
    let mut blobs = vec![0, 6, 0x20, 2, 0x01, 0x1C, 0x1D, 0x1C];
    assert!(value.len() < 0x80);
    blobs.push(value.len() as u8);
    blobs.extend(value);
    let value_signature = blobs.len() as u16;
    blobs.extend([2, 0x06, 0x0B]);
    let literal_signature = blobs.len() as u16;
    blobs.extend([3, 0x06, 0x11, 4]);
    let constant_value = blobs.len() as u16;
    blobs.push(8);
    blobs.extend(u64::MAX.to_le_bytes());
    let present = [(1, 2u32), (2, 1), (4, 3), (10, 1), (11, 2), (12, 1), (35, 1)];
    let valid = present.iter().fold(0u64, |mask, &(table, _)| mask | (1 << table));
    let mut tables = vec![0, 0, 0, 0, 2, 0, 0, 1];
    tables.extend(valid.to_le_bytes());
    tables.extend(0u64.to_le_bytes());
    for &(_, rows) in &present {
        tables.extend(rows.to_le_bytes());
    }
    for row in [
        vec![0, attribute, namespace],
        vec![6, enum_name, system],
        vec![1, 0, mode, namespace, 9, 1, 1],
        vec![0x0606, value_field, value_signature],
        vec![0x8056, all, literal_signature],
        vec![0x8056, alias, literal_signature],
        vec![9, ctor, 1],
        vec![0x0B, 8, constant_value],
        vec![0x0B, 12, constant_value],
        vec![34, 11, 8],
        vec![4, 0, 0, 0, 0, 0, 0, mscorlib, 0, 0],
    ] {
        for column in row {
            tables.extend(column.to_le_bytes());
        }
    }
    let streams: [(&str, &[u8]); 3] = [("#~", &tables), ("#Strings", &strings), ("#Blob", &blobs)];
    let version = b"v4.0.30319\0\0";
    let mut root = b"BSJB\x01\0\x01\0\0\0\0\0".to_vec();
    root.extend((version.len() as u32).to_le_bytes());
    root.extend(version);
    root.extend([0, 0, 3, 0]);
    let mut offset =
        root.len() + streams.iter().map(|(name, _)| 8 + (name.len() + 1).next_multiple_of(4)).sum::<usize>();
    for (name, data) in streams {
        root.extend((offset as u32).to_le_bytes());
        root.extend((data.len() as u32).to_le_bytes());
        root.extend(name.as_bytes());
        root.push(0);
        root.resize(root.len().next_multiple_of(4), 0);
        offset += data.len().next_multiple_of(4);
    }
    for (_, data) in streams {
        root.extend(data);
        root.resize(root.len().next_multiple_of(4), 0);
    }
    let mut image = std::fs::read(fixture(ASSEMBLY)).unwrap();
    let metadata = rampage_loaders::dotnet::parse_image(&image).unwrap().unwrap();
    let start = image.windows(4).position(|bytes| bytes == b"BSJB").unwrap();
    assert!(root.len() <= metadata.cli.metadata_size as usize);
    image[start..start + root.len()].copy_from_slice(&root);
    image
}

#[test]
fn dotnet_attribute_json_preserves_boxed_types_without_changing_value_or_named_argument_schema() {
    let scratch = EventImage(std::env::temp_dir().join(format!("rampage-api-dotnet-boxed-{}.dll", std::process::id())));
    std::fs::write(&scratch.0, boxed_attribute_image()).unwrap();
    let project = rampage_api::Project::new(rampage_loaders::Binary::open(&scratch.0).unwrap());
    let query = DotNetQuery { list: DotNetList::Attributes, ..Default::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    let json = serde_json::to_value(&summary).unwrap();
    assert_eq!(json["custom_attributes"]["total"], 1);
    let attribute = &json["custom_attributes"]["items"][0];
    assert_eq!(attribute["attribute_type"], "Demo.BoxedAttribute");
    assert_eq!(
        attribute["arguments"],
        serde_json::json!(["box(int32, 42)", "[box(string, \"42\"), box(int32[], [-2, 7])]"])
    );
    assert_eq!(
        attribute["named_arguments"],
        serde_json::json!([
            {"kind": "property", "name": "Value", "argument_type": "object",
             "value": "box(System.Type, typeof(Demo.Target))"},
            {"kind": "field", "name": "Items", "argument_type": "object[]",
             "value": "[box(string, null), box(bool, true)]"},
        ])
    );
    assert!(attribute.get("arguments_error").is_none_or(serde_json::Value::is_null));
    assert!(json.get("types").is_none() && json.get("resources").is_none());
    let query = DotNetQuery { contains: Some("boxedattribute".to_owned()), ..query };
    assert_eq!(project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes.unwrap().total, 1);
}

#[test]
fn dotnet_type_json_preserves_verified_enum_constants_as_exact_strings_and_keeps_aliases() {
    let scratch = EventImage(std::env::temp_dir().join(format!("rampage-api-dotnet-enums-{}.dll", std::process::id())));
    std::fs::write(&scratch.0, boxed_attribute_image()).unwrap();
    let project = rampage_api::Project::new(rampage_loaders::Binary::open(&scratch.0).unwrap());
    let query = DotNetQuery { list: DotNetList::Types, contains: Some("mode".to_owned()), ..Default::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    let json = serde_json::to_value(&summary).unwrap();
    assert_eq!(json["types"]["total"], 1);
    let fields = json["types"]["items"][0]["fields"].as_array().unwrap();
    assert!(fields[0].get("enum_constant").is_none());
    for (field, name, token) in [(&fields[1], "All", 0x0400_0002), (&fields[2], "Alias", 0x0400_0003)] {
        assert_eq!(field["name"], name);
        assert_eq!(field["token"], token);
        assert_eq!(
            field["enum_constant"],
            serde_json::json!({
                "underlying_integral_type": "uint64", "value": "18446744073709551615"
            })
        );
    }
    assert!(json.get("custom_attributes").is_none());
    let query = DotNetQuery { offset: Some(1), limit: Some(1), contains: None, ..query };
    assert!(project.dotnet_metadata(&query).unwrap().unwrap().types.unwrap().items.is_empty());
}

#[test]
fn dotnet_resources_have_independent_pages_filters_counts_and_json_evidence() {
    use std::str::FromStr;

    assert_eq!(DotNetList::from_str("resources").unwrap(), DotNetList::Resources);
    assert_eq!(serde_json::from_str::<DotNetList>("\"resources\"").unwrap(), DotNetList::Resources);
    let project = resource_project(4, 0);
    let query = DotNetQuery { list: DotNetList::Resources, offset: Some(1), limit: Some(2), ..Default::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    assert_eq!(summary.counts.resources, 4);
    assert!(summary.resource_counts.declared_known);
    assert_eq!(
        (
            summary.resource_counts.declared,
            summary.resource_counts.readable,
            summary.resource_counts.retained,
            summary.resource_counts.returned,
            summary.resource_counts.truncated
        ),
        (4, 4, 4, 2, false)
    );
    assert!(summary.types.is_none() && summary.pinvokes.is_none() && summary.custom_attributes.is_none());
    let json = serde_json::to_value(&summary).unwrap();
    assert!(json.get("types").is_none() && json.get("custom_attributes").is_none());
    assert_eq!(json["list"], "resources");
    assert_eq!(json["resources"]["total"], 4);
    assert_eq!(json["resources"]["offset"], 1);
    assert_eq!(json["resource_counts"]["returned"], 2);
    let file = &json["resources"]["items"][0];
    assert_eq!(file["token"], 0x2800_0002u32);
    assert_eq!(file["offset"], 4);
    assert_eq!(file["implementation_raw"], 4);
    assert_eq!(file["implementation"]["kind"], "file");
    assert_eq!(file["implementation"]["status"], "readable");
    assert_eq!(file["implementation"]["token"], 0x2600_0001u32);
    assert_eq!(file["implementation"]["name"], "Part.netmodule");
    assert_eq!(file["availability"]["kind"], "external");
    assert_eq!(json["resources"]["items"][1]["implementation"]["kind"], "assembly_ref");
    for (contains, expected) in [("aLpHa", 2), ("PART.NETMODULE", 1), ("otherassembly", 1), ("absent", 0)] {
        let query =
            DotNetQuery { list: DotNetList::Resources, contains: Some(contains.to_owned()), ..Default::default() };
        let summary = project.dotnet_metadata(&query).unwrap().unwrap();
        assert_eq!(summary.resources.unwrap().total, expected, "{contains}");
        assert_eq!(summary.counts.resources, 4, "counts precede filtering");
    }
    let query = DotNetQuery { list: DotNetList::Resources, offset: Some(99), limit: Some(1), ..Default::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    assert_eq!(summary.resource_counts.returned, 0);
    let page = summary.resources.unwrap();
    assert_eq!((page.total, page.offset, page.items.len()), (4, 4, 0));
    let query = DotNetQuery { list: DotNetList::Resources, parent_token: Some(0x2800_0001), ..Default::default() };
    assert!(matches!(project.dotnet_metadata(&query), Err(ApiError::Invalid(_))));
    let types = project.dotnet_metadata(&DotNetQuery::default()).unwrap().unwrap();
    assert!(types.resources.is_none());
    assert_eq!((types.counts.resources, types.resource_counts.returned), (4, 0));
}

#[test]
fn dotnet_resource_counts_separate_declared_readable_retained_and_returned_rows() {
    let project = resource_project(4, 1);
    let query = DotNetQuery { list: DotNetList::Resources, limit: Some(1), ..Default::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    let json = serde_json::to_value(&summary).unwrap();
    assert_eq!(
        json["resource_counts"],
        serde_json::json!({
            "declared": 4, "declared_known": true, "readable": 3, "retained": 3, "returned": 1, "truncated": true,
        })
    );
    let page = summary.resources.unwrap();
    assert_eq!((page.total, page.items.len()), (3, 1));
    let embedded = &json["resources"]["items"][0];
    assert_eq!(embedded["implementation"]["kind"], "embedded");
    assert_eq!(embedded["availability"]["kind"], "embedded");
    assert!(embedded["availability"].get("status").is_some());
    assert!(embedded.get("size").is_none() && embedded.get("payload").is_none());
    let project = resource_project(u32::MAX, 0);
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    assert_eq!((summary.resource_counts.declared, summary.resource_counts.readable), (u32::MAX, 4));
    assert!(summary.resource_counts.truncated);
}

#[test]
fn dotnet_resource_json_distinguishes_unknown_and_recovered_partial_header_counts() {
    for count_available in [false, true] {
        let mut image = resource_image(4, 0);
        let root = image.windows(4).position(|bytes| bytes == b"BSJB").unwrap();
        let table_header = root + 32;
        let relative = u32::from_le_bytes(image[table_header..table_header + 4].try_into().unwrap()) as usize;
        let stream = root + relative;
        let valid = (1u64 << 40) | (1 << 42);
        image[stream + 8..stream + 16].copy_from_slice(&valid.to_le_bytes());
        image[stream + 24..stream + 28].copy_from_slice(&17u32.to_le_bytes());
        let size = if count_available { 28u32 } else { 24 };
        image[table_header + 4..table_header + 8].copy_from_slice(&size.to_le_bytes());
        let path = std::env::temp_dir()
            .join(format!("rampage-api-dotnet-partial-resource-header-{}-{count_available}.dll", std::process::id()));
        let scratch = EventImage(path);
        std::fs::write(&scratch.0, image).unwrap();
        let project = rampage_api::Project::new(rampage_loaders::Binary::open(&scratch.0).unwrap());
        let query = DotNetQuery { list: DotNetList::Resources, ..Default::default() };
        let summary = project.dotnet_metadata(&query).unwrap().unwrap();
        let json = serde_json::to_value(summary).unwrap();
        assert_eq!(
            json["resource_counts"],
            serde_json::json!({
                "declared": if count_available { 17 } else { 0 },
                "declared_known": count_available,
                "readable": 0, "retained": 0, "returned": 0, "truncated": true,
            })
        );
        assert_eq!(json["resources"]["total"], 0);
        assert_eq!(json["resources"]["items"], serde_json::json!([]));
    }
}

#[test]
fn dotnet_metadata_serializes_events_and_filters_the_current_type_view() {
    let scratch = event_image();
    let project = rampage_api::Project::new(rampage_loaders::Binary::open(&scratch.0).unwrap());
    let query = DotNetQuery { contains: Some("cHaNgEd".to_owned()), ..Default::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    assert_eq!((summary.counts.types, summary.counts.events, summary.counts.properties), (2, 2, 0));
    let json = serde_json::to_value(&summary).unwrap();
    assert_eq!(json["counts"]["events"], 2);
    assert_eq!(json["types"]["total"], 1);
    let ty = &json["types"]["items"][0];
    assert_eq!(ty["name"], "Publisher");
    assert_eq!(ty["events"][0]["token"], 0x1400_0001u32);
    assert_eq!(ty["events"][0]["name"], "Changed");
    assert_eq!(ty["events"][0]["flags"], 0x0200);
    assert_eq!(ty["events"][0]["event_type"], "Demo.Handler");
    assert_eq!(ty["events"][0]["accessors"][0]["semantics"], 8);
    assert_eq!(ty["events"][0]["accessors"][1]["method_token"], 0x0600_0002u32);
    assert_eq!(ty["events"][1]["event_type"], "<unreadable>");
    assert!(summary.warnings.iter().any(|warning| warning.contains("Event row 2: type reference")));
    assert!(summary.pinvokes.is_none() && summary.custom_attributes.is_none());

    let query =
        DotNetQuery { contains: Some("BROKEN".to_owned()), offset: Some(1), limit: Some(1), ..Default::default() };
    let page = project.dotnet_metadata(&query).unwrap().unwrap().types.unwrap();
    assert_eq!((page.offset, page.total, page.items.len()), (1, 1, 0));
    let query = DotNetQuery { contains: Some("Handler".to_owned()), ..Default::default() };
    assert_eq!(
        project.dotnet_metadata(&query).unwrap().unwrap().types.unwrap().total,
        0,
        "filter matches event names, not types"
    );
}

#[test]
fn dotnet_metadata_reports_identity_and_filters_types() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let all = project.dotnet_metadata(&DotNetQuery::default()).unwrap().expect("managed assembly");
    assert_eq!(all.assembly.as_ref().unwrap().name, "Microsoft.Bcl.HashCode");
    assert_eq!(all.counts.methods, 48);
    assert_eq!(all.counts.il_methods, 48);
    assert_eq!(all.types.unwrap().total, all.counts.types);

    let query = DotNetQuery { contains: Some("combine".to_owned()), ..DotNetQuery::default() };
    let filtered = project.dotnet_metadata(&query).unwrap().unwrap();
    let names: Vec<String> = filtered.types.unwrap().items.iter().map(|ty| ty.full_name()).collect();
    assert_eq!(names, ["System.HashCode"], "a method-name match selects its type");

    let page = project.dotnet_metadata(&DotNetQuery { limit: Some(1), ..DotNetQuery::default() }).unwrap().unwrap();
    let types = page.types.unwrap();
    assert_eq!((types.items.len(), types.total), (1, all.counts.types));
    assert!(page.pinvokes.is_none() && page.custom_attributes.is_none(), "only the selected list is paged");
    assert_eq!((page.counts.custom_attributes, page.counts.pinvokes), (76, 0));

    // Each list pages on its own: the second attribute is not the second type's neighbour.
    let query = DotNetQuery { list: DotNetList::Attributes, offset: Some(1), limit: Some(1), ..DotNetQuery::default() };
    let page = project.dotnet_metadata(&query).unwrap().unwrap();
    assert!(page.types.is_none());
    let attributes = page.custom_attributes.unwrap();
    assert_eq!((attributes.offset, attributes.items.len(), attributes.total), (1, 1, 76));
}

#[test]
fn dotnet_metadata_reports_signatures_and_filters_attributes() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let query = DotNetQuery { contains: Some("combine".to_owned()), ..DotNetQuery::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    let hash_code = &summary.types.unwrap().items[0];
    let combine = hash_code.methods.iter().find(|method| method.name == "Combine").unwrap();
    assert_eq!(combine.signature, "int32 Combine<T1>(T1)");
    let equals = hash_code.methods.iter().find(|method| method.name == "Equals").unwrap().token;
    let query = DotNetQuery { list: DotNetList::Pinvokes, ..DotNetQuery::default() };
    assert_eq!(project.dotnet_metadata(&query).unwrap().unwrap().pinvokes.unwrap().total, 0);

    let attributes = |contains: &str| {
        let query =
            DotNetQuery { list: DotNetList::Attributes, contains: Some(contains.to_owned()), ..DotNetQuery::default() };
        project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes.unwrap()
    };
    let obsolete = attributes("obsolete");
    let parents: Vec<Option<&str>> = obsolete.items.iter().map(|attribute| attribute.parent.as_deref()).collect();
    assert_eq!(parents, [Some("System.HashCode::GetHashCode"), Some("System.HashCode::Equals")]);
    assert_eq!(attributes("HashCode::Equals").total, 3, "attributes match by their target too");

    let query = DotNetQuery { list: DotNetList::Attributes, parent_token: Some(equals), ..DotNetQuery::default() };
    let on_equals = project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes.unwrap();
    assert!(on_equals.total > 0);
    assert!(on_equals.items.iter().all(|attribute| attribute.parent_token == equals));
    let query = DotNetQuery { parent_token: Some(equals), ..DotNetQuery::default() };
    assert!(matches!(project.dotnet_metadata(&query), Err(ApiError::Invalid(_))), "parent_token needs attributes");
}

#[test]
fn dotnet_metadata_exposes_properties_named_values_and_unknown_external_enums() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let all = project.dotnet_metadata(&DotNetQuery { limit: Some(100), ..Default::default() }).unwrap().unwrap();
    let types = all.types.unwrap().items;
    assert_eq!(all.counts.properties, types.iter().map(|ty| ty.properties.len()).sum::<usize>());
    let query = DotNetQuery { contains: Some("useNonRandomizedHashSeed".to_owned()), ..Default::default() };
    let filtered = project.dotnet_metadata(&query).unwrap().unwrap().types.unwrap();
    assert_eq!(filtered.total, 1);
    let ty = &filtered.items[0];
    assert_eq!(ty.full_name(), "System.LocalAppContextSwitches");
    let property = ty.properties.iter().find(|property| property.name == "UseNonRandomizedHashSeed").unwrap();
    assert_eq!(property.signature, "bool UseNonRandomizedHashSeed()");
    let getter = property.accessors.iter().find(|binding| binding.semantics == 2).unwrap();
    assert!(
        ty.methods
            .iter()
            .any(|method| method.token == getter.method_token && method.name == "get_UseNonRandomizedHashSeed")
    );

    let query = DotNetQuery {
        list: DotNetList::Attributes,
        contains: Some("RuntimeCompatibilityAttribute".to_owned()),
        ..Default::default()
    };
    let attributes = project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes.unwrap();
    let compatibility = &attributes.items[0];
    let named = compatibility.named_arguments.as_ref().unwrap();
    assert!(named.iter().any(|argument| {
        argument.name == "WrapNonExceptionThrows" && argument.argument_type == "bool" && argument.value == "true"
    }));
    assert!(compatibility.arguments_error.is_none());
    let query = DotNetQuery {
        list: DotNetList::Attributes,
        contains: Some("DebuggableAttribute".to_owned()),
        ..Default::default()
    };
    let attributes = project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes.unwrap();
    let debuggable = &attributes.items[0];
    assert!(debuggable.arguments.is_none() && debuggable.named_arguments.is_none());
    assert!(debuggable.arguments_error.as_deref().unwrap().contains("enum underlying type is unknown"));
    let json = serde_json::to_value(debuggable).unwrap();
    assert!(json["arguments_error"].as_str().unwrap().contains("unknown"));
}

#[test]
fn dotnet_il_pages_one_method_by_token_or_name() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let query = |method: &str, offset, limit| DotNetIlQuery { method: method.to_owned(), offset, limit, at: None };
    let by_token = project.dotnet_il(&query("0x0600000d", Some(5), Some(3))).unwrap().expect("managed assembly");
    assert_eq!(by_token.method, "System.HashCode::Combine");
    let page = &by_token.instructions;
    assert_eq!((page.offset, page.items.len()), (5, 3));
    assert!(page.total > 50);
    assert_eq!(page.items[0].text(), "IL_000b: ldarga.s 0");
    assert_eq!(by_token.locals.len(), 10);
    assert_eq!((by_token.locals_total, by_token.locals_truncated), (10, false));
    let decimal = project.dotnet_il(&query(&0x0600_000D_u32.to_string(), None, Some(1))).unwrap().unwrap();
    assert_eq!(decimal.token, by_token.token);

    let by_name = project.dotnet_il(&query("System.SR::GetResourceString", None, None)).unwrap().unwrap();
    assert_eq!(by_name.exception_clauses.len(), 1);
    assert_eq!(by_name.instructions.items.len(), by_name.instructions.total);

    let ambiguous = project.dotnet_il(&query("System.HashCode::Combine", None, None)).unwrap_err();
    assert!(matches!(&ambiguous, ApiError::Invalid(text) if text.contains("0x0600000d")), "{ambiguous}");
    let missing = project.dotnet_il(&query("System.HashCode::Missing", None, None)).unwrap_err();
    assert!(matches!(missing, ApiError::NotFound(_)), "{missing}");
    assert!(matches!(project.dotnet_il(&query(" ", None, None)), Err(ApiError::Invalid(_))));
    let native = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    assert!(native.dotnet_il(&query("0x06000001", None, None)).unwrap().is_none());
}

#[test]
fn dotnet_il_pages_from_an_il_offset() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let at = |at: &str, offset| DotNetIlQuery {
        method: "0x0600000d".to_owned(),
        offset,
        limit: Some(2),
        at: Some(rampage_api::parse_il_offset(at).unwrap()),
    };
    // IL_000b is the sixth instruction; IL_000c is the second byte of the same `ldarga.s`.
    for label in ["IL_000b", "0xc", "11"] {
        let page = project.dotnet_il(&at(label, None)).unwrap().unwrap().instructions;
        assert_eq!((page.offset, page.items[0].text()), (5, "IL_000b: ldarga.s 0".to_owned()), "{label}");
    }
    assert_eq!(project.dotnet_il(&at("IL_0000", None)).unwrap().unwrap().instructions.offset, 0);
    let last = project.dotnet_il(&at("IL_00e0", None)).unwrap().unwrap().instructions;
    assert_eq!((last.offset, last.items.len()), (last.total - 1, 1));
    let past = project.dotnet_il(&at("IL_00e1", None)).unwrap_err();
    assert!(matches!(&past, ApiError::Invalid(text) if text.contains("past the end")), "{past}");
    assert!(matches!(project.dotnet_il(&at("IL_0000", Some(1))), Err(ApiError::Invalid(_))));
    assert!(rampage_api::parse_il_offset("IL_zz").is_err());
}

#[test]
fn native_images_have_no_dotnet_metadata() {
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    assert!(project.dotnet_metadata(&DotNetQuery::default()).unwrap().is_none());
}

#[test]
fn managed_dll_is_detected_strongly_and_triaged_as_managed() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let detections = project.detect_tools(None).unwrap().detections;
    assert!(
        detections.iter().any(|d| d.name == ".NET" && d.confidence == DetectionConfidence::Strong),
        "{detections:?}"
    );
    let report = project.triage_report(ReportLimits::default()).unwrap();
    assert!(report.next_steps.iter().any(|step| step.tool == "dotnet_metadata"), "{report:#?}");
    // A library has no entry point: the CIL of its first method with an IL body is suggested instead.
    let il = report.next_steps.iter().find(|step| step.tool == "dotnet_il").expect("dotnet_il is suggested");
    assert_eq!(il.group, Some("dotnet"));
    let method = il.arguments["method"].as_str().unwrap();
    let query = rampage_api::DotNetIlQuery { method: method.to_owned(), ..Default::default() };
    assert!(project.dotnet_il(&query).unwrap().is_some(), "{method}");
    assert!(report.next_steps.iter().all(|step| step.tool != "find_main"), "{report:#?}");
    assert!(report.limitations.iter().any(|text| text.contains("CIL bytecode")), "{report:#?}");
}
