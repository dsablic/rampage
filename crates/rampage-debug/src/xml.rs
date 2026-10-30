//! A bounded element tree over quick-xml for the stub's small XML documents (target descriptions, library lists,
//! memory maps). Names keep their prefixes (`xi:include`): GDB stubs use the prefix without declaring the
//! namespace. No DTD is processed and no entity other than the predefined and character references is expanded.

use quick_xml::events::Event;

/// Most elements in one document.
const MAX_ELEMENTS: usize = 65_536;
/// Deepest element nesting.
const MAX_DEPTH: usize = 32;

#[derive(Debug, Default)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Element>,
    pub text: String,
}

impl Element {
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }
}

/// The root element of `text`.
pub fn parse(text: &str) -> Result<Element, String> {
    let mut reader = quick_xml::Reader::from_str(text);
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut elements = 0;
    loop {
        let event = reader.read_event().map_err(|error| format!("malformed XML: {error}"))?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() > MAX_DEPTH {
                    return Err("XML document exceeds its element or depth limit".into());
                }
                let name = start.name().as_ref().to_owned();
                let mut attributes = Vec::new();
                for attribute in start.attributes() {
                    let attribute = attribute.map_err(|error| format!("malformed XML attribute: {error}"))?;
                    let key = attribute.key.as_ref().to_owned();
                    let value = attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|error| format!("malformed XML attribute value: {error}"))?;
                    attributes.push((key, value.into_owned()));
                }
                let element = Element { name, attributes, ..Element::default() };
                if empty {
                    stack.last_mut().expect("the document element").children.push(element);
                } else {
                    stack.push(element);
                }
            }
            Event::End(_) => {
                let element = stack.pop().expect("quick-xml matches end tags");
                stack.last_mut().ok_or("unbalanced XML end tag")?.children.push(element);
            }
            Event::Text(text) => stack.last_mut().expect("the document element").text.push_str(&text.xml10_content()),
            Event::CData(data) => stack.last_mut().expect("the document element").text.push_str(&data.xml10_content()),
            Event::GeneralRef(reference) => {
                let text = &mut stack.last_mut().expect("the document element").text;
                if let Some(character) = reference.resolve_char_ref().map_err(|error| error.to_string())? {
                    text.push(character);
                } else {
                    let name = reference.xml10_content();
                    let character = match name.as_ref() {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "apos" => '\'',
                        "quot" => '"',
                        _ => return Err(format!("unsupported XML entity `&{name};`")),
                    };
                    text.push(character);
                }
            }
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }
    if stack.len() != 1 {
        return Err("XML document ends inside an element".into());
    }
    let mut document = stack.pop().expect("the document element");
    if document.children.len() != 1 {
        return Err("XML document must have exactly one root element".into());
    }
    Ok(document.children.pop().expect("one root"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefixed_names_attributes_and_references() {
        let root = parse(
            "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target>\
             <architecture>arm&amp;x&#65;</architecture><xi:include href=\"a.xml\"/></target>",
        )
        .unwrap();
        assert_eq!(root.name, "target");
        assert_eq!(root.children[0].text, "arm&xA");
        assert_eq!(root.children[1].name, "xi:include");
        assert_eq!(root.children[1].attribute("href"), Some("a.xml"));
    }

    #[test]
    fn refuses_malformed_and_hostile_documents() {
        for text in [
            "",
            "<a>",
            "<a></b>",
            "<a/><b/>",
            "<a>&custom;</a>",
            "<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>",
            "<a x='1' x='2'/>",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        let deep = "<a>".repeat(40) + &"</a>".repeat(40);
        assert!(parse(&deep).is_err());
        let wide = format!("<a>{}</a>", "<b/>".repeat(MAX_ELEMENTS + 1));
        assert!(parse(&wide).is_err());
    }

    #[test]
    fn random_text_never_panics() {
        let mut rng = crate::packet::tests::Rng::new(4);
        for _ in 0..2000 {
            let length = rng.below(120);
            let alphabet: Vec<char> = "<>/=\"'ab&;#x!-?[] ".chars().collect();
            let text: String = (0..length).map(|_| alphabet[rng.below(alphabet.len())]).collect();
            let _ = parse(&text);
        }
    }
}
