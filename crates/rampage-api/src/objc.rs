//! Objective-C message sends as the API shows them: the `objc_sends` listing, the comment a send site carries in
//! disassembly, and the comments decompiled C gains at send sites.

use rampage_analysis::objc_dispatch::{Confidence, Send};
use serde::Serialize;

use crate::decompile::DecompiledToken;
use crate::rows::Page;
use crate::{ApiError, Decompilation, Project};

#[derive(Debug, Serialize)]
pub struct ObjcSends {
    pub summary: ObjcSendSummary,
    pub sends: Page<ObjcSendRow>,
    pub limitations: Vec<String>,
}

/// Counts over every send the request selects (the whole binary, or one function).
#[derive(Debug, Default, Serialize)]
pub struct ObjcSendSummary {
    pub sends: usize,
    /// Sends whose selector is statically evident.
    pub with_selector: usize,
    /// Sends whose receiver class is statically evident.
    pub with_receiver_class: usize,
    pub resolved: usize,
    pub ambiguous: usize,
    pub framework: usize,
    pub candidates: usize,
    pub unknown_receiver: usize,
    pub unknown_selector: usize,
    /// arm64 `__objc_stubs` selector stubs found (named `_objc_msgSend$<selector>`).
    pub selector_stubs: usize,
}

#[derive(Debug, Serialize)]
pub struct ObjcSendRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub site: u64,
    pub function: String,
    pub via: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<rampage_analysis::objc_dispatch::Receiver>,
    pub confidence: &'static str,
    pub targets: Vec<ObjcTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ObjcTarget {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
}

const LIMITATIONS: [&str; 3] = [
    "Registers are followed through each function's blocks; a receiver or selector kept in memory (a stack \
     spill, an ivar, a block capture) or returned by a method other than +alloc/+new/-init.../-class is unknown.",
    "A receiver known only by static type (self, super's class methods) may be a subclass instance: overrides in \
     local subclasses make the send ambiguous. Unknown receivers list the selector's implementations in this \
     binary as candidates (up to 8), never one guessed target.",
    "Implementations outside the binary (frameworks, dynamically added methods, forwarding) are reported as \
     framework, without a target.",
];

impl Project {
    /// The Objective-C message sends of the function at `function` (or of the whole binary), with how each
    /// resolves, optionally only those of `selector`.
    pub fn objc_sends(
        &self,
        function: Option<u64>,
        selector: Option<&str>,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<ObjcSends, ApiError> {
        let dispatch = self.objc_dispatch()?;
        let start = match function {
            Some(address) => Some(
                self.function_containing(address)?
                    .ok_or_else(|| ApiError::NotFound(format!("no function contains {address:#x}")))?,
            ),
            None => None,
        };
        let selected: Vec<&Send> = dispatch
            .sends
            .iter()
            .filter(|send| start.is_none_or(|start| send.function == start))
            .filter(|send| selector.is_none_or(|selector| send.selector.as_deref() == Some(selector)))
            .collect();
        let mut summary = ObjcSendSummary {
            sends: selected.len(),
            selector_stubs: dispatch.stubs.len(),
            ..ObjcSendSummary::default()
        };
        for send in &selected {
            summary.with_selector += usize::from(send.selector.is_some());
            summary.with_receiver_class += usize::from(send.receiver.is_some());
            *match send.confidence {
                Confidence::Resolved => &mut summary.resolved,
                Confidence::Ambiguous => &mut summary.ambiguous,
                Confidence::Framework => &mut summary.framework,
                Confidence::Candidates => &mut summary.candidates,
                Confidence::UnknownReceiver => &mut summary.unknown_receiver,
                Confidence::UnknownSelector => &mut summary.unknown_selector,
            } += 1;
        }
        let page = Page::of(selected, offset, Some(limit.unwrap_or(100)));
        let items = page
            .items
            .iter()
            .map(|send| ObjcSendRow {
                site: send.site,
                function: self.function_name(send.function),
                via: send.via,
                selector: send.selector.clone(),
                receiver: send.receiver.clone(),
                confidence: send.confidence.as_str(),
                targets: send
                    .targets
                    .iter()
                    .map(|&address| ObjcTarget { address, name: self.function_name(address) })
                    .collect(),
                candidates: send.candidates,
            })
            .collect();
        let mut limitations: Vec<String> = LIMITATIONS.iter().map(|text| (*text).to_owned()).collect();
        limitations.extend(dispatch.warnings.iter().cloned());
        if self.binary.format != rampage_loaders::Format::MachO
            || !matches!(self.binary.arch, rampage_arch::Arch::Aarch64 | rampage_arch::Arch::X86_64)
        {
            limitations.push("Sends are resolved only in arm64 and x86-64 Mach-O images.".to_owned());
        }
        Ok(ObjcSends { summary, sends: Page { total: page.total, offset: page.offset, items }, limitations })
    }

    /// How a send reads as a comment: `[(Shape *) area] -> -[Shape area] | -[Circle area] (ambiguous)`.
    pub(crate) fn objc_send_comment(&self, send: &Send) -> Option<String> {
        let selector = send.selector.as_deref()?;
        let receiver = match &send.receiver {
            Some(receiver) if receiver.class_object => receiver.class.clone(),
            Some(receiver) => format!("({} *)", receiver.class),
            None => "?".to_owned(),
        };
        let names = || send.targets.iter().map(|&target| self.function_name(target)).collect::<Vec<_>>().join(" | ");
        let resolution = match send.confidence {
            Confidence::Resolved => format!(" -> {}", names()),
            Confidence::Ambiguous => format!(" -> {} (ambiguous)", names()),
            Confidence::Candidates if send.targets.is_empty() => {
                format!(" -> {} candidates", send.candidates.unwrap_or_default())
            }
            Confidence::Candidates => format!(" -> candidates: {}", names()),
            Confidence::Framework => " (framework)".to_owned(),
            Confidence::UnknownReceiver | Confidence::UnknownSelector => String::new(),
        };
        Some(format!("[{receiver} {selector}]{resolution}"))
    }

    /// Adds a `/* objc: … */` comment at the end of each decompiled line holding an Objective-C send, after the
    /// line's last token, with a `comment` token of the send's address. Lines and other tokens are unchanged.
    pub(crate) fn annotate_objc_sends(&self, decompilation: &mut Decompilation) {
        let Ok(Some(dispatch)) = self.objc_dispatch_for_function(decompilation.address) else { return };
        let sends: Vec<&Send> = dispatch.sends.iter().filter(|send| send.function == decompilation.address).collect();
        if sends.is_empty() {
            return;
        }
        // Each send's comment goes at the end of the first line with a token of its site.
        let mut insertions: std::collections::BTreeMap<usize, Vec<(u64, String)>> = Default::default();
        for send in sends {
            let Some(comment) = self.objc_send_comment(send) else { continue };
            let Some(end) = decompilation
                .tokens
                .iter()
                .filter(|token| token.address == Some(send.site))
                .find_map(|token| token.span.map(|(_, end)| end))
            else {
                continue;
            };
            let Some(line_end) = decompilation.code.get(end..).map(|rest| end + rest.find('\n').unwrap_or(rest.len()))
            else {
                continue;
            };
            insertions.entry(line_end).or_default().push((send.site, comment));
        }
        for (position, comments) in insertions.into_iter().rev() {
            let mut shift = 0;
            let mut added = Vec::new();
            for (site, comment) in comments {
                let text = format!(" /* objc: {comment} */");
                let start = position + shift;
                added.push(DecompiledToken {
                    text: text.clone(),
                    kind: "comment".to_owned(),
                    address: Some(site),
                    span: Some((start, start + text.len())),
                });
                decompilation.code.insert_str(start, &text);
                shift += text.len();
            }
            for token in &mut decompilation.tokens {
                if let Some((start, end)) = token.span.as_mut().filter(|(start, _)| *start >= position) {
                    *start += shift;
                    *end += shift;
                }
            }
            let at = decompilation
                .tokens
                .iter()
                .position(|token| token.span.is_some_and(|(start, _)| start >= position + shift))
                .unwrap_or(decompilation.tokens.len());
            decompilation.tokens.splice(at..at, added);
        }
    }
}
