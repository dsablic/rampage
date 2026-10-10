//! The assistant panel: a conversation with a Claude model about the open binary. The model reads the project
//! through rampage's analysis tools on a background thread; its renames and comments land in the listing, and
//! `show_address` moves the cursor.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use egui::{Key, Modifiers, RichText, ScrollArea, TextEdit, Ui};
use rampage_agent::{Agent, Anthropic, Event};
use rampage_api::Project;

use crate::theme;

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_api::tools::Effect;

    #[test]
    fn tool_effects_drive_refresh_and_navigation_without_name_matching() {
        for (effect, failed, annotations, show) in [
            (Effect::Annotations, false, true, None),
            (Effect::ShowAddress, false, false, Some("0x1000")),
            (Effect::Annotations, true, false, None),
            (Effect::ShowAddress, true, false, None),
            (Effect::None, false, false, None),
        ] {
            let (sender, receiver) = channel();
            sender
                .send(Message::Event(Event::Tool {
                    name: "arbitrary_tool_name".to_owned(),
                    input: serde_json::json!({"at": "0x1000"}),
                    failed,
                    effect,
                }))
                .unwrap();
            let mut assistant = Assistant { running: Some(receiver), ..Default::default() };
            let effects = assistant.poll();
            assert_eq!(effects.annotations_changed, annotations);
            assert_eq!(effects.show.as_deref(), show);
            assert_eq!(assistant.transcript.len(), 1);
        }
    }
}

pub enum Entry {
    Question(String),
    Answer(String),
    /// A tool call, summarized: its name and main argument.
    Tool {
        summary: String,
        failed: bool,
    },
    Error(String),
}

enum Message {
    Event(Event),
    Finished(Box<Agent>, Result<(), String>),
}

#[derive(Default)]
pub struct Assistant {
    pub transcript: Vec<Entry>,
    pub input: String,
    agent: Option<Box<Agent>>,
    running: Option<Receiver<Message>>,
}

/// What the workspace should do after the model's tools ran.
#[derive(Default)]
pub struct Effects {
    pub annotations_changed: bool,
    pub show: Option<String>,
}

impl Assistant {
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// Sends the typed question to the model on a background thread.
    pub fn ask(&mut self, project: &Arc<Project>, ctx: &egui::Context) {
        let question = self.input.trim().to_owned();
        if question.is_empty() || self.is_running() {
            return;
        }
        let Some(transport) = Anthropic::from_environment() else {
            self.transcript.push(Entry::Error("Set ANTHROPIC_API_KEY to use the assistant.".to_owned()));
            return;
        };
        self.input.clear();
        self.transcript.push(Entry::Question(question.clone()));
        let mut agent = self.agent.take().unwrap_or_else(|| Box::new(Agent::new(project)));
        let project = Arc::clone(project);
        let (sender, receiver) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let events = sender.clone();
            let repaint = ctx.clone();
            let result = agent.ask(&transport, &project, &question, &mut |event| {
                let _ = events.send(Message::Event(event));
                repaint.request_repaint();
            });
            let _ = sender.send(Message::Finished(agent, result));
            ctx.request_repaint();
        });
        self.running = Some(receiver);
    }

    /// Collects progress from the background conversation.
    pub fn poll(&mut self) -> Effects {
        let mut effects = Effects::default();
        let Some(receiver) = &self.running else { return effects };
        loop {
            match receiver.try_recv() {
                Ok(Message::Event(Event::Text(text))) => self.transcript.push(Entry::Answer(text)),
                Ok(Message::Event(Event::Tool { name, input, failed, effect })) => {
                    let argument = ["at", "to", "from", "name_contains", "contains"]
                        .iter()
                        .find_map(|key| input[key].as_str())
                        .unwrap_or("");
                    if !failed {
                        match effect {
                            rampage_api::tools::Effect::Annotations => effects.annotations_changed = true,
                            rampage_api::tools::Effect::ShowAddress => effects.show = Some(argument.to_owned()),
                            rampage_api::tools::Effect::None => {}
                        }
                    }
                    self.transcript.push(Entry::Tool { summary: format!("{name} {argument}"), failed });
                }
                Ok(Message::Finished(agent, result)) => {
                    self.agent = Some(agent);
                    if let Err(error) = result {
                        self.transcript.push(Entry::Error(error));
                    }
                    self.running = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.transcript.push(Entry::Error("the assistant stopped unexpectedly".to_owned()));
                    self.running = None;
                    break;
                }
            }
        }
        effects
    }
}

/// The panel: the conversation, and a box to ask in below it. Returns whether a question was submitted.
pub fn show(ui: &mut Ui, assistant: &mut Assistant) -> bool {
    const INPUT_HEIGHT: f32 = 96.0;
    ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .max_height((ui.available_height() - INPUT_HEIGHT).max(40.0))
        .show(ui, |ui| {
            if assistant.transcript.is_empty() {
                ui.label(
                    RichText::new(
                        "Ask about the binary: what a function does, where a string is used, what to rename.",
                    )
                    .color(theme::DIM),
                );
            }
            for entry in &assistant.transcript {
                match entry {
                    Entry::Question(text) => {
                        ui.add_space(6.0);
                        ui.label(RichText::new(text).strong().color(theme::LINK));
                    }
                    Entry::Answer(text) => {
                        ui.label(text);
                    }
                    Entry::Tool { summary, failed } => {
                        let color = if *failed { theme::WARNING } else { theme::FAINT };
                        ui.label(RichText::new(format!("> {summary}")).monospace().small().color(color));
                    }
                    Entry::Error(text) => {
                        ui.label(RichText::new(text).color(theme::WARNING));
                    }
                }
            }
        });
    ui.separator();
    let input = ui.add(
        TextEdit::multiline(&mut assistant.input)
            .hint_text("Ask about this binary (Enter to send)")
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    );
    // Enter sends; Shift+Enter starts a new line.
    let mut submit = input.has_focus() && ui.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Enter));
    ui.horizontal(|ui| {
        let busy = assistant.is_running();
        submit |= ui.add_enabled(!busy, egui::Button::new("Ask")).clicked();
        if busy {
            ui.spinner();
        }
    });
    ui.label(RichText::new("Questions and the code the model reads go to Anthropic's API.").small().color(theme::DIM));
    submit
}
