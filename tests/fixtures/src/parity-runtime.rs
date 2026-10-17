// SPDX-License-Identifier: Apache-2.0

use std::hint::black_box;

#[derive(Clone, Copy, Debug)]
enum PipelineError {
    InvalidConfig,
    InvalidUnits,
    UnknownCommand,
    MissingCheckpoint,
    OutOfRange,
    TooManyCommands,
}

struct Config {
    limit: i64,
    factor: i64,
}

#[derive(Default)]
struct State {
    total: i64,
    checkpoint: Option<i64>,
    applied: u32,
    rejected: u32,
}

enum Command {
    Add(i64),
    Remove(i64),
    Checkpoint,
    Restore,
}

trait Operation {
    fn candidate(&self, total: i64, units: i64, factor: i64) -> i64;
}

struct Add;
struct Remove;

impl Operation for Add {
    #[inline(never)]
    fn candidate(&self, total: i64, units: i64, factor: i64) -> i64 {
        total + units * factor
    }
}

impl Operation for Remove {
    #[inline(never)]
    fn candidate(&self, total: i64, units: i64, factor: i64) -> i64 {
        total - units * factor
    }
}

#[inline(never)]
fn parse_units(text: &str) -> Result<i64, PipelineError> {
    let value = text.parse::<i64>().map_err(|_| PipelineError::InvalidUnits)?;
    if !(0..=10000).contains(&value) {
        return Err(PipelineError::InvalidUnits);
    }
    Ok(value)
}

#[inline(never)]
fn parse_config(text: &str) -> Result<Config, PipelineError> {
    if text.len() > 96 {
        return Err(PipelineError::InvalidConfig);
    }
    let mut limit = None;
    let mut factor = None;
    for field in text.split(';') {
        let (name, raw) = field.split_once('=').ok_or(PipelineError::InvalidConfig)?;
        let value = parse_units(raw)?;
        if value == 0 {
            return Err(PipelineError::InvalidConfig);
        }
        let slot = match name {
            "limit" => &mut limit,
            "factor" => &mut factor,
            _ => return Err(PipelineError::InvalidConfig),
        };
        if slot.replace(value).is_some() {
            return Err(PipelineError::InvalidConfig);
        }
    }
    Ok(Config {
        limit: limit.ok_or(PipelineError::InvalidConfig)?,
        factor: factor.ok_or(PipelineError::InvalidConfig)?,
    })
}

#[inline(never)]
fn parse_command(text: &str) -> Result<Command, PipelineError> {
    if text.len() > 96 {
        return Err(PipelineError::UnknownCommand);
    }
    match text {
        "checkpoint" => Ok(Command::Checkpoint),
        "restore" => Ok(Command::Restore),
        _ => {
            let (name, raw) = text.split_once(':').ok_or(PipelineError::UnknownCommand)?;
            match name {
                "add" => Ok(Command::Add(parse_units(raw)?)),
                "remove" => Ok(Command::Remove(parse_units(raw)?)),
                _ => Err(PipelineError::UnknownCommand),
            }
        }
    }
}

#[inline(never)]
fn dispatch_operation(operation: &dyn Operation, total: i64, units: i64, factor: i64) -> i64 {
    operation.candidate(total, units, factor)
}

#[inline(never)]
fn apply_command(current: &mut State, config: &Config, command: Command) -> Result<(), PipelineError> {
    let next = match command {
        Command::Add(units) => {
            dispatch_operation(black_box(&Add as &dyn Operation), current.total, units, config.factor)
        }
        Command::Remove(units) => {
            dispatch_operation(black_box(&Remove as &dyn Operation), current.total, units, config.factor)
        }
        Command::Checkpoint => {
            current.checkpoint = Some(current.total);
            current.total
        }
        Command::Restore => current.checkpoint.ok_or(PipelineError::MissingCheckpoint)?,
    };
    if next < 0 || next > config.limit {
        return Err(PipelineError::OutOfRange);
    }
    current.total = next;
    current.applied += 1;
    Ok(())
}

#[inline(never)]
fn run_pipeline(text: &str, commands: &[String]) -> Result<State, PipelineError> {
    if commands.len() > 16 {
        return Err(PipelineError::TooManyCommands);
    }
    let config = parse_config(text)?;
    let mut current = State::default();
    for text in commands {
        let result = parse_command(text).and_then(|command| apply_command(&mut current, &config, command));
        if result.is_err() {
            current.rejected += 1;
        }
    }
    Ok(current)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (text, commands) = match args.next() {
        Some(text) => (text, args.take(17).collect::<Vec<_>>()),
        None => (
            String::from("limit=40;factor=3"),
            ["add:5", "checkpoint", "remove:2", "add:20", "restore", "remove:1", "unknown:2"]
                .iter()
                .map(|text| String::from(*text))
                .collect(),
        ),
    };
    match run_pipeline(&text, &commands) {
        Ok(current) => {
            black_box((current.total, current.checkpoint, current.applied, current.rejected));
        }
        Err(error) => {
            black_box(error);
        }
    }
}
