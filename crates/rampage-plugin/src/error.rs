use std::fmt;

use rampage_decompiler::worker::WorkerError;
use serde::{Deserialize, Serialize};

/// Static classifications only: guest, compiler, OS, and worker diagnostic text is never exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginError {
    Busy,
    Cancelled,
    Timeout,
    Configuration,
    UnsupportedPlatform,
    ComponentTooLarge,
    InputTooLarge,
    OutputTooLarge,
    InvalidInput,
    InvalidOutput,
    Protocol,
    Preflight,
    StructuralLimit,
    Abi,
    Compile,
    Fuel,
    ExecutionDeadline,
    Resource,
    Trap,
    Worker,
    Cleanup,
}

impl PluginError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Busy => "plugin_busy",
            Self::Cancelled => "plugin_cancelled",
            Self::Timeout => "plugin_timeout",
            Self::Configuration => "plugin_configuration",
            Self::UnsupportedPlatform => "plugin_unsupported_platform",
            Self::ComponentTooLarge => "plugin_component_too_large",
            Self::InputTooLarge => "plugin_input_too_large",
            Self::OutputTooLarge => "plugin_output_too_large",
            Self::InvalidInput => "plugin_invalid_input",
            Self::InvalidOutput => "plugin_invalid_output",
            Self::Protocol => "plugin_protocol",
            Self::Preflight => "plugin_preflight",
            Self::StructuralLimit => "plugin_structural_limit",
            Self::Abi => "plugin_abi",
            Self::Compile => "plugin_compile",
            Self::Fuel => "plugin_fuel",
            Self::ExecutionDeadline => "plugin_execution_deadline",
            Self::Resource => "plugin_resource",
            Self::Trap => "plugin_trap",
            Self::Worker => "plugin_worker",
            Self::Cleanup => "plugin_cleanup",
        }
    }

    pub(crate) fn from_wire_name(name: &str) -> Option<Self> {
        const ERRORS: &[PluginError] = &[
            PluginError::Busy,
            PluginError::Cancelled,
            PluginError::Timeout,
            PluginError::Configuration,
            PluginError::UnsupportedPlatform,
            PluginError::ComponentTooLarge,
            PluginError::InputTooLarge,
            PluginError::OutputTooLarge,
            PluginError::InvalidInput,
            PluginError::InvalidOutput,
            PluginError::Protocol,
            PluginError::Preflight,
            PluginError::StructuralLimit,
            PluginError::Abi,
            PluginError::Compile,
            PluginError::Fuel,
            PluginError::ExecutionDeadline,
            PluginError::Resource,
            PluginError::Trap,
            PluginError::Worker,
            PluginError::Cleanup,
        ];
        ERRORS.iter().copied().find(|error| error.code().strip_prefix("plugin_") == Some(name))
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PluginError {}

impl From<WorkerError> for PluginError {
    fn from(error: WorkerError) -> Self {
        match error {
            WorkerError::Cancelled => Self::Cancelled,
            WorkerError::Timeout => Self::Timeout,
            WorkerError::MemoryLimit { .. } => Self::Resource,
            WorkerError::OutputTooLarge { .. } => Self::OutputTooLarge,
            WorkerError::RequestTooLarge { .. } | WorkerError::Protocol(_) => Self::Protocol,
            WorkerError::Cleanup { .. } => Self::Cleanup,
            WorkerError::UnsupportedPlatform => Self::UnsupportedPlatform,
            WorkerError::Io { .. } | WorkerError::Exit { .. } | WorkerError::Decompile(_) => Self::Worker,
        }
    }
}
