use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_agent::{Anthropic, Transport};
use rampage_eval::parity_agent::{AgentConfig, AgentRun, ModelSource, run_task};
use rampage_eval::parity_tasks::ParityTask;
use rmcp::model::ClientConfig;
use rmcp::{ClientHandler, ServiceExt};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct BenchClient;
impl ClientHandler for BenchClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct FixtureCopy {
    directory: PathBuf,
    path: PathBuf,
}
impl FixtureCopy {
    fn new(path: &Path, expected: &str) -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-parity-live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).map_err(|error| error.to_string())?;
        let copy = Self { path: directory.join("fixture.bin"), directory };
        std::fs::copy(path, &copy.path).map_err(|error| error.to_string())?;
        let bytes = std::fs::read(&copy.path).map_err(|error| error.to_string())?;
        if rampage_arch::hex::bytes(&Sha256::digest(&bytes)) != expected {
            return Err("prepared task fixture differs from its declared digest".into());
        }
        Ok(copy)
    }
}
impl Drop for FixtureCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub(super) fn run(task: &ParityTask, original: &Path, model: &str) -> Result<AgentRun, String> {
    let config = AgentConfig::new(model);
    let Some(transport) = Anthropic::from_environment() else {
        return Ok(AgentRun::without_provider(&config));
    };
    let copied = FixtureCopy::new(original, &task.fixture.sha256)?;
    run_prepared(task, &copied.path, transport, &config)
}

fn run_prepared<T: Transport + 'static>(
    task: &ParityTask,
    path: &Path,
    transport: T,
    config: &AgentConfig,
) -> Result<AgentRun, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let (server, client) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            rampage_mcp::RampageServer::default()
                .serve(server)
                .await
                .map_err(|error| error.to_string())?
                .waiting()
                .await
                .map_err(|error| error.to_string())
        });
        let client = BenchClient.serve(client).await.map_err(|error| error.to_string())?;
        let result = run_task(&client, Some(transport), ModelSource::Provider, task, path, config).await;
        client.cancel().await.map_err(|error| error.to_string())?;
        server.await.map_err(|error| error.to_string())??;
        Ok(result)
    })
}
