use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub player_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub config_hash: String,
    pub ebpf_active: bool,
    pub sandbox_detected: Vec<String>,
    pub suspicious_processes: Vec<SuspiciousProcess>,
    pub cheat_matches: Vec<CheatMatch>,
    pub cross_traces: Vec<CrossTrace>,
    pub network_connections: Vec<NetworkConnection>,
    pub module_changes: Vec<ModuleChange>,
    pub file_integrity: FileIntegrity,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousProcess {
    pub pid: u64,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheatMatch {
    pub pid: u64,
    pub name: String,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrossTrace {
    pub tracer_pid: u64,
    pub targets: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkConnection {
    pub pid: u64,
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleChange {
    pub name: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileIntegrity {
    pub status: String,
    pub modified: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

// reads /etc/hostname for the machine name
// falls back to "unknown" if the file cant be read
pub fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

// computes sha256 hash of /etc/vigil/config.toml
// used by server to verify all players run the same config
// returns "no-config" if config file doesnt exist
pub fn hash_config() -> String {
    match std::fs::read("/etc/vigil/config.toml") {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            format!("{:x}", hasher.finalize())
        }
        Err(_) => "no-config".to_string(),
    }
}

// builds a full scan report from all collected data in one scan cycle
// called at the end of each daemon loop iteration
// hostname and config_hash are read fresh each time
// timestamp is set to now (UTC) so server can check freshness
pub fn build_report(
    player_id: Uuid,
    ebpf_active: bool,
    sandbox: &[String],
    suspicious: Vec<SuspiciousProcess>,
    cheats: Vec<CheatMatch>,
    traces: Vec<CrossTrace>,
    connections: Vec<NetworkConnection>,
    modules: Vec<ModuleChange>,
    integrity: FileIntegrity,
) -> ScanReport {
    ScanReport {
        player_id,
        timestamp: Utc::now(),
        hostname: get_hostname(),
        config_hash: hash_config(),
        ebpf_active,
        sandbox_detected: sandbox.to_vec(),
        suspicious_processes: suspicious,
        cheat_matches: cheats,
        cross_traces: traces,
        network_connections: connections,
        module_changes: modules,
        file_integrity: integrity,
    }
}
