use crate::crypto::sha256_hex;
use crate::json::{json_arr, json_bool, json_obj, json_str, stringify, JsonValue};
use crate::timestamp::now_rfc3339;

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub player_id: String,
    pub timestamp: String,
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

#[derive(Debug, Clone)]
pub struct SuspiciousProcess {
    pub pid: u64,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CheatMatch {
    pub pid: u64,
    pub name: String,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct CrossTrace {
    pub tracer_pid: u64,
    pub targets: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub pid: u64,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct ModuleChange {
    pub name: String,
    pub action: String,
}

#[derive(Debug, Clone)]
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
        Ok(bytes) => sha256_hex(&bytes),
        Err(_) => "no-config".to_string(),
    }
}

// builds a full scan report from all collected data in one scan cycle
// called at the end of each daemon loop iteration
// hostname and config_hash are read fresh each time
// timestamp is set to now (UTC) so server can check freshness
pub fn build_report(
    player_id: &str,
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
        player_id: player_id.to_string(),
        timestamp: now_rfc3339(),
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

// manually serializes a ScanReport to a json string
pub fn to_json(report: &ScanReport) -> String {
    let suspicious: Vec<JsonValue> = report
        .suspicious_processes
        .iter()
        .map(|p| {
            json_obj(vec![
                ("pid", JsonValue::Number(p.pid as f64)),
                ("name", json_str(&p.name)),
                ("reason", json_str(&p.reason)),
            ])
        })
        .collect();

    let cheats: Vec<JsonValue> = report
        .cheat_matches
        .iter()
        .map(|c| {
            json_obj(vec![
                ("pid", JsonValue::Number(c.pid as f64)),
                ("name", json_str(&c.name)),
                ("category", json_str(&c.category)),
                ("description", json_str(&c.description)),
            ])
        })
        .collect();

    let traces: Vec<JsonValue> = report
        .cross_traces
        .iter()
        .map(|t| {
            let targets: Vec<JsonValue> = t
                .targets
                .iter()
                .map(|&pid| JsonValue::Number(pid as f64))
                .collect();
            json_obj(vec![
                ("tracer_pid", JsonValue::Number(t.tracer_pid as f64)),
                ("targets", json_arr(targets)),
            ])
        })
        .collect();

    let connections: Vec<JsonValue> = report
        .network_connections
        .iter()
        .map(|c| {
            json_obj(vec![
                ("pid", JsonValue::Number(c.pid as f64)),
                ("address", json_str(&c.address)),
            ])
        })
        .collect();

    let modules: Vec<JsonValue> = report
        .module_changes
        .iter()
        .map(|m| {
            json_obj(vec![
                ("name", json_str(&m.name)),
                ("action", json_str(&m.action)),
            ])
        })
        .collect();

    let sandbox: Vec<JsonValue> = report
        .sandbox_detected
        .iter()
        .map(|s| json_str(s))
        .collect();

    let fi = &report.file_integrity;
    let integrity = json_obj(vec![
        ("status", json_str(&fi.status)),
        (
            "modified",
            json_arr(fi.modified.iter().map(|s| json_str(s)).collect()),
        ),
        (
            "added",
            json_arr(fi.added.iter().map(|s| json_str(s)).collect()),
        ),
        (
            "removed",
            json_arr(fi.removed.iter().map(|s| json_str(s)).collect()),
        ),
    ]);

    let obj = json_obj(vec![
        ("player_id", json_str(&report.player_id)),
        ("timestamp", json_str(&report.timestamp)),
        ("hostname", json_str(&report.hostname)),
        ("config_hash", json_str(&report.config_hash)),
        ("ebpf_active", json_bool(report.ebpf_active)),
        ("sandbox_detected", json_arr(sandbox)),
        ("suspicious_processes", json_arr(suspicious)),
        ("cheat_matches", json_arr(cheats)),
        ("cross_traces", json_arr(traces)),
        ("network_connections", json_arr(connections)),
        ("module_changes", json_arr(modules)),
        ("file_integrity", integrity),
    ]);

    stringify(&obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn report_to_json_empty() {
        let report = ScanReport {
            player_id: "test-player".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            hostname: "testhost".to_string(),
            config_hash: "abc123".to_string(),
            ebpf_active: false,
            sandbox_detected: vec![],
            suspicious_processes: vec![],
            cheat_matches: vec![],
            cross_traces: vec![],
            network_connections: vec![],
            module_changes: vec![],
            file_integrity: FileIntegrity {
                status: "ok".to_string(),
                modified: vec![],
                added: vec![],
                removed: vec![],
            },
        };

        let json = to_json(&report);
        let parsed = parse(&json).unwrap();

        assert_eq!(parsed.get("player_id").unwrap().as_str().unwrap(), "test-player");
        assert_eq!(parsed.get("hostname").unwrap().as_str().unwrap(), "testhost");
        assert_eq!(parsed.get("ebpf_active").unwrap().as_bool().unwrap(), false);
        assert_eq!(parsed.get("suspicious_processes").unwrap().as_array().unwrap().len(), 0);
    }

    #[test]
    fn report_to_json_with_data() {
        let report = ScanReport {
            player_id: "p1".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            hostname: "host".to_string(),
            config_hash: "hash".to_string(),
            ebpf_active: true,
            sandbox_detected: vec!["hypervisor".to_string()],
            suspicious_processes: vec![SuspiciousProcess {
                pid: 123,
                name: "hack".to_string(),
                reason: "cheat name".to_string(),
            }],
            cheat_matches: vec![CheatMatch {
                pid: 456,
                name: "aimbot".to_string(),
                category: "cheat".to_string(),
                description: "aim assist".to_string(),
            }],
            cross_traces: vec![CrossTrace {
                tracer_pid: 789,
                targets: vec![100, 200],
            }],
            network_connections: vec![NetworkConnection {
                pid: 123,
                address: "1.2.3.4:8080".to_string(),
            }],
            module_changes: vec![ModuleChange {
                name: "evil_mod".to_string(),
                action: "loaded".to_string(),
            }],
            file_integrity: FileIntegrity {
                status: "modified".to_string(),
                modified: vec!["game.dll".to_string()],
                added: vec![],
                removed: vec![],
            },
        };

        let json = to_json(&report);
        let parsed = parse(&json).unwrap();

        assert_eq!(parsed.get("ebpf_active").unwrap().as_bool().unwrap(), true);

        let procs = parsed.get("suspicious_processes").unwrap().as_array().unwrap();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].get("name").unwrap().as_str().unwrap(), "hack");

        let cheats = parsed.get("cheat_matches").unwrap().as_array().unwrap();
        assert_eq!(cheats[0].get("name").unwrap().as_str().unwrap(), "aimbot");

        let traces = parsed.get("cross_traces").unwrap().as_array().unwrap();
        let targets = traces[0].get("targets").unwrap().as_array().unwrap();
        assert_eq!(targets.len(), 2);

        let fi = parsed.get("file_integrity").unwrap();
        assert_eq!(fi.get("status").unwrap().as_str().unwrap(), "modified");
    }
}
