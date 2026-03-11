use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousProcess {
    pub pid: u64,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheatMatch {
    pub pid: u64,
    pub name: String,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossTrace {
    pub tracer_pid: u64,
    pub targets: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub pid: u64,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleChange {
    pub name: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrity {
    pub status: String,
    pub modified: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Player {
    pub id: Uuid,
    pub name: String,
    pub registered_at: DateTime<Utc>,
    pub last_report: Option<DateTime<Utc>>,
    pub is_clean: bool,
    pub config_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub player_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchIntegrity {
    pub match_id: Uuid,
    pub players: Vec<PlayerMatchStatus>,
    pub all_clean: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerMatchStatus {
    pub player_id: Uuid,
    pub player_name: String,
    pub reports_during_match: usize,
    pub is_clean: bool,
    pub violations: Vec<String>,
}

#[derive(Deserialize)]
pub struct RegisterPlayer {
    pub name: String,
}

#[derive(Deserialize)]
pub struct CreateMatch {
    pub player_ids: Vec<Uuid>,
}

#[derive(Deserialize)]
pub struct EndMatch {
    pub match_id: Uuid,
}

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }
}

fn api_error<T: Serialize>(msg: &str) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }),
    )
}

#[derive(Default)]
pub struct AppState {
    players: Mutex<HashMap<Uuid, Player>>,
    reports: Mutex<Vec<ScanReport>>,
    matches: Mutex<HashMap<Uuid, Match>>,
    expected_config_hash: Mutex<Option<String>>,
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok", "service": "vigil-server"}))
}

// registers a new player with a generated uuid
// stores in memory — resets on server restart
async fn register_player(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterPlayer>,
) -> impl IntoResponse {
    let player = Player {
        id: Uuid::new_v4(),
        name: req.name,
        registered_at: Utc::now(),
        last_report: None,
        is_clean: true,
        config_hash: None,
    };
    let id = player.id;
    state.players.lock().unwrap().insert(id, player.clone());
    ApiResponse::ok(player)
}

// returns full player data by uuid
async fn get_player(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<Player>>)> {
    let players = state.players.lock().unwrap();
    match players.get(&id) {
        Some(p) => Ok(ApiResponse::ok(p.clone())),
        None => Err(api_error("player not found")),
    }
}

// checks if player is verified (last report within 30 seconds)
// also checks if their config hash matches the expected one
// used by match servers to verify players are running vigil
async fn player_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<serde_json::Value>>)> {
    let players = state.players.lock().unwrap();
    match players.get(&id) {
        Some(p) => {
            let verified = p.last_report.map_or(false, |t| {
                Utc::now().signed_duration_since(t).num_seconds() < 30
            });
            Ok(ApiResponse::ok(serde_json::json!({
                "player_id": p.id,
                "player_name": p.name,
                "verified": verified,
                "is_clean": p.is_clean,
                "last_report": p.last_report,
                "config_hash_match": match (&p.config_hash, &*state.expected_config_hash.lock().unwrap()) {
                    (Some(ph), Some(eh)) => ph == eh,
                    _ => false,
                },
            })))
        }
        None => Err(api_error("player not found")),
    }
}

// receives a scan report from vigil client
// updates player last_report timestamp and clean status
// player is clean if: no suspicious processes, no cheat matches, no sandbox, files ok
// also validates config hash against expected (set by admin) — mismatch = not clean
async fn receive_report(
    State(state): State<Arc<AppState>>,
    Json(report): Json<ScanReport>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<String>>)> {
    let is_clean = report.suspicious_processes.is_empty()
        && report.cheat_matches.is_empty()
        && report.sandbox_detected.is_empty()
        && report.file_integrity.status == "ok";

    {
        let mut players = state.players.lock().unwrap();
        if let Some(player) = players.get_mut(&report.player_id) {
            player.last_report = Some(report.timestamp);
            player.is_clean = is_clean;
            player.config_hash = Some(report.config_hash.clone());
        } else {
            return Err(api_error("player not registered"));
        }
    }

    {
        let expected = state.expected_config_hash.lock().unwrap();
        if let Some(ref expected_hash) = *expected {
            if report.config_hash != *expected_hash {
                let mut players = state.players.lock().unwrap();
                if let Some(player) = players.get_mut(&report.player_id) {
                    player.is_clean = false;
                }
            }
        }
    }

    state.reports.lock().unwrap().push(report);

    Ok(ApiResponse::ok("report received".to_string()))
}

// creates a match with a list of player uuids
// match gets a generated uuid and timestamp
async fn create_match(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateMatch>,
) -> impl IntoResponse {
    let m = Match {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        ended_at: None,
        player_ids: req.player_ids,
    };
    let id = m.id;
    state.matches.lock().unwrap().insert(id, m.clone());
    ApiResponse::ok(m)
}

// marks a match as ended with current timestamp
async fn end_match(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EndMatch>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<Match>>)> {
    let mut matches = state.matches.lock().unwrap();
    match matches.get_mut(&req.match_id) {
        Some(m) => {
            m.ended_at = Some(Utc::now());
            Ok(ApiResponse::ok(m.clone()))
        }
        None => Err(api_error("match not found")),
    }
}

// aggregates all player reports during a match timeframe
// for each player: counts reports, collects violations (cheats, sandbox, file changes)
// player with no reports during match = violation (not running vigil)
// returns per-player status + overall all_clean flag
async fn match_integrity(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<MatchIntegrity>>)> {
    let matches = state.matches.lock().unwrap();
    let m = match matches.get(&id) {
        Some(m) => m.clone(),
        None => return Err(api_error("match not found")),
    };
    drop(matches);

    let reports = state.reports.lock().unwrap();
    let players = state.players.lock().unwrap();

    let match_start = m.created_at;
    let match_end = m.ended_at.unwrap_or_else(Utc::now);

    let mut player_statuses = vec![];
    let mut all_clean = true;

    for &pid in &m.player_ids {
        let player_name = players
            .get(&pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let player_reports: Vec<&ScanReport> = reports
            .iter()
            .filter(|r| {
                r.player_id == pid && r.timestamp >= match_start && r.timestamp <= match_end
            })
            .collect();

        let mut violations = vec![];
        let mut is_clean = true;

        for r in &player_reports {
            for sp in &r.suspicious_processes {
                violations.push(format!("suspicious process: {} ({})", sp.name, sp.reason));
                is_clean = false;
            }
            for cm in &r.cheat_matches {
                violations.push(format!("cheat detected: {} [{}]", cm.name, cm.category));
                is_clean = false;
            }
            if !r.sandbox_detected.is_empty() {
                violations.push(format!("sandbox: {:?}", r.sandbox_detected));
                is_clean = false;
            }
            if r.file_integrity.status != "ok" {
                violations.push(format!(
                    "file integrity: {} modified, {} added, {} removed",
                    r.file_integrity.modified.len(),
                    r.file_integrity.added.len(),
                    r.file_integrity.removed.len()
                ));
                is_clean = false;
            }
        }

        if player_reports.is_empty() {
            violations.push("no reports received during match".to_string());
            is_clean = false;
        }

        if !is_clean {
            all_clean = false;
        }

        player_statuses.push(PlayerMatchStatus {
            player_id: pid,
            player_name,
            reports_during_match: player_reports.len(),
            is_clean,
            violations,
        });
    }

    Ok(ApiResponse::ok(MatchIntegrity {
        match_id: id,
        players: player_statuses,
        all_clean,
    }))
}

// sets the expected config hash for all players
// takes raw config content, hashes it with sha256
// reports with different config_hash will mark player as not clean
async fn set_expected_config(
    State(state): State<Arc<AppState>>,
    body: String,
) -> impl IntoResponse {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    *state.expected_config_hash.lock().unwrap() = Some(hash.clone());
    ApiResponse::ok(serde_json::json!({"config_hash": hash}))
}

async fn list_players(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let players = state.players.lock().unwrap();
    let res: Vec<Player> = players.values().cloned().collect();
    ApiResponse::ok(res)
}

async fn list_matches(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let matches = state.matches.lock().unwrap();
    let res: Vec<Match> = matches.values().cloned().collect();
    ApiResponse::ok(res)
}

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState::default());

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/player/register", post(register_player))
        .route("/api/player/{id}", get(get_player))
        .route("/api/player/{id}/status", get(player_status))
        .route("/api/players", get(list_players))
        .route("/api/report", post(receive_report))
        .route("/api/match", post(create_match))
        .route("/api/match/end", post(end_match))
        .route("/api/match/{id}/integrity", get(match_integrity))
        .route("/api/matches", get(list_matches))
        .route("/api/admin/config", post(set_expected_config))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    println!("Vigil server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
