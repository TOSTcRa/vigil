use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::{check_admin, check_auth, create_token, hash_pw, verify_pw};
use crate::crypto::{sha256_hex, uuid_v4};
use crate::db::{self, MatchData, PlayerData};
use crate::http::{Request, Response};
use crate::json::{
    json_arr, json_bool, json_null, json_num, json_obj, json_str, parse, stringify, JsonValue,
};
use crate::router::Params;

// global data dir - set once at startup via init()
static DATA_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn init(dir: &str) {
    DATA_DIR.set(dir.to_string()).ok();
}

fn dir() -> &'static str {
    DATA_DIR.get().map(|s| s.as_str()).unwrap_or("data")
}

// current unix timestamp in seconds
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// format a unix timestamp as a minimal RFC3339 UTC string: "2024-01-15T10:30:00Z"
fn secs_to_rfc3339(secs: u64) -> String {
    // days since unix epoch
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    // gregorian calendar calculation
    // using algorithm from https://www.researchgate.net/publication/316558298
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

// parse RFC3339 UTC string back to unix seconds (minimal, handles "Z" suffix only)
fn rfc3339_to_secs(s: &str) -> Option<u64> {
    // expected: "2024-01-15T10:30:00Z" or "2024-01-15T10:30:00.000Z"
    let s = s.trim_end_matches('Z');
    // strip fractional seconds if present
    let s = if let Some(dot) = s.find('.') { &s[..dot] } else { s };
    if s.len() < 19 {
        return None;
    }
    let year: u64 = s[..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;

    // days since epoch using same algorithm in reverse (civil to days)
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let era = y / 400;
    let yoe = y % 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe;
    // subtract offset to get days since unix epoch
    let epoch_days = days.checked_sub(719468)?;
    Some(epoch_days * 86400 + hour * 3600 + min * 60 + sec)
}

// wraps data in {"success":true,"data":...,"error":null}
fn ok_response(data: JsonValue) -> Response {
    let body = stringify(&json_obj(vec![
        ("success", json_bool(true)),
        ("data", data),
        ("error", json_null()),
    ]));
    Response::json(body)
}

// wraps error in {"success":false,"data":null,"error":"msg"}
fn err_response(status: u16, msg: &str) -> Response {
    let body = stringify(&json_obj(vec![
        ("success", json_bool(false)),
        ("data", json_null()),
        ("error", json_str(msg)),
    ]));
    Response::new(status)
        .header("Content-Type", "application/json")
        .body(body)
}

fn player_to_json(p: &PlayerData) -> JsonValue {
    json_obj(vec![
        ("id", json_str(&p.id)),
        ("name", json_str(&p.name)),
        ("registered_at", json_str(&p.registered_at)),
        (
            "last_report",
            p.last_report.as_deref().map(json_str).unwrap_or_else(json_null),
        ),
        ("is_clean", json_bool(p.is_clean)),
        (
            "config_hash",
            p.config_hash.as_deref().map(json_str).unwrap_or_else(json_null),
        ),
    ])
}

fn match_to_json(m: &MatchData) -> JsonValue {
    let pids = json_arr(m.player_ids.iter().map(|s| json_str(s)).collect());
    json_obj(vec![
        ("id", json_str(&m.id)),
        ("created_at", json_str(&m.created_at)),
        (
            "ended_at",
            m.ended_at.as_deref().map(json_str).unwrap_or_else(json_null),
        ),
        ("player_ids", pids),
    ])
}

// GET /api/health
pub fn health(_req: &Request, _params: Params) -> Response {
    ok_response(json_obj(vec![
        ("status", json_str("ok")),
        ("service", json_str("vigil-server")),
    ]))
}

// POST /api/player/register - body: {"name":"..","password":".."}
pub fn register(req: &Request, _params: Params) -> Response {
    let v = match parse(&req.body) {
        Ok(v) => v,
        Err(_) => return err_response(400, "invalid json"),
    };

    let name = match v.get("name").and_then(|x| x.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return err_response(400, "name required"),
    };

    let password = match v.get("password").and_then(|x| x.as_str()) {
        Some(p) if p.len() >= 6 => p.to_string(),
        Some(_) => return err_response(400, "password min 6 chars"),
        None => return err_response(400, "password required"),
    };

    // check if name is taken
    match db::get_player_by_name(dir(), &name) {
        Ok(Some(_)) => return err_response(400, "player name already taken"),
        Err(e) => return err_response(500, &format!("db error: {}", e)),
        Ok(None) => {}
    }

    let id = uuid_v4();
    let now = secs_to_rfc3339(now_secs());
    let hash = hash_pw(&password);

    if let Err(e) = db::insert_player(dir(), &id, &name, &hash, &now) {
        return err_response(500, &format!("db error: {}", e));
    }

    let token = match create_token(&id) {
        Ok(t) => t,
        Err(e) => return err_response(500, &format!("token error: {}", e)),
    };

    ok_response(json_obj(vec![
        (
            "player",
            json_obj(vec![
                ("id", json_str(&id)),
                ("name", json_str(&name)),
                ("registered_at", json_str(&now)),
            ]),
        ),
        ("token", json_str(&token)),
    ]))
}

// POST /api/player/login - body: {"name":"..","password":".."}
pub fn login(req: &Request, _params: Params) -> Response {
    let v = match parse(&req.body) {
        Ok(v) => v,
        Err(_) => return err_response(400, "invalid json"),
    };

    let name = match v.get("name").and_then(|x| x.as_str()) {
        Some(n) => n.to_string(),
        None => return err_response(400, "name required"),
    };

    let password = match v.get("password").and_then(|x| x.as_str()) {
        Some(p) => p.to_string(),
        None => return err_response(400, "password required"),
    };

    let (player, hash) = match db::get_player_by_name(dir(), &name) {
        Ok(Some(pair)) => pair,
        Ok(None) => return err_response(401, "invalid credentials"),
        Err(e) => return err_response(500, &format!("db error: {}", e)),
    };

    if !verify_pw(&password, &hash) {
        return err_response(401, "invalid credentials");
    }

    let token = match create_token(&player.id) {
        Ok(t) => t,
        Err(e) => return err_response(500, &format!("token error: {}", e)),
    };

    ok_response(json_obj(vec![
        ("player", player_to_json(&player)),
        ("token", json_str(&token)),
    ]))
}

// GET /api/player/{id} - requires JWT auth
pub fn get_player(req: &Request, params: Params) -> Response {
    if let Err(code) = check_auth(req) {
        return err_response(code, "unauthorized");
    }

    let id = match params.get("id") {
        Some(id) => id.to_string(),
        None => return err_response(400, "missing id"),
    };

    match db::get_player(dir(), &id) {
        Ok(Some(p)) => ok_response(player_to_json(&p)),
        Ok(None) => err_response(404, "player not found"),
        Err(e) => err_response(500, &format!("db error: {}", e)),
    }
}

// GET /api/player/{id}/status - requires JWT auth
pub fn player_status(req: &Request, params: Params) -> Response {
    if let Err(code) = check_auth(req) {
        return err_response(code, "unauthorized");
    }

    let id = match params.get("id") {
        Some(id) => id.to_string(),
        None => return err_response(400, "missing id"),
    };

    let player = match db::get_player(dir(), &id) {
        Ok(Some(p)) => p,
        Ok(None) => return err_response(404, "player not found"),
        Err(e) => return err_response(500, &format!("db error: {}", e)),
    };

    // check if last report is within 30 seconds of now
    let verified = player
        .last_report
        .as_deref()
        .and_then(rfc3339_to_secs)
        .map(|t| now_secs().saturating_sub(t) < 30)
        .unwrap_or(false);

    let expected_hash = match db::get_config(dir(), "expected_config_hash") {
        Ok(h) => h,
        Err(e) => return err_response(500, &format!("db error: {}", e)),
    };

    let config_hash_match = match (&player.config_hash, &expected_hash) {
        (Some(ph), Some(eh)) => ph == eh,
        _ => false,
    };

    ok_response(json_obj(vec![
        ("player_id", json_str(&player.id)),
        ("player_name", json_str(&player.name)),
        ("verified", json_bool(verified)),
        ("is_clean", json_bool(player.is_clean)),
        (
            "last_report",
            player.last_report.as_deref().map(json_str).unwrap_or_else(json_null),
        ),
        ("config_hash_match", json_bool(config_hash_match)),
    ]))
}

// POST /api/report - requires JWT auth, body is full ScanReport JSON
pub fn receive_report(req: &Request, _params: Params) -> Response {
    if let Err(code) = check_auth(req) {
        return err_response(code, "unauthorized");
    }

    let v = match parse(&req.body) {
        Ok(v) => v,
        Err(_) => return err_response(400, "invalid json"),
    };

    let player_id = match v.get("player_id").and_then(|x| x.as_str()) {
        Some(id) => id.to_string(),
        None => return err_response(400, "missing player_id"),
    };

    let timestamp = match v.get("timestamp").and_then(|x| x.as_str()) {
        Some(t) => t.to_string(),
        None => secs_to_rfc3339(now_secs()),
    };

    let config_hash = v
        .get("config_hash")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    // determine if player is clean from this report
    let suspicious_empty = v
        .get("suspicious_processes")
        .and_then(|x| x.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(true);

    let cheats_empty = v
        .get("cheat_matches")
        .and_then(|x| x.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(true);

    let sandbox_empty = v
        .get("sandbox_detected")
        .and_then(|x| x.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(true);

    let file_ok = v
        .get("file_integrity")
        .and_then(|fi| fi.get("status"))
        .and_then(|x| x.as_str())
        .map(|s| s == "ok")
        .unwrap_or(true);

    let is_clean = suspicious_empty && cheats_empty && sandbox_empty && file_ok;

    match db::update_player_report(dir(), &player_id, &timestamp, is_clean, &config_hash) {
        Ok(false) => return err_response(400, "player not registered"),
        Err(e) => return err_response(500, &format!("db error: {}", e)),
        Ok(true) => {}
    }

    // if config hash doesn't match expected, mark player dirty
    if let Ok(Some(expected)) = db::get_config(dir(), "expected_config_hash") {
        if config_hash != expected {
            let _ = db::mark_player_dirty(dir(), &player_id);
        }
    }

    // store the raw report
    if let Err(e) = db::insert_report(dir(), &player_id, &timestamp, &req.body) {
        return err_response(500, &format!("db error: {}", e));
    }

    ok_response(json_str("report received"))
}

// POST /api/match - requires JWT auth, body: {"player_ids":["uuid",..]}
pub fn create_match(req: &Request, _params: Params) -> Response {
    if let Err(code) = check_auth(req) {
        return err_response(code, "unauthorized");
    }

    let v = match parse(&req.body) {
        Ok(v) => v,
        Err(_) => return err_response(400, "invalid json"),
    };

    let player_ids: Vec<String> = v
        .get("player_ids")
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_default();

    if player_ids.is_empty() {
        return err_response(400, "player_ids required");
    }

    let id = uuid_v4();
    let now = secs_to_rfc3339(now_secs());

    if let Err(e) = db::insert_match(dir(), &id, &now, &player_ids) {
        return err_response(500, &format!("db error: {}", e));
    }

    let m = MatchData {
        id,
        created_at: now,
        ended_at: None,
        player_ids,
    };

    ok_response(match_to_json(&m))
}

// POST /api/match/end - requires JWT auth, body: {"match_id":"uuid"}
pub fn end_match_handler(req: &Request, _params: Params) -> Response {
    if let Err(code) = check_auth(req) {
        return err_response(code, "unauthorized");
    }

    let v = match parse(&req.body) {
        Ok(v) => v,
        Err(_) => return err_response(400, "invalid json"),
    };

    let match_id = match v.get("match_id").and_then(|x| x.as_str()) {
        Some(id) => id.to_string(),
        None => return err_response(400, "match_id required"),
    };

    let now = secs_to_rfc3339(now_secs());

    match db::end_match(dir(), &match_id, &now) {
        Ok(false) => err_response(404, "match not found"),
        Err(e) => err_response(500, &format!("db error: {}", e)),
        Ok(true) => ok_response(json_str("match ended")),
    }
}

// GET /api/match/{id}/integrity - requires JWT auth
pub fn match_integrity(req: &Request, params: Params) -> Response {
    if let Err(code) = check_auth(req) {
        return err_response(code, "unauthorized");
    }

    let match_id = match params.get("id") {
        Some(id) => id.to_string(),
        None => return err_response(400, "missing id"),
    };

    let m = match db::get_match(dir(), &match_id) {
        Ok(Some(m)) => m,
        Ok(None) => return err_response(404, "match not found"),
        Err(e) => return err_response(500, &format!("db error: {}", e)),
    };

    let start = &m.created_at;
    // use ended_at or current time as end bound
    let end_owned;
    let end: &str = match &m.ended_at {
        Some(t) => t.as_str(),
        None => {
            end_owned = secs_to_rfc3339(now_secs());
            &end_owned
        }
    };

    let mut player_statuses = Vec::new();
    let mut all_clean = true;

    for pid in &m.player_ids {
        let player_name = match db::get_player(dir(), pid) {
            Ok(Some(p)) => p.name,
            _ => "unknown".to_string(),
        };

        let report_jsons = match db::get_reports_in_range(dir(), pid, start, end) {
            Ok(r) => r,
            Err(e) => return err_response(500, &format!("db error: {}", e)),
        };

        let mut violations: Vec<JsonValue> = Vec::new();
        let mut is_clean = true;

        for raw in &report_jsons {
            if let Ok(r) = parse(raw) {
                // check suspicious_processes
                if let Some(arr) = r.get("suspicious_processes").and_then(|x| x.as_array()) {
                    for sp in arr {
                        let name = sp.get("name").and_then(|x| x.as_str()).unwrap_or("unknown");
                        let reason = sp.get("reason").and_then(|x| x.as_str()).unwrap_or("");
                        violations.push(json_str(&format!("suspicious process: {} ({})", name, reason)));
                        is_clean = false;
                    }
                }

                // check cheat_matches
                if let Some(arr) = r.get("cheat_matches").and_then(|x| x.as_array()) {
                    for cm in arr {
                        let name = cm.get("name").and_then(|x| x.as_str()).unwrap_or("unknown");
                        let cat = cm.get("category").and_then(|x| x.as_str()).unwrap_or("");
                        violations.push(json_str(&format!("cheat detected: {} [{}]", name, cat)));
                        is_clean = false;
                    }
                }

                // check sandbox_detected
                if let Some(arr) = r.get("sandbox_detected").and_then(|x| x.as_array()) {
                    if !arr.is_empty() {
                        let items: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
                        violations.push(json_str(&format!("sandbox: {:?}", items)));
                        is_clean = false;
                    }
                }

                // check file_integrity
                if let Some(fi) = r.get("file_integrity") {
                    let status = fi.get("status").and_then(|x| x.as_str()).unwrap_or("ok");
                    if status != "ok" {
                        let modified = fi.get("modified").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
                        let added = fi.get("added").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
                        let removed = fi.get("removed").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
                        violations.push(json_str(&format!(
                            "file integrity: {} modified, {} added, {} removed",
                            modified, added, removed
                        )));
                        is_clean = false;
                    }
                }
            }
        }

        if report_jsons.is_empty() {
            violations.push(json_str("no reports received during match"));
            is_clean = false;
        }

        if !is_clean {
            all_clean = false;
        }

        player_statuses.push(json_obj(vec![
            ("player_id", json_str(pid)),
            ("player_name", json_str(&player_name)),
            ("reports_during_match", json_num(report_jsons.len() as f64)),
            ("is_clean", json_bool(is_clean)),
            ("violations", json_arr(violations)),
        ]));
    }

    ok_response(json_obj(vec![
        ("match_id", json_str(&match_id)),
        ("players", json_arr(player_statuses)),
        ("all_clean", json_bool(all_clean)),
    ]))
}

// POST /api/admin/config - requires admin key, body is raw config text
pub fn set_config(req: &Request, _params: Params) -> Response {
    if let Err(code) = check_admin(req) {
        return err_response(code, "forbidden");
    }

    let hash = sha256_hex(req.body.as_bytes());

    if let Err(e) = db::set_config(dir(), "expected_config_hash", &hash) {
        return err_response(500, &format!("db error: {}", e));
    }

    ok_response(json_obj(vec![("config_hash", json_str(&hash))]))
}

// GET /api/players - requires admin key
pub fn list_players_handler(req: &Request, _params: Params) -> Response {
    if let Err(code) = check_admin(req) {
        return err_response(code, "forbidden");
    }

    match db::list_players(dir()) {
        Ok(players) => {
            let arr = json_arr(players.iter().map(player_to_json).collect());
            ok_response(arr)
        }
        Err(e) => err_response(500, &format!("db error: {}", e)),
    }
}

// GET /api/matches - requires admin key
pub fn list_matches_handler(req: &Request, _params: Params) -> Response {
    if let Err(code) = check_admin(req) {
        return err_response(code, "forbidden");
    }

    match db::list_matches(dir()) {
        Ok(matches) => {
            let arr = json_arr(matches.iter().map(match_to_json).collect());
            ok_response(arr)
        }
        Err(e) => err_response(500, &format!("db error: {}", e)),
    }
}
