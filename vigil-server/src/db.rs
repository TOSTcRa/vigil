use std::fs;
use std::io;
use std::path::PathBuf;

use crate::json::{
    json_arr, json_bool, json_null, json_obj, json_str, parse, stringify, JsonValue,
};

// player record returned by get_player / list_players
pub struct PlayerData {
    pub id: String,
    pub name: String,
    pub registered_at: String,
    pub last_report: Option<String>,
    pub is_clean: bool,
    pub config_hash: Option<String>,
}

// match record returned by get_match / list_matches
pub struct MatchData {
    pub id: String,
    pub created_at: String,
    pub ended_at: Option<String>,
    pub player_ids: Vec<String>,
}

// create all subdirectories under data_dir
pub fn init_db(data_dir: &str) {
    for sub in &["players", "reports", "matches"] {
        let p = PathBuf::from(data_dir).join(sub);
        fs::create_dir_all(&p).expect("failed to create data directory");
    }
}

// ---- helpers ----

fn player_path(data_dir: &str, id: &str) -> PathBuf {
    PathBuf::from(data_dir).join("players").join(format!("{}.json", id))
}

fn match_path(data_dir: &str, id: &str) -> PathBuf {
    PathBuf::from(data_dir).join("matches").join(format!("{}.json", id))
}

fn config_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("config.json")
}

// read a file, return None if it doesn't exist
fn read_file(path: &PathBuf) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {}: {}", path.display(), e)),
    }
}

// write a file atomically via a temp file + rename
fn write_file(path: &PathBuf, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents).map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {}", path.display(), e))
}

// list all .json files in a directory, return their contents
fn read_dir_jsons(dir: PathBuf) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let rd = match fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("read_dir {}: {}", dir.display(), e)),
    };
    for entry in rd {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Some(s) = read_file(&path)? {
                out.push(s);
            }
        }
    }
    Ok(out)
}

// deserialize a player from a JsonValue
fn player_from_json(v: &JsonValue) -> Result<PlayerData, String> {
    let id = v.get("id").and_then(|x| x.as_str()).ok_or("missing id")?.to_string();
    let name = v.get("name").and_then(|x| x.as_str()).ok_or("missing name")?.to_string();
    let registered_at = v.get("registered_at").and_then(|x| x.as_str()).ok_or("missing registered_at")?.to_string();
    let last_report = v.get("last_report").and_then(|x| x.as_str()).map(|s| s.to_string());
    let is_clean = v.get("is_clean").and_then(|x| x.as_bool()).unwrap_or(true);
    let config_hash = v.get("config_hash").and_then(|x| x.as_str()).map(|s| s.to_string());
    Ok(PlayerData { id, name, registered_at, last_report, is_clean, config_hash })
}

// serialize a player to a JsonValue (includes password_hash for internal storage)
fn player_to_json(p: &PlayerData, password_hash: &str) -> JsonValue {
    json_obj(vec![
        ("id", json_str(&p.id)),
        ("name", json_str(&p.name)),
        ("password_hash", json_str(password_hash)),
        ("registered_at", json_str(&p.registered_at)),
        ("last_report", p.last_report.as_deref().map(json_str).unwrap_or_else(json_null)),
        ("is_clean", json_bool(p.is_clean)),
        ("config_hash", p.config_hash.as_deref().map(json_str).unwrap_or_else(json_null)),
    ])
}

fn match_from_json(v: &JsonValue) -> Result<MatchData, String> {
    let id = v.get("id").and_then(|x| x.as_str()).ok_or("missing id")?.to_string();
    let created_at = v.get("created_at").and_then(|x| x.as_str()).ok_or("missing created_at")?.to_string();
    let ended_at = v.get("ended_at").and_then(|x| x.as_str()).map(|s| s.to_string());
    let player_ids = v
        .get("player_ids")
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_default();
    Ok(MatchData { id, created_at, ended_at, player_ids })
}

fn match_to_json(m: &MatchData) -> JsonValue {
    let pids = json_arr(m.player_ids.iter().map(|s| json_str(s)).collect());
    json_obj(vec![
        ("id", json_str(&m.id)),
        ("created_at", json_str(&m.created_at)),
        ("ended_at", m.ended_at.as_deref().map(json_str).unwrap_or_else(json_null)),
        ("player_ids", pids),
    ])
}

// ---- player operations ----

pub fn insert_player(
    data_dir: &str,
    id: &str,
    name: &str,
    password_hash: &str,
    registered_at: &str,
) -> Result<(), String> {
    let path = player_path(data_dir, id);
    if read_file(&path)?.is_some() {
        return Err(format!("player {} already exists", id));
    }
    let p = PlayerData {
        id: id.to_string(),
        name: name.to_string(),
        registered_at: registered_at.to_string(),
        last_report: None,
        is_clean: true,
        config_hash: None,
    };
    let json = stringify(&player_to_json(&p, password_hash));
    write_file(&path, &json)
}

pub fn get_player(data_dir: &str, id: &str) -> Result<Option<PlayerData>, String> {
    let path = player_path(data_dir, id);
    match read_file(&path)? {
        None => Ok(None),
        Some(s) => {
            let v = parse(&s).map_err(|e| format!("parse player {}: {}", id, e))?;
            Ok(Some(player_from_json(&v)?))
        }
    }
}

// returns (PlayerData, password_hash) - scans all player files
pub fn get_player_by_name(data_dir: &str, name: &str) -> Result<Option<(PlayerData, String)>, String> {
    let dir = PathBuf::from(data_dir).join("players");
    let contents = read_dir_jsons(dir)?;
    for s in contents {
        let v = parse(&s).map_err(|e| format!("parse player file: {}", e))?;
        if v.get("name").and_then(|x| x.as_str()) == Some(name) {
            let hash = v.get("password_hash").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let p = player_from_json(&v)?;
            return Ok(Some((p, hash)));
        }
    }
    Ok(None)
}

pub fn list_players(data_dir: &str) -> Result<Vec<PlayerData>, String> {
    let dir = PathBuf::from(data_dir).join("players");
    let contents = read_dir_jsons(dir)?;
    let mut out = Vec::new();
    for s in contents {
        let v = parse(&s).map_err(|e| format!("parse player file: {}", e))?;
        out.push(player_from_json(&v)?);
    }
    Ok(out)
}

// updates last_report, is_clean, config_hash; returns false if player not found
pub fn update_player_report(
    data_dir: &str,
    id: &str,
    last_report: &str,
    is_clean: bool,
    config_hash: &str,
) -> Result<bool, String> {
    let path = player_path(data_dir, id);
    let s = match read_file(&path)? {
        None => return Ok(false),
        Some(s) => s,
    };
    let v = parse(&s).map_err(|e| format!("parse player {}: {}", id, e))?;
    let hash = v.get("password_hash").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut p = player_from_json(&v)?;
    p.last_report = Some(last_report.to_string());
    p.is_clean = is_clean;
    p.config_hash = Some(config_hash.to_string());
    write_file(&path, &stringify(&player_to_json(&p, &hash)))?;
    Ok(true)
}

pub fn mark_player_dirty(data_dir: &str, id: &str) -> Result<(), String> {
    let path = player_path(data_dir, id);
    let s = match read_file(&path)? {
        None => return Err(format!("player {} not found", id)),
        Some(s) => s,
    };
    let v = parse(&s).map_err(|e| format!("parse player {}: {}", id, e))?;
    let hash = v.get("password_hash").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut p = player_from_json(&v)?;
    p.is_clean = false;
    write_file(&path, &stringify(&player_to_json(&p, &hash)))
}

// ---- report operations ----

pub fn insert_report(data_dir: &str, player_id: &str, timestamp: &str, data: &str) -> Result<(), String> {
    // sanitize timestamp for use as filename component
    let ts_safe = timestamp.replace(':', "-").replace('+', "p");
    let filename = format!("{}_{}.json", player_id, ts_safe);
    let path = PathBuf::from(data_dir).join("reports").join(filename);
    let v = json_obj(vec![
        ("player_id", json_str(player_id)),
        ("timestamp", json_str(timestamp)),
        ("data", json_str(data)),
    ]);
    write_file(&path, &stringify(&v))
}

// returns report data strings for a player within [start, end] inclusive
// timestamps are rfc3339 - lexicographic comparison is correct
pub fn get_reports_in_range(
    data_dir: &str,
    player_id: &str,
    start: &str,
    end: &str,
) -> Result<Vec<String>, String> {
    let dir = PathBuf::from(data_dir).join("reports");
    let contents = read_dir_jsons(dir)?;
    let mut out = Vec::new();
    for s in contents {
        let v = parse(&s).map_err(|e| format!("parse report: {}", e))?;
        let pid = v.get("player_id").and_then(|x| x.as_str()).unwrap_or("");
        if pid != player_id {
            continue;
        }
        let ts = v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
        if ts >= start && ts <= end {
            if let Some(d) = v.get("data").and_then(|x| x.as_str()) {
                out.push(d.to_string());
            }
        }
    }
    Ok(out)
}

// ---- match operations ----

pub fn insert_match(data_dir: &str, id: &str, created_at: &str, player_ids: &[String]) -> Result<(), String> {
    let path = match_path(data_dir, id);
    if read_file(&path)?.is_some() {
        return Err(format!("match {} already exists", id));
    }
    let m = MatchData {
        id: id.to_string(),
        created_at: created_at.to_string(),
        ended_at: None,
        player_ids: player_ids.to_vec(),
    };
    write_file(&path, &stringify(&match_to_json(&m)))
}

pub fn get_match(data_dir: &str, id: &str) -> Result<Option<MatchData>, String> {
    let path = match_path(data_dir, id);
    match read_file(&path)? {
        None => Ok(None),
        Some(s) => {
            let v = parse(&s).map_err(|e| format!("parse match {}: {}", id, e))?;
            Ok(Some(match_from_json(&v)?))
        }
    }
}

// sets ended_at; returns false if match not found
pub fn end_match(data_dir: &str, id: &str, ended_at: &str) -> Result<bool, String> {
    let path = match_path(data_dir, id);
    let s = match read_file(&path)? {
        None => return Ok(false),
        Some(s) => s,
    };
    let v = parse(&s).map_err(|e| format!("parse match {}: {}", id, e))?;
    let mut m = match_from_json(&v)?;
    m.ended_at = Some(ended_at.to_string());
    write_file(&path, &stringify(&match_to_json(&m)))?;
    Ok(true)
}

pub fn list_matches(data_dir: &str) -> Result<Vec<MatchData>, String> {
    let dir = PathBuf::from(data_dir).join("matches");
    let contents = read_dir_jsons(dir)?;
    let mut out = Vec::new();
    for s in contents {
        let v = parse(&s).map_err(|e| format!("parse match file: {}", e))?;
        out.push(match_from_json(&v)?);
    }
    Ok(out)
}

// ---- config operations ----

// load config.json as a vec of pairs, or empty vec if missing
fn load_config(data_dir: &str) -> Result<Vec<(String, String)>, String> {
    let path = config_path(data_dir);
    let s = match read_file(&path)? {
        None => return Ok(vec![]),
        Some(s) => s,
    };
    let v = parse(&s).map_err(|e| format!("parse config: {}", e))?;
    let pairs = v.as_object().ok_or("config is not an object")?;
    Ok(pairs
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect())
}

fn save_config(data_dir: &str, pairs: &[(String, String)]) -> Result<(), String> {
    let path = config_path(data_dir);
    let v = JsonValue::Object(
        pairs.iter().map(|(k, v)| (k.clone(), json_str(v))).collect(),
    );
    write_file(&path, &stringify(&v))
}

pub fn get_config(data_dir: &str, key: &str) -> Result<Option<String>, String> {
    let pairs = load_config(data_dir)?;
    Ok(pairs.into_iter().find(|(k, _)| k == key).map(|(_, v)| v))
}

pub fn set_config(data_dir: &str, key: &str, value: &str) -> Result<(), String> {
    let mut pairs = load_config(data_dir)?;
    if let Some(entry) = pairs.iter_mut().find(|(k, _)| k == key) {
        entry.1 = value.to_string();
    } else {
        pairs.push((key.to_string(), value.to_string()));
    }
    save_config(data_dir, &pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Creates a unique temp directory for a test and returns its path as a String.
    /// Uses process id + a caller-provided label to avoid collisions.
    fn tmp_dir(label: &str) -> String {
        let dir = std::env::temp_dir()
            .join(format!("vigil_db_test_{}_{}", std::process::id(), label));
        // clean up any leftover from a previous failed run
        let _ = fs::remove_dir_all(&dir);
        dir.to_string_lossy().to_string()
    }

    /// Removes the temp directory after a test.
    fn cleanup(dir: &str) {
        let _ = fs::remove_dir_all(dir);
    }

    // ---- init_db ----

    #[test]
    fn init_db_creates_subdirectories() {
        let dir = tmp_dir("init");
        init_db(&dir);

        assert!(Path::new(&dir).join("players").is_dir());
        assert!(Path::new(&dir).join("reports").is_dir());
        assert!(Path::new(&dir).join("matches").is_dir());

        cleanup(&dir);
    }

    #[test]
    fn init_db_is_idempotent() {
        let dir = tmp_dir("init_idem");
        init_db(&dir);
        init_db(&dir); // should not panic
        assert!(Path::new(&dir).join("players").is_dir());
        cleanup(&dir);
    }

    // ---- player operations ----

    #[test]
    fn insert_and_get_player_roundtrip() {
        let dir = tmp_dir("player_rt");
        init_db(&dir);

        insert_player(&dir, "p1", "alice", "hash123", "2025-01-01T00:00:00Z").unwrap();

        let p = get_player(&dir, "p1").unwrap().expect("player should exist");
        assert_eq!(p.id, "p1");
        assert_eq!(p.name, "alice");
        assert_eq!(p.registered_at, "2025-01-01T00:00:00Z");
        assert!(p.last_report.is_none());
        assert!(p.is_clean);
        assert!(p.config_hash.is_none());

        cleanup(&dir);
    }

    #[test]
    fn get_player_returns_none_for_missing() {
        let dir = tmp_dir("player_miss");
        init_db(&dir);

        assert!(get_player(&dir, "nonexistent").unwrap().is_none());

        cleanup(&dir);
    }

    #[test]
    fn insert_player_rejects_duplicate_id() {
        let dir = tmp_dir("player_dup");
        init_db(&dir);

        insert_player(&dir, "p1", "alice", "h1", "2025-01-01T00:00:00Z").unwrap();
        let result = insert_player(&dir, "p1", "bob", "h2", "2025-01-02T00:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));

        cleanup(&dir);
    }

    #[test]
    fn get_player_by_name_finds_correct_player() {
        let dir = tmp_dir("player_byname");
        init_db(&dir);

        insert_player(&dir, "p1", "alice", "h1", "2025-01-01T00:00:00Z").unwrap();
        insert_player(&dir, "p2", "bob", "h2", "2025-01-02T00:00:00Z").unwrap();

        let (p, hash) = get_player_by_name(&dir, "bob").unwrap().expect("bob should exist");
        assert_eq!(p.id, "p2");
        assert_eq!(p.name, "bob");
        assert_eq!(hash, "h2");

        cleanup(&dir);
    }

    #[test]
    fn get_player_by_name_returns_none_for_missing() {
        let dir = tmp_dir("player_byname_miss");
        init_db(&dir);

        assert!(get_player_by_name(&dir, "charlie").unwrap().is_none());

        cleanup(&dir);
    }

    #[test]
    fn list_players_returns_all() {
        let dir = tmp_dir("player_list");
        init_db(&dir);

        insert_player(&dir, "p1", "alice", "h1", "2025-01-01T00:00:00Z").unwrap();
        insert_player(&dir, "p2", "bob", "h2", "2025-01-02T00:00:00Z").unwrap();
        insert_player(&dir, "p3", "charlie", "h3", "2025-01-03T00:00:00Z").unwrap();

        let players = list_players(&dir).unwrap();
        assert_eq!(players.len(), 3);

        let mut names: Vec<&str> = players.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["alice", "bob", "charlie"]);

        cleanup(&dir);
    }

    #[test]
    fn list_players_returns_empty_when_no_players() {
        let dir = tmp_dir("player_list_empty");
        init_db(&dir);

        let players = list_players(&dir).unwrap();
        assert!(players.is_empty());

        cleanup(&dir);
    }

    // ---- update_player_report ----

    #[test]
    fn update_player_report_updates_fields() {
        let dir = tmp_dir("player_update");
        init_db(&dir);

        insert_player(&dir, "p1", "alice", "h1", "2025-01-01T00:00:00Z").unwrap();

        let updated = update_player_report(&dir, "p1", "2025-06-15T12:00:00Z", false, "abc123")
            .unwrap();
        assert!(updated);

        let p = get_player(&dir, "p1").unwrap().unwrap();
        assert_eq!(p.last_report.as_deref(), Some("2025-06-15T12:00:00Z"));
        assert!(!p.is_clean);
        assert_eq!(p.config_hash.as_deref(), Some("abc123"));

        cleanup(&dir);
    }

    #[test]
    fn update_player_report_returns_false_for_missing() {
        let dir = tmp_dir("player_update_miss");
        init_db(&dir);

        let result = update_player_report(&dir, "noone", "2025-01-01T00:00:00Z", true, "h")
            .unwrap();
        assert!(!result);

        cleanup(&dir);
    }

    #[test]
    fn update_player_report_preserves_password_hash() {
        let dir = tmp_dir("player_update_pw");
        init_db(&dir);

        insert_player(&dir, "p1", "alice", "secret-hash-value", "2025-01-01T00:00:00Z").unwrap();
        update_player_report(&dir, "p1", "2025-06-01T00:00:00Z", true, "cfg1").unwrap();

        // verify password hash is preserved by looking up by name
        let (_, hash) = get_player_by_name(&dir, "alice").unwrap().unwrap();
        assert_eq!(hash, "secret-hash-value");

        cleanup(&dir);
    }

    // ---- mark_player_dirty ----

    #[test]
    fn mark_player_dirty_sets_is_clean_false() {
        let dir = tmp_dir("player_dirty");
        init_db(&dir);

        insert_player(&dir, "p1", "alice", "h1", "2025-01-01T00:00:00Z").unwrap();
        assert!(get_player(&dir, "p1").unwrap().unwrap().is_clean);

        mark_player_dirty(&dir, "p1").unwrap();
        assert!(!get_player(&dir, "p1").unwrap().unwrap().is_clean);

        cleanup(&dir);
    }

    #[test]
    fn mark_player_dirty_errors_for_missing() {
        let dir = tmp_dir("player_dirty_miss");
        init_db(&dir);

        let result = mark_player_dirty(&dir, "noone");
        assert!(result.is_err());

        cleanup(&dir);
    }

    // ---- report operations ----

    #[test]
    fn insert_and_get_reports_in_range() {
        let dir = tmp_dir("report_range");
        init_db(&dir);

        insert_report(&dir, "p1", "2025-01-10T00:00:00Z", "data-a").unwrap();
        insert_report(&dir, "p1", "2025-01-15T00:00:00Z", "data-b").unwrap();
        insert_report(&dir, "p1", "2025-01-20T00:00:00Z", "data-c").unwrap();
        // different player
        insert_report(&dir, "p2", "2025-01-15T00:00:00Z", "data-other").unwrap();

        // query range that includes b and c but not a
        let reports = get_reports_in_range(
            &dir, "p1", "2025-01-12T00:00:00Z", "2025-01-20T00:00:00Z",
        ).unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports.contains(&"data-b".to_string()));
        assert!(reports.contains(&"data-c".to_string()));

        cleanup(&dir);
    }

    #[test]
    fn get_reports_in_range_filters_by_player() {
        let dir = tmp_dir("report_filter");
        init_db(&dir);

        insert_report(&dir, "p1", "2025-01-15T00:00:00Z", "p1-data").unwrap();
        insert_report(&dir, "p2", "2025-01-15T00:00:00Z", "p2-data").unwrap();

        let reports = get_reports_in_range(
            &dir, "p1", "2025-01-01T00:00:00Z", "2025-12-31T00:00:00Z",
        ).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0], "p1-data");

        cleanup(&dir);
    }

    #[test]
    fn get_reports_in_range_returns_empty_for_no_matches() {
        let dir = tmp_dir("report_empty");
        init_db(&dir);

        insert_report(&dir, "p1", "2025-01-15T00:00:00Z", "data").unwrap();

        let reports = get_reports_in_range(
            &dir, "p1", "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z",
        ).unwrap();
        assert!(reports.is_empty());

        cleanup(&dir);
    }

    // ---- match operations ----

    #[test]
    fn insert_and_get_match_roundtrip() {
        let dir = tmp_dir("match_rt");
        init_db(&dir);

        let player_ids = vec!["p1".to_string(), "p2".to_string()];
        insert_match(&dir, "m1", "2025-03-01T10:00:00Z", &player_ids).unwrap();

        let m = get_match(&dir, "m1").unwrap().expect("match should exist");
        assert_eq!(m.id, "m1");
        assert_eq!(m.created_at, "2025-03-01T10:00:00Z");
        assert!(m.ended_at.is_none());
        assert_eq!(m.player_ids, vec!["p1", "p2"]);

        cleanup(&dir);
    }

    #[test]
    fn get_match_returns_none_for_missing() {
        let dir = tmp_dir("match_miss");
        init_db(&dir);

        assert!(get_match(&dir, "nonexistent").unwrap().is_none());

        cleanup(&dir);
    }

    #[test]
    fn insert_match_rejects_duplicate() {
        let dir = tmp_dir("match_dup");
        init_db(&dir);

        let pids = vec!["p1".to_string()];
        insert_match(&dir, "m1", "2025-03-01T10:00:00Z", &pids).unwrap();
        let result = insert_match(&dir, "m1", "2025-03-02T10:00:00Z", &pids);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));

        cleanup(&dir);
    }

    #[test]
    fn end_match_sets_ended_at() {
        let dir = tmp_dir("match_end");
        init_db(&dir);

        let pids = vec!["p1".to_string()];
        insert_match(&dir, "m1", "2025-03-01T10:00:00Z", &pids).unwrap();

        let ended = end_match(&dir, "m1", "2025-03-01T11:00:00Z").unwrap();
        assert!(ended);

        let m = get_match(&dir, "m1").unwrap().unwrap();
        assert_eq!(m.ended_at.as_deref(), Some("2025-03-01T11:00:00Z"));

        cleanup(&dir);
    }

    #[test]
    fn end_match_returns_false_for_missing() {
        let dir = tmp_dir("match_end_miss");
        init_db(&dir);

        let result = end_match(&dir, "noone", "2025-01-01T00:00:00Z").unwrap();
        assert!(!result);

        cleanup(&dir);
    }

    #[test]
    fn list_matches_returns_all() {
        let dir = tmp_dir("match_list");
        init_db(&dir);

        let p1 = vec!["p1".to_string()];
        let p2 = vec!["p2".to_string(), "p3".to_string()];
        insert_match(&dir, "m1", "2025-03-01T10:00:00Z", &p1).unwrap();
        insert_match(&dir, "m2", "2025-03-02T10:00:00Z", &p2).unwrap();

        let matches = list_matches(&dir).unwrap();
        assert_eq!(matches.len(), 2);

        let mut ids: Vec<&str> = matches.iter().map(|m| m.id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, vec!["m1", "m2"]);

        cleanup(&dir);
    }

    #[test]
    fn list_matches_returns_empty_when_none() {
        let dir = tmp_dir("match_list_empty");
        init_db(&dir);

        let matches = list_matches(&dir).unwrap();
        assert!(matches.is_empty());

        cleanup(&dir);
    }

    // ---- config operations ----

    #[test]
    fn get_config_returns_none_when_no_config_file() {
        let dir = tmp_dir("config_none");
        init_db(&dir);

        assert!(get_config(&dir, "anything").unwrap().is_none());

        cleanup(&dir);
    }

    #[test]
    fn set_and_get_config_roundtrip() {
        let dir = tmp_dir("config_rt");
        init_db(&dir);

        set_config(&dir, "expected_config_hash", "abc123").unwrap();
        let val = get_config(&dir, "expected_config_hash").unwrap();
        assert_eq!(val.as_deref(), Some("abc123"));

        cleanup(&dir);
    }

    #[test]
    fn set_config_overwrites_existing_key() {
        let dir = tmp_dir("config_overwrite");
        init_db(&dir);

        set_config(&dir, "key", "old-value").unwrap();
        set_config(&dir, "key", "new-value").unwrap();

        assert_eq!(get_config(&dir, "key").unwrap().as_deref(), Some("new-value"));

        cleanup(&dir);
    }

    #[test]
    fn set_config_supports_multiple_keys() {
        let dir = tmp_dir("config_multi");
        init_db(&dir);

        set_config(&dir, "key_a", "val_a").unwrap();
        set_config(&dir, "key_b", "val_b").unwrap();

        assert_eq!(get_config(&dir, "key_a").unwrap().as_deref(), Some("val_a"));
        assert_eq!(get_config(&dir, "key_b").unwrap().as_deref(), Some("val_b"));

        cleanup(&dir);
    }

    #[test]
    fn get_config_returns_none_for_missing_key() {
        let dir = tmp_dir("config_miss_key");
        init_db(&dir);

        set_config(&dir, "existing", "value").unwrap();
        assert!(get_config(&dir, "nonexistent").unwrap().is_none());

        cleanup(&dir);
    }
}
