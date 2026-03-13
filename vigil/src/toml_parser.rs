// minimal toml parser for the vigil config format
// only handles [sections] and key = "quoted string" assignments

#[derive(Debug)]
pub struct Config {
    pub game: GameConfig,
    pub logging: LogConfig,
    pub server: Option<ServerConfig>,
}

#[derive(Debug)]
pub struct GameConfig {
    pub path: String,
}

#[derive(Debug)]
pub struct LogConfig {
    pub path: String,
}

#[derive(Debug)]
pub struct ServerConfig {
    pub url: String,
    pub player_id: String,
}

pub fn parse_config(content: &str) -> Result<Config, String> {
    let mut section = "";

    // fields we collect
    let mut game_path: Option<String> = None;
    let mut log_path: Option<String> = None;
    let mut server_url: Option<String> = None;
    let mut server_player_id: Option<String> = None;

    for (lineno, raw) in content.lines().enumerate() {
        let line = raw.trim();

        // skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // section header
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(format!("line {}: malformed section header: {}", lineno + 1, line));
            }
            section = &line[1..line.len() - 1];
            continue;
        }

        // key = "value"
        let (key, val) = parse_kv(line, lineno + 1)?;

        match section {
            "game" => match key {
                "path" => game_path = Some(val),
                _ => {} // ignore unknown keys
            },
            "logging" => match key {
                "path" => log_path = Some(val),
                _ => {}
            },
            "server" => match key {
                "url" => server_url = Some(val),
                "player_id" => server_player_id = Some(val),
                _ => {}
            },
            _ => {} // ignore unknown sections
        }
    }

    let game_path = game_path.ok_or("missing [game] path")?;
    let log_path = log_path.ok_or("missing [logging] path")?;

    // server section is optional - only include if both fields present
    let server = match (server_url, server_player_id) {
        (Some(url), Some(player_id)) => Some(ServerConfig { url, player_id }),
        (None, None) => None,
        (Some(_), None) => return Err("missing server.player_id".to_string()),
        (None, Some(_)) => return Err("missing server.url".to_string()),
    };

    Ok(Config {
        game: GameConfig { path: game_path },
        logging: LogConfig { path: log_path },
        server,
    })
}

// parse a single "key = \"value\"" line
fn parse_kv(line: &str, lineno: usize) -> Result<(&str, String), String> {
    let eq = line.find('=').ok_or_else(|| format!("line {}: expected '=' in: {}", lineno, line))?;

    let key = line[..eq].trim();
    let rest = line[eq + 1..].trim();

    // value must be a quoted string
    if !rest.starts_with('"') || !rest.ends_with('"') || rest.len() < 2 {
        return Err(format!("line {}: value must be a quoted string: {}", lineno, rest));
    }

    // strip the surrounding quotes
    let inner = &rest[1..rest.len() - 1];
    Ok((key, inner.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_CONFIG: &str = r#"
[game]
path = "/home/user/.steam/steam/steamapps/common/GameName"

[logging]
path = "/var/log/vigil.log"

[server]
url = "http://localhost:3000"
player_id = "00000000-0000-0000-0000-000000000000"
"#;

    const NO_SERVER_CONFIG: &str = r#"
# vigil config without server block

[game]
path = "/opt/game"

[logging]
path = "/tmp/vigil.log"
"#;

    #[test]
    fn test_full_config() {
        let cfg = parse_config(FULL_CONFIG).unwrap();
        assert_eq!(cfg.game.path, "/home/user/.steam/steam/steamapps/common/GameName");
        assert_eq!(cfg.logging.path, "/var/log/vigil.log");
        let srv = cfg.server.unwrap();
        assert_eq!(srv.url, "http://localhost:3000");
        assert_eq!(srv.player_id, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn test_no_server() {
        let cfg = parse_config(NO_SERVER_CONFIG).unwrap();
        assert_eq!(cfg.game.path, "/opt/game");
        assert_eq!(cfg.logging.path, "/tmp/vigil.log");
        assert!(cfg.server.is_none());
    }

    #[test]
    fn test_missing_game_path() {
        let input = "[logging]\npath = \"/tmp/vigil.log\"\n";
        let res = parse_config(input);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("game"));
    }

    #[test]
    fn test_missing_log_path() {
        let input = "[game]\npath = \"/opt/game\"\n";
        let res = parse_config(input);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("logging"));
    }

    #[test]
    fn test_partial_server_missing_player_id() {
        let input = "[game]\npath = \"/opt/game\"\n[logging]\npath = \"/tmp/v.log\"\n[server]\nurl = \"http://localhost:3000\"\n";
        let res = parse_config(input);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("player_id"));
    }

    #[test]
    fn test_comments_and_blank_lines() {
        let input = "# top comment\n\n[game]\n# inline comment\npath = \"/opt/game\"\n\n[logging]\npath = \"/tmp/vigil.log\"\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.game.path, "/opt/game");
    }

    #[test]
    fn test_unknown_keys_ignored() {
        let input = "[game]\npath = \"/opt/game\"\nunknown = \"value\"\n[logging]\npath = \"/tmp/vigil.log\"\n";
        let cfg = parse_config(input).unwrap();
        assert_eq!(cfg.game.path, "/opt/game");
    }

    #[test]
    fn test_unquoted_value_error() {
        let input = "[game]\npath = /opt/game\n[logging]\npath = \"/tmp/v.log\"\n";
        let res = parse_config(input);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("quoted string"));
    }
}
