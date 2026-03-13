use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{base64url_decode, base64url_encode, hash_password, hmac_sha256, verify_password};
use crate::json::{json_num, json_obj, json_str, parse, stringify};

// reads jwt secret from VIGIL_JWT_SECRET env var, falls back to default
fn jwt_secret() -> String {
    std::env::var("VIGIL_JWT_SECRET").unwrap_or_else(|_| "vigil-server-secret-change-me".to_string())
}

// reads admin key from VIGIL_ADMIN_KEY env var, falls back to default
fn admin_key() -> String {
    std::env::var("VIGIL_ADMIN_KEY").unwrap_or_else(|_| "vigil-admin-key-change-me".to_string())
}

// re-exports for convenience
pub fn hash_pw(password: &str) -> String {
    hash_password(password)
}

pub fn verify_pw(password: &str, stored: &str) -> bool {
    verify_password(password, stored)
}

// current unix timestamp in seconds
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// creates a JWT token (HS256) for a player, expires in 24 hours
pub fn create_token(player_id: &str) -> Result<String, String> {
    let exp = now_secs() + 86400;

    // header: {"alg":"HS256","typ":"JWT"}
    let header = stringify(&json_obj(vec![
        ("alg", json_str("HS256")),
        ("typ", json_str("JWT")),
    ]));

    // payload: {"sub":"player_id","exp":timestamp}
    let payload = stringify(&json_obj(vec![
        ("sub", json_str(player_id)),
        ("exp", json_num(exp as f64)),
    ]));

    let enc_header = base64url_encode(header.as_bytes());
    let enc_payload = base64url_encode(payload.as_bytes());

    // signing input: base64url(header).base64url(payload)
    let signing_input = format!("{}.{}", enc_header, enc_payload);

    let secret = jwt_secret();
    let sig = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    let enc_sig = base64url_encode(&sig);

    Ok(format!("{}.{}", signing_input, enc_sig))
}

// validates a JWT token, returns the player_id (sub claim) if valid
pub fn validate_token(token: &str) -> Result<String, String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid token format".to_string());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let secret = jwt_secret();
    let expected_sig = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    let expected_enc = base64url_encode(&expected_sig);

    // constant-time compare
    let provided = parts[2].as_bytes();
    let expected = expected_enc.as_bytes();
    if provided.len() != expected.len() {
        return Err("invalid signature".to_string());
    }
    let mut diff = 0u8;
    for i in 0..provided.len() {
        diff |= provided[i] ^ expected[i];
    }
    if diff != 0 {
        return Err("invalid signature".to_string());
    }

    // decode payload
    let payload_bytes = base64url_decode(parts[1])?;
    let payload_str = String::from_utf8(payload_bytes)
        .map_err(|_| "payload is not valid utf-8".to_string())?;
    let payload = parse(&payload_str)?;

    // check expiry
    let exp = payload
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "missing exp claim".to_string())?;

    if (exp as u64) < now_secs() {
        return Err("token expired".to_string());
    }

    // return player id
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing sub claim".to_string())?
        .to_string();

    Ok(sub)
}

// checks if a request has a valid JWT Bearer token
pub fn check_auth(req: &crate::http::Request) -> Result<String, u16> {
    let header = req.get_header("Authorization").ok_or(401u16)?;

    if !header.starts_with("Bearer ") {
        return Err(401);
    }

    let token = &header[7..];
    validate_token(token).map_err(|_| 401u16)
}

// checks if request has valid admin API key
pub fn check_admin(req: &crate::http::Request) -> Result<(), u16> {
    let key = req.get_header("X-Admin-Key").ok_or(403u16)?;

    if key == admin_key() {
        Ok(())
    } else {
        Err(403)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- JWT token tests ----

    #[test]
    fn create_token_has_three_dot_separated_parts() {
        let token = create_token("player-123").unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have exactly 3 parts: {}", token);
        // each part should be non-empty base64url
        for (i, part) in parts.iter().enumerate() {
            assert!(!part.is_empty(), "JWT part {} is empty", i);
        }
    }

    #[test]
    fn validate_token_accepts_own_tokens() {
        let token = create_token("player-abc").unwrap();
        let sub = validate_token(&token).unwrap();
        assert_eq!(sub, "player-abc");
    }

    #[test]
    fn validate_token_preserves_player_id() {
        // test various player id shapes
        for id in &["simple", "uuid-like-1234-5678", "with spaces", ""] {
            let token = create_token(id).unwrap();
            let sub = validate_token(&token).unwrap();
            assert_eq!(sub, *id);
        }
    }

    #[test]
    fn validate_token_rejects_tampered_signature() {
        let token = create_token("player-x").unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        // flip a character in the signature
        let mut sig = parts[2].to_string();
        let bytes = unsafe { sig.as_bytes_mut() };
        bytes[0] ^= 0x01; // flip one bit
        let tampered = format!("{}.{}.{}", parts[0], parts[1], sig);
        assert!(validate_token(&tampered).is_err());
    }

    #[test]
    fn validate_token_rejects_tampered_payload() {
        let token = create_token("player-x").unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        // use a different payload but keep original signature
        let other_token = create_token("ATTACKER").unwrap();
        let other_parts: Vec<&str> = other_token.splitn(3, '.').collect();
        let franken = format!("{}.{}.{}", parts[0], other_parts[1], parts[2]);
        assert!(validate_token(&franken).is_err());
    }

    #[test]
    fn validate_token_rejects_garbage() {
        assert!(validate_token("").is_err());
        assert!(validate_token("not-a-token").is_err());
        assert!(validate_token("a.b").is_err());
        assert!(validate_token("a.b.c").is_err());
        assert!(validate_token("...").is_err());
        assert!(validate_token("hello world garbage").is_err());
    }

    #[test]
    fn validate_token_rejects_wrong_part_count() {
        assert!(validate_token("onlyonepart").is_err());
        assert!(validate_token("two.parts").is_err());
    }

    // ---- password hashing tests ----

    #[test]
    fn hash_pw_verify_pw_roundtrip() {
        let hash = hash_pw("my-secret-123");
        assert!(verify_pw("my-secret-123", &hash));
    }

    #[test]
    fn verify_pw_rejects_wrong_password() {
        let hash = hash_pw("correct-password");
        assert!(!verify_pw("wrong-password", &hash));
        assert!(!verify_pw("", &hash));
        assert!(!verify_pw("correct-passwor", &hash)); // off by one
        assert!(!verify_pw("correct-password ", &hash)); // trailing space
    }

    #[test]
    fn hash_pw_produces_different_hashes_for_same_password() {
        // because of random salt, hashing the same password twice should differ
        let h1 = hash_pw("same-password");
        let h2 = hash_pw("same-password");
        assert_ne!(h1, h2, "hashes should differ due to random salt");
        // but both should verify
        assert!(verify_pw("same-password", &h1));
        assert!(verify_pw("same-password", &h2));
    }

    #[test]
    fn verify_pw_rejects_bad_format() {
        assert!(!verify_pw("anything", "not-valid"));
        assert!(!verify_pw("anything", ""));
        assert!(!verify_pw("anything", ":"));
        assert!(!verify_pw("anything", "zzzz:1234"));
    }

    // ---- check_auth / check_admin tests ----

    #[test]
    fn check_auth_accepts_valid_bearer_token() {
        let token = create_token("player-42").unwrap();
        let req = crate::http::Request {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers: vec![("Authorization".to_string(), format!("Bearer {}", token))],
            body: String::new(),
        };
        let result = check_auth(&req);
        assert_eq!(result.unwrap(), "player-42");
    }

    #[test]
    fn check_auth_rejects_missing_header() {
        let req = crate::http::Request {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers: vec![],
            body: String::new(),
        };
        assert_eq!(check_auth(&req), Err(401));
    }

    #[test]
    fn check_auth_rejects_non_bearer() {
        let req = crate::http::Request {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers: vec![("Authorization".to_string(), "Basic abc123".to_string())],
            body: String::new(),
        };
        assert_eq!(check_auth(&req), Err(401));
    }

    #[test]
    fn check_admin_accepts_correct_key() {
        let key = admin_key();
        let req = crate::http::Request {
            method: "POST".to_string(),
            path: "/api/admin/config".to_string(),
            headers: vec![("X-Admin-Key".to_string(), key)],
            body: String::new(),
        };
        assert!(check_admin(&req).is_ok());
    }

    #[test]
    fn check_admin_rejects_wrong_key() {
        let req = crate::http::Request {
            method: "POST".to_string(),
            path: "/api/admin/config".to_string(),
            headers: vec![("X-Admin-Key".to_string(), "wrong-key".to_string())],
            body: String::new(),
        };
        assert_eq!(check_admin(&req), Err(403));
    }

    #[test]
    fn check_admin_rejects_missing_header() {
        let req = crate::http::Request {
            method: "POST".to_string(),
            path: "/api/admin/config".to_string(),
            headers: vec![],
            body: String::new(),
        };
        assert_eq!(check_admin(&req), Err(403));
    }
}
