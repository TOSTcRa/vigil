use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

// sends a POST request with json body to a url
// url format: "http://host:port/path" or "http://host/path"
pub fn post_json(url: &str, body: &str, token: Option<&str>) -> Result<HttpResponse, String> {
    let (host, port, path) = parse_url(url)?;

    let mut stream = TcpStream::connect(format!("{}:{}", host, port))
        .map_err(|e| format!("connect failed: {}", e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set_read_timeout failed: {}", e))?;

    let mut req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        path,
        host,
        body.len()
    );

    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {}\r\n", t));
    }

    req.push_str("Connection: close\r\n");
    req.push_str("\r\n");
    req.push_str(body);

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write failed: {}", e))?;

    read_response(&mut stream)
}

// sends a GET request
pub fn get(url: &str, token: Option<&str>) -> Result<HttpResponse, String> {
    let (host, port, path) = parse_url(url)?;

    let mut stream = TcpStream::connect(format!("{}:{}", host, port))
        .map_err(|e| format!("connect failed: {}", e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set_read_timeout failed: {}", e))?;

    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n",
        path, host
    );

    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {}\r\n", t));
    }

    req.push_str("Connection: close\r\n");
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write failed: {}", e))?;

    read_response(&mut stream)
}

// parses "http://host:port/path" into (host, port, path)
fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("unsupported scheme in url: {}", url))?;

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };

    let (host, port) = match authority.find(':') {
        Some(i) => {
            let p = authority[i + 1..]
                .parse::<u16>()
                .map_err(|_| format!("invalid port in url: {}", url))?;
            (authority[..i].to_string(), p)
        }
        None => (authority.to_string(), 80u16),
    };

    Ok((host, port, path))
}

// reads an http response from stream
fn read_response(stream: &mut TcpStream) -> Result<HttpResponse, String> {
    let mut reader = BufReader::new(stream);

    // read status line
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("read status line failed: {}", e))?;

    let status = parse_status_line(&status_line)?;

    // read headers until blank line, collect content-length
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read header failed: {}", e))?;

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }

        let lower = trimmed.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("content-length:") {
            if let Ok(n) = val.trim().parse::<usize>() {
                content_length = Some(n);
            }
        }
    }

    // read body
    let body = if let Some(n) = content_length {
        let mut buf = vec![0u8; n];
        reader
            .read_exact(&mut buf)
            .map_err(|e| format!("read body failed: {}", e))?;
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        // no content-length - read until eof
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| format!("read body to end failed: {}", e))?;
        String::from_utf8_lossy(&buf).into_owned()
    };

    Ok(HttpResponse { status, body })
}

// parses "HTTP/1.1 200 OK" and returns the status code
fn parse_status_line(line: &str) -> Result<u16, String> {
    let mut parts = line.splitn(3, ' ');
    let _version = parts.next().ok_or("empty status line")?;
    let code = parts
        .next()
        .ok_or("missing status code")?
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("invalid status code in: {}", line.trim()))?;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_full() {
        let (host, port, path) = parse_url("http://localhost:3000/api/report").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 3000);
        assert_eq!(path, "/api/report");
    }

    #[test]
    fn parse_url_no_port() {
        let (host, port, path) = parse_url("http://example.com/test").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/test");
    }

    #[test]
    fn parse_url_no_path() {
        let (host, port, path) = parse_url("http://host:8080").unwrap();
        assert_eq!(host, "host");
        assert_eq!(port, 8080);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_just_host() {
        let (host, port, path) = parse_url("http://myserver").unwrap();
        assert_eq!(host, "myserver");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_rejects_https() {
        assert!(parse_url("https://example.com").is_err());
    }

    #[test]
    fn parse_url_rejects_garbage() {
        assert!(parse_url("not-a-url").is_err());
    }

    #[test]
    fn parse_status_200() {
        assert_eq!(parse_status_line("HTTP/1.1 200 OK\r\n").unwrap(), 200);
    }

    #[test]
    fn parse_status_404() {
        assert_eq!(parse_status_line("HTTP/1.1 404 Not Found\r\n").unwrap(), 404);
    }

    #[test]
    fn parse_status_500() {
        assert_eq!(parse_status_line("HTTP/1.1 500 Internal Server Error").unwrap(), 500);
    }

    #[test]
    fn parse_status_empty_fails() {
        assert!(parse_status_line("").is_err());
    }

    #[test]
    fn parse_status_no_code_fails() {
        assert!(parse_status_line("HTTP/1.1").is_err());
    }
}
