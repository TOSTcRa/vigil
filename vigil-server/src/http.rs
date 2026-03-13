use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    // reads and parses an HTTP/1.1 request from a tcp stream
    // sets a 5 second read timeout so we dont hang on slow clients
    pub fn parse(stream: &mut TcpStream) -> Result<Request, String> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("timeout setup failed: {}", e))?;

        let mut reader = BufReader::new(stream);

        // read request line: GET /path HTTP/1.1
        let mut req_line = String::new();
        reader
            .read_line(&mut req_line)
            .map_err(|e| format!("failed to read request line: {}", e))?;

        let req_line = req_line.trim();
        if req_line.is_empty() {
            return Err("empty request line".to_string());
        }

        let parts: Vec<&str> = req_line.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(format!("malformed request line: {}", req_line));
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();
        // parts[2] is HTTP/1.1, we dont care about the version

        // read headers until empty line
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| format!("failed to read header: {}", e))?;

            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }

            // split on first colon
            if let Some(pos) = trimmed.find(':') {
                let key = trimmed[..pos].trim().to_string();
                let val = trimmed[pos + 1..].trim().to_string();
                headers.push((key, val));
            }
        }

        // read body if content-length is present
        let mut body = String::new();
        let content_len = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .unwrap_or(0);

        if content_len > 0 {
            let mut buf = vec![0u8; content_len];
            reader
                .read_exact(&mut buf)
                .map_err(|e| format!("failed to read body: {}", e))?;
            body = String::from_utf8(buf).map_err(|e| format!("body not utf8: {}", e))?;
        }

        Ok(Request {
            method,
            path,
            headers,
            body,
        })
    }

    // case-insensitive header lookup
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl Response {
    // creates a response with the right status text for common codes
    pub fn new(status: u16) -> Response {
        let status_text = match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
        .to_string();

        Response {
            status,
            status_text,
            headers: Vec::new(),
            body: String::new(),
        }
    }

    // builder - add a header
    pub fn header(mut self, key: &str, val: &str) -> Self {
        self.headers.push((key.to_string(), val.to_string()));
        self
    }

    // builder - set the body
    pub fn body(mut self, body: String) -> Self {
        self.body = body;
        self
    }

    // shortcut for a 200 json response
    pub fn json(body: String) -> Response {
        Response::new(200)
            .header("Content-Type", "application/json")
            .body(body)
    }

    // writes the full http response to the stream
    pub fn write_to(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        // status line
        let mut out = format!("HTTP/1.1 {} {}\r\n", self.status, self.status_text);

        // collect headers, add content-length if body is present
        for (k, v) in &self.headers {
            out.push_str(&format!("{}: {}\r\n", k, v));
        }

        // always send content-length so the client knows when to stop reading
        let has_cl = self
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
        if !has_cl {
            out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }

        // end of headers
        out.push_str("\r\n");

        // body
        out.push_str(&self.body);

        stream.write_all(out.as_bytes())?;
        stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Response::new status text mapping ----

    #[test]
    fn response_new_200_ok() {
        let r = Response::new(200);
        assert_eq!(r.status, 200);
        assert_eq!(r.status_text, "OK");
        assert!(r.headers.is_empty());
        assert!(r.body.is_empty());
    }

    #[test]
    fn response_new_201_created() {
        let r = Response::new(201);
        assert_eq!(r.status_text, "Created");
    }

    #[test]
    fn response_new_204_no_content() {
        let r = Response::new(204);
        assert_eq!(r.status_text, "No Content");
    }

    #[test]
    fn response_new_400_bad_request() {
        let r = Response::new(400);
        assert_eq!(r.status_text, "Bad Request");
    }

    #[test]
    fn response_new_401_unauthorized() {
        let r = Response::new(401);
        assert_eq!(r.status_text, "Unauthorized");
    }

    #[test]
    fn response_new_403_forbidden() {
        let r = Response::new(403);
        assert_eq!(r.status_text, "Forbidden");
    }

    #[test]
    fn response_new_404_not_found() {
        let r = Response::new(404);
        assert_eq!(r.status_text, "Not Found");
    }

    #[test]
    fn response_new_405_method_not_allowed() {
        let r = Response::new(405);
        assert_eq!(r.status_text, "Method Not Allowed");
    }

    #[test]
    fn response_new_500_internal_server_error() {
        let r = Response::new(500);
        assert_eq!(r.status_text, "Internal Server Error");
    }

    #[test]
    fn response_new_unknown_status() {
        let r = Response::new(418);
        assert_eq!(r.status_text, "Unknown");
    }

    // ---- Response::json ----

    #[test]
    fn response_json_sets_content_type_and_status() {
        let r = Response::json(r#"{"ok":true}"#.to_string());
        assert_eq!(r.status, 200);
        assert_eq!(r.status_text, "OK");
        assert_eq!(r.body, r#"{"ok":true}"#);

        let ct = r.headers.iter().find(|(k, _)| k == "Content-Type");
        assert!(ct.is_some());
        assert_eq!(ct.unwrap().1, "application/json");
    }

    // ---- builder chain ----

    #[test]
    fn response_header_builder_adds_headers() {
        let r = Response::new(200)
            .header("X-Custom", "value1")
            .header("X-Other", "value2");

        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.headers[0], ("X-Custom".to_string(), "value1".to_string()));
        assert_eq!(r.headers[1], ("X-Other".to_string(), "value2".to_string()));
    }

    #[test]
    fn response_body_builder_sets_body() {
        let r = Response::new(200).body("hello world".to_string());
        assert_eq!(r.body, "hello world");
    }

    #[test]
    fn response_full_builder_chain() {
        let r = Response::new(201)
            .header("Content-Type", "application/json")
            .header("X-Request-Id", "abc")
            .body(r#"{"id":"abc"}"#.to_string());

        assert_eq!(r.status, 201);
        assert_eq!(r.status_text, "Created");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.body, r#"{"id":"abc"}"#);
    }

    // ---- Request helpers ----

    #[test]
    fn request_get_header_case_insensitive() {
        let req = Request {
            method: "GET".to_string(),
            path: "/test".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Authorization".to_string(), "Bearer tok123".to_string()),
            ],
            body: String::new(),
        };

        assert_eq!(req.get_header("content-type"), Some("application/json"));
        assert_eq!(req.get_header("CONTENT-TYPE"), Some("application/json"));
        assert_eq!(req.get_header("Content-Type"), Some("application/json"));
        assert_eq!(req.get_header("authorization"), Some("Bearer tok123"));
        assert_eq!(req.get_header("X-Missing"), None);
    }

    #[test]
    fn request_get_header_returns_none_when_empty() {
        let req = Request {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![],
            body: String::new(),
        };
        assert_eq!(req.get_header("Anything"), None);
    }
}
