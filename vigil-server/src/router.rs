use std::fs;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use crate::http::{Request, Response};

// handler function signature - takes a request and extracted path params
pub type Handler = fn(&Request, Params) -> Response;

// extracted path parameters from url matching
pub struct Params {
    pairs: Vec<(String, String)>,
}

impl Params {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

// a registered route with its parsed path segments
struct Route {
    method: String,
    segments: Vec<Segment>,
    handler: Handler,
}

// a path segment is either a literal match or a named param capture
enum Segment {
    Literal(String),
    Param(String),
}

pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    pub fn new() -> Self {
        Router { routes: Vec::new() }
    }

    // register a GET route
    pub fn get(&mut self, path: &str, handler: Handler) {
        self.add("GET", path, handler);
    }

    // register a POST route
    pub fn post(&mut self, path: &str, handler: Handler) {
        self.add("POST", path, handler);
    }

    // parses the path into segments and stores the route
    fn add(&mut self, method: &str, path: &str, handler: Handler) {
        let segments = parse_segments(path);
        self.routes.push(Route {
            method: method.to_string(),
            segments,
            handler,
        });
    }

    // finds the matching route for a method+path, returns handler and extracted params
    pub fn resolve(&self, method: &str, path: &str) -> Option<(Handler, Params)> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        for route in &self.routes {
            if !route.method.eq_ignore_ascii_case(method) {
                continue;
            }

            if route.segments.len() != parts.len() {
                continue;
            }

            let mut pairs = Vec::new();
            let mut matched = true;

            for (seg, part) in route.segments.iter().zip(parts.iter()) {
                match seg {
                    Segment::Literal(lit) => {
                        if lit != part {
                            matched = false;
                            break;
                        }
                    }
                    Segment::Param(name) => {
                        pairs.push((name.clone(), part.to_string()));
                    }
                }
            }

            if matched {
                return Some((route.handler, Params { pairs }));
            }
        }

        None
    }
}

// parses "/api/player/{id}" into [Literal("api"), Literal("player"), Param("id")]
fn parse_segments(path: &str) -> Vec<Segment> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.starts_with('{') && s.ends_with('}') {
                Segment::Param(s[1..s.len() - 1].to_string())
            } else {
                Segment::Literal(s.to_string())
            }
        })
        .collect()
}

// adds cors headers to every response
fn add_cors(res: &mut Response) {
    res.headers
        .push(("Access-Control-Allow-Origin".to_string(), "*".to_string()));
    res.headers.push((
        "Access-Control-Allow-Methods".to_string(),
        "GET, POST, PUT, DELETE, OPTIONS".to_string(),
    ));
    res.headers.push((
        "Access-Control-Allow-Headers".to_string(),
        "Content-Type, Authorization, X-Admin-Key".to_string(),
    ));
}

// serves a static file from the public/ directory
// paths without a file extension get index.html (SPA support)
fn serve_static(path: &str) -> Response {
    // strip leading slash and sanitize - prevent path traversal
    let clean: String = path
        .trim_start_matches('/')
        .replace("..", "")
        .replace("//", "/");

    // pick the filesystem path
    let fs_path = if clean.is_empty() || !clean.contains('.') {
        "public/index.html".to_string()
    } else {
        format!("public/{}", clean)
    };

    let content = match fs::read(&fs_path) {
        Ok(b) => b,
        Err(_) => {
            // fallback to index.html for SPA deep links
            match fs::read("public/index.html") {
                Ok(b) => b,
                Err(_) => {
                    return Response::new(404)
                        .header("Content-Type", "application/json")
                        .body("{\"error\":\"not found\"}".to_string());
                }
            }
        }
    };

    let content_type = mime_type(&fs_path);
    let body = String::from_utf8(content).unwrap_or_default();

    Response::new(200)
        .header("Content-Type", content_type)
        .body(body)
}

// returns content-type based on file extension
fn mime_type(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else if path.ends_with(".woff") {
        "font/woff"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, Response};

    // dummy handlers for testing
    fn handler_a(_req: &Request, _params: Params) -> Response {
        Response::new(200).body("handler_a".to_string())
    }

    fn handler_b(_req: &Request, _params: Params) -> Response {
        Response::new(200).body("handler_b".to_string())
    }

    fn handler_c(_req: &Request, params: Params) -> Response {
        let id = params.get("id").unwrap_or("none");
        Response::new(200).body(format!("id={}", id))
    }

    // ---- resolve exact paths ----

    #[test]
    fn resolve_matches_exact_get_path() {
        let mut router = Router::new();
        router.get("/api/health", handler_a);

        let result = router.resolve("GET", "/api/health");
        assert!(result.is_some());
        let (handler, _params) = result.unwrap();
        let req = Request {
            method: "GET".to_string(),
            path: "/api/health".to_string(),
            headers: vec![],
            body: String::new(),
        };
        let resp = handler(&req, Params { pairs: vec![] });
        assert_eq!(resp.body, "handler_a");
    }

    #[test]
    fn resolve_matches_exact_post_path() {
        let mut router = Router::new();
        router.post("/api/report", handler_b);

        let result = router.resolve("POST", "/api/report");
        assert!(result.is_some());
    }

    #[test]
    fn resolve_distinguishes_get_from_post() {
        let mut router = Router::new();
        router.get("/api/data", handler_a);
        router.post("/api/data", handler_b);

        // GET should match handler_a
        let (handler, _) = router.resolve("GET", "/api/data").unwrap();
        let req = Request {
            method: "GET".to_string(),
            path: "/api/data".to_string(),
            headers: vec![],
            body: String::new(),
        };
        let resp = handler(&req, Params { pairs: vec![] });
        assert_eq!(resp.body, "handler_a");

        // POST should match handler_b
        let (handler, _) = router.resolve("POST", "/api/data").unwrap();
        let resp = handler(&req, Params { pairs: vec![] });
        assert_eq!(resp.body, "handler_b");
    }

    // ---- path parameters ----

    #[test]
    fn resolve_extracts_single_path_param() {
        let mut router = Router::new();
        router.get("/api/player/{id}", handler_c);

        let (_, params) = router.resolve("GET", "/api/player/abc-123").unwrap();
        assert_eq!(params.get("id"), Some("abc-123"));
    }

    #[test]
    fn resolve_extracts_multiple_path_params() {
        let mut router = Router::new();
        router.get("/api/{resource}/{id}", handler_a);

        let (_, params) = router.resolve("GET", "/api/player/42").unwrap();
        assert_eq!(params.get("resource"), Some("player"));
        assert_eq!(params.get("id"), Some("42"));
    }

    #[test]
    fn resolve_param_at_different_positions() {
        let mut router = Router::new();
        router.get("/api/match/{id}/integrity", handler_a);

        let (_, params) = router.resolve("GET", "/api/match/m-001/integrity").unwrap();
        assert_eq!(params.get("id"), Some("m-001"));
    }

    // ---- no match ----

    #[test]
    fn resolve_returns_none_for_unregistered_path() {
        let mut router = Router::new();
        router.get("/api/health", handler_a);

        assert!(router.resolve("GET", "/api/nonexistent").is_none());
    }

    #[test]
    fn resolve_returns_none_for_wrong_method() {
        let mut router = Router::new();
        router.get("/api/health", handler_a);

        assert!(router.resolve("POST", "/api/health").is_none());
        assert!(router.resolve("DELETE", "/api/health").is_none());
    }

    #[test]
    fn resolve_returns_none_for_wrong_segment_count() {
        let mut router = Router::new();
        router.get("/api/player/{id}", handler_a);

        // too few segments
        assert!(router.resolve("GET", "/api/player").is_none());
        // too many segments
        assert!(router.resolve("GET", "/api/player/123/extra").is_none());
    }

    #[test]
    fn resolve_returns_none_for_partial_literal_mismatch() {
        let mut router = Router::new();
        router.get("/api/player/{id}", handler_a);

        // "players" != "player"
        assert!(router.resolve("GET", "/api/players/123").is_none());
    }

    #[test]
    fn resolve_method_is_case_insensitive() {
        let mut router = Router::new();
        router.get("/api/health", handler_a);

        assert!(router.resolve("get", "/api/health").is_some());
        assert!(router.resolve("Get", "/api/health").is_some());
    }

    // ---- params.get ----

    #[test]
    fn params_get_returns_none_for_missing_key() {
        let params = Params { pairs: vec![("id".to_string(), "42".to_string())] };
        assert_eq!(params.get("id"), Some("42"));
        assert_eq!(params.get("name"), None);
    }

    // ---- parse_segments ----

    #[test]
    fn parse_segments_handles_empty_and_root() {
        let router = Router::new();
        // empty router should return None for root path
        assert!(router.resolve("GET", "/").is_none());
    }
}

// starts the server - binds to addr, spawns a thread pool, dispatches requests
pub fn serve(addr: &str, router: Router) {
    let listener = TcpListener::bind(addr).expect("failed to bind");
    println!("vigil server listening on {}", addr);

    let router = Arc::new(router);

    // simple thread pool - 8 worker threads pulling from a shared channel
    let (tx, rx) = std::sync::mpsc::channel::<std::net::TcpStream>();
    let rx = Arc::new(std::sync::Mutex::new(rx));

    for _ in 0..8 {
        let rx = Arc::clone(&rx);
        let router = Arc::clone(&router);

        thread::spawn(move || loop {
            // grab next connection from the channel
            let mut stream = match rx.lock().unwrap().recv() {
                Ok(s) => s,
                Err(_) => break, // channel closed, shut down
            };

            // parse the request
            let req = match Request::parse(&mut stream) {
                Ok(r) => r,
                Err(_) => continue, // bad request, just drop it
            };

            // handle OPTIONS preflight
            if req.method.eq_ignore_ascii_case("OPTIONS") {
                let mut res = Response::new(204);
                add_cors(&mut res);
                let _ = res.write_to(&mut stream);
                continue;
            }

            // strip query string for routing - only match on path
            let path = req.path.split('?').next().unwrap_or(&req.path);

            // find handler or try static file, then 404
            let mut res = match router.resolve(&req.method, path) {
                Some((handler, params)) => handler(&req, params),
                None if req.method.eq_ignore_ascii_case("GET") => serve_static(path),
                None => Response::new(404)
                    .header("Content-Type", "application/json")
                    .body("{\"error\":\"not found\"}".to_string()),
            };

            add_cors(&mut res);
            let _ = res.write_to(&mut stream);
        });
    }

    // accept loop - push connections to the thread pool
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let _ = tx.send(s);
            }
            Err(e) => {
                eprintln!("accept error: {}", e);
            }
        }
    }
}
