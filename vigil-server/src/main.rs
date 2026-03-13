mod auth;
mod crypto;
mod db;
mod handlers;
mod http;
mod json;
mod router;

fn main() {
    let data_dir = std::env::var("VIGIL_DATA").unwrap_or_else(|_| "data".to_string());

    db::init_db(&data_dir);
    handlers::init(&data_dir);

    let mut r = router::Router::new();

    // public routes
    r.get("/api/health", handlers::health);
    r.post("/api/player/register", handlers::register);
    r.post("/api/player/login", handlers::login);

    // auth routes
    r.get("/api/player/{id}", handlers::get_player);
    r.get("/api/player/{id}/status", handlers::player_status);
    r.post("/api/report", handlers::receive_report);
    r.post("/api/match", handlers::create_match);
    r.post("/api/match/end", handlers::end_match_handler);
    r.get("/api/match/{id}/integrity", handlers::match_integrity);

    // admin routes
    r.post("/api/admin/config", handlers::set_config);
    r.get("/api/players", handlers::list_players_handler);
    r.get("/api/matches", handlers::list_matches_handler);

    let addr = std::env::var("VIGIL_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    router::serve(&addr, r);
}
