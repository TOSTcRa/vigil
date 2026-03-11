use crate::report::ScanReport;

// sends a scan report to the vigil-server via POST /api/report
// serializes report to JSON and sends with reqwest
// returns error if server is unreachable or returns non-2xx status
pub async fn send_report(
    server_url: &str,
    report: &ScanReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/report", server_url);
    let body = serde_json::to_string(report)?;

    let client = reqwest::Client::new();
    let res = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(format!("server returned {}: {}", status, text).into());
    }

    Ok(())
}
