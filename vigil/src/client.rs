use crate::http_client;
use crate::report::ScanReport;

// sends a scan report to the vigil-server via POST /api/report
// serializes report to json and sends with raw tcp
pub fn send_report(server_url: &str, report: &ScanReport, token: Option<&str>) -> Result<(), String> {
    let url = format!("{}/api/report", server_url);
    let body = crate::report::to_json(report);

    let res = http_client::post_json(&url, &body, token)?;

    if res.status >= 400 {
        return Err(format!("server returned {}: {}", res.status, res.body));
    }

    Ok(())
}
