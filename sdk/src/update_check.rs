use napi_derive::napi;
use serde::Deserialize;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_OWNER: &str = "TrulyNimz";
const DEFAULT_REPO: &str = "Rust-Fingerprint-Library";

#[napi(object)]
pub struct UpdateInfo {
    pub update_available: bool,
    pub current_version: String,
    pub latest_version: Option<String>,
    pub release_url: Option<String>,
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
}

#[napi]
pub async fn check_for_update() -> napi::Result<UpdateInfo> {
    let current = semver::Version::parse(CURRENT_VERSION)
        .map_err(|e| napi::Error::from_reason(format!("Bad version: {e}")))?;

    let client = reqwest::Client::builder()
        .user_agent("fingerprint-sdk")
        .build()
        .map_err(|e| napi::Error::from_reason(format!("HTTP client error: {e}")))?;

    let url = format!(
        "https://api.github.com/repos/{DEFAULT_OWNER}/{DEFAULT_REPO}/releases/latest"
    );

    let mut req = client.get(&url).header("Accept", "application/vnd.github+json");
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await.map_err(|e| {
        napi::Error::from_reason(format!("Failed to check for updates: {e}"))
    })?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(UpdateInfo {
            update_available: false,
            current_version: CURRENT_VERSION.to_string(),
            latest_version: None,
            release_url: None,
        });
    }

    let release: GitHubRelease = resp
        .error_for_status()
        .map_err(|e| napi::Error::from_reason(format!("GitHub API error: {e}")))?
        .json()
        .await
        .map_err(|e| napi::Error::from_reason(format!("Failed to parse response: {e}")))?;

    let tag = release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name);
    let latest = semver::Version::parse(tag)
        .map_err(|e| napi::Error::from_reason(format!("Bad release version: {e}")))?;

    Ok(UpdateInfo {
        update_available: latest > current,
        current_version: CURRENT_VERSION.to_string(),
        latest_version: Some(latest.to_string()),
        release_url: Some(release.html_url),
    })
}
