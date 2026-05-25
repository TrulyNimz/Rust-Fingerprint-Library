use semver::Version;
use serde::Deserialize;

use crate::version::{asset_checksum_name, asset_zip_name};

#[derive(Debug, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub prerelease: bool,
    pub assets: Vec<GitHubAsset>,
    pub html_url: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

#[derive(Debug)]
pub struct UpdateInfo {
    pub version: Version,
    pub zip_url: String,
    pub checksum_url: Option<String>,
    pub release_url: String,
}

pub async fn fetch_latest_release(
    owner: &str,
    repo: &str,
    include_prerelease: bool,
) -> Result<Option<GitHubRelease>, UpdateError> {
    let client = build_client()?;

    if include_prerelease {
        // Must list releases and find the first one (includes prereleases)
        let url = format!("https://api.github.com/repos/{owner}/{repo}/releases?per_page=10");
        let mut req = client.get(&url).header("Accept", "application/vnd.github+json");
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().await?.error_for_status()?;
        let releases: Vec<GitHubRelease> = resp.json().await?;
        Ok(releases.into_iter().next())
    } else {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
        let mut req = client.get(&url).header("Accept", "application/vnd.github+json");
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let release: GitHubRelease = resp.error_for_status()?.json().await?;
        Ok(Some(release))
    }
}

pub async fn check_for_update(
    owner: &str,
    repo: &str,
    current: &Version,
    include_prerelease: bool,
) -> Result<Option<UpdateInfo>, UpdateError> {
    let release = match fetch_latest_release(owner, repo, include_prerelease).await? {
        Some(r) => r,
        None => return Ok(None),
    };

    let tag = release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name);
    let latest = Version::parse(tag).map_err(|e| UpdateError::InvalidVersion(e.to_string()))?;

    if latest <= *current {
        return Ok(None);
    }

    let zip_name = asset_zip_name(tag);
    let checksum_name = asset_checksum_name(tag);

    let zip_asset = release
        .assets
        .iter()
        .find(|a| a.name == zip_name)
        .ok_or_else(|| UpdateError::MissingAsset(zip_name.clone()))?;

    let checksum_asset = release.assets.iter().find(|a| a.name == checksum_name);

    Ok(Some(UpdateInfo {
        version: latest,
        zip_url: zip_asset.browser_download_url.clone(),
        checksum_url: checksum_asset.map(|a| a.browser_download_url.clone()),
        release_url: release.html_url,
    }))
}

fn build_client() -> Result<reqwest::Client, UpdateError> {
    reqwest::Client::builder()
        .user_agent("fingerprint-updater")
        .build()
        .map_err(UpdateError::Http)
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Invalid version in release tag: {0}")]
    InvalidVersion(String),
    #[error("Release is missing expected asset: {0}")]
    MissingAsset(String),
    #[error("Download failed: {0}")]
    Download(String),
    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("Zip extraction failed: {0}")]
    ZipError(String),
    #[error("File operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Manifest error: {0}")]
    Manifest(String),
}
