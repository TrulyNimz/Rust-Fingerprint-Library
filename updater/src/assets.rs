use std::path::Path;

use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::github::UpdateError;

/// Download a file from `url` to `dest`, returning the SHA-256 hex digest.
pub async fn download_file(
    url: &str,
    dest: &Path,
    progress: Option<&dyn Fn(u64, u64)>,
) -> Result<String, UpdateError> {
    let client = reqwest::Client::builder()
        .user_agent("fingerprint-updater")
        .build()?;

    let mut req = client.get(url);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    req = req.header("Accept", "application/octet-stream");

    let resp = req.send().await?.error_for_status()?;
    let total = resp.content_length().unwrap_or(0);

    let mut file = tokio::fs::File::create(dest).await?;
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(UpdateError::Http)?;
        file.write_all(&chunk).await?;
        hasher.update(&chunk);
        downloaded += chunk.len() as u64;
        if let Some(cb) = progress {
            cb(downloaded, total);
        }
    }

    file.flush().await?;
    drop(file);

    let hash = format!("{:x}", hasher.finalize());
    Ok(hash)
}

/// Download and parse a `.sha256` checksum file. Returns the hex digest (first field).
pub async fn download_checksum(url: &str) -> Result<String, UpdateError> {
    let client = reqwest::Client::builder()
        .user_agent("fingerprint-updater")
        .build()?;

    let mut req = client.get(url);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let text = req.send().await?.error_for_status()?.text().await?;
    // Format: "<hex>  <filename>" or just "<hex>"
    let checksum = text
        .split_whitespace()
        .next()
        .ok_or_else(|| UpdateError::Download("Empty checksum file".into()))?
        .to_lowercase();

    Ok(checksum)
}

/// Verify a file's SHA-256 against an expected hex digest.
pub fn verify_checksum(actual: &str, expected: &str) -> Result<(), UpdateError> {
    if actual != expected {
        return Err(UpdateError::ChecksumMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

/// Extract a zip archive to the destination directory.
pub fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<Vec<String>, UpdateError> {
    let file =
        std::fs::File::open(zip_path).map_err(|e| UpdateError::ZipError(e.to_string()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| UpdateError::ZipError(e.to_string()))?;

    let mut extracted = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UpdateError::ZipError(e.to_string()))?;

        let name = entry.name().to_string();

        // Skip directories
        if entry.is_dir() {
            continue;
        }

        // Sanitize: only use the filename, no directory traversal
        let file_name = Path::new(&name)
            .file_name()
            .ok_or_else(|| UpdateError::ZipError(format!("Invalid entry name: {name}")))?;

        let out_path = dest_dir.join(file_name);
        let mut out_file =
            std::fs::File::create(&out_path).map_err(|e| UpdateError::ZipError(e.to_string()))?;
        std::io::copy(&mut entry, &mut out_file)
            .map_err(|e| UpdateError::ZipError(e.to_string()))?;

        extracted.push(file_name.to_string_lossy().to_string());
    }

    Ok(extracted)
}

/// Compute SHA-256 of a file on disk.
pub fn sha256_file(path: &Path) -> Result<String, UpdateError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
