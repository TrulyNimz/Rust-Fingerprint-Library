pub mod apply;
pub mod assets;
pub mod github;
pub mod version;

use std::path::{Path, PathBuf};

use github::UpdateError;
use semver::Version;
use serde::{Deserialize, Serialize};

/// Manifest included inside the release zip (`version.json`).
#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub files: std::collections::HashMap<String, FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub sha256: String,
    #[serde(default)]
    pub arch: String,
}

/// Full update orchestration: check → download → verify → apply.
pub async fn perform_update(
    owner: &str,
    repo: &str,
    install_dir: &Path,
    current: &Version,
    include_prerelease: bool,
    force: bool,
) -> Result<Version, UpdateError> {
    // Step 0: Clean up old files from previous updates
    apply::cleanup_old_files(install_dir)?;

    // Step 1: Check for update
    let info = if force {
        // Force: fetch latest regardless of version comparison
        let release = github::fetch_latest_release(owner, repo, include_prerelease)
            .await?
            .ok_or_else(|| UpdateError::Download("No releases found".into()))?;

        let tag = release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name);
        let ver = Version::parse(tag)
            .map_err(|e| UpdateError::InvalidVersion(e.to_string()))?;

        let zip_name = version::asset_zip_name(tag);
        let checksum_name = version::asset_checksum_name(tag);

        let zip_asset = release
            .assets
            .iter()
            .find(|a| a.name == zip_name)
            .ok_or_else(|| UpdateError::MissingAsset(zip_name))?;

        let checksum_asset = release.assets.iter().find(|a| a.name == checksum_name);

        github::UpdateInfo {
            version: ver,
            zip_url: zip_asset.browser_download_url.clone(),
            checksum_url: checksum_asset.map(|a| a.browser_download_url.clone()),
            release_url: release.html_url,
        }
    } else {
        github::check_for_update(owner, repo, current, include_prerelease)
            .await?
            .ok_or_else(|| UpdateError::Download("Already up to date".into()))?
    };

    println!("Updating to v{} ...", info.version);
    println!("Release: {}", info.release_url);

    // Step 2: Download to temp directory
    let tmp_dir = tempfile::tempdir()?;
    let zip_path = tmp_dir.path().join("update.zip");

    println!("Downloading...");
    let actual_hash = assets::download_file(&info.zip_url, &zip_path, Some(&|done, total| {
        if total > 0 {
            let pct = (done as f64 / total as f64 * 100.0) as u32;
            eprint!("\r  {done}/{total} bytes ({pct}%)   ");
        }
    }))
    .await?;
    eprintln!();

    // Step 3: Verify checksum if available
    if let Some(ref checksum_url) = info.checksum_url {
        println!("Verifying checksum...");
        let expected = assets::download_checksum(checksum_url).await?;
        assets::verify_checksum(&actual_hash, &expected)?;
        println!("Checksum OK.");
    }

    // Step 4: Extract zip
    let staging_dir = tmp_dir.path().join("staging");
    std::fs::create_dir_all(&staging_dir)?;
    println!("Extracting...");
    let extracted_files = assets::extract_zip(&zip_path, &staging_dir)?;
    println!("Extracted {} files.", extracted_files.len());

    // Step 5: Verify individual files against manifest (if present)
    let manifest_path = staging_dir.join("version.json");
    if manifest_path.exists() {
        let manifest_text = std::fs::read_to_string(&manifest_path)?;
        let manifest: ReleaseManifest = serde_json::from_str(&manifest_text)
            .map_err(|e| UpdateError::Manifest(e.to_string()))?;

        for (name, entry) in &manifest.files {
            let file_path = staging_dir.join(name);
            if file_path.exists() {
                let hash = assets::sha256_file(&file_path)?;
                if hash != entry.sha256 {
                    return Err(UpdateError::ChecksumMismatch {
                        expected: entry.sha256.clone(),
                        actual: hash,
                    });
                }
            }
        }
        println!("Manifest verification OK.");
    }

    // Step 6: Apply update
    // Filter out version.json from the files to install
    let install_files: Vec<String> = extracted_files
        .into_iter()
        .filter(|f| f != "version.json")
        .collect();

    let plan = apply::UpdatePlan::new(
        install_dir.to_path_buf(),
        staging_dir.clone(),
        &install_files,
    )?;

    println!("Applying update...");
    apply::apply_update(&plan)?;

    // Step 7: Write update record
    write_update_record(install_dir, &info.version)?;

    println!("Update to v{} complete!", info.version);
    println!("Please restart the application to use the new version.");

    Ok(info.version)
}

/// Roll back to the previous version using the latest backup.
pub fn perform_rollback(install_dir: &Path) -> Result<(), UpdateError> {
    let backup_dir = apply::find_latest_backup(install_dir)
        .ok_or_else(|| UpdateError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No backup directory found to roll back from",
        )))?;

    println!("Rolling back from backup: {}", backup_dir.display());

    // List files in the backup
    let files: Vec<String> = std::fs::read_dir(&backup_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    if files.is_empty() {
        return Err(UpdateError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Backup directory is empty",
        )));
    }

    let plan = apply::UpdatePlan {
        install_dir: install_dir.to_path_buf(),
        staging_dir: backup_dir.clone(),
        backup_dir: install_dir.join(".rollback-tmp"),
        files: files
            .iter()
            .map(|name| apply::FileUpdate {
                filename: name.clone(),
                source: backup_dir.join(name),
                target: install_dir.join(name),
                backup: install_dir.join(".rollback-tmp").join(name),
            })
            .collect(),
    };

    std::fs::create_dir_all(&plan.backup_dir)?;
    apply::apply_update(&plan)?;

    // Clean up the rollback tmp
    let _ = std::fs::remove_dir_all(install_dir.join(".rollback-tmp"));
    // Clean up the backup dir we just used
    let _ = std::fs::remove_dir_all(&backup_dir);

    println!("Rollback complete.");
    Ok(())
}

/// Detect the install directory from the updater executable's location.
pub fn detect_install_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn write_update_record(install_dir: &Path, version: &Version) -> Result<(), UpdateError> {
    let record = serde_json::json!({
        "version": version.to_string(),
        "updated_at": chrono_lite_now(),
    });
    let path = install_dir.join("last-update.json");
    std::fs::write(path, serde_json::to_string_pretty(&record).unwrap())?;
    Ok(())
}

fn chrono_lite_now() -> String {
    // Simple ISO-ish timestamp without pulling in chrono
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    format!("{}", d.as_secs())
}
