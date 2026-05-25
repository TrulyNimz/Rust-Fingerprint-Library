use std::fs;
use std::path::{Path, PathBuf};

use crate::github::UpdateError;

pub struct UpdatePlan {
    pub install_dir: PathBuf,
    pub staging_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub files: Vec<FileUpdate>,
}

pub struct FileUpdate {
    pub filename: String,
    pub source: PathBuf,
    pub target: PathBuf,
    pub backup: PathBuf,
}

impl UpdatePlan {
    pub fn new(
        install_dir: PathBuf,
        staging_dir: PathBuf,
        filenames: &[String],
    ) -> Result<Self, UpdateError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let backup_dir = install_dir.join(format!(".update-backup-{timestamp}"));
        fs::create_dir_all(&backup_dir)?;

        let files = filenames
            .iter()
            .map(|name| FileUpdate {
                filename: name.clone(),
                source: staging_dir.join(name),
                target: install_dir.join(name),
                backup: backup_dir.join(name),
            })
            .collect();

        Ok(Self {
            install_dir,
            staging_dir,
            backup_dir,
            files,
        })
    }
}

/// Apply the update: back up old files, replace with new ones.
/// On any failure, automatically rolls back.
pub fn apply_update(plan: &UpdatePlan) -> Result<(), UpdateError> {
    let mut applied: Vec<&FileUpdate> = Vec::new();

    for file in &plan.files {
        if let Err(e) = replace_file(file) {
            eprintln!("Failed to replace {}: {e}", file.filename);
            // Rollback everything applied so far
            for done in applied.iter().rev() {
                if let Err(re) = restore_file(done) {
                    eprintln!("Rollback failed for {}: {re}", done.filename);
                }
            }
            return Err(e);
        }
        applied.push(file);
    }

    println!("All {} files updated successfully.", applied.len());
    Ok(())
}

/// Roll back an entire update from the backup directory.
pub fn rollback(plan: &UpdatePlan) -> Result<(), UpdateError> {
    let mut errors = Vec::new();
    for file in &plan.files {
        if let Err(e) = restore_file(file) {
            errors.push(format!("{}: {e}", file.filename));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(UpdateError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Rollback errors: {}", errors.join(", ")),
        )))
    }
}

/// Replace a single file: back up the old, move in the new.
fn replace_file(file: &FileUpdate) -> Result<(), UpdateError> {
    // Back up existing file if it exists
    if file.target.exists() {
        // Try normal rename first
        match fs::rename(&file.target, &file.backup) {
            Ok(()) => {}
            Err(_) => {
                // File may be locked (loaded DLL); try Windows rename API
                #[cfg(windows)]
                {
                    windows_rename(&file.target, &file.backup)?;
                }
                #[cfg(not(windows))]
                {
                    return Err(UpdateError::Io(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("Cannot rename locked file: {}", file.target.display()),
                    )));
                }
            }
        }
    }

    // Move new file into place
    fs::rename(&file.source, &file.target).or_else(|_| -> Result<(), UpdateError> {
        // Cross-device: fall back to copy + delete
        fs::copy(&file.source, &file.target)?;
        fs::remove_file(&file.source)?;
        Ok(())
    })?;

    Ok(())
}

/// Restore a single file from backup.
fn restore_file(file: &FileUpdate) -> Result<(), UpdateError> {
    if file.backup.exists() {
        // Remove the new file if it's in place
        if file.target.exists() {
            let _ = fs::remove_file(&file.target);
        }
        fs::rename(&file.backup, &file.target)?;
    }
    Ok(())
}

/// Windows-specific rename using MoveFileExW (works on loaded DLLs).
#[cfg(windows)]
fn windows_rename(from: &Path, to: &Path) -> Result<(), UpdateError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING};

    fn to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    let from_w = to_wide(from);
    let to_w = to_wide(to);

    let ok = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };

    if ok == 0 {
        Err(UpdateError::Io(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Clean up stale `.old` files and old backup directories from the install dir.
pub fn cleanup_old_files(install_dir: &Path) -> Result<(), UpdateError> {
    // Remove any .old files from previous updates
    if let Ok(entries) = fs::read_dir(install_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "old" {
                    let _ = fs::remove_file(&path);
                }
            }
            // Remove old backup dirs (keep at most the latest one)
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with(".update-backup-") && path.is_dir() {
                    let _ = fs::remove_dir_all(&path);
                }
            }
        }
    }
    Ok(())
}

/// Find the most recent backup directory in install_dir for rollback.
pub fn find_latest_backup(install_dir: &Path) -> Option<PathBuf> {
    let mut backups: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(install_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with(".update-backup-") && path.is_dir() {
                    backups.push(path);
                }
            }
        }
    }
    backups.sort();
    backups.pop()
}
