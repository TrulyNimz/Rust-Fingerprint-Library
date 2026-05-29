use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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

/// Download a raw binary asset (e.g. an ed25519 signature) into memory.
pub async fn download_bytes(url: &str) -> Result<Vec<u8>, UpdateError> {
    let client = reqwest::Client::builder()
        .user_agent("fingerprint-updater")
        .build()?;

    let mut req = client.get(url);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    req = req.header("Accept", "application/octet-stream");

    let resp = req.send().await?.error_for_status()?;
    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}

/// Parse a 32-byte Ed25519 public key from a hex string (64 chars, optionally
/// `0x`-prefixed, whitespace-tolerant).
fn parse_pubkey_hex(hex: &str) -> Result<[u8; 32], UpdateError> {
    let cleaned: String = hex
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    if cleaned.len() != 64 {
        return Err(UpdateError::SignatureInvalid(format!(
            "public key must be 64 hex chars, got {}",
            cleaned.len()
        )));
    }

    let mut out = [0u8; 32];
    for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| {
            UpdateError::SignatureInvalid("public key contains non-ASCII".into())
        })?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| {
            UpdateError::SignatureInvalid("public key contains non-hex chars".into())
        })?;
    }
    Ok(out)
}

/// Verify an Ed25519 signature over `message` using a hex-encoded public key.
/// The signature must be exactly 64 raw bytes (the standard Ed25519 layout).
pub fn verify_signature(
    message: &[u8],
    signature_bytes: &[u8],
    pubkey_hex: &str,
) -> Result<(), UpdateError> {
    if signature_bytes.len() != 64 {
        return Err(UpdateError::SignatureInvalid(format!(
            "signature must be 64 bytes, got {}",
            signature_bytes.len()
        )));
    }

    let pubkey = parse_pubkey_hex(pubkey_hex)?;
    let vk = VerifyingKey::from_bytes(&pubkey)
        .map_err(|e| UpdateError::SignatureInvalid(format!("invalid public key: {e}")))?;

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    vk.verify(message, &signature)
        .map_err(|e| UpdateError::SignatureInvalid(e.to_string()))?;
    Ok(())
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

/// Maximum uncompressed size per file inside the release zip.
const ZIP_PER_FILE_LIMIT: u64 = 64 * 1024 * 1024;
/// Maximum total uncompressed size across all files in the release zip.
const ZIP_TOTAL_LIMIT: u64 = 256 * 1024 * 1024;

/// Extract a zip archive to the destination directory using production caps.
/// See `extract_zip_with_limits` for the security model.
pub fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<Vec<String>, UpdateError> {
    extract_zip_with_limits(zip_path, dest_dir, ZIP_PER_FILE_LIMIT, ZIP_TOTAL_LIMIT)
}

/// Extract a zip with explicit caps. ZipSlip is mitigated by reducing every
/// entry name to its bare file component before joining `dest_dir`. Zip bombs
/// are caught by (a) rejecting entries whose declared uncompressed size
/// already exceeds the cap and (b) wrapping the actual copy in `take(per_file
/// + 1)` so a lying entry can't stream past the limit.
pub(crate) fn extract_zip_with_limits(
    zip_path: &Path,
    dest_dir: &Path,
    per_file_limit: u64,
    total_limit: u64,
) -> Result<Vec<String>, UpdateError> {
    let file =
        std::fs::File::open(zip_path).map_err(|e| UpdateError::ZipError(e.to_string()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| UpdateError::ZipError(e.to_string()))?;

    let mut extracted = Vec::new();
    let mut total_written: u64 = 0;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UpdateError::ZipError(e.to_string()))?;

        let name = entry.name().to_string();

        // Skip directories
        if entry.is_dir() {
            continue;
        }

        // Up-front check on declared uncompressed size.
        let claimed = entry.size();
        if claimed > per_file_limit {
            return Err(UpdateError::ZipError(format!(
                "entry {name} declares uncompressed size {claimed} > per-file limit {per_file_limit}"
            )));
        }
        if total_written.saturating_add(claimed) > total_limit {
            return Err(UpdateError::ZipError(format!(
                "zip total uncompressed size would exceed {total_limit} bytes"
            )));
        }

        // Sanitize: only use the filename, no directory traversal.
        let file_name = Path::new(&name)
            .file_name()
            .ok_or_else(|| UpdateError::ZipError(format!("Invalid entry name: {name}")))?;

        let out_path = dest_dir.join(file_name);
        let mut out_file =
            std::fs::File::create(&out_path).map_err(|e| UpdateError::ZipError(e.to_string()))?;

        // Defense-in-depth: cap actual bytes copied so a malicious entry that
        // lies about `size()` can't stream past the limit.
        use std::io::Read;
        let mut limited = (&mut entry).take(per_file_limit + 1);
        let written = std::io::copy(&mut limited, &mut out_file)
            .map_err(|e| UpdateError::ZipError(e.to_string()))?;

        if written > per_file_limit {
            let _ = std::fs::remove_file(&out_path);
            return Err(UpdateError::ZipError(format!(
                "entry {name} exceeded per-file limit during extraction (zip bomb suspected)"
            )));
        }

        total_written = total_written.saturating_add(written);
        if total_written > total_limit {
            let _ = std::fs::remove_file(&out_path);
            return Err(UpdateError::ZipError(format!(
                "zip total uncompressed size exceeded {total_limit} bytes"
            )));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Write;
    use std::path::PathBuf;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    // ─── verify_signature ────────────────────────────────────────────────────

    /// Deterministic test keypair (seed of zero). Never use in production.
    fn test_keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0u8; 32]);
        let vk = sk.verifying_key();
        let hex: String = vk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        (sk, hex)
    }

    #[test]
    fn verify_signature_accepts_valid_signature() {
        let (sk, pk_hex) = test_keypair();
        let msg = b"release zip contents";
        let sig = sk.sign(msg);
        verify_signature(msg, &sig.to_bytes(), &pk_hex)
            .expect("a freshly signed message must verify");
    }

    #[test]
    fn verify_signature_rejects_tampered_message() {
        let (sk, pk_hex) = test_keypair();
        let sig = sk.sign(b"original");
        match verify_signature(b"tampered", &sig.to_bytes(), &pk_hex) {
            Err(UpdateError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[test]
    fn verify_signature_rejects_wrong_pubkey() {
        let (sk, _) = test_keypair();
        let other = SigningKey::from_bytes(&[7u8; 32]);
        let other_pk_hex: String = other
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let sig = sk.sign(b"x");
        match verify_signature(b"x", &sig.to_bytes(), &other_pk_hex) {
            Err(UpdateError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[test]
    fn verify_signature_rejects_wrong_length() {
        let (_, pk_hex) = test_keypair();
        match verify_signature(b"x", &[0u8; 32], &pk_hex) {
            Err(UpdateError::SignatureInvalid(m)) if m.contains("64 bytes") => {}
            other => panic!("expected length error, got {:?}", other),
        }
    }

    // ─── parse_pubkey_hex ────────────────────────────────────────────────────

    #[test]
    fn parse_pubkey_hex_accepts_plain_hex() {
        let hex = "0".repeat(63) + "f";
        let bytes = parse_pubkey_hex(&hex).unwrap();
        assert_eq!(bytes[31], 0x0f);
        assert!(bytes[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn parse_pubkey_hex_strips_0x_and_whitespace() {
        let hex = "0x 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f \
                   10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f";
        let bytes = parse_pubkey_hex(hex).unwrap();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[15], 0x0f);
        assert_eq!(bytes[31], 0x1f);
    }

    #[test]
    fn parse_pubkey_hex_rejects_wrong_length() {
        match parse_pubkey_hex("abcd") {
            Err(UpdateError::SignatureInvalid(m)) if m.contains("64 hex chars") => {}
            other => panic!("expected length error, got {:?}", other),
        }
    }

    #[test]
    fn parse_pubkey_hex_rejects_non_hex_chars() {
        match parse_pubkey_hex(&"zz".repeat(32)) {
            Err(UpdateError::SignatureInvalid(_)) => {}
            other => panic!("expected non-hex error, got {:?}", other),
        }
    }

    // ─── verify_checksum ─────────────────────────────────────────────────────

    #[test]
    fn verify_checksum_accepts_match() {
        verify_checksum("deadbeef", "deadbeef").unwrap();
    }

    #[test]
    fn verify_checksum_rejects_mismatch() {
        match verify_checksum("deadbeef", "cafebabe") {
            Err(UpdateError::ChecksumMismatch { expected, actual }) => {
                assert_eq!(expected, "cafebabe");
                assert_eq!(actual, "deadbeef");
            }
            other => panic!("expected ChecksumMismatch, got {:?}", other),
        }
    }

    // ─── extract_zip ─────────────────────────────────────────────────────────

    fn build_zip(dir: &Path, name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        let opts = SimpleFileOptions::default();
        for (entry_name, data) in entries {
            writer.start_file(*entry_name, opts).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        path
    }

    #[test]
    fn extract_zip_extracts_normal_entries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let zip = build_zip(
            tmp.path(),
            "ok.zip",
            &[("hello.txt", b"world"), ("data.bin", &[1, 2, 3, 4])],
        );
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();

        let extracted = extract_zip(&zip, &dest).unwrap();
        assert_eq!(extracted.len(), 2);
        assert!(extracted.contains(&"hello.txt".to_string()));
        assert!(extracted.contains(&"data.bin".to_string()));
        assert_eq!(std::fs::read(dest.join("hello.txt")).unwrap(), b"world");
        assert_eq!(std::fs::read(dest.join("data.bin")).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn extract_zip_flattens_path_traversal() {
        let tmp = tempfile::TempDir::new().unwrap();
        let zip = build_zip(tmp.path(), "evil.zip", &[("../../etc/evil.txt", b"pwn")]);
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();

        let extracted = extract_zip(&zip, &dest).unwrap();
        assert_eq!(extracted, vec!["evil.txt"]);
        // File lands inside dest, NOT at any traversed location.
        assert!(dest.join("evil.txt").exists());
        assert!(!tmp.path().join("evil.txt").exists());
        assert!(!tmp.path().parent().unwrap().join("evil.txt").exists());
    }

    #[test]
    fn extract_zip_rejects_oversized_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let zip = build_zip(tmp.path(), "big.zip", &[("big.bin", &vec![0u8; 2048])]);
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();

        // per_file=1024, total=4096 — entry's 2048 bytes blow per-file cap.
        match extract_zip_with_limits(&zip, &dest, 1024, 4096) {
            Err(UpdateError::ZipError(m)) if m.contains("per-file limit") => {}
            other => panic!("expected per-file limit error, got {:?}", other),
        }
        // Nothing should have been extracted.
        assert!(!dest.join("big.bin").exists());
    }

    #[test]
    fn extract_zip_rejects_total_over_limit() {
        let tmp = tempfile::TempDir::new().unwrap();
        let zip = build_zip(
            tmp.path(),
            "many.zip",
            &[
                ("a.bin", &vec![0u8; 600]),
                ("b.bin", &vec![0u8; 600]),
            ],
        );
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();

        // per_file=2048 (fine), total=1000 — first entry passes, second tips over.
        match extract_zip_with_limits(&zip, &dest, 2048, 1000) {
            Err(UpdateError::ZipError(m)) if m.contains("total uncompressed") => {}
            other => panic!("expected total cap error, got {:?}", other),
        }
    }

    #[test]
    fn extract_zip_within_limits_succeeds() {
        let tmp = tempfile::TempDir::new().unwrap();
        let zip = build_zip(tmp.path(), "ok.zip", &[("a.bin", &vec![0u8; 500])]);
        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();

        let extracted = extract_zip_with_limits(&zip, &dest, 1024, 4096).unwrap();
        assert_eq!(extracted, vec!["a.bin"]);
    }
}
