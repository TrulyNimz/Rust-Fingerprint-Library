//! Sign a release zip with the fingerprint-sdk Ed25519 signing key.
//!
//! Usage:
//!     FINGERPRINT_UPDATE_PUBKEY=<hex> \
//!         cargo run --example sign_release -p fingerprint-updater --release -- \
//!             <private-key-path> <zip-path> [output-sig-path]
//!
//! Writes a 64-byte raw Ed25519 signature next to <zip-path> with the `.sig`
//! extension (or at the explicit output path if supplied). The output filename
//! is what the updater expects to fetch from GitHub Releases — see
//! `version::asset_signature_name`.
//!
//! Belt-and-braces safety: this example refuses to write the signature unless
//!   (1) the private key on disk derives the public key in
//!       FINGERPRINT_UPDATE_PUBKEY (so you can't accidentally sign with the
//!       wrong key for a build), AND
//!   (2) the signature it just produced round-trips through the actual
//!       `assets::verify_signature` function that every install will run.
//!
//! Both checks happen BEFORE the .sig file is written.

use ed25519_dalek::{Signer, SigningKey, Verifier};
use fingerprint_updater::assets::verify_signature;
use std::path::PathBuf;
use zeroize::Zeroize;

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("ERROR: {}", msg.as_ref());
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !(3..=4).contains(&args.len()) {
        eprintln!(
            "Usage: FINGERPRINT_UPDATE_PUBKEY=<hex> \\\n  \
             cargo run --example sign_release -p fingerprint-updater --release -- \\\n  \
             <private-key-path> <zip-path> [output-sig-path]"
        );
        std::process::exit(2);
    }
    let key_path = PathBuf::from(&args[1]);
    let zip_path = PathBuf::from(&args[2]);
    let sig_path = if args.len() == 4 {
        PathBuf::from(&args[3])
    } else {
        // Default: same dir, .zip -> .sig.
        let mut p = zip_path.clone();
        if !p.set_extension("sig") {
            die("input zip path has no file name; pass an explicit output-sig-path");
        }
        p
    };

    // The expected public key MUST match what release builds bake in. Pulling
    // it from the same env var the build uses keeps signing and verifying in
    // lockstep — if you forget to set it here, signing aborts before producing
    // a bad .sig.
    let expected_pub_hex = match std::env::var("FINGERPRINT_UPDATE_PUBKEY") {
        Ok(v) => v.trim().trim_start_matches("0x").to_ascii_lowercase(),
        Err(_) => die(
            "FINGERPRINT_UPDATE_PUBKEY env var is not set. Set it to the 64-hex \
             public key that release binaries are built with.",
        ),
    };
    if expected_pub_hex.len() != 64 || !expected_pub_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        die("FINGERPRINT_UPDATE_PUBKEY must be exactly 64 hex chars");
    }

    if sig_path.exists() {
        die(format!(
            "refusing to overwrite existing signature file: {}\n\
             Delete it manually if you intend to re-sign.",
            sig_path.display()
        ));
    }
    if !zip_path.exists() {
        die(format!("input zip not found: {}", zip_path.display()));
    }
    if !key_path.exists() {
        die(format!("private key not found: {}", key_path.display()));
    }

    // ─── Load and consume the private key ─────────────────────────────────
    // Read into a Vec, copy into a fixed-size array, then wipe the Vec.
    let mut key_buf = std::fs::read(&key_path).unwrap_or_else(|e| die(format!("read key: {e}")));
    if key_buf.len() != 32 {
        key_buf.zeroize();
        die(format!(
            "private key file must be exactly 32 bytes, got {}",
            key_buf.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key_buf);
    key_buf.zeroize();

    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize(); // SigningKey now owns the only live copy
    let verifying_key = signing_key.verifying_key();

    // ─── Guard 1: private key must derive the expected public key ────────
    let actual_pub_hex: String = verifying_key
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    if actual_pub_hex != expected_pub_hex {
        die(format!(
            "private key does NOT match FINGERPRINT_UPDATE_PUBKEY\n  \
             expected: {expected_pub_hex}\n  \
             actual:   {actual_pub_hex}\n\
             You are about to sign with a key the release binary cannot verify."
        ));
    }
    eprintln!(
        "[1/3] Private key matches FINGERPRINT_UPDATE_PUBKEY: {}",
        &expected_pub_hex[..16]
    );

    // ─── Sign the zip ────────────────────────────────────────────────────
    let zip_bytes = std::fs::read(&zip_path).unwrap_or_else(|e| die(format!("read zip: {e}")));
    eprintln!(
        "[2/3] Read {} bytes from {}",
        zip_bytes.len(),
        zip_path.display()
    );
    let signature = signing_key.sign(&zip_bytes);
    let sig_bytes: [u8; 64] = signature.to_bytes();

    // Sanity: ed25519-dalek's own verifier accepts the signature we just
    // produced. Should never fail; if it does, the key state is corrupted.
    verifying_key
        .verify(&zip_bytes, &signature)
        .unwrap_or_else(|e| die(format!("internal self-verify failed: {e}")));

    // ─── Guard 2: production verifier accepts the signature ──────────────
    // This is the exact code path that runs on every install. If this fails,
    // do NOT write the .sig file — something is wrong.
    verify_signature(&zip_bytes, &sig_bytes, &expected_pub_hex)
        .unwrap_or_else(|e| die(format!("production verify_signature rejected our signature: {e}")));
    eprintln!("[3/3] Production assets::verify_signature accepts the signature.");

    // ─── Write the .sig file ─────────────────────────────────────────────
    std::fs::write(&sig_path, sig_bytes)
        .unwrap_or_else(|e| die(format!("write signature: {e}")));

    eprintln!();
    eprintln!(
        "Signed {} ({} bytes) -> {}",
        zip_path.display(),
        zip_bytes.len(),
        sig_path.display()
    );
    eprintln!("Upload {} alongside the zip in the GitHub release.", sig_path.display());
}
