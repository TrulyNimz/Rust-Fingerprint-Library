//! One-shot Ed25519 keypair generator for the fingerprint-sdk release signer.
//!
//! Usage:
//!     cargo run --example keygen -p fingerprint-updater -- <private-key-path>
//!
//! The private key is written as 32 raw bytes to <private-key-path>. The
//! corresponding public key is printed to stdout as 64 hex chars — that value
//! is what you set as `FINGERPRINT_UPDATE_PUBKEY` when building release
//! versions of the updater. Lose the private key and you can no longer sign
//! releases that existing installs will trust.
//!
//! Randomness comes from the OS CSPRNG via the `getrandom` crate
//! (`BCryptGenRandom` on Windows, `getrandom(2)` on Linux).

use ed25519_dalek::{Signer, SigningKey, Verifier};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: cargo run --example keygen -p fingerprint-updater -- <private-key-path>");
        eprintln!();
        eprintln!("Writes a 32-byte Ed25519 private key to <private-key-path>");
        eprintln!("and prints the corresponding public key (64 hex chars) to stdout.");
        std::process::exit(2);
    }
    let out_path = PathBuf::from(&args[1]);

    // Refuse to silently overwrite an existing key — losing a private key is
    // a real operational hazard, so this prompt forces the operator to delete
    // it manually if they really mean to rotate.
    if out_path.exists() {
        eprintln!(
            "ERROR: refusing to overwrite existing file: {}",
            out_path.display()
        );
        eprintln!("Delete the file manually if you intend to rotate the key.");
        std::process::exit(1);
    }

    // Pull 32 bytes from the OS CSPRNG. This seed IS the private key — every
    // future signing operation derives from it. If this read fails the OS is
    // in a bad state and we should not produce a weak key.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS CSPRNG must be available");

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // Self-check: sign a known message and verify it round-trips. Catches a
    // bad RNG / corrupted memory before the key is ever used in production.
    let probe = b"fingerprint-sdk keygen self-test";
    let probe_sig = signing_key.sign(probe);
    verifying_key
        .verify(probe, &probe_sig)
        .expect("freshly generated key failed self-verification");

    // Write the private key. Raw 32 bytes, no PEM, no armor — matches what
    // updater/src/assets.rs::verify_signature expects on the public side.
    let priv_bytes: [u8; 32] = signing_key.to_bytes();
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir for private key");
    }
    std::fs::write(&out_path, priv_bytes).expect("write private key file");

    // Tighten file permissions where the platform allows it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&out_path, perms);
    }

    let pub_hex: String = verifying_key
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    // Wipe the seed copy in our stack frame so it doesn't linger longer than
    // necessary. (The signing_key still holds a copy on the heap; that's fine
    // because we're about to drop the whole process.)
    seed.iter_mut().for_each(|b| *b = 0);

    println!("PUBLIC_KEY={pub_hex}");
    eprintln!();
    eprintln!("Private key (32 bytes) written to: {}", out_path.display());
    eprintln!("Self-test (sign + verify with this keypair): PASSED");
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Move the private key to secure storage (HSM, password manager,");
    eprintln!("     encrypted USB). The current path is for convenience, not security.");
    eprintln!("  2. Build release binaries with:");
    eprintln!("       FINGERPRINT_UPDATE_PUBKEY={pub_hex} \\");
    eprintln!("           cargo build --release -p fingerprint-updater");
    eprintln!("  3. Sign each release zip with:");
    eprintln!("       openssl pkeyutl -sign -rawin \\");
    eprintln!("           -inkey <private-key-as-pkcs8.pem> \\");
    eprintln!("           -in fingerprint-sdk-v<ver>-win32-x64.zip \\");
    eprintln!("           -out fingerprint-sdk-v<ver>-win32-x64.sig");
    eprintln!("     (Convert the raw 32-byte key to PKCS#8 first if your signer needs PEM.)");
}
