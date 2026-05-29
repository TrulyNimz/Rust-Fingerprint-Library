//! Round-trip test for a generated keypair against the production verifier.
//!
//! Usage:
//!     cargo run --example verify_self_test -p fingerprint-updater -- \
//!         <private-key-path> <public-key-hex>
//!
//! Reads the 32-byte private key, signs a probe message, and verifies it
//! using the same `assets::verify_signature` function that every installed
//! updater will use. If this passes, the keypair is wired up correctly for
//! production signing.

use ed25519_dalek::{Signer, SigningKey};
use fingerprint_updater::assets::verify_signature;
use std::convert::TryInto;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: cargo run --example verify_self_test -p fingerprint-updater -- \
             <private-key-path> <public-key-hex>"
        );
        std::process::exit(2);
    }
    let key_path = &args[1];
    let pub_hex = &args[2];

    let bytes = std::fs::read(key_path).expect("read private key file");
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .expect("private key file must be exactly 32 bytes");
    let sk = SigningKey::from_bytes(&seed);

    // Probe message — content doesn't matter, only that we sign and verify
    // the *same* bytes via the production verifier.
    let probe: &[u8] = b"production verify_signature round-trip probe";
    let sig = sk.sign(probe).to_bytes();

    match verify_signature(probe, &sig, pub_hex) {
        Ok(()) => {
            println!("PASS: assets::verify_signature accepted the freshly-signed probe.");
            println!("Keypair is wired up correctly for production signing.");
        }
        Err(e) => {
            eprintln!("FAIL: production verifier rejected the keypair's signature.");
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Likely causes:");
            eprintln!("  - public-key hex doesn't match private key (typo?)");
            eprintln!("  - private key file is not 32 raw bytes");
            std::process::exit(1);
        }
    }

    // Also assert that a tampered message is rejected — guards against any
    // future bug where the verifier accepts everything.
    let tampered: &[u8] = b"production verify_signature round-trip probe!";
    match verify_signature(tampered, &sig, pub_hex) {
        Ok(()) => {
            eprintln!("FAIL: verifier accepted a signature over different bytes — broken.");
            std::process::exit(1);
        }
        Err(_) => {
            println!("PASS: verifier correctly rejects a tampered message.");
        }
    }
}
