#![allow(dead_code)]

mod fp_core;
mod update_check;
mod vendors;

use std::sync::{Mutex, MutexGuard};

use napi_derive::napi;

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;
use crate::fp_core::types::{
    CaptureOptions, DeviceInfo, MatchResult, ScanResult, ScannerStatusInfo, Template,
};
use crate::vendors::get_scanner;
use crate::vendors::secugen::constants::{DEFAULT_MIN_QUALITY, DEFAULT_TIMEOUT_MS};

pub use crate::update_check::check_for_update;

static SCANNER: Mutex<Option<Box<dyn FingerprintScanner>>> = Mutex::new(None);

fn join_err_to_napi(e: tokio::task::JoinError) -> napi::Error {
    let reason = if e.is_panic() {
        "Vendor library panicked during operation"
    } else if e.is_cancelled() {
        "Operation cancelled"
    } else {
        "Operation aborted"
    };
    napi::Error::new(
        napi::Status::GenericFailure,
        format!("[SDK_ERROR] {}", reason),
    )
}

/// Take the global scanner lock, recovering from poisoning. A poisoned mutex
/// only means a previous holder panicked — the inner state is still readable,
/// and a process-wide wedge serves nobody.
fn lock_scanner() -> MutexGuard<'static, Option<Box<dyn FingerprintScanner>>> {
    SCANNER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Await a `spawn_blocking` task, turning a JoinError (task panic or
/// cancellation) into a clean `[SDK_ERROR]` napi error instead of
/// re-raising the panic into the napi runtime.
async fn join_blocking<T>(
    handle: tokio::task::JoinHandle<Result<T, FingerprintError>>,
) -> napi::Result<T> {
    handle
        .await
        .map_err(join_err_to_napi)?
        .map_err(napi::Error::from)
}

fn with_scanner<F, T>(f: F) -> Result<T, FingerprintError>
where
    F: FnOnce(&dyn FingerprintScanner) -> Result<T, FingerprintError>,
{
    let guard = lock_scanner();
    let scanner = guard.as_ref().ok_or(FingerprintError::NotInitialized)?;
    f(scanner.as_ref())
}

#[napi]
pub async fn init_scanner(vendor: Option<String>) -> napi::Result<DeviceInfo> {
    join_blocking(tokio::task::spawn_blocking(move || {
        // L-4 pre-check: refuse to overwrite an existing scanner.
        if lock_scanner().is_some() {
            return Err(FingerprintError::SdkError(
                "Scanner already initialized; call disconnectScanner() first".to_string(),
            ));
        }

        let scanner = get_scanner(vendor.as_deref())?;
        let info = scanner.init()?;

        // Re-check after the (possibly slow) hardware init. If a concurrent
        // caller raced past us, drop our scanner — its Drop disconnects.
        let mut guard = lock_scanner();
        if guard.is_some() {
            drop(scanner);
            return Err(FingerprintError::SdkError(
                "Scanner already initialized by concurrent call; this attempt was discarded"
                    .to_string(),
            ));
        }
        *guard = Some(scanner);
        Ok(info)
    }))
    .await
}

#[napi]
pub async fn capture_fingerprint(options: Option<CaptureOptions>) -> napi::Result<ScanResult> {
    join_blocking(tokio::task::spawn_blocking(move || {
        let opts = options.unwrap_or_default();
        let timeout = opts.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        let quality = opts.min_quality.unwrap_or(DEFAULT_MIN_QUALITY);
        with_scanner(|s| s.capture(timeout, quality))
    }))
    .await
}

#[napi]
pub async fn enroll_user(user_id: String, samples: Option<u8>) -> napi::Result<Template> {
    join_blocking(tokio::task::spawn_blocking(move || {
        let count = samples.unwrap_or(0);
        with_scanner(|s| s.enroll(&user_id, count))
    }))
    .await
}

#[napi]
pub async fn verify_user(user_id: String, template: Template) -> napi::Result<MatchResult> {
    join_blocking(tokio::task::spawn_blocking(move || {
        with_scanner(|s| s.verify(&user_id, &template))
    }))
    .await
}

#[napi]
pub async fn identify_user(templates: Vec<Template>) -> napi::Result<MatchResult> {
    join_blocking(tokio::task::spawn_blocking(move || {
        with_scanner(|s| s.identify(&templates))
    }))
    .await
}

#[napi]
pub async fn disconnect_scanner() -> napi::Result<()> {
    join_blocking(tokio::task::spawn_blocking(move || {
        let mut guard = lock_scanner();
        if let Some(scanner) = guard.take() {
            scanner.disconnect()
        } else {
            Ok(())
        }
    }))
    .await
}

#[napi]
pub async fn get_scanner_status() -> napi::Result<ScannerStatusInfo> {
    let guard = lock_scanner();
    match guard.as_ref() {
        Some(_) => Ok(ScannerStatusInfo {
            status: "Connected".into(),
            vendor: Some("SecuGen".into()),
            model: Some("Hamster Plus".into()),
        }),
        None => Ok(ScannerStatusInfo {
            status: "Disconnected".into(),
            vendor: None,
            model: None,
        }),
    }
}
