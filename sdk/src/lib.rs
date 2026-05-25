#![allow(dead_code)]

mod fp_core;
mod update_check;
mod vendors;

use std::sync::Mutex;

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

fn with_scanner<F, T>(f: F) -> Result<T, napi::Error>
where
    F: FnOnce(&dyn FingerprintScanner) -> Result<T, FingerprintError>,
{
    let guard = SCANNER.lock().unwrap();
    let scanner = guard
        .as_ref()
        .ok_or(FingerprintError::NotInitialized)?;
    f(scanner.as_ref()).map_err(Into::into)
}

#[napi]
pub async fn init_scanner(vendor: Option<String>) -> napi::Result<DeviceInfo> {
    tokio::task::spawn_blocking(move || {
        let scanner = get_scanner(vendor.as_deref())?;
        let info = scanner.init()?;
        *SCANNER.lock().unwrap() = Some(scanner);
        Ok(info)
    })
    .await
    .unwrap()
    .map_err(|e: FingerprintError| e.into())
}

#[napi]
pub async fn capture_fingerprint(options: Option<CaptureOptions>) -> napi::Result<ScanResult> {
    tokio::task::spawn_blocking(move || {
        let opts = options.unwrap_or_default();
        let timeout = opts.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        let quality = opts.min_quality.unwrap_or(DEFAULT_MIN_QUALITY);
        with_scanner(|s| s.capture(timeout, quality))
    })
    .await
    .unwrap()
}

#[napi]
pub async fn enroll_user(user_id: String, samples: Option<u8>) -> napi::Result<Template> {
    tokio::task::spawn_blocking(move || {
        let count = samples.unwrap_or(0);
        with_scanner(|s| s.enroll(&user_id, count))
    })
    .await
    .unwrap()
}

#[napi]
pub async fn verify_user(user_id: String, template: Template) -> napi::Result<MatchResult> {
    tokio::task::spawn_blocking(move || with_scanner(|s| s.verify(&user_id, &template)))
        .await
        .unwrap()
}

#[napi]
pub async fn identify_user(templates: Vec<Template>) -> napi::Result<MatchResult> {
    tokio::task::spawn_blocking(move || with_scanner(|s| s.identify(&templates)))
        .await
        .unwrap()
}

#[napi]
pub async fn disconnect_scanner() -> napi::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut guard = SCANNER.lock().unwrap();
        if let Some(scanner) = guard.take() {
            scanner.disconnect().map_err(napi::Error::from)
        } else {
            Ok(())
        }
    })
    .await
    .unwrap()
}

#[napi]
pub async fn get_scanner_status() -> napi::Result<ScannerStatusInfo> {
    let guard = SCANNER.lock().unwrap();
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
