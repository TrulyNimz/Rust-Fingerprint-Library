use napi_derive::napi;

#[napi(object)]
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub image_width: u32,
    pub image_height: u32,
    pub dpi: u32,
}

#[napi(object)]
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub image: Vec<u8>,
    pub quality: u8,
    pub template: Vec<u8>,
    pub timestamp: i64,
}

#[napi(object)]
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub matched: bool,
    pub score: u32,
    pub user_id: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone)]
pub struct Template {
    pub user_id: String,
    pub data: Vec<u8>,
    pub created_at: i64,
}

#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    pub timeout_ms: Option<u32>,
    pub min_quality: Option<u8>,
    pub auto_capture: Option<bool>,
}

#[napi(string_enum)]
#[derive(Debug)]
pub enum ScannerStatus {
    Connected,
    Disconnected,
    Capturing,
    Error,
}

#[napi(object)]
#[derive(Debug, Clone)]
pub struct ScannerStatusInfo {
    pub status: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
}
