use serde::{Deserialize, Serialize};

/// Command sent from the 64-bit host to the 32-bit bridge over stdin.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum BridgeCommand {
    #[serde(rename = "init")]
    Init,

    #[serde(rename = "capture")]
    Capture {
        timeout_ms: u32,
        min_quality: u8,
    },

    #[serde(rename = "enroll")]
    Enroll {
        user_id: String,
        samples: u8,
    },

    #[serde(rename = "verify")]
    Verify {
        user_id: String,
        template_data: Vec<u8>,
    },

    #[serde(rename = "identify")]
    Identify {
        templates: Vec<TemplateEntry>,
    },

    #[serde(rename = "get_quality")]
    GetQuality {
        image: Vec<u8>,
    },

    #[serde(rename = "disconnect")]
    Disconnect,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TemplateEntry {
    pub user_id: String,
    pub data: Vec<u8>,
}

/// Response sent from the 32-bit bridge back to the host over stdout.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum BridgeResponse {
    #[serde(rename = "ok")]
    Ok { data: ResponseData },

    #[serde(rename = "error")]
    Error { code: String, message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResponseData {
    #[serde(rename = "device_info")]
    DeviceInfo {
        vendor: String,
        model: String,
        serial: String,
        firmware: String,
        image_width: u32,
        image_height: u32,
        dpi: u32,
    },

    #[serde(rename = "scan_result")]
    ScanResult {
        image: Vec<u8>,
        quality: u8,
        template: Vec<u8>,
        timestamp: i64,
    },

    #[serde(rename = "template")]
    Template {
        user_id: String,
        data: Vec<u8>,
        created_at: i64,
    },

    #[serde(rename = "match_result")]
    MatchResult {
        matched: bool,
        score: u32,
        user_id: Option<String>,
    },

    #[serde(rename = "quality")]
    Quality {
        score: u8,
    },

    #[serde(rename = "void")]
    Void,
}
