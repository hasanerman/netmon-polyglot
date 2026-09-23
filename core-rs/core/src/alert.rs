use std::net::IpAddr;

use serde::Deserialize;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSource {
    Rule = 0,
    Anomaly = 1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub ts_us: u64,
    pub source: AlertSource,
    pub severity: Severity,
    pub rule_id: String,
    pub message: String,
    pub src: Option<IpAddr>,
    pub score: f64,
}
