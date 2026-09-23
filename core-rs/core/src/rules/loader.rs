use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use serde::Deserialize;

use crate::alert::Severity;

pub const SUPPORTED_VERSION: u32 = 1;
const DEFAULT_COOLDOWN_SECS: f64 = 60.0;
const DEFAULT_MIN_LABEL_LEN: usize = 30;
const DEFAULT_MIN_ENTROPY: f64 = 3.5;
const MAX_RULE_ID_LEN: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    PortScan,
    HostSweep,
    DnsTunnel,
    PacketRate,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub kind: RuleKind,
    pub severity: Severity,
    #[serde(default)]
    pub description: String,
    pub window_secs: f64,
    pub threshold: u32,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: f64,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_label_len")]
    pub min_label_len: usize,
    #[serde(default = "default_min_entropy")]
    pub min_entropy: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    version: u32,
    rules: Vec<RuleSpec>,
}

fn default_cooldown() -> f64 {
    DEFAULT_COOLDOWN_SECS
}

fn default_enabled() -> bool {
    true
}

fn default_min_label_len() -> usize {
    DEFAULT_MIN_LABEL_LEN
}

fn default_min_entropy() -> f64 {
    DEFAULT_MIN_ENTROPY
}

#[derive(Debug)]
pub enum RuleError {
    Io(std::io::Error),
    Syntax(String),
    Invalid { rule: String, reason: String },
    Version(u32),
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::Io(e) => write!(f, "cannot read rules: {e}"),
            RuleError::Syntax(e) => write!(f, "rules yaml: {e}"),
            RuleError::Invalid { rule, reason } => write!(f, "rule '{rule}': {reason}"),
            RuleError::Version(v) => write!(f, "rules version {v} not supported (expected {SUPPORTED_VERSION})"),
        }
    }
}

impl std::error::Error for RuleError {}

pub fn parse(text: &str) -> Result<Vec<RuleSpec>, RuleError> {
    let file: RuleFile = serde_yaml::from_str(text).map_err(|e| RuleError::Syntax(e.to_string()))?;
    if file.version != SUPPORTED_VERSION {
        return Err(RuleError::Version(file.version));
    }
    let mut seen = HashSet::new();
    for rule in &file.rules {
        validate(rule)?;
        if !seen.insert(rule.id.as_str()) {
            return Err(invalid(rule, "duplicate id"));
        }
    }
    Ok(file.rules)
}

pub fn load(path: &Path) -> Result<Vec<RuleSpec>, RuleError> {
    let text = std::fs::read_to_string(path).map_err(RuleError::Io)?;
    parse(&text)
}

fn validate(rule: &RuleSpec) -> Result<(), RuleError> {
    if rule.id.is_empty() || rule.id.len() > MAX_RULE_ID_LEN {
        return Err(invalid(rule, "id must be 1-63 characters"));
    }
    if !(rule.window_secs.is_finite() && rule.window_secs > 0.0) {
        return Err(invalid(rule, "window_secs must be a positive number"));
    }
    if !(rule.cooldown_secs.is_finite() && rule.cooldown_secs >= 0.0) {
        return Err(invalid(rule, "cooldown_secs must be zero or positive"));
    }
    if rule.threshold == 0 {
        return Err(invalid(rule, "threshold must be at least 1"));
    }
    if rule.kind == RuleKind::DnsTunnel && !(rule.min_entropy.is_finite() && rule.min_entropy >= 0.0) {
        return Err(invalid(rule, "min_entropy must be zero or positive"));
    }
    Ok(())
}

fn invalid(rule: &RuleSpec, reason: &str) -> RuleError {
    RuleError::Invalid {
        rule: rule.id.clone(),
        reason: reason.to_string(),
    }
}
