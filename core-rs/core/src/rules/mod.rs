mod engine;
mod loader;
mod window;

use std::path::Path;

pub use engine::{shannon_entropy, MAX_TRACKED_SOURCES};
pub use loader::{load, parse, RuleError, RuleKind, RuleSpec, SUPPORTED_VERSION};

use crate::alert::Alert;
use crate::packet::Packet;
use engine::CompiledRule;

pub const DEFAULT_RULES_YAML: &str = include_str!("../../../../rules/default.yaml");

pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

impl RuleEngine {
    pub fn from_specs(specs: Vec<RuleSpec>) -> Self {
        RuleEngine {
            rules: specs.into_iter().filter(|s| s.enabled).map(CompiledRule::new).collect(),
        }
    }

    pub fn from_yaml(text: &str) -> Result<Self, RuleError> {
        loader::parse(text).map(Self::from_specs)
    }

    pub fn load(path: &Path) -> Result<Self, RuleError> {
        loader::load(path).map(Self::from_specs)
    }

    pub fn builtin() -> Self {
        Self::from_yaml(DEFAULT_RULES_YAML).expect("bundled rules/default.yaml is valid")
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rule_ids(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.spec.id.as_str())
    }

    pub fn evaluate(&mut self, packet: &Packet, out: &mut Vec<Alert>) {
        out.extend(self.rules.iter_mut().filter_map(|rule| rule.evaluate(packet)));
    }
}
