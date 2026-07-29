use serde::{Deserialize, Serialize};

use crate::{
    model::{ServiceState, Transition},
    protocol::ViabilityRules,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckerVerdict {
    pub implementation: String,
    pub safe: bool,
    pub reasons: Vec<String>,
}

#[must_use]
pub fn check(
    current: &ServiceState,
    transition: &Transition,
    rules: &ViabilityRules,
) -> CheckerVerdict {
    let mut reasons = Vec::new();
    if transition.before_digest != crate::model::digest(current) {
        reasons.push("transition is not bound to the current state".into());
    }
    if transition.after.replicas.len() != rules.replica_count {
        reasons.push("replica count invariant failed".into());
    }
    if rules.require_consensus && transition.after.consensus().is_none() {
        reasons.push("replica consensus invariant failed".into());
    }
    for (key, required_value) in &rules.required_keys {
        if transition
            .after
            .replicas
            .values()
            .any(|values| values.get(key) != Some(required_value))
        {
            reasons.push(format!("required key invariant failed: {key}"));
        }
    }
    CheckerVerdict {
        implementation: "telosieve-independent-checker/v0".into(),
        safe: reasons.is_empty(),
        reasons,
    }
}
