use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    checker::CheckerVerdict,
    model::{ServiceState, Transition},
    protocol::AuthorityKind,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Applied,
    Refused,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HypothesisRecord {
    pub suspected: Vec<AuthorityKind>,
    pub excluded: Vec<AuthorityKind>,
    pub proposed_transition: Option<Transition>,
    pub checker: Option<CheckerVerdict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub hypothesis_count: usize,
    pub unsafe_approvals: usize,
    pub false_refusals: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineRecord {
    pub name: String,
    pub transition: Transition,
    pub checker: CheckerVerdict,
    pub unsafe_approval: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub certificate_version: String,
    pub scenario_id: String,
    pub seed: u64,
    pub authority_digests: BTreeMap<AuthorityKind, String>,
    pub hypotheses: Vec<HypothesisRecord>,
    pub decision: Decision,
    pub refusal_reason: Option<String>,
    pub transition: Option<Transition>,
    pub rollback: Option<Transition>,
    pub final_state: ServiceState,
    pub baseline: BaselineRecord,
    pub metrics: Metrics,
}
