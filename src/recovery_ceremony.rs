use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{model::digest, protocol::AuthorityKind};

pub const CEREMONY_SCHEMA_VERSION: &str = "telosieve.recovery-ceremony/v1";
pub const MAX_CEREMONY_PARTICIPANTS: usize = 7;
pub const MAX_CEREMONY_DURATION_SECONDS: u64 = 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteDecision {
    Approve,
    Veto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyVote {
    pub participant: String,
    pub decision: VoteDecision,
    pub ceremony_id: String,
    pub request_digest: String,
    pub observed_at: u64,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyRequest {
    pub schema_version: String,
    pub ceremony_id: String,
    pub subject: String,
    pub issuer: String,
    pub authority_kind: AuthorityKind,
    pub lifecycle_tip_digest: String,
    pub trusted_time_digest: String,
    pub proposed_public_key: String,
    pub opens_at: u64,
    pub closes_at: u64,
    pub evaluated_at: u64,
    pub participants: BTreeSet<String>,
    pub quorum: usize,
    pub excluded_participants: BTreeSet<String>,
    pub votes: Vec<CeremonyVote>,
}

#[derive(Serialize)]
struct RequestContext<'a> {
    schema_version: &'a str,
    ceremony_id: &'a str,
    subject: &'a str,
    issuer: &'a str,
    authority_kind: AuthorityKind,
    lifecycle_tip_digest: &'a str,
    trusted_time_digest: &'a str,
    proposed_public_key: &'a str,
    opens_at: u64,
    closes_at: u64,
    evaluated_at: u64,
    participants: &'a BTreeSet<String>,
    quorum: usize,
    excluded_participants: &'a BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyApproval {
    pub schema_version: String,
    pub ceremony_id: String,
    pub request_digest: String,
    pub lifecycle_tip_digest: String,
    pub trusted_time_digest: String,
    pub proposed_key_digest: String,
    pub approvals: Vec<String>,
    pub excluded_participants: Vec<String>,
    pub quorum: usize,
    pub evaluated_at: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CeremonyError {
    #[error("ceremony schema or bounded context is invalid")]
    InvalidContext,
    #[error("ceremony participant set or quorum is invalid")]
    InvalidQuorum,
    #[error("ceremony vote is duplicated")]
    DuplicateVote,
    #[error("ceremony vote context or evidence diverges")]
    DivergentEvidence,
    #[error("ceremony vote is outside the approved time window")]
    StaleVote,
    #[error("excluded or compromised participant supplied a vote")]
    ExcludedParticipant,
    #[error("participant vetoed the ceremony")]
    Veto,
    #[error("ceremony has insufficient approvals")]
    InsufficientApprovals,
}

#[must_use]
pub fn request_digest(request: &CeremonyRequest) -> String {
    digest(&RequestContext {
        schema_version: &request.schema_version,
        ceremony_id: &request.ceremony_id,
        subject: &request.subject,
        issuer: &request.issuer,
        authority_kind: request.authority_kind,
        lifecycle_tip_digest: &request.lifecycle_tip_digest,
        trusted_time_digest: &request.trusted_time_digest,
        proposed_public_key: &request.proposed_public_key,
        opens_at: request.opens_at,
        closes_at: request.closes_at,
        evaluated_at: request.evaluated_at,
        participants: &request.participants,
        quorum: request.quorum,
        excluded_participants: &request.excluded_participants,
    })
}

#[must_use]
pub fn vote_evidence_digest(vote: &CeremonyVote) -> String {
    digest(&(
        CEREMONY_SCHEMA_VERSION,
        &vote.participant,
        vote.decision,
        &vote.ceremony_id,
        &vote.request_digest,
        vote.observed_at,
    ))
}

/// Evaluates a bounded, credential-free recovery-root ceremony rehearsal.
///
/// # Errors
///
/// Refuses malformed context, weak quorum, divergent/duplicate/stale evidence,
/// excluded participants, any veto, or insufficient approvals.
pub fn evaluate(request: &CeremonyRequest) -> Result<CeremonyApproval, CeremonyError> {
    if request.schema_version != CEREMONY_SCHEMA_VERSION
        || !valid_text(&request.ceremony_id)
        || !valid_text(&request.subject)
        || !valid_text(&request.issuer)
        || !valid_digest(&request.lifecycle_tip_digest)
        || !valid_digest(&request.trusted_time_digest)
        || !valid_key(&request.proposed_public_key)
        || request.opens_at >= request.closes_at
        || request.closes_at - request.opens_at > MAX_CEREMONY_DURATION_SECONDS
        || request.evaluated_at < request.opens_at
        || request.evaluated_at > request.closes_at
    {
        return Err(CeremonyError::InvalidContext);
    }
    let participant_count = request.participants.len();
    if !(3..=MAX_CEREMONY_PARTICIPANTS).contains(&participant_count)
        || request.participants.iter().any(|name| !valid_text(name))
        || request.quorum <= participant_count / 2
        || request.quorum > participant_count
        || !request
            .excluded_participants
            .is_subset(&request.participants)
        || participant_count - request.excluded_participants.len() < request.quorum
        || request.votes.len() > participant_count
    {
        return Err(CeremonyError::InvalidQuorum);
    }

    let expected_request_digest = request_digest(request);
    let mut voters = BTreeSet::new();
    let mut approvals = Vec::new();
    for vote in &request.votes {
        if !voters.insert(&vote.participant) {
            return Err(CeremonyError::DuplicateVote);
        }
        if !request.participants.contains(&vote.participant)
            || request.excluded_participants.contains(&vote.participant)
        {
            return Err(CeremonyError::ExcludedParticipant);
        }
        if vote.ceremony_id != request.ceremony_id
            || vote.request_digest != expected_request_digest
            || vote.evidence_digest != vote_evidence_digest(vote)
        {
            return Err(CeremonyError::DivergentEvidence);
        }
        if vote.observed_at < request.opens_at
            || vote.observed_at > request.closes_at
            || vote.observed_at > request.evaluated_at
        {
            return Err(CeremonyError::StaleVote);
        }
        match vote.decision {
            VoteDecision::Approve => approvals.push(vote.participant.clone()),
            VoteDecision::Veto => return Err(CeremonyError::Veto),
        }
    }
    if approvals.len() < request.quorum {
        return Err(CeremonyError::InsufficientApprovals);
    }
    approvals.sort();
    Ok(CeremonyApproval {
        schema_version: CEREMONY_SCHEMA_VERSION.into(),
        ceremony_id: request.ceremony_id.clone(),
        request_digest: expected_request_digest,
        lifecycle_tip_digest: request.lifecycle_tip_digest.clone(),
        trusted_time_digest: request.trusted_time_digest.clone(),
        proposed_key_digest: digest(&request.proposed_public_key),
        approvals,
        excluded_participants: request.excluded_participants.iter().cloned().collect(),
        quorum: request.quorum,
        evaluated_at: request.evaluated_at,
    })
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn valid_key(value: &str) -> bool {
    valid_digest(value)
        && hex::decode(value)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
            .is_some()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn request() -> CeremonyRequest {
        let mut request = CeremonyRequest {
            schema_version: CEREMONY_SCHEMA_VERSION.into(),
            ceremony_id: "recovery-2026-07-30".into(),
            subject: "kv/research".into(),
            issuer: "goal-lab".into(),
            authority_kind: AuthorityKind::Goal,
            lifecycle_tip_digest: "11".repeat(32),
            trusted_time_digest: "22".repeat(32),
            proposed_public_key: hex::encode(
                SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
            ),
            opens_at: 1_760_000_000,
            closes_at: 1_760_000_300,
            evaluated_at: 1_760_000_200,
            participants: BTreeSet::from([
                "custodian-a".into(),
                "custodian-b".into(),
                "custodian-c".into(),
            ]),
            quorum: 2,
            excluded_participants: BTreeSet::new(),
            votes: Vec::new(),
        };
        let request_digest = request_digest(&request);
        request.votes = ["custodian-a", "custodian-b"]
            .into_iter()
            .map(|participant| {
                let mut vote = CeremonyVote {
                    participant: participant.into(),
                    decision: VoteDecision::Approve,
                    ceremony_id: request.ceremony_id.clone(),
                    request_digest: request_digest.clone(),
                    observed_at: 1_760_000_100,
                    evidence_digest: String::new(),
                };
                vote.evidence_digest = vote_evidence_digest(&vote);
                vote
            })
            .collect();
        request
    }

    fn refresh_evidence(request: &mut CeremonyRequest) {
        let request_digest = request_digest(request);
        for vote in &mut request.votes {
            vote.request_digest.clone_from(&request_digest);
            vote.evidence_digest = vote_evidence_digest(vote);
        }
    }

    #[test]
    fn quorum_ceremony_emits_bound_approval_and_survives_exclusion() {
        let request = request();
        let approval = evaluate(&request).unwrap();
        assert_eq!(approval.quorum, 2);
        assert_eq!(approval.approvals, ["custodian-a", "custodian-b"]);
        assert_eq!(approval.request_digest, request_digest(&request));
        assert_eq!(approval.trusted_time_digest, request.trusted_time_digest);

        let mut compromised = request;
        compromised
            .excluded_participants
            .insert("custodian-a".into());
        compromised
            .votes
            .retain(|vote| vote.participant != "custodian-a");
        let mut replacement = compromised.votes[0].clone();
        replacement.participant = "custodian-c".into();
        compromised.votes.push(replacement);
        refresh_evidence(&mut compromised);
        let approval = evaluate(&compromised).unwrap();
        assert_eq!(approval.approvals, ["custodian-b", "custodian-c"]);
        assert_eq!(approval.excluded_participants, ["custodian-a"]);
    }

    #[test]
    fn duplicate_missing_divergent_stale_veto_and_compromised_votes_abort() {
        let original = request();

        let mut duplicate = original.clone();
        duplicate.votes.push(duplicate.votes[0].clone());
        assert_eq!(evaluate(&duplicate), Err(CeremonyError::DuplicateVote));

        let mut missing = original.clone();
        missing.votes.pop();
        assert_eq!(
            evaluate(&missing),
            Err(CeremonyError::InsufficientApprovals)
        );

        let mut divergent = original.clone();
        divergent.votes[0].request_digest = "22".repeat(32);
        divergent.votes[0].evidence_digest = vote_evidence_digest(&divergent.votes[0]);
        assert_eq!(evaluate(&divergent), Err(CeremonyError::DivergentEvidence));

        let mut stale = original.clone();
        stale.votes[0].observed_at = stale.opens_at - 1;
        stale.votes[0].evidence_digest = vote_evidence_digest(&stale.votes[0]);
        assert_eq!(evaluate(&stale), Err(CeremonyError::StaleVote));

        let mut veto = original.clone();
        veto.votes[0].decision = VoteDecision::Veto;
        veto.votes[0].evidence_digest = vote_evidence_digest(&veto.votes[0]);
        assert_eq!(evaluate(&veto), Err(CeremonyError::Veto));

        let mut compromised = original;
        compromised
            .excluded_participants
            .insert("custodian-a".into());
        refresh_evidence(&mut compromised);
        assert_eq!(
            evaluate(&compromised),
            Err(CeremonyError::ExcludedParticipant)
        );
    }
}
