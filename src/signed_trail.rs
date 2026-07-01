//! Cryptographically signed audit trail with `SHA-256` hash chain + optional `Ed25519` signatures.
//!
//! Complements the legacy [`AuditTrail`](crate::AuditTrail) (based on
//! `DefaultHasher::u64`) with:
//!
//! - `SHA-256` content hashes over deterministically serialised event fields.
//! - Optional per-event `Ed25519` signatures binding an event to a specific signer.
//! - Merkle root computation for anchoring the trail into an external ledger.
//!
//! Backward compatibility: the pre-existing `AuditEvent` / `AuditTrail` API is
//! left untouched so downstream code keeps working.

use crate::{Actor, Resource, Severity};
use alice_blockchain::{
    hash_data, Hash, KeyPair, MerkleProof, MerkleTree, PublicKey, Signature, VerifiableCredential,
    VerifiableCredentialBuilder,
};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// SignedAuditEvent
// ---------------------------------------------------------------------------

/// A single audit event whose contents are committed to via a `SHA-256`
/// content hash and optionally signed by an `Ed25519` key.
#[derive(Debug, Clone)]
pub struct SignedAuditEvent {
    pub sequence: u64,
    pub timestamp_unix_ns: u128,
    pub severity: Severity,
    pub actor: Actor,
    pub resource: Resource,
    pub action: String,
    pub detail: String,
    /// `BTreeMap` for deterministic (lexicographic) key ordering in the hash input.
    pub metadata: BTreeMap<String, String>,
    /// Hash chain: `SHA-256` digest of the previous event's `content_hash`,
    /// or zero for the genesis event.
    pub prev_hash: Hash,
    /// `SHA-256` digest of the canonical byte layout of this event.
    pub content_hash: Hash,
    /// Optional signature produced by `signer.sign(content_hash.0)`.
    pub signature: Option<Signature>,
    /// Public key of the signer, if signed.
    pub signer: Option<PublicKey>,
}

impl SignedAuditEvent {
    /// Recompute the content hash from the current field values.
    #[must_use]
    pub fn compute_content_hash(&self) -> Hash {
        compute_content_hash(
            self.sequence,
            self.timestamp_unix_ns,
            self.severity,
            &self.actor,
            &self.resource,
            &self.action,
            &self.detail,
            &self.metadata,
            &self.prev_hash,
        )
    }

    /// Return `true` iff `content_hash` matches the recomputed hash.
    #[must_use]
    pub fn verify_content_hash(&self) -> bool {
        self.content_hash == self.compute_content_hash()
    }

    /// Return `true` iff the event is unsigned, or the signature verifies
    /// against the recorded signer public key over `content_hash`.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        match (self.signer.as_ref(), self.signature.as_ref()) {
            (None, None) => true,
            (Some(pk), Some(sig)) => pk.verify(&self.content_hash.0, sig),
            _ => false,
        }
    }

    /// Full verification: content hash matches AND signature (if any) verifies.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_content_hash() && self.verify_signature()
    }
}

fn compute_content_hash(
    sequence: u64,
    timestamp_unix_ns: u128,
    severity: Severity,
    actor: &Actor,
    resource: &Resource,
    action: &str,
    detail: &str,
    metadata: &BTreeMap<String, String>,
    prev_hash: &Hash,
) -> Hash {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    buf.extend_from_slice(&sequence.to_le_bytes());
    buf.extend_from_slice(&timestamp_unix_ns.to_le_bytes());
    buf.push(severity_tag(severity));
    push_str(&mut buf, &actor.id);
    push_str(&mut buf, &actor.name);
    push_str(&mut buf, &actor.role);
    push_str(&mut buf, &resource.kind);
    push_str(&mut buf, &resource.id);
    push_str(&mut buf, &resource.name);
    push_str(&mut buf, action);
    push_str(&mut buf, detail);
    // BTreeMap iteration is sorted by key, giving deterministic layout.
    buf.extend_from_slice(&(metadata.len() as u64).to_le_bytes());
    for (k, v) in metadata {
        push_str(&mut buf, k);
        push_str(&mut buf, v);
    }
    buf.extend_from_slice(&prev_hash.0);
    hash_data(&buf)
}

const fn severity_tag(s: Severity) -> u8 {
    match s {
        Severity::Info => 1,
        Severity::Warning => 2,
        Severity::Error => 3,
        Severity::Critical => 4,
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// SignedAuditTrail
// ---------------------------------------------------------------------------

/// Append-only chain of `SignedAuditEvent`, each linked to the previous by
/// `SHA-256`. Events may optionally carry `Ed25519` signatures.
#[derive(Debug, Clone, Default)]
pub struct SignedAuditTrail {
    events: Vec<SignedAuditEvent>,
}

impl SignedAuditTrail {
    /// Empty trail.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Append a new event.  If `signer` is provided, the resulting event's
    /// `content_hash` is signed and stored alongside `signer.public()`.
    ///
    /// Returns the sequence number of the appended event.
    pub fn append(
        &mut self,
        severity: Severity,
        actor: Actor,
        resource: Resource,
        action: impl Into<String>,
        detail: impl Into<String>,
        metadata: BTreeMap<String, String>,
        signer: Option<&KeyPair>,
    ) -> u64 {
        self.append_at(
            severity,
            actor,
            resource,
            action,
            detail,
            metadata,
            SystemTime::now(),
            signer,
        )
    }

    /// Append a new event with an explicit timestamp (useful for tests and
    /// replayable trails).
    pub fn append_at(
        &mut self,
        severity: Severity,
        actor: Actor,
        resource: Resource,
        action: impl Into<String>,
        detail: impl Into<String>,
        metadata: BTreeMap<String, String>,
        timestamp: SystemTime,
        signer: Option<&KeyPair>,
    ) -> u64 {
        let sequence = self.events.len() as u64;
        let prev_hash = self.events.last().map_or(Hash::zero(), |e| e.content_hash);
        let action = action.into();
        let detail = detail.into();
        let timestamp_unix_ns = timestamp
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());

        let content_hash = compute_content_hash(
            sequence,
            timestamp_unix_ns,
            severity,
            &actor,
            &resource,
            &action,
            &detail,
            &metadata,
            &prev_hash,
        );

        let (signature, signer_pk) = signer.map_or((None, None), |kp| {
            (Some(kp.sign(&content_hash.0)), Some(kp.public()))
        });

        self.events.push(SignedAuditEvent {
            sequence,
            timestamp_unix_ns,
            severity,
            actor,
            resource,
            action,
            detail,
            metadata,
            prev_hash,
            content_hash,
            signature,
            signer: signer_pk,
        });
        sequence
    }

    /// All events in insertion order.
    #[must_use]
    pub fn events(&self) -> &[SignedAuditEvent] {
        &self.events
    }

    /// Verify that every event's content hash matches its declared fields and
    /// that the `prev_hash` chain is unbroken.
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = Hash::zero();
        for (i, e) in self.events.iter().enumerate() {
            if e.sequence != i as u64 {
                return false;
            }
            if e.prev_hash != expected_prev {
                return false;
            }
            if !e.verify_content_hash() {
                return false;
            }
            expected_prev = e.content_hash;
        }
        true
    }

    /// Verify every signature attached to an event.  Unsigned events pass.
    /// Returns `false` on the first invalid signature.
    #[must_use]
    pub fn verify_signatures(&self) -> bool {
        self.events.iter().all(SignedAuditEvent::verify_signature)
    }

    /// Full verification: hash chain + signatures.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_chain() && self.verify_signatures()
    }

    /// Build a Merkle tree over all events' content hashes.  The returned
    /// root is suitable for anchoring into an external ledger (e.g.
    /// [`alice_blockchain::Blockchain`]).
    #[must_use]
    pub fn merkle_tree(&self) -> Option<MerkleTree> {
        if self.events.is_empty() {
            return None;
        }
        let leaves: Vec<Hash> = self.events.iter().map(|e| e.content_hash).collect();
        Some(MerkleTree::build(&leaves))
    }

    /// Convenience: root hash of the Merkle tree, or `None` if the trail is empty.
    #[must_use]
    pub fn merkle_root(&self) -> Option<Hash> {
        self.merkle_tree().map(|t| t.root())
    }

    /// Merkle inclusion proof for the event at `index`, or `None` if out of range.
    #[must_use]
    pub fn merkle_proof(&self, index: usize) -> Option<MerkleProof> {
        let tree = self.merkle_tree()?;
        tree.prove(index)
    }

    /// Number of stored events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the trail contains no events.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Export the event at `index` as a W3C `VerifiableCredential 2.0` under
    /// the supplied issuer identity.
    ///
    /// The credential subject is set to the event's actor id, and the
    /// payload hash is the event's `content_hash`. The credential is signed
    /// with `issuer_key` (which may or may not be the original event signer,
    /// depending on the SPACID role model).
    ///
    /// Returns `None` when `index` is out of range.
    #[must_use]
    pub fn export_vc(
        &self,
        index: usize,
        vc_id: impl Into<String>,
        issuer_did: impl Into<String>,
        issuer_key: &KeyPair,
    ) -> Option<VerifiableCredential> {
        let event = self.events.get(index)?;
        let subject_did = format!("did:actor:{}", event.actor.id);
        let clamped = event.timestamp_unix_ns.min(u128::from(u64::MAX));
        let secs = u64::try_from(clamped).unwrap_or(u64::MAX) / 1_000_000_000;
        Some(
            VerifiableCredentialBuilder::new(
                vc_id,
                issuer_did,
                subject_did,
                event.content_hash,
                secs,
            )
            .build_signed(issuer_key),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn actor() -> Actor {
        Actor::new("u-001", "Alice", "admin")
    }

    fn resource() -> Resource {
        Resource::new("document", "d-42", "report.pdf")
    }

    fn at(seconds_after_epoch: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds_after_epoch)
    }

    #[test]
    fn empty_trail_verifies() {
        let trail = SignedAuditTrail::new();
        assert!(trail.verify_chain());
        assert!(trail.verify_signatures());
        assert!(trail.is_empty());
        assert!(trail.merkle_root().is_none());
    }

    #[test]
    fn single_unsigned_event_verifies() {
        let mut trail = SignedAuditTrail::new();
        trail.append_at(
            Severity::Info,
            actor(),
            resource(),
            "read",
            "opened file",
            BTreeMap::new(),
            at(1000),
            None,
        );
        assert!(trail.verify());
        assert_eq!(trail.len(), 1);
    }

    #[test]
    fn chain_of_five_events_verifies() {
        let mut trail = SignedAuditTrail::new();
        for i in 0..5 {
            trail.append_at(
                Severity::Info,
                actor(),
                resource(),
                format!("action-{i}"),
                format!("detail-{i}"),
                BTreeMap::new(),
                at(1000 + i),
                None,
            );
        }
        assert!(trail.verify_chain());
        // Sequence numbers are contiguous.
        for (i, e) in trail.events().iter().enumerate() {
            assert_eq!(e.sequence, i as u64);
        }
    }

    #[test]
    fn tampering_content_breaks_chain() {
        let mut trail = SignedAuditTrail::new();
        for i in 0..3 {
            trail.append_at(
                Severity::Info,
                actor(),
                resource(),
                "act",
                format!("d-{i}"),
                BTreeMap::new(),
                at(1000 + i),
                None,
            );
        }
        // Mutate the middle event's detail directly (simulating a raw-memory attack).
        // Safety in production is provided by rebuilding the chain; here we mutate
        // the internal Vec through a getter cast for testing purposes only.
        // We simulate tampering by replacing detail via unsafe interior mutation:
        let ev = &mut trail.events[1];
        ev.detail = "tampered".into();
        assert!(!trail.verify_chain());
    }

    #[test]
    fn signed_event_verifies_and_wrong_key_rejects() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let other = KeyPair::from_seed([2u8; 32]);
        let mut trail = SignedAuditTrail::new();
        trail.append_at(
            Severity::Critical,
            actor(),
            resource(),
            "delete",
            "purged record",
            BTreeMap::new(),
            at(2000),
            Some(&signer),
        );
        assert!(trail.verify_signatures());
        // Substitute a valid signature under a different key.
        let bad_sig = other.sign(&trail.events[0].content_hash.0);
        trail.events[0].signature = Some(bad_sig);
        assert!(!trail.verify_signatures());
    }

    #[test]
    fn merkle_root_matches_manual_build() {
        let signer = KeyPair::from_seed([9u8; 32]);
        let mut trail = SignedAuditTrail::new();
        for i in 0..4 {
            trail.append_at(
                Severity::Info,
                actor(),
                resource(),
                "read",
                format!("event-{i}"),
                BTreeMap::new(),
                at(3000 + i),
                Some(&signer),
            );
        }
        let root = trail.merkle_root().expect("non-empty trail");
        // Rebuild manually and compare.
        let leaves: Vec<Hash> = trail.events().iter().map(|e| e.content_hash).collect();
        let manual = MerkleTree::build(&leaves);
        assert_eq!(root, manual.root());
    }

    #[test]
    fn merkle_proof_verifies_membership() {
        let mut trail = SignedAuditTrail::new();
        for i in 0..8 {
            trail.append_at(
                Severity::Info,
                actor(),
                resource(),
                "read",
                format!("event-{i}"),
                BTreeMap::new(),
                at(4000 + i),
                None,
            );
        }
        let root = trail.merkle_root().unwrap();
        for i in 0..8 {
            let proof = trail.merkle_proof(i).expect("in range");
            let leaf = trail.events()[i].content_hash;
            assert!(proof.verify(leaf, root), "proof for index {i} failed");
        }
    }

    #[test]
    fn metadata_key_order_is_deterministic() {
        let signer = KeyPair::from_seed([5u8; 32]);
        let mut trail_a = SignedAuditTrail::new();
        let mut trail_b = SignedAuditTrail::new();

        let mut meta_a = BTreeMap::new();
        meta_a.insert("zone".into(), "kitchen".into());
        meta_a.insert("app".into(), "spacid".into());
        let mut meta_b = BTreeMap::new();
        // Insert in different order to confirm BTreeMap normalises.
        meta_b.insert("app".into(), "spacid".into());
        meta_b.insert("zone".into(), "kitchen".into());

        trail_a.append_at(
            Severity::Info,
            actor(),
            resource(),
            "read",
            "d",
            meta_a,
            at(1000),
            Some(&signer),
        );
        trail_b.append_at(
            Severity::Info,
            actor(),
            resource(),
            "read",
            "d",
            meta_b,
            at(1000),
            Some(&signer),
        );
        assert_eq!(
            trail_a.events()[0].content_hash,
            trail_b.events()[0].content_hash
        );
    }

    #[test]
    fn unsigned_event_signature_verification_passes() {
        let mut trail = SignedAuditTrail::new();
        trail.append_at(
            Severity::Info,
            actor(),
            resource(),
            "read",
            "d",
            BTreeMap::new(),
            at(1000),
            None,
        );
        assert!(trail.verify_signatures());
    }

    #[test]
    fn export_vc_produces_verifiable_credential() {
        let issuer = KeyPair::from_seed([2u8; 32]);
        let mut trail = SignedAuditTrail::new();
        trail.append_at(
            Severity::Info,
            actor(),
            resource(),
            "read",
            "opened file",
            BTreeMap::new(),
            at(1_720_000_000),
            None,
        );
        let vc = trail
            .export_vc(0, "urn:spacid:vc:trail-0", "did:example:spacid", &issuer)
            .expect("in range");
        assert!(vc.verify());
        assert!(vc.verify_by(&issuer.public()));
        let json = vc.to_json();
        assert!(json.contains("did:actor:u-001"));
    }

    #[test]
    fn export_vc_out_of_range_returns_none() {
        let issuer = KeyPair::from_seed([3u8; 32]);
        let trail = SignedAuditTrail::new();
        assert!(trail
            .export_vc(0, "urn:x", "did:example:issuer", &issuer)
            .is_none());
    }

    #[test]
    fn mismatched_signer_only_rejects() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let mut trail = SignedAuditTrail::new();
        trail.append_at(
            Severity::Info,
            actor(),
            resource(),
            "read",
            "d",
            BTreeMap::new(),
            at(1000),
            Some(&signer),
        );
        // Drop the signature but keep the signer field.
        trail.events[0].signature = None;
        assert!(!trail.verify_signatures());
    }
}
