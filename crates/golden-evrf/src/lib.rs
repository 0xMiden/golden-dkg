//! Public-verification proof backends for Golden DKG.
//!
//! [`paper`] is the Golden eVRF backend from the 2024 paper, built on the
//! Secp256k1/Secq256k1 curve cycle via `bulletproofs-cycle` and
//! `golden-halo2curves`. It is feature-gated on `halo2curves-secp256k1`
//! and verifies end-to-end. When the feature is off, `prove_batch` and
//! `verify_batch` return `Error::ProofVerificationFailed` so a misconfigured
//! caller fails closed instead of silently skipping the proof.
//!
//! [`prototype`] is a lighter Schnorr/Chaum-Pedersen backend that proves the
//! scalar opening of each public share commitment and pad/DH commitment.
//! It is not the Golden eVRF proof; it exists as a self-contained,
//! curve-agnostic fallback for testing the DKG transport without pulling
//! in the curve-cycle R1CS layer.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use golden_core::{
    Error, EvrfProofBackend, EvrfStatement, EvrfWitness, GoldenGroup, GoldenScalar,
    ParticipantIndex, Result, TranscriptRoot,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

pub mod paper;

/// Curve-agnostic Schnorr/Chaum-Pedersen backend for DKG share/pad/DH
/// openings. Not the Golden eVRF proof; see [`paper`] for that.
pub mod prototype {
    use super::*;

    /// Schnorr proof that `share_commitment = G * share` and that the same pad
    /// scalar opens both `pad_commitment = G * pad` and
    /// `dh_commitment = receiver_public_key * pad`.
    #[derive(Clone, Debug)]
    pub struct ShareOpeningProof<G: GoldenGroup> {
        /// Nonce commitment for the share opening, `G * r_share`.
        pub nonce_commitment: G::Element,
        /// Response `r_share + c * share`.
        pub response: G::Scalar,
        /// Nonce commitment for the pad opening, `G * r_pad`.
        pub pad_nonce_commitment: G::Element,
        /// Nonce commitment for the DH relation, `receiver_public_key * r_pad`.
        pub dh_nonce_commitment: G::Element,
        /// Response `r_pad + c * pad`.
        pub pad_response: G::Scalar,
    }

    impl<G: GoldenGroup> PartialEq for ShareOpeningProof<G> {
        fn eq(&self, other: &Self) -> bool {
            self.nonce_commitment == other.nonce_commitment
                && self.response == other.response
                && self.pad_nonce_commitment == other.pad_nonce_commitment
                && self.dh_nonce_commitment == other.dh_nonce_commitment
                && self.pad_response == other.pad_response
        }
    }

    impl<G: GoldenGroup> Eq for ShareOpeningProof<G> {}

    /// Batched proof: one [`ShareOpeningProof`] per receiver, keyed by receiver.
    #[derive(Clone, Debug)]
    pub struct ShareOpeningBatchedProof<G: GoldenGroup>(
        pub std::collections::BTreeMap<ParticipantIndex, ShareOpeningProof<G>>,
    );

    impl<G: GoldenGroup> PartialEq for ShareOpeningBatchedProof<G> {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl<G: GoldenGroup> Eq for ShareOpeningBatchedProof<G> {}

    /// Generic proof backend for DKG share, pad, and DH commitments.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ShareOpeningBackend {}

    impl<G: GoldenGroup> EvrfProofBackend<G> for ShareOpeningBackend {
        type Proof = ShareOpeningBatchedProof<G>;

        fn prove_batch(
            statements: &[EvrfStatement<G>],
            witnesses: &[EvrfWitness<G>],
            rng: &mut impl CryptoRngCore,
        ) -> Result<Self::Proof> {
            if statements.len() != witnesses.len() {
                return Err(Error::ProofVerificationFailed);
            }
            let mut map = std::collections::BTreeMap::new();
            for (statement, witness) in statements.iter().zip(witnesses.iter()) {
                ensure_backend_matches::<G>(statement)?;
                // Fail fast on inconsistent statements so the dealer surfaces a
                // programming error at prove time rather than relying on every
                // downstream verifier to re-check the relation.
                ensure_encrypted_share_relation::<G>(statement)?;
                let share_nonce = random_nonzero_scalar::<G>(rng);
                let pad_nonce = random_nonzero_scalar::<G>(rng);
                let nonce_commitment = G::mul_generator(&share_nonce);
                let pad_nonce_commitment = G::mul_generator(&pad_nonce);
                let dh_nonce_commitment = G::mul(&statement.receiver_public_key, &pad_nonce);
                let challenge = challenge::<G>(
                    statement,
                    &nonce_commitment,
                    &pad_nonce_commitment,
                    &dh_nonce_commitment,
                )?;
                let response = share_nonce.add(&challenge.mul(&witness.share));
                let pad_response = pad_nonce.add(&challenge.mul(&witness.pad));
                if map
                    .insert(
                        statement.receiver,
                        ShareOpeningProof {
                            nonce_commitment,
                            response,
                            pad_nonce_commitment,
                            dh_nonce_commitment,
                            pad_response,
                        },
                    )
                    .is_some()
                {
                    // Duplicate receiver in the input would silently overwrite
                    // the earlier proof entry. The trait contract is one proof
                    // per receiver in the canonical ordered list, so treat a
                    // duplicate as a caller bug, not a silent rewrite.
                    return Err(Error::ProofVerificationFailed);
                }
            }
            Ok(ShareOpeningBatchedProof(map))
        }

        fn verify_batch(statements: &[EvrfStatement<G>], proof: &Self::Proof) -> Result<()> {
            if proof.0.len() != statements.len() {
                return Err(Error::ProofVerificationFailed);
            }
            // Track consumed proof entries so an attacker cannot reuse a
            // single proof to cover duplicate statement receivers. Combined
            // with the length check above, this also rejects extra proof
            // entries that are never addressed by any statement.
            let mut seen = std::collections::BTreeSet::new();
            for statement in statements {
                if !seen.insert(statement.receiver) {
                    return Err(Error::ProofVerificationFailed);
                }
                ensure_backend_matches::<G>(statement)?;
                ensure_encrypted_share_relation::<G>(statement)?;
                let entry = proof
                    .0
                    .get(&statement.receiver)
                    .ok_or(Error::ProofVerificationFailed)?;
                let challenge = challenge::<G>(
                    statement,
                    &entry.nonce_commitment,
                    &entry.pad_nonce_commitment,
                    &entry.dh_nonce_commitment,
                )?;
                let share_left = G::mul_generator(&entry.response);
                let share_right = G::add(
                    &entry.nonce_commitment,
                    &G::mul(&statement.share_commitment, &challenge),
                );
                let pad_left = G::mul_generator(&entry.pad_response);
                let pad_right = G::add(
                    &entry.pad_nonce_commitment,
                    &G::mul(&statement.pad_commitment, &challenge),
                );
                let dh_left = G::mul(&statement.receiver_public_key, &entry.pad_response);
                let dh_right = G::add(
                    &entry.dh_nonce_commitment,
                    &G::mul(&statement.dh_commitment, &challenge),
                );

                if !(share_left == share_right && pad_left == pad_right && dh_left == dh_right) {
                    return Err(Error::ProofVerificationFailed);
                }
            }
            Ok(())
        }
    }

    /// Verify a batch of Schnorr share-opening proofs.
    pub fn verify_share_opening_batch<'a, G, I>(items: I) -> Result<()>
    where
        G: GoldenGroup + 'a,
        I: IntoIterator<Item = (&'a EvrfStatement<G>, &'a ShareOpeningProof<G>)>,
    {
        for (statement, proof) in items {
            let map = core::iter::once((statement.receiver, proof.clone())).collect();
            ShareOpeningBackend::verify_batch(
                core::slice::from_ref(statement),
                &ShareOpeningBatchedProof(map),
            )?;
        }
        Ok(())
    }

    fn ensure_backend_matches<G: GoldenGroup>(statement: &EvrfStatement<G>) -> Result<()> {
        if statement.protocol_version == golden_core::PROTOCOL_VERSION
            && statement.backend_id == G::BACKEND_ID
        {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }

    fn ensure_encrypted_share_relation<G: GoldenGroup>(statement: &EvrfStatement<G>) -> Result<()> {
        let encrypted_share_commitment = G::mul_generator(&statement.encrypted_share);
        let expected_encrypted_share_commitment =
            G::add(&statement.share_commitment, &statement.pad_commitment);
        if encrypted_share_commitment == expected_encrypted_share_commitment {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }

    fn challenge<G: GoldenGroup>(
        statement: &EvrfStatement<G>,
        nonce_commitment: &G::Element,
        pad_nonce_commitment: &G::Element,
        dh_nonce_commitment: &G::Element,
    ) -> Result<G::Scalar> {
        let mut transcript = Sha256::new();
        transcript.update(b"golden-share-opening-proof-v1");
        transcript.update(statement.root());
        update_element::<G>(&mut transcript, b"nonce-commitment", nonce_commitment);
        update_element::<G>(
            &mut transcript,
            b"pad-nonce-commitment",
            pad_nonce_commitment,
        );
        update_element::<G>(&mut transcript, b"dh-nonce-commitment", dh_nonce_commitment);
        let digest: TranscriptRoot = transcript.finalize().into();
        G::Scalar::hash_to_scalar(b"golden-share-opening-challenge-v1", &digest)
    }

    fn update_element<G: GoldenGroup>(
        transcript: &mut Sha256,
        label: &'static [u8],
        point: &G::Element,
    ) {
        let encoded = G::encode_element(point);
        transcript.update((label.len() as u64).to_be_bytes());
        transcript.update(label);
        transcript.update((encoded.as_ref().len() as u64).to_be_bytes());
        transcript.update(encoded.as_ref());
    }

    fn random_nonzero_scalar<G: GoldenGroup>(rng: &mut impl CryptoRngCore) -> G::Scalar {
        loop {
            let scalar = G::Scalar::random(rng);
            if !bool::from(scalar.is_zero()) {
                return scalar;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use golden_core::{
        complete, create_dealing, verify_dealing, DealerMessage, DealerMessageNonce, DkgConfig,
        DkgDealing, FeldmanCommitment, ParticipantIndex, ParticipantRegistry, Polynomial,
        SessionId, Share,
    };
    use golden_rustcrypto::{P256Backend, P256Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use super::prototype::{
        verify_share_opening_batch, ShareOpeningBackend, ShareOpeningBatchedProof,
        ShareOpeningProof,
    };
    use super::*;

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn prove_one<G: GoldenGroup>(
        statement: &EvrfStatement<G>,
        witness: &EvrfWitness<G>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ShareOpeningProof<G>> {
        let batched = ShareOpeningBackend::prove_batch(
            core::slice::from_ref(statement),
            core::slice::from_ref(witness),
            rng,
        )?;
        Ok(batched.0.into_values().next().expect("one proof"))
    }

    fn verify_one<G: GoldenGroup>(
        statement: &EvrfStatement<G>,
        proof: &ShareOpeningProof<G>,
    ) -> Result<()> {
        let map = core::iter::once((statement.receiver, proof.clone())).collect();
        ShareOpeningBackend::verify_batch(
            core::slice::from_ref(statement),
            &ShareOpeningBatchedProof(map),
        )
    }

    fn participants() -> Vec<ParticipantIndex> {
        vec![idx(1), idx(2), idx(3), idx(4)]
    }

    fn identity_secret(participant: ParticipantIndex) -> P256Scalar {
        P256Scalar::from_u64(100 + u64::from(participant.get())).unwrap()
    }

    fn config() -> DkgConfig<P256Backend> {
        let registry = ParticipantRegistry::new(
            participants()
                .iter()
                .map(|participant| {
                    (
                        *participant,
                        P256Backend::mul_generator(&identity_secret(*participant)),
                    )
                })
                .collect(),
        )
        .unwrap();
        DkgConfig::new(
            3,
            SessionId([42u8; 32]),
            P256Scalar::from_u64(77).unwrap(),
            registry,
        )
        .unwrap()
    }

    fn dealings(
        config: &DkgConfig<P256Backend>,
        rng: &mut ChaCha20Rng,
    ) -> BTreeMap<ParticipantIndex, DkgDealing<P256Backend, ShareOpeningBatchedProof<P256Backend>>>
    {
        config
            .registry
            .indexes()
            .map(|dealer| {
                (
                    dealer,
                    create_dealing::<P256Backend, ShareOpeningBackend>(
                        dealer,
                        &identity_secret(dealer),
                        config,
                        rng,
                    )
                    .unwrap(),
                )
            })
            .collect()
    }

    fn peer_dealings(
        receiver: ParticipantIndex,
        dealings: &BTreeMap<
            ParticipantIndex,
            DkgDealing<P256Backend, ShareOpeningBatchedProof<P256Backend>>,
        >,
    ) -> BTreeMap<ParticipantIndex, DealerMessage<P256Backend, ShareOpeningBatchedProof<P256Backend>>>
    {
        dealings
            .iter()
            .filter_map(|(dealer, dealing)| {
                if *dealer == receiver {
                    None
                } else {
                    Some((*dealer, dealing.message.clone()))
                }
            })
            .collect()
    }

    fn statement_for(
        config: &DkgConfig<P256Backend>,
        message: &DealerMessage<P256Backend, ShareOpeningBatchedProof<P256Backend>>,
        receiver: ParticipantIndex,
    ) -> EvrfStatement<P256Backend> {
        EvrfStatement {
            protocol_version: golden_core::PROTOCOL_VERSION,
            backend_id: P256Backend::BACKEND_ID,
            session_id: config.session_id,
            registry_root: config.registry.root(),
            dealer: message.dealer,
            receiver,
            msg_i: message.msg_i,
            beta: config.beta.clone(),
            dealer_public_key: *config.registry.public_key(message.dealer).unwrap(),
            receiver_public_key: *config.registry.public_key(receiver).unwrap(),
            share_commitment: message.commitment.public_key_share(receiver).unwrap(),
            pad_commitment: message.encrypted_shares[&receiver].pad_commitment,
            dh_commitment: message.encrypted_shares[&receiver].dh_commitment,
            encrypted_share: message.encrypted_shares[&receiver].encrypted_share.clone(),
            transcript_root: message.transcript_root,
        }
    }

    #[test]
    fn public_verifier_validates_dealings_without_secret_material() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let config = config();
        let dealings = dealings(&config, &mut rng);

        for dealing in dealings.values() {
            verify_dealing::<P256Backend, ShareOpeningBackend>(&dealing.message, &config).unwrap();
        }
    }

    #[test]
    fn dkg_completes_with_share_opening_backend() {
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let config = config();
        let dealings = dealings(&config, &mut rng);
        let receiver = idx(2);

        let output = complete::<P256Backend, ShareOpeningBackend>(
            receiver,
            &identity_secret(receiver),
            dealings.get(&receiver).unwrap(),
            &peer_dealings(receiver, &dealings),
            &config,
        )
        .unwrap();

        assert_eq!(
            output.public_key_shares[&receiver],
            P256Backend::mul_generator(&output.secret_share.value)
        );
    }

    #[test]
    fn invalid_opening_relation_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let config = config();
        let mut dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let proof = dealing.message.proof.0.get_mut(&idx(2)).unwrap();
        proof.response = proof.response.add(&P256Scalar::one());

        assert_eq!(
            verify_dealing::<P256Backend, ShareOpeningBackend>(&dealing.message, &config)
                .unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn invalid_pad_commitment_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut statement = statement_for(&config, &dealing.message, idx(2));
        statement.pad_commitment =
            P256Backend::add(&statement.pad_commitment, &P256Backend::generator());

        assert_eq!(
            verify_one(&statement, &dealing.message.proof.0[&idx(2)]).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn invalid_dh_relation_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut statement = statement_for(&config, &dealing.message, idx(2));
        statement.dh_commitment =
            P256Backend::add(&statement.dh_commitment, &P256Backend::generator());

        assert_eq!(
            verify_one(&statement, &dealing.message.proof.0[&idx(2)]).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn invalid_encrypted_share_relation_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut statement = statement_for(&config, &dealing.message, idx(2));
        statement.encrypted_share = statement.encrypted_share.add(&P256Scalar::one());

        assert_eq!(
            verify_one(&statement, &dealing.message.proof.0[&idx(2)]).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn proof_replay_across_sessions_fails() {
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut statement = statement_for(&config, &dealing.message, idx(2));
        statement.session_id = SessionId([99u8; 32]);

        assert_eq!(
            verify_one(&statement, &dealing.message.proof.0[&idx(2)]).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn proof_replay_across_curves_fails_by_backend_binding() {
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut statement = statement_for(&config, &dealing.message, idx(2));
        statement.backend_id = "rustcrypto-k256-v1";

        assert_eq!(
            verify_one(&statement, &dealing.message.proof.0[&idx(2)]).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn proof_replay_across_recipients_fails() {
        let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let statement = statement_for(&config, &dealing.message, idx(3));

        assert_eq!(
            verify_one(&statement, &dealing.message.proof.0[&idx(2)]).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn batch_verification_rejects_one_bad_statement() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let good = statement_for(&config, &dealing.message, idx(2));
        let mut bad = statement_for(&config, &dealing.message, idx(3));
        bad.receiver = idx(4);

        assert_eq!(
            verify_share_opening_batch::<P256Backend, _>([
                (&good, &dealing.message.proof.0[&idx(2)]),
                (&bad, &dealing.message.proof.0[&idx(3)]),
            ])
            .unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn batch_and_non_batch_verification_agree() {
        let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let statements = participants()
            .into_iter()
            .filter(|receiver| *receiver != dealing.message.dealer)
            .map(|receiver| statement_for(&config, &dealing.message, receiver))
            .collect::<Vec<_>>();

        for statement in &statements {
            verify_one(statement, &dealing.message.proof.0[&statement.receiver]).unwrap();
        }

        let batch = statements
            .iter()
            .map(|statement| (statement, &dealing.message.proof.0[&statement.receiver]))
            .collect::<Vec<_>>();
        verify_share_opening_batch::<P256Backend, _>(batch).unwrap();
    }

    #[test]
    fn proof_checks_share_commitment_not_plaintext_share_only() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let config = config();
        let secret = P256Scalar::random(&mut rng);
        let polynomial = Polynomial::random_with_secret(secret, 3, &mut rng).unwrap();
        let commitment = FeldmanCommitment::<P256Backend>::commit(&polynomial).unwrap();
        let share: Share<P256Scalar> = polynomial.evaluate(idx(2)).unwrap();
        let share_commitment = commitment.public_key_share(idx(2)).unwrap();
        let mut statement: EvrfStatement<P256Backend> = EvrfStatement {
            protocol_version: golden_core::PROTOCOL_VERSION,
            backend_id: P256Backend::BACKEND_ID,
            session_id: config.session_id,
            registry_root: config.registry.root(),
            dealer: idx(1),
            receiver: idx(2),
            msg_i: DealerMessageNonce([7u8; 32]),
            beta: config.beta.clone(),
            dealer_public_key: *config.registry.public_key(idx(1)).unwrap(),
            receiver_public_key: *config.registry.public_key(idx(2)).unwrap(),
            share_commitment,
            pad_commitment: P256Backend::mul_generator(&P256Scalar::from_u64(5).unwrap()),
            dh_commitment: P256Backend::mul(
                config.registry.public_key(idx(2)).unwrap(),
                &P256Scalar::from_u64(5).unwrap(),
            ),
            encrypted_share: share.value.add(&P256Scalar::from_u64(5).unwrap()),
            transcript_root: [11u8; 32],
        };
        let witness = EvrfWitness {
            identity_secret: identity_secret(idx(1)),
            share: share.value,
            pad: P256Scalar::from_u64(5).unwrap(),
        };
        let proof = prove_one(&statement, &witness, &mut rng).unwrap();

        statement.share_commitment =
            P256Backend::add(&statement.share_commitment, &P256Backend::generator());
        assert_eq!(
            verify_one(&statement, &proof).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn verify_batch_rejects_extra_proof_entries() {
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        let config = config();
        let mut dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let extra = dealing.message.proof.0.get(&idx(2)).unwrap().clone();
        dealing.message.proof.0.insert(idx(99), extra);

        assert_eq!(
            verify_dealing::<P256Backend, ShareOpeningBackend>(&dealing.message, &config)
                .unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn prove_batch_rejects_length_mismatch() {
        // prove_batch used to zip statements and witnesses, silently
        // truncating to the shorter. Pin the fail-fast contract: an extra
        // witness or an extra statement is a caller bug and must surface as
        // ProofVerificationFailed, not a partial proof.
        let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let statement = statement_for(&config, &dealing.message, idx(2));
        let witness = dealing
            .message
            .proof
            .0
            .keys()
            .map(|receiver| EvrfWitness {
                identity_secret: identity_secret(idx(1)),
                share: dealing
                    .message
                    .commitment
                    .public_key_share(*receiver)
                    .map(|_| P256Scalar::zero())
                    .unwrap_or(P256Scalar::zero()),
                pad: P256Scalar::zero(),
            })
            .next()
            .unwrap();

        assert_eq!(
            ShareOpeningBackend::prove_batch(
                core::slice::from_ref(&statement),
                &[witness.clone(), witness.clone()],
                &mut rng,
            )
            .unwrap_err(),
            Error::ProofVerificationFailed
        );
        assert_eq!(
            ShareOpeningBackend::prove_batch(
                &[statement.clone(), statement],
                core::slice::from_ref(&witness),
                &mut rng,
            )
            .unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn prove_batch_rejects_duplicate_receiver() {
        // prove_batch keyed proofs by receiver and silently overwrote on
        // duplicate receivers. Pin the new contract: a duplicate receiver is
        // a caller bug and must surface as ProofVerificationFailed, not a
        // silent rewrite.
        let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let statement = statement_for(&config, &dealing.message, idx(2));
        let witness = EvrfWitness {
            identity_secret: identity_secret(idx(1)),
            share: P256Scalar::zero(),
            pad: P256Scalar::zero(),
        };

        assert_eq!(
            ShareOpeningBackend::prove_batch(
                &[statement.clone(), statement],
                &[witness.clone(), witness],
                &mut rng,
            )
            .unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn prove_batch_rejects_inconsistent_encrypted_share_relation() {
        // ensure_encrypted_share_relation used to be enforced only on verify.
        // Pin the prove-time check: a statement whose encrypted_share is not
        // share + pad must not produce a proof that later fails at verify.
        let mut rng = ChaCha20Rng::from_seed([16u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut statement = statement_for(&config, &dealing.message, idx(2));
        statement.encrypted_share = statement.encrypted_share.add(&P256Scalar::one());
        let witness = EvrfWitness {
            identity_secret: identity_secret(idx(1)),
            share: P256Scalar::zero(),
            pad: P256Scalar::zero(),
        };

        assert_eq!(
            ShareOpeningBackend::prove_batch(
                core::slice::from_ref(&statement),
                core::slice::from_ref(&witness),
                &mut rng,
            )
            .unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn verify_batch_rejects_duplicate_receiver_reusing_one_proof() {
        // verify_batch used to walk the statements list and look up each
        // statement's receiver in the proof map. If two statements shared a
        // receiver (and the proof map happened to be the same length via an
        // extra unused entry), the single proof entry would satisfy both
        // statements. Pin the seen-set guard: a duplicate receiver in
        // statements must fail at verify, even when the proof map has the
        // right length.
        let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
        let config = config();
        let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let statement = statement_for(&config, &dealing.message, idx(2));
        let proof_entry = dealing.message.proof.0.get(&idx(2)).unwrap().clone();
        // Build a "length matches" proof map: two entries that both point at
        // idx(2) so verify_batch sees len == statements.len() but the second
        // entry reuses the same proof for an attacker-controlled extra key.
        let mut proof_map = std::collections::BTreeMap::new();
        proof_map.insert(idx(2), proof_entry.clone());
        proof_map.insert(idx(99), proof_entry);
        let proof = ShareOpeningBatchedProof(proof_map);

        // statements has duplicate idx(2); verify_batch must reject it.
        assert_eq!(
            ShareOpeningBackend::verify_batch(&[statement.clone(), statement], &proof).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }
}
