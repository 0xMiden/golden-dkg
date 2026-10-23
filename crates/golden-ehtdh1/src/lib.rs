//! Context-dependent threshold encryption using Golden DKG output.
//!
//! Run Golden with exactly `[Random, Zero]`, then convert its completed local
//! output with [`material_from_dkg_output`]. Clients use [`SealingKey`]; validators
//! use [`UnsealingShare`]; [`Combiner`] checks and combines a threshold of shares.
//! Setup context binds the batch session, configuration, completion and epoch.
//!
//! Callers own authenticated setup agreement, confidential secret storage,
//! associated-data policy, transport authentication and replay handling. Restored
//! DKG output requires trusted completion provenance. The online algorithms retain
//! EHTDH1's static below-threshold corruption/RO/LOMDH security targets; mixed
//! setup composition requires independent security approval.
//!
//! Secret storage is redacted and cleaned up on normal drop. Application-owned
//! scalar copies and serialized bytes remain the caller's responsibility.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod codec;
pub mod context;
pub mod decrypt;
pub mod dkg_bridge;
pub mod encrypt;
mod secret;
pub mod wire;

pub use context::{CombineError, Error, PublicKeySet, PublicShare, SecretShare, SetupContext};
pub use decrypt::{Combiner, DecryptionShare, UnsealingShare};
pub use dkg_bridge::{material_from_dkg_output, Ehtdh1Material};
pub use encrypt::{Ciphertext, SealingKey};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{apply_payload_mask, encryption_challenge, encryption_group};
    use golden_core::{DkgGroup, ParticipantIndex, SessionId};
    use golden_curves::{JubjubGroup, Secp256k1Group};
    use group::Group;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use std::collections::BTreeMap;

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }
    pub(crate) struct Material<G: DkgGroup> {
        pub(crate) key: SealingKey<G>,
        pub(crate) public: PublicKeySet<G>,
        pub(crate) secrets: Vec<SecretShare<G>>,
        pub(crate) setup: SetupContext,
    }
    pub(crate) fn material<G: DkgGroup>() -> Material<G> {
        let mut public_shares = BTreeMap::new();
        let mut secrets = Vec::new();
        for participant in [idx(1), idx(2), idx(3)] {
            let x = G::Scalar::from(u64::from(participant.get()));
            let decryption = G::Scalar::from(11) + G::Scalar::from(7) * x;
            let context = G::Scalar::from(13) * x;
            public_shares.insert(
                participant,
                PublicShare {
                    decryption: G::mul_generator(&decryption),
                    context: G::mul_generator(&context),
                },
            );
            secrets.push(SecretShare::new(participant, &decryption, &context));
        }
        let joint_key = G::mul_generator(&G::Scalar::from(11));
        let rows: Vec<_> = public_shares
            .iter()
            .map(|(id, share)| (*id, share.decryption, share.context))
            .collect();
        let config_root = [1; 32];
        let completion_root =
            golden_core::output::ehtdh1_completion_root::<G>(config_root, &joint_key, &rows)
                .unwrap();
        let context = SetupContext {
            group_id: G::GROUP_ID.into(),
            threshold: 2,
            participants: vec![idx(1), idx(2), idx(3)],
            session_id: SessionId([2; 32]),
            config_root,
            completion_root,
            epoch: [5; 32],
        };
        Material {
            key: SealingKey::new(joint_key).unwrap(),
            public: PublicKeySet::new(2, joint_key, public_shares).unwrap(),
            secrets,
            setup: context,
        }
    }
    fn shares_for<G: DkgGroup>(
        secrets: &[SecretShare<G>],
        setup: &SetupContext,
        message: &Ciphertext<G>,
        context: &[u8],
    ) -> Vec<DecryptionShare<G>> {
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        secrets
            .iter()
            .map(|share| {
                UnsealingShare::new(share.clone())
                    .decrypt_share(&mut rng, setup, message, context)
                    .unwrap()
            })
            .collect()
    }
    fn malformed(result: Result<Vec<u8>, CombineError>, expected: &[u32]) {
        assert!(matches!(result, Err(CombineError::MalformedShares(ref ids)) if ids == expected));
    }

    fn threshold_and_quorums<G: DkgGroup>() {
        let Material {
            key,
            public,
            secrets,
            setup,
        } = material::<G>();
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let message = key
            .seal_bytes_with_associated_data(&mut rng, b"payload", b"ad")
            .unwrap();
        let shares = shares_for(&secrets, &setup, &message, b"context");
        let combiner = Combiner::new(public, setup).unwrap();
        for pair in [[0, 1], [0, 2], [1, 2]] {
            assert_eq!(
                combiner
                    .combine_exact(
                        &message,
                        b"context",
                        &[shares[pair[0]].clone(), shares[pair[1]].clone()]
                    )
                    .unwrap(),
                b"payload"
            );
        }
        assert_eq!(
            combiner.combine_exact(&message, b"context", &shares[..1]),
            Err(CombineError::InsufficientShares {
                required: 2,
                provided: 1
            })
        );
        malformed(
            combiner.combine_exact(
                &message,
                b"context",
                &[shares[0].clone(), shares[0].clone()],
            ),
            &[1],
        );
        let mut altered = shares.clone();
        altered[2].share += G::Point::generator();
        assert_eq!(
            combiner
                .combine_quorum(&message, b"context", &altered)
                .unwrap(),
            b"payload"
        );
        malformed(
            combiner.combine_exact(
                &message,
                b"context",
                &[altered[0].clone(), altered[2].clone()],
            ),
            &[3],
        );
    }

    fn ciphertext_and_context_binding<G: DkgGroup>() {
        let Material {
            key,
            public,
            secrets,
            setup,
        } = material::<G>();
        let mut first_rng = ChaCha20Rng::from_seed([7; 32]);
        let mut same_rng = ChaCha20Rng::from_seed([7; 32]);
        let mut different_rng = ChaCha20Rng::from_seed([8; 32]);
        let message = key
            .seal_bytes_with_associated_data(&mut first_rng, b"payload", b"expected ad")
            .unwrap();
        assert_eq!(
            message,
            key.seal_bytes_with_associated_data(&mut same_rng, b"payload", b"expected ad")
                .unwrap()
        );
        let other = key
            .seal_bytes_with_associated_data(&mut different_rng, b"payload", b"expected ad")
            .unwrap();
        message.verify().unwrap();
        let shares = shares_for(&secrets, &setup, &message, b"context");
        let combiner = Combiner::new(public.clone(), setup.clone()).unwrap();
        malformed(
            combiner.combine_exact(&other, b"context", &shares[..2]),
            &[1, 2],
        );
        malformed(
            combiner.combine_exact(&message, b"another context", &shares[..2]),
            &[1, 2],
        );
        let mut changed_epoch = setup.clone();
        changed_epoch.epoch[0] ^= 1;
        malformed(
            Combiner::new(public, changed_epoch).unwrap().combine_exact(
                &message,
                b"context",
                &shares[..2],
            ),
            &[1, 2],
        );
        assert_eq!(
            message.verify_with_associated_data(b"wrong ad"),
            Err(Error::AssociatedDataMismatch)
        );
        assert_eq!(
            UnsealingShare::new(secrets[0].clone()).decrypt_share_with_associated_data(
                &mut first_rng,
                &setup,
                &message,
                b"context",
                b"wrong ad"
            ),
            Err(Error::AssociatedDataMismatch)
        );
        assert_eq!(
            combiner.combine_exact_with_associated_data(
                &message,
                b"context",
                b"wrong ad",
                &shares[..2]
            ),
            Err(CombineError::Ciphertext(Error::AssociatedDataMismatch))
        );
        assert_eq!(
            combiner
                .combine_exact_with_associated_data(
                    &message,
                    b"context",
                    b"expected ad",
                    &shares[..2]
                )
                .unwrap(),
            b"payload"
        );
        for mutate_ad in [false, true] {
            let mut altered = message.clone();
            if mutate_ad {
                altered.associated_data.push(0);
            } else {
                altered.encrypted_payload[0] ^= 1;
            }
            assert_eq!(altered.verify(), Err(Error::InvalidCiphertextProof));
        }
    }

    fn setup_integrity<G: DkgGroup>() {
        let Material {
            public,
            secrets,
            setup,
            ..
        } = material::<G>();
        assert_eq!(
            SealingKey::<G>::new(G::Point::identity()),
            Err(Error::InvalidJointPublicKey)
        );
        for decryption in [false, true] {
            let mut altered = public.public_shares.clone();
            let share = altered.get_mut(&idx(3)).unwrap();
            if decryption {
                share.decryption += G::Point::generator();
            } else {
                share.context += G::Point::generator();
            }
            assert_eq!(
                PublicKeySet::<G>::new(2, public.joint_public_key, altered),
                Err(Error::InvalidPublicKeySet)
            );
        }
        let mut contexts = Vec::new();
        let mut changed = setup.clone();
        changed.threshold += 1;
        contexts.push(changed);
        let mut changed = setup.clone();
        changed.participants.reverse();
        contexts.push(changed);
        let mut changed = setup.clone();
        changed.group_id.push('x');
        contexts.push(changed);
        let mut changed = setup.clone();
        changed.config_root[0] ^= 1;
        contexts.push(changed);
        let mut changed = setup.clone();
        changed.completion_root[0] ^= 1;
        contexts.push(changed);
        for context in contexts {
            assert!(matches!(
                Combiner::<G>::new(public.clone(), context),
                Err(Error::InvalidBridge(_))
            ));
        }
        // Public fields cannot bypass constructor invariants at the combiner.
        let mut invalid_threshold = public.clone();
        invalid_threshold.threshold = 0;
        let mut invalid_context = setup.clone();
        invalid_context.threshold = 0;
        assert_eq!(
            Combiner::new(invalid_threshold, invalid_context),
            Err(Error::InvalidThreshold)
        );
        // A second internally consistent key set still must match the approved
        // completion identity; interpolation alone cannot establish this binding.
        let mut other_public = public.public_shares.clone();
        for share in other_public.values_mut() {
            share.decryption += G::Point::generator();
        }
        let other = PublicKeySet::<G>::new(
            2,
            public.joint_public_key + G::Point::generator(),
            other_public,
        )
        .unwrap();
        assert!(matches!(
            Combiner::new(other, setup.clone()),
            Err(Error::InvalidBridge(_))
        ));
        let mut changed_session = setup.clone();
        changed_session.session_id.0[0] ^= 1;
        assert_ne!(changed_session.root(), setup.root());
        let debug = format!("{:?}", secrets[0]);
        assert!(debug.contains("participant") && debug.contains("<redacted>"));
    }

    fn zero_ephemeral<G: DkgGroup>() {
        let mut payload = b"payload".to_vec();
        let ephemeral = G::Point::identity();
        let response = G::Scalar::from(17);
        let commitment = G::mul_generator(&response);
        apply_payload_mask::<G>(&mut payload, &ephemeral, &G::Point::identity()).unwrap();
        let point = encryption_group::<G>(&ephemeral, &commitment, b"ad", &payload).unwrap();
        let encryption_point = G::Point::identity();
        let challenge =
            encryption_challenge::<G>(&point, &encryption_point, &(point * response)).unwrap();
        let message = Ciphertext::<G> {
            associated_data: b"ad".to_vec(),
            encrypted_payload: payload,
            ephemeral_public: ephemeral,
            encryption_point,
            challenge,
            response,
        };
        assert_eq!(message.verify(), Err(Error::InvalidCiphertextProof));
    }
    macro_rules! both {
        ($name:ident, $body:ident) => {
            #[test]
            fn $name() {
                $body::<Secp256k1Group>();
                $body::<JubjubGroup>();
            }
        };
    }
    both!(
        valid_quorums_and_malformed_share_reporting,
        threshold_and_quorums
    );
    both!(
        ciphertext_context_and_expected_associated_data_are_bound,
        ciphertext_and_context_binding
    );
    both!(
        keysets_must_match_the_approved_batch_completion,
        setup_integrity
    );
    both!(
        zero_ephemeral_points_fail_even_with_a_constructed_relation,
        zero_ephemeral
    );
}
