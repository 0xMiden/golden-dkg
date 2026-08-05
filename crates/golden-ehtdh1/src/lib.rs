//! EHTDH1 context dependent threshold decryption over Golden groups.
//!
//! This crate implements the EHTDH1 protocol from
//! [ePrint 2025/279](https://eprint.iacr.org/2025/279). Golden DKG remains a
//! setup step. The online path uses only the
//! joint public key `X`, public shares `(X_i, Z_i)`, secret shares `(x_i, z_i)`,
//! and a setup context.
//!
//! # Exact-ciphertext EHTDH1
//!
//! The paper scheme uses two independent threshold sharings. The first sharing
//! has decryption secret `x`. The second sharing has secret zero and binds shares
//! to context. A validator returns `W_i = x_i R + z_i S`, where `R` comes from
//! the ciphertext and `S = Hdgd(ad, dc, ctxt)` binds the complete ciphertext.
//! The combiner checks each share against `(X_i, Z_i)`, combines a threshold set
//! to recover `xR`, and opens that exact ciphertext. Existing [`DecryptionShare`]
//! and [`Combiner::combine_exact`] / [`Combiner::combine_quorum`] APIs retain
//! these exact-ciphertext semantics.
//!
//! # Disclosure-scope EHTDH1 extension
//!
//! [`DisclosureScope`] is a separate extension, not the exact paper scheme. It
//! holds stable common `R`, associated data, and an application-defined scope ID.
//! A later [`DisclosureRequest`] borrows that scope and adds one request-specific
//! decryption context. Request construction describes transcript inputs; it does
//! not authorize release. Participants may cache secret-bearing `x_iR` in a
//! [`DecryptionPrecomputation`] before a request exists, reuse it across permitted
//! requests for that stable scope, and issue fresh [`DisclosureDecryptionShare`]
//! values with `W_i = x_iR + z_iS_scope,request` and fresh proof nonces.
//!
//! Each domain-separated `S_scope,request` must behave as an independent random
//! group element with no exploitable relation to the generator, `R`, or another
//! selected point; implementations must not replace hash-to-group with publicly
//! computable `hash_to_scalar(...) * G`. Security across repeated adaptive requests
//! is extension intuition and an explicit review assumption, not a claim that the
//! original EHTDH1 proof directly covers the modified statement.
//!
//! Combining a threshold returns an opaque, reusable [`DisclosureKey`] containing
//! `xR`. **Scope ID and request context determine which shares can reconstruct
//! `xR`; they do not restrict what `xR` can open after reconstruction.** The key
//! opens every valid ciphertext with the same `R` and expected associated data,
//! including ciphertexts Golden cannot know were intended scope members. The
//! associated-data check in [`DisclosureKey::open`] is defensive API policy, not a
//! cryptographic restriction on raw `xR`.
//!
//! **Scope membership and release authorization are application-layer
//! responsibilities.** The application release authorizer must authenticate
//! complete ciphertext envelopes and decide whether participants may issue shares.
//! Keep precomputed `x_iR` in protected participant storage only for the legitimate
//! disclosure window; a threshold of those values reconstructs `xR`.
//!
//! See the [disclosure-scope protocol and security model](https://github.com/0xMiden/golden-dkg/blob/main/crates/golden-ehtdh1/DISCLOSURE_SCOPE_SECURITY.md)
//! for transcript compatibility, assumptions, lifecycle, and blast-radius details.
//!
//! # Golden setup bridge
//!
//! [`material_from_dkg_outputs`] converts two completed Golden DKG runs into
//! EHTDH1 material:
//!
//! - a normal decryption run for `x`;
//! - a zero sharing run for `z`, whose session id is derived with
//!   [`derive_context_session_id`].
//!
//! The bridge rejects mismatched thresholds, registries, participants, local
//! share owners, nonzero zero sharing output, and identity decryption keys. It
//! binds both DKG transcript roots into [`SetupContext`].
//!
//! [`Combiner::new`] checks that a manually supplied [`PublicKeySet`] and
//! [`SetupContext`] agree on backend id, threshold, participant order, and
//! context session derivation.
//!
//! # Paper mapping
//!
//! This crate follows EHTDH1 from ePrint 2025/279 with Golden setup context
//! binding:
//!
//! | Paper value | Crate field or function |
//! | --- | --- |
//! | `X` | [`SealingKey::joint_public_key`] and [`PublicKeySet::joint_public_key`] |
//! | `X_i` | [`PublicShare::decryption`] |
//! | `Z_i` | [`PublicShare::context`] |
//! | `x_i` | [`SecretShare::decryption`] |
//! | `z_i` | [`SecretShare::context`] |
//! | `R = rG` | [`Ciphertext::ephemeral_public`] |
//! | `V = rY` | [`Ciphertext::encryption_point`] |
//! | encryption challenge `e` | [`Ciphertext::challenge`] |
//! | response `r''` | [`Ciphertext::response`] |
//! | `S = Hdgd(ad, dc, ctxt)` | internal `decryption_group` over [`SetupContext::root`] |
//! | `W_i = x_i R + z_i S` | [`DecryptionShare::share`] |
//!
//! The disclosure-scope types are an explicitly separate extension and are not
//! part of this paper mapping.
//!
//! This crate also binds [`SetupContext::root`] into `Hdgd`. That root commits
//! to the Golden backend id, participant registry root, both DKG session ids,
//! both DKG transcript roots, and the caller provided epoch.
//!
//! # Security goals
//!
//! A normally randomized exact-mode payload stays hidden unless the combiner
//! receives a threshold of valid EHTDH1 decryption shares. This assumes sound
//! Golden DKG outputs, group operations, random-oracle-style hash to group with
//! unknown discrete-log relations, and randomness.
//!
//! Seeded sealing reuses one payload mask. For siblings `c_1 = m_1 XOR mask` and
//! `c_2 = m_2 XOR mask`, observers learn `c_1 XOR c_2 = m_1 XOR m_2`; this is
//! unsafe for arbitrary structured or correlated plaintexts. The motivating
//! disclosure-scope use requires independently uniform, fixed-length content
//! keys, for which their XOR reveals no useful structure to ciphertext-only
//! observers. It does not protect against known plaintext: anyone who derives
//! `r`, guesses the seed, or learns one wrapped plaintext and its mask can open
//! every sibling without threshold shares.
//!
//! Ciphertext checks reject malformed EHTDH1 encryption proofs. Share checks
//! reject malformed shares and shares made for the wrong context.
//!
//! # Caller obligations
//!
//! Callers are responsible for:
//!
//! - running Golden setup for their threat model;
//! - distributing `SecretShare` values only to their owning validators;
//! - choosing a stable application epoch for [`SetupContext`];
//! - supplying the same associated data to encryption and verification paths;
//! - checking [`Ciphertext::associated_data`] or using the `*_with_associated_data`
//!   methods when the application expects a specific associated data value;
//! - supplying the intended request-specific decryption context to validators
//!   and combiners;
//! - deriving each supplied 32-byte sealing seed with an application/protocol/
//!   version domain and inputs that include the transaction or disclosure-scope
//!   identity, a high-entropy nonce, a private-payload commitment where appropriate,
//!   and the application setup epoch or identity where relevant; Golden binds the
//!   backend and joint public key internally, but not these application values;
//! - recognizing that validators cannot verify caller-provided seed entropy and
//!   that public `R = rG` permits offline testing of low-entropy seed candidates;
//! - limiting intentional mask reuse to independently uniform, fixed-length
//!   content keys, never arbitrary structured or correlated plaintexts;
//! - using a fresh encryption proof nonce `r'` for every encryption, including
//!   encryptions sharing a seeded `r`; repeating `r'` can reveal `r` and bypass
//!   threshold decryption for every payload sharing it;
//! - using fresh disclosure-share proof nonces for every release; repeating them
//!   across distinct challenges reveals the participant's `x_i` and `z_i`;
//! - authenticating disclosure-scope membership and externally authorizing release
//!   before issuing request-bound disclosure shares;
//! - keeping [`DecryptionPrecomputation`] values in protected participant storage;
//! - handling replay, validator identity, transport authentication, and
//!   malformed share reporting outside this crate.
//!
//! Associated data is stored in the ciphertext and is part of the EHTDH1 proof
//! transcript. It is not an outside API parameter. If the application expects a
//! specific value, compare the stored value before accepting plaintext. These
//! methods do that check: [`Ciphertext::verify_with_associated_data`],
//! [`UnsealingShare::decrypt_share_with_associated_data`],
//! [`Combiner::combine_exact_with_associated_data`], and
//! [`Combiner::combine_quorum_with_associated_data`].
//!
//! Types that hold secrets redact `Debug` output. [`SecretShare`] is still
//! cloneable because callers need to move owned shares through APIs. Keep it in
//! validator local storage and avoid long lived copies. This crate cannot
//! promise that every backend scalar is wiped on drop because
//! [`GoldenScalar`](golden_core::GoldenScalar) does not require zeroization.
//!
//! # Non-goals
//!
//! This crate does not provide AEAD authentication of plaintext, validator
//! networking, accountable decryption, refresh, resharing, TEE custody, replay
//! prevention.
//!
//! [`wire`] defines canonical bytes for setup material, keys, ciphertexts, exact
//! decryption shares, and released disclosure shares. The `miden-serde`
//! and `serde` features adapt those same bytes to their respective serialization
//! traits. [`DisclosureScope`], [`DisclosureRequest`], secret-bearing
//! [`DecryptionPrecomputation`], and [`DisclosureKey`] intentionally have no
//! public wire encoding.
//!
//! # Provided APIs
//!
//! This crate provides client sealing, validator decryption shares, exact
//! combining, quorum search, and a bridge from two Golden DKG runs.
//!
//! Run the full three party threshold record example with:
//!
//! ```text
//! cargo run -p golden-ehtdh1 --example threshold_records --features prototype-bridge
//! ```
//!
//! # Example
//!
//! This example builds a two of three EHTDH1 setup without running Golden DKG.
//! Production callers should normally use [`material_from_dkg_outputs`].
//!
//! ```rust
//! use std::collections::BTreeMap;
//!
//! use golden_core::{GoldenGroup, GoldenScalar, ParticipantIndex, SessionId};
//! use golden_ehtdh1::{
//!     derive_context_session_id, Combiner, PublicKeySet, PublicShare, SealingKey,
//!     SecretShare, SetupContext, UnsealingShare,
//! };
//! use golden_rustcrypto::{P256Backend, P256Scalar};
//! use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
//!
//! type G = P256Backend;
//!
//! fn idx(value: u32) -> ParticipantIndex {
//!     ParticipantIndex::new(value).unwrap()
//! }
//!
//! fn scalar(value: u64) -> P256Scalar {
//!     P256Scalar::from_u64(value).unwrap()
//! }
//!
//! fn eval_linear(secret: P256Scalar, coefficient: P256Scalar, x: ParticipantIndex) -> P256Scalar {
//!     secret.add(&coefficient.mul(&x.to_scalar::<P256Scalar>().unwrap()))
//! }
//!
//! let participants = [idx(1), idx(2), idx(3)];
//! let decryption_secret = scalar(11);
//! let decryption_coefficient = scalar(7);
//! let context_coefficient = scalar(13);
//! let mut public_shares = BTreeMap::new();
//! let mut secret_shares = Vec::new();
//!
//! for participant in participants {
//!     let decryption = eval_linear(
//!         decryption_secret.clone(),
//!         decryption_coefficient.clone(),
//!         participant,
//!     );
//!     let context = eval_linear(P256Scalar::zero(), context_coefficient.clone(), participant);
//!     public_shares.insert(
//!         participant,
//!         PublicShare {
//!             decryption: G::mul_generator(&decryption),
//!             context: G::mul_generator(&context),
//!         },
//!     );
//!     secret_shares.push(SecretShare {
//!         participant,
//!         decryption,
//!         context,
//!     });
//! }
//!
//! let joint_public_key = G::mul_generator(&decryption_secret);
//! let public_key_set = PublicKeySet::<G>::new(2, joint_public_key, public_shares)?;
//! let sealing_key = SealingKey::<G>::new(joint_public_key)?;
//! let setup_context = SetupContext {
//!     backend_id: G::BACKEND_ID.to_owned(),
//!     threshold: 2,
//!     registry_root: [1u8; 32],
//!     participants: participants.to_vec(),
//!     decryption_session_id: SessionId([2u8; 32]),
//!     context_session_id: derive_context_session_id(SessionId([2u8; 32])),
//!     decryption_transcript_root: [3u8; 32],
//!     context_transcript_root: [4u8; 32],
//!     epoch: [5u8; 32],
//! };
//!
//! let mut seal_rng = ChaCha20Rng::from_seed([6u8; 32]);
//! let ciphertext = sealing_key.seal_bytes_with_associated_data(
//!     &mut seal_rng,
//!     b"payload",
//!     b"associated data",
//! )?;
//! let mut share_rng = ChaCha20Rng::from_seed([7u8; 32]);
//! let shares = secret_shares
//!     .iter()
//!     .map(|share| {
//!         UnsealingShare::new(share.clone()).decrypt_share(
//!             &mut share_rng,
//!             &setup_context,
//!             &ciphertext,
//!             b"decryption context",
//!         )
//!     })
//!     .collect::<Result<Vec<_>, _>>()?;
//!
//! let opened = Combiner::new(public_key_set, setup_context)?.combine_exact(
//!     &ciphertext,
//!     b"decryption context",
//!     &shares[..2],
//! )?;
//! assert_eq!(opened, b"payload");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod context;
pub mod decrypt;
pub mod disclosure;
pub mod dkg_bridge;
pub mod encrypt;
pub mod wire;

pub use context::{
    derive_context_session_id, CombineError, Error, PublicKeySet, PublicShare, SecretShare,
    SetupContext,
};
pub use decrypt::{Combiner, DecryptionShare, UnsealingShare};
pub use disclosure::{
    DecryptionPrecomputation, DisclosureDecryptionShare, DisclosureError, DisclosureKey,
    DisclosureRequest, DisclosureScope,
};
pub use dkg_bridge::{material_from_dkg_outputs, Ehtdh1Material};
pub use encrypt::{Ciphertext, SealingKey};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use golden_core::{GoldenGroup, GoldenScalar, ParticipantIndex, SessionId};
    use golden_rustcrypto::{P256Backend, P256Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use super::*;
    use crate::encrypt::{apply_payload_mask, encryption_challenge, encryption_group};

    type G = P256Backend;

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> P256Scalar {
        P256Scalar::from_u64(value).unwrap()
    }

    fn participants() -> [ParticipantIndex; 3] {
        [idx(1), idx(2), idx(3)]
    }

    fn eval_linear(secret: P256Scalar, coefficient: P256Scalar, x: ParticipantIndex) -> P256Scalar {
        secret.add(&coefficient.mul(&x.to_scalar::<P256Scalar>().unwrap()))
    }

    fn setup_context() -> SetupContext {
        SetupContext {
            backend_id: G::BACKEND_ID.to_owned(),
            threshold: 2,
            registry_root: [1u8; 32],
            participants: participants().to_vec(),
            decryption_session_id: SessionId([2u8; 32]),
            context_session_id: derive_context_session_id(SessionId([2u8; 32])),
            decryption_transcript_root: [3u8; 32],
            context_transcript_root: [4u8; 32],
            epoch: [5u8; 32],
        }
    }

    fn material() -> (
        SealingKey<G>,
        PublicKeySet<G>,
        Vec<SecretShare<G>>,
        SetupContext,
    ) {
        let decryption_secret = scalar(11);
        let decryption_coefficient = scalar(7);
        let context_coefficient = scalar(13);
        let mut public_shares = BTreeMap::new();
        let mut secret_shares = Vec::new();

        for participant in participants() {
            let decryption = eval_linear(
                decryption_secret.clone(),
                decryption_coefficient.clone(),
                participant,
            );
            let context = eval_linear(P256Scalar::zero(), context_coefficient.clone(), participant);
            public_shares.insert(
                participant,
                PublicShare {
                    decryption: G::mul_generator(&decryption),
                    context: G::mul_generator(&context),
                },
            );
            secret_shares.push(SecretShare {
                participant,
                decryption,
                context,
            });
        }

        let joint_public_key = G::mul_generator(&decryption_secret);
        let public_key_set: PublicKeySet<G> =
            PublicKeySet::new(2, joint_public_key, public_shares).unwrap();
        let sealing_key = SealingKey::new(joint_public_key).unwrap();
        (sealing_key, public_key_set, secret_shares, setup_context())
    }

    fn shares_for(
        secret_shares: &[SecretShare<G>],
        setup_context: &SetupContext,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
    ) -> Vec<DecryptionShare<G>> {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        secret_shares
            .iter()
            .map(|share| {
                UnsealingShare::new(share.clone())
                    .decrypt_share(&mut rng, setup_context, message, decryption_context)
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn threshold_shares_decrypt_exact() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let plaintext = b"seal this payload";
        let message = sealing_key
            .seal_bytes_with_associated_data(&mut rng, plaintext, b"ad")
            .unwrap();
        let shares = shares_for(&secret_shares, &setup_context, &message, b"context");

        let opened = Combiner::new(public_key_set, setup_context)
            .unwrap()
            .combine_exact(&message, b"context", &shares[..2])
            .unwrap();

        assert_eq!(opened, plaintext);
    }

    #[test]
    fn identity_joint_public_key_is_rejected() {
        let mut public_shares = BTreeMap::new();
        public_shares.insert(
            idx(1),
            PublicShare {
                decryption: G::generator(),
                context: G::generator(),
            },
        );

        assert_eq!(
            SealingKey::<G>::new(G::identity()),
            Err(Error::InvalidJointPublicKey)
        );
        assert_eq!(
            PublicKeySet::<G>::new(1, G::identity(), public_shares),
            Err(Error::InvalidJointPublicKey)
        );
    }

    #[test]
    fn inconsistent_decryption_public_shares_are_rejected() {
        let (_, public_key_set, _, _) = material();
        let mut public_shares = public_key_set.public_shares.clone();
        let share = public_shares.get_mut(&idx(3)).unwrap();
        share.decryption = G::add(&share.decryption, &G::generator());

        assert_eq!(
            PublicKeySet::<G>::new(2, public_key_set.joint_public_key, public_shares),
            Err(Error::InvalidPublicKeySet)
        );
    }

    #[test]
    fn inconsistent_context_public_shares_are_rejected() {
        let (_, public_key_set, _, _) = material();
        let mut public_shares = public_key_set.public_shares.clone();
        let share = public_shares.get_mut(&idx(3)).unwrap();
        share.context = G::add(&share.context, &G::generator());

        assert_eq!(
            PublicKeySet::<G>::new(2, public_key_set.joint_public_key, public_shares),
            Err(Error::InvalidPublicKeySet)
        );
    }

    #[test]
    fn seeded_encryption_is_deterministic() {
        let (sealing_key, _, _, _) = material();
        let mut first_rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut second_rng = ChaCha20Rng::from_seed([7u8; 32]);

        let first = sealing_key
            .seal_bytes_with_associated_data(&mut first_rng, b"payload", b"ad")
            .unwrap();
        let second = sealing_key
            .seal_bytes_with_associated_data(&mut second_rng, b"payload", b"ad")
            .unwrap();

        assert_eq!(first, second);
        first.verify().unwrap();
    }

    #[test]
    fn shares_are_bound_to_ciphertext_with_same_context() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut first_rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut second_rng = ChaCha20Rng::from_seed([8u8; 32]);
        let plaintext = b"payload";
        let associated_data = b"ad";
        let decryption_context = b"context";
        let first = sealing_key
            .seal_bytes_with_associated_data(&mut first_rng, plaintext, associated_data)
            .unwrap();
        let second = sealing_key
            .seal_bytes_with_associated_data(&mut second_rng, plaintext, associated_data)
            .unwrap();
        assert_ne!(first, second);

        let shares = shares_for(&secret_shares, &setup_context, &first, decryption_context);
        let combiner = Combiner::new(public_key_set, setup_context).unwrap();
        assert_eq!(
            combiner
                .combine_exact(&first, decryption_context, &shares[..2])
                .unwrap(),
            plaintext
        );

        let result = combiner.combine_exact(&second, decryption_context, &shares[..2]);
        assert!(matches!(result, Err(CombineError::MalformedShares(ids)) if ids == vec![1, 2]));
    }

    #[test]
    fn seed_determines_r_independently_of_encryption_inputs() {
        let (sealing_key, _, _, _) = material();
        let mut first_rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut second_rng = ChaCha20Rng::from_seed([8u8; 32]);
        let seed = [42u8; 32];

        let first = sealing_key
            .seal_bytes_with_associated_data_and_seed(
                &mut first_rng,
                &[1u8; 32],
                b"first associated data",
                &seed,
            )
            .unwrap();
        let second = sealing_key
            .seal_bytes_with_associated_data_and_seed(
                &mut second_rng,
                &[2u8; 32],
                b"second associated data",
                &seed,
            )
            .unwrap();

        assert_eq!(first.ephemeral_public, second.ephemeral_public);
    }

    #[test]
    fn seeded_encryption_opens_with_threshold_shares() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let content_key = [3u8; 32];
        let message = sealing_key
            .seal_bytes_with_associated_data_and_seed(
                &mut rng,
                &content_key,
                b"transaction context",
                &[42u8; 32],
            )
            .unwrap();
        let shares = shares_for(&secret_shares, &setup_context, &message, b"request");

        let opened = Combiner::new(public_key_set, setup_context)
            .unwrap()
            .combine_exact(&message, b"request", &shares[..2])
            .unwrap();

        assert_eq!(opened, content_key);
    }

    #[test]
    fn quorum_search_ignores_surplus_malformed_share() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let message = sealing_key
            .seal_bytes_with_associated_data(&mut rng, b"payload", b"ad")
            .unwrap();
        let mut shares = shares_for(&secret_shares, &setup_context, &message, b"context");
        shares[2].share = G::add(&shares[2].share, &G::generator());

        let opened = Combiner::new(public_key_set, setup_context)
            .unwrap()
            .combine_quorum(&message, b"context", &shares)
            .unwrap();

        assert_eq!(opened, b"payload");
    }

    #[test]
    fn exact_combiner_rejects_malformed_share() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let message = sealing_key.seal_bytes(&mut rng, b"payload").unwrap();
        let mut shares = shares_for(&secret_shares, &setup_context, &message, b"context");
        shares[1].share = G::add(&shares[1].share, &G::generator());

        let result = Combiner::new(public_key_set, setup_context)
            .unwrap()
            .combine_exact(&message, b"context", &shares[..2]);

        assert!(matches!(result, Err(CombineError::MalformedShares(ids)) if ids == vec![2]));
    }

    #[test]
    fn exact_combiner_rejects_fewer_than_threshold_shares() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
        let message = sealing_key.seal_bytes(&mut rng, b"payload").unwrap();
        let shares = shares_for(&secret_shares, &setup_context, &message, b"context");

        let result = Combiner::new(public_key_set, setup_context)
            .unwrap()
            .combine_exact(&message, b"context", &shares[..1]);

        assert!(matches!(
            result,
            Err(CombineError::InsufficientShares {
                required: 2,
                provided: 1
            })
        ));
    }

    #[test]
    fn exact_combiner_rejects_duplicate_participant_shares() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let message = sealing_key.seal_bytes(&mut rng, b"payload").unwrap();
        let shares = shares_for(&secret_shares, &setup_context, &message, b"context");
        let duplicate = vec![shares[0].clone(), shares[0].clone()];

        let result = Combiner::new(public_key_set, setup_context)
            .unwrap()
            .combine_exact(&message, b"context", &duplicate);

        assert!(matches!(result, Err(CombineError::MalformedShares(ids)) if ids == vec![1]));
    }

    #[test]
    fn decryption_context_is_bound_to_share_proofs() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let message = sealing_key.seal_bytes(&mut rng, b"payload").unwrap();
        let shares = shares_for(&secret_shares, &setup_context, &message, b"context");

        let result = Combiner::new(public_key_set, setup_context)
            .unwrap()
            .combine_exact(&message, b"different context", &shares[..2]);

        assert!(matches!(result, Err(CombineError::MalformedShares(ids)) if ids == vec![1, 2]));
    }

    #[test]
    fn setup_context_is_bound_to_share_proofs() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        let message = sealing_key.seal_bytes(&mut rng, b"payload").unwrap();
        let shares = shares_for(&secret_shares, &setup_context, &message, b"context");
        let mut wrong_setup_context = setup_context.clone();
        wrong_setup_context.epoch = [99u8; 32];

        let result = Combiner::new(public_key_set, wrong_setup_context)
            .unwrap()
            .combine_exact(&message, b"context", &shares[..2]);

        assert!(matches!(result, Err(CombineError::MalformedShares(ids)) if ids == vec![1, 2]));
    }

    #[test]
    fn tampered_associated_data_fails_proof_verification() {
        let (sealing_key, _, _, _) = material();
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let mut message = sealing_key
            .seal_bytes_with_associated_data(&mut rng, b"payload", b"ad")
            .unwrap();

        message.associated_data = b"different ad".to_vec();

        assert_eq!(message.verify(), Err(Error::InvalidCiphertextProof));
    }

    #[test]
    fn expected_associated_data_is_checked_explicitly() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        let message = sealing_key
            .seal_bytes_with_associated_data(&mut rng, b"payload", b"expected ad")
            .unwrap();
        let shares = shares_for(&secret_shares, &setup_context, &message, b"context");
        let combiner = Combiner::new(public_key_set, setup_context.clone()).unwrap();

        assert_eq!(message.associated_data(), b"expected ad");
        assert_eq!(
            message.verify_with_associated_data(b"wrong ad"),
            Err(Error::AssociatedDataMismatch)
        );
        assert_eq!(
            UnsealingShare::new(secret_shares[0].clone()).decrypt_share_with_associated_data(
                &mut rng,
                &setup_context,
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

        message.verify_with_associated_data(b"expected ad").unwrap();
        let opened = combiner
            .combine_exact_with_associated_data(&message, b"context", b"expected ad", &shares[..2])
            .unwrap();
        assert_eq!(opened, b"payload");
    }

    #[test]
    fn combiner_rejects_inconsistent_setup_context() {
        let (_, public_key_set, _, setup_context) = material();
        let mut wrong_threshold = setup_context.clone();
        wrong_threshold.threshold += 1;
        let mut wrong_participants = setup_context.clone();
        wrong_participants.participants.reverse();
        let mut wrong_context_session = setup_context;
        wrong_context_session.context_session_id = SessionId([99u8; 32]);

        assert_eq!(
            Combiner::<G>::new(public_key_set.clone(), wrong_threshold),
            Err(Error::InvalidBridge("setup threshold mismatch"))
        );
        assert_eq!(
            Combiner::<G>::new(public_key_set.clone(), wrong_participants),
            Err(Error::InvalidBridge("setup participant mismatch"))
        );
        assert_eq!(
            Combiner::<G>::new(public_key_set, wrong_context_session),
            Err(Error::InvalidBridge("setup context session mismatch"))
        );
    }

    #[test]
    fn secret_share_debug_is_redacted() {
        let (_, _, secret_shares, _) = material();

        let debug = format!("{:?}", secret_shares[0]);

        assert!(debug.contains("participant"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("decryption: P256Scalar"));
        assert!(!debug.contains("context: P256Scalar"));
    }

    #[test]
    fn different_valid_quorums_recover_same_plaintext() {
        let (sealing_key, public_key_set, secret_shares, setup_context) = material();
        let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
        let message = sealing_key.seal_bytes(&mut rng, b"payload").unwrap();
        let shares = shares_for(&secret_shares, &setup_context, &message, b"context");
        let combiner = Combiner::new(public_key_set, setup_context).unwrap();

        let first = combiner
            .combine_exact(
                &message,
                b"context",
                &[shares[0].clone(), shares[1].clone()],
            )
            .unwrap();
        let second = combiner
            .combine_exact(
                &message,
                b"context",
                &[shares[1].clone(), shares[2].clone()],
            )
            .unwrap();

        assert_eq!(first, b"payload");
        assert_eq!(second, first);
    }

    #[test]
    fn tampered_ciphertext_fails_proof_verification() {
        let (sealing_key, _, _, _) = material();
        let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
        let mut message = sealing_key.seal_bytes(&mut rng, b"payload").unwrap();

        message.encrypted_payload[0] ^= 1;

        assert_eq!(message.verify(), Err(Error::InvalidCiphertextProof));
    }

    #[test]
    fn zero_ephemeral_ciphertext_fails_proof_verification() {
        let mut encrypted_payload = b"payload".to_vec();
        let ephemeral_public = G::identity();
        let proof_commitment = G::mul_generator(&scalar(17));
        apply_payload_mask::<G>(&mut encrypted_payload, &ephemeral_public, &G::identity()).unwrap();
        let encryption_group = encryption_group::<G>(
            &ephemeral_public,
            &proof_commitment,
            b"ad",
            &encrypted_payload,
        )
        .unwrap();
        let encryption_point = G::identity();
        let encryption_commitment = G::mul(&encryption_group, &scalar(17));
        let challenge =
            encryption_challenge::<G>(&encryption_group, &encryption_point, &encryption_commitment)
                .unwrap();
        let message: Ciphertext<G> = Ciphertext {
            associated_data: b"ad".to_vec(),
            encrypted_payload,
            ephemeral_public,
            encryption_point,
            challenge,
            response: scalar(17),
        };

        assert_eq!(message.verify(), Err(Error::InvalidCiphertextProof));
    }
}
