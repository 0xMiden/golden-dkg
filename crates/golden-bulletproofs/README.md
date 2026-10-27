# Golden Bulletproofs

Explicitly prepared proof systems for core's fixed Main Golden dealer relation.
Enable `secp-secq` or `jubjub-bls12-381`; default features are empty. The optional
`parallel` feature enables engine parallelism. BLS MSM retains its existing blst
thread pool independently of that feature.

`SecpSecqPrepared::prepare_for(&config)` and `BlsJubjubPrepared::prepare_for(&config)`
expand the minimally padded generator requirement. A proof system is constructed
with `from_prepared(prepared)` and shares immutable owned state. Larger compatible
prefixes serve smaller configurations, with no lazy growth or process-wide
generator cache. Configurations without receivers, which are exactly the plain
single-participant ones, require zero capacity and no bases.

Byte and serde restoration require intact authenticated storage from approved
generation. Canonical subgroup encodings and exact dimensions do not establish
correct generation; an arbitrary producer's signature or a digest of received bytes
does not establish that provenance. Restoration deliberately does not regenerate
bases. Applications own authentication, approval, storage, and deployment admission.

Both circuits share the dealer-secret prefix once, repeat DH constraints per slot,
constrain canonical nonzero reduced DH exponents, and bind one transcript through
one R1CS proof and every Random constant-opening proof. The integer quotient bounds
exclude circuit-field wrapping. Secp chord denominators have explicit inverse
constraints. Native policy and exact witness checking remain in `golden-core`.

Engineering checks are distinct from the independently owned final composition and
security approval required before release of both concrete backends.

The checked-in fixtures use disposable identity scalars 11 and 22 and the complete
`n=2,t=2,[Random,Zero]` workflow. `cargo run --release -p golden-bulletproofs
--example check_fixtures --features secp-secq,jubjub-bls12-381` reads configuration,
prepared bases, own state, broadcasts, public outputs and local outputs independently,
then replays production verification/completion. Missing or stale data fails. Only
an explicit trailing `-- --regenerate` replaces fixtures. Rerun without that flag
after regeneration. Fixtures contain disposable secrets and are not deployment keys.

`cargo bench -p golden-bulletproofs --bench joint_dkg --features
secp-secq,jubjub-bls12-381,parallel` measures deal and completion separately, with
explicit preparation and the candidate board outside both timed regions.
