# Validating Golden packages

The five Golden workspace crates target the `2.0.0` family: `golden-core`,
`golden-curves`, `golden-bulletproofs`, `bulletproofs-cycle`, and `golden-ehtdh1`.
The workflows discover package names, versions, and dependencies through Cargo
metadata. They run validation and package dry-runs only; they do not upload crates
or create a release.

## Validate changes

Keep the shared workspace version and internal dependency requirements consistent.
Review the breaking API, format, and crate migration. Issue #71 requires fresh
configurations and key setup; old persisted states and wire messages do not migrate
to the new formats.

Run `CI`, `Workspace release dry-run`, `Nightly slow tests`, and `Package version
gate` on the exact commit under review. All must pass. CI covers both native
curves, both proof backends in sequential and parallel mode, each supported
feature, documentation, browser recovery crates on WASM, and Rust 1.93. Nightly
also runs ignored joint proof and EHTDH1 production bridge tests for both groups.

The normal fixture check verifies both checked-in joint dealer-message fixture
sets. Regenerate fixtures only through the explicit updater after reviewing the
format or relation change; the CI check must not rewrite them.

## Package dry-run

Run `Workspace release dry-run` with `packages` empty to check every package whose
version is not already on crates.io. Supply package names to narrow the check.
The equivalent local command, using Rust 1.93, is:

```sh
RUSTUP_TOOLCHAIN=1.93 cargo publish --workspace --registry crates-io --locked --dry-run
```

The dry-run packages and verifies crates without uploading them. The explicit
registry keeps workspace publication settings unambiguous. No crate upload
workflow is configured.

## Check versions and APIs

The package version gate reads crates.io metadata and compares local packages:

- An existing version must have the same package archive.
- A new version must be newer than the latest published version.
- A new version must pass `cargo-semver-checks`.

The gate derives `cargo-semver-checks --release-type` from each actual version
change using Rust semver rules, including the pre-1.0 boundary. For example,
`0.4.x` to `0.5.0` permits intentional breaking changes, while a patch within
`0.5.x` still rejects them. This applies to both the source and prebuilt rustdoc
comparison paths. Keep the package version gate enabled for the `2.0.0` changes;
a breaking version bump does not require a bypass.

Each library comparison covers its defaults and the shared public feature names
declared by the current and baseline package metadata. This checks both optional
proof backends once they exist in both versions, without applying renamed features
to older sources. The insecure revealed-witness feature is excluded. The engine's
`bulletproofs-compat` mode is checked separately with `cycle-pedersen` disabled.
Registry fallback uses explicit feature flags instead of the tool's all-feature
heuristic, and every applicable profile must pass. Removing a public feature also
requires a breaking version bump; intersection selection cannot hide its removal.

Never change or reuse a version that reached crates.io.

## Review boundaries

Confirm the independent relation, interface, and Standards/Spec reviews required
by [`docs/issue-71.md`](docs/issue-71.md). Engineering workflows validate the
implementation; they do not establish the separately owned composition/security
approval required for any future release.
