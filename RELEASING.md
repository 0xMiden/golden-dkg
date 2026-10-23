# Publishing Golden crates

Publish the five Golden workspace crates together from the current `main`
commit: `golden-core`, `golden-curves`, `golden-bulletproofs`,
`bulletproofs-cycle`, and `golden-ehtdh1`. The issue #71 release starts the
`0.5.0` family. The release workflows discover publishable members, versions,
and dependencies through Cargo metadata; package names and publication order
are not maintained in a separate release list.

## Prepare the release

Update the shared workspace version and internal dependency requirements for
every publishable crate. Review the breaking API, format, and crate migration.
Issue #71 starts fresh configurations and key setup; old persisted states and
wire messages do not migrate to the new formats. Merge the changes into `main`.

Run `CI`, `Workspace release dry-run`, `Nightly slow tests`, and `Package version
gate` on the exact commit to be released. All must pass. CI covers both native
curves, both proof backends in sequential and parallel mode, each supported
feature, documentation, browser recovery crates on WASM, and Rust 1.93. Nightly
also runs ignored joint proof and EHTDH1 production bridge tests for both groups.

The normal fixture check verifies both checked-in joint dealer-message fixture
sets. Regenerate fixtures only through the explicit updater after reviewing the
format or relation change; the CI check must not rewrite them. Confirm the
independent relation, interface, and Standards/Spec reviews required by
[`docs/issue-71.md`](docs/issue-71.md). Obtain the separately owned final
composition/security approval before release. Passing engineering workflows
does not establish that cryptographic approval.

## Publish

Run `Publish workspace to crates.io` with these inputs:

- Set `ref` to `main`.
- Leave `packages` empty.
- Leave `allow_existing` set to `false`.
- Leave `skip_package_version_gate` set to `false`.

The workflow uses crates.io trusted publishing. It also checks that the release
commit is the current `main` commit. Before publishing, it checks each package
against crates.io:

- An existing version must have the same package archive.
- A new version must be newer than the latest published version.
- A new version must pass `cargo-semver-checks`.

The package gate derives `cargo-semver-checks --release-type` from each actual
version change using Rust semver rules, including the pre-1.0 boundary. For
example, `0.4.x` to `0.5.0` permits intentional breaking changes, while a patch
within `0.5.x` still rejects them. This applies to both the source and prebuilt
rustdoc comparison paths. Keep the package version gate enabled for the `0.5.0`
release; the breaking release does not require a bypass.

Each library comparison covers its defaults and the shared public feature names
declared by the current and baseline package metadata. This checks both optional
proof backends once they exist in both releases, without applying renamed features
to older sources. The insecure revealed-witness feature is excluded. The engine's
`bulletproofs-compat` mode is checked separately with `cycle-pedersen` disabled.
Registry fallback uses explicit feature flags instead of the tool's all-feature
heuristic, and every applicable profile must pass. Removing a public feature also
requires a breaking version bump; intersection selection cannot hide its removal.

After publication:

- Verify the crate versions and owners on crates.io.
- Build downstream consumers against the published crates.
- Tag the published commit with the release version.

## Resume a partial release

If a run stops after publishing some crates, check which versions reached
crates.io. Run the workflow again with `allow_existing` set to `true`. The
workflow skips those versions and publishes the rest.

Set `skip_package_version_gate` to `true` only if the gate itself blocks a
release recovery and maintainers have checked the release plan by hand.

Never change or reuse a version that reached crates.io.
