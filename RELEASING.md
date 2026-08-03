# Publishing Golden crates

Publish all Golden crates together from the current `main` commit.

## Prepare the release

Update each publishable crate to the new release version. Merge the changes
into `main`.

Run `Workspace release dry-run` and `Nightly slow tests` on the commit to be
released. Run `Package version gate` for the same commit. All three workflows
must pass.

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
