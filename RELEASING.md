# Publishing Golden crates

Publish all Golden crates together from the current `main` commit.

## Prepare the release

Update each publishable crate to the new release version. Merge the changes
into `main`.

Run `Workspace release dry-run` and `Nightly slow tests` on the commit to be
released. Both workflows must pass.

## Publish

Run `Publish workspace to crates.io` with these inputs:

- Set `ref` to `main`.
- Leave `packages` empty.
- Leave `allow_existing` set to `false`.

The workflow uses crates.io trusted publishing. It also checks that the release
commit is the current `main` commit and that none of the selected versions
already exist.

After publication:

- Verify the crate versions and owners on crates.io.
- Build downstream consumers against the published crates.
- Tag the published commit with the release version.

## Resume a partial release

If a run stops after publishing some crates, check which versions reached
crates.io. Run the workflow again with `allow_existing` set to `true`. The
workflow skips those versions and publishes the rest.

Never change or reuse a version that reached crates.io.
