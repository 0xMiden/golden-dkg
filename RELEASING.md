# Publishing Golden crates

All Golden crates are published together from the current `main` commit.

## First publication

The first version of a crate cannot use trusted publishing. A release admin
must publish version `0.1.0` with a temporary crates.io token.

Before the release window, confirm that every crate name is available:

```bash
for crate in \
  bulletproofs-cycle \
  golden-core \
  golden-ehtdh1 \
  golden-evrf \
  golden-halo2curves \
  golden-rustcrypto
do
  curl --silent --show-error \
    --user-agent "0xMiden/golden-dkg release check" \
    --output /dev/null \
    --write-out "$crate %{http_code}\n" \
    "https://crates.io/api/v1/crates/$crate"
done
```

Each name must return `404`. Stop if any name returns another status.

From a clean checkout of the exact `origin/main` commit, authenticate Cargo
with the temporary token and run:

```bash
cargo publish --workspace --locked
```

If only some crates are published, rerun the command with one `--exclude`
argument for each published crate. Never reuse or change a version that reached
crates.io.

After all six crates are public, verify their owners and build consumers for
the P256 and Secp/Secq paths. Add the trusted publisher to each crate:

- owner: `0xMiden`
- repository: `golden-dkg`
- workflow: `workspace-publish.yml`
- environment: `release`

Revoke the temporary token after trusted publishing is configured.

## Later publications

Prepare new crate versions on `main`, then run the
`Publish workspace to crates.io` workflow. Leave `packages` empty to publish
every new workspace version.

Use `allow_existing` only to resume a partial publication. The default remains
strict so an existing crate version stops the workflow.
