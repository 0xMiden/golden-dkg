# Contributing to Golden DKG

#### First off, thanks for taking the time to contribute!

We want to make contributing to this project as easy and transparent as possible, whether it is:

- Reporting a [bug](https://github.com/0xMiden/golden-dkg/issues/new)
- Taking part in [discussions](https://github.com/0xMiden/golden-dkg/discussions)
- Submitting a [fix](https://github.com/0xMiden/golden-dkg/pulls)
- Proposing a new [feature](https://github.com/0xMiden/golden-dkg/issues/new)

## Contribution quality

To keep review time focused on meaningful improvements, we generally do not accept:

- Trivial typo fixes
- Minor code or documentation changes that do not materially improve clarity or completeness

Contributions should:

- Include clear reasoning for the change
- Be linked to an issue the author has been assigned to
- Be testable and reviewable without unnecessary overhead
- Pass all CI tests

**We reserve the right to close pull requests at our discretion or batch trivial valid fixes into
internal commits.**

## Flow

We use [GitHub Flow](https://docs.github.com/en/get-started/using-github/github-flow), so all code
changes happen through pull requests from a
[forked repository](https://docs.github.com/en/get-started/quickstart/fork-a-repo).

### Branching

- The current active branch is `main`. Every fix or feature branch must be forked from `main`.
- The branch name should contain a short issue or feature description in
  [kebab case](https://en.wikipedia.org/wiki/Letter_case#Kebab_case). For example, an issue titled
  `Fix functionality X in component Y` could use the branch name `fix-x-in-y`.
- Rebase your branch onto `main` before submitting a pull request so the branch does not contain
  merge commits.

For example, this branch state:

```text
        A---B---C fix-x-in-y
       /
  D---E---F---G main
          |   |
       (F, G) changes happened after fix-x-in-y forked
```

should become this after the rebase:

```text
                A'--B'--C' fix-x-in-y
               /
  D---E---F---G main
```

Read more about rebasing in the [Git documentation](https://git-scm.com/docs/git-rebase).

### Signing commits

We require all commits to be
[signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification).

### Commit messages

- Commit messages should be short and descriptive. Prefix them with the change type and scope
  when possible, following the
  [semantic commit](https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716)
  scheme. For example: `fix(evrf): reject malformed proofs`.
- Keep commits as logically separate stages and squash fixup commits so the Git history remains
  clean.

### Code style and documentation

- Follow [rustdoc](https://doc.rust-lang.org/rust-by-example/meta/doc.html) conventions for code
  documentation and keep lines to no more than 100 characters where practical.
- Rustfmt and Clippy run in CI. Run the checks relevant to your change before pushing. The
  standard commands are also listed in the [README](README.md#useful-checks).

```bash
cargo fmt --all --check
cargo clippy --all --benches --tests --examples --all-features --exclude bulletproofs-cycle -- -D warnings
cargo nextest run --workspace --features golden-rustcrypto/p256,golden-rustcrypto/k256,golden-ehtdh1/halo2curves-secp256k1,golden-evrf/halo2curves-secp256k1,golden-halo2curves/halo2curves-secp256k1
cargo test --workspace --doc
```

### Versioning

We use [semantic versioning](https://semver.org/).

## Pre-PR checklist

1. Fork the repository and create a branch from `main` using the naming convention above.
2. Sign every commit.
3. Follow the commit message and code style conventions.
4. Add tests for new functionality.
5. Update documentation and comments affected by the change.
6. Run Rustfmt, Clippy, and the relevant tests.
7. Rebase the branch onto the latest `main`.

## Write bug reports with detail, background, and sample code

Good bug reports tend to include:

- A quick summary or background
- Steps to reproduce the problem
- What you expected to happen
- What actually happened
- Notes about possible causes or earlier debugging attempts

## Licensing

When you submit a contribution, it is understood to be under the dual [MIT](LICENSE-MIT) and
[Apache 2.0](LICENSE-APACHE) licenses that cover the project. Contact the maintainers if that is a
concern.
