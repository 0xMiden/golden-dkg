# Golden DKG worktree consolidation manifest

Captured on 2026-08-31 before retiring redundant Golden DKG worktrees.

The active source tree is `adr1anh/batch-refactor`. Its pre-checkpoint HEAD was
`04780ab424b955b3273566b7ae9481ee5f60aa37`; the current working tree contains
the incomplete Ticket 09 compatibility cut and artifact refresh. Ticket 10
validation has not been completed.

## Consolidated planning and research

- `.scratch/batch-dkg/` is the active batch-refactor planning set. Its
  production specification and resolution ledger remain authoritative.
- `.scratch/batch-dkg/history/onyx-falcon/` preserves the newer Onyx Falcon
  handoff, checkpoint, and historical `CONTEXT.md` without overwriting the
  active files.
- `.scratch/batch-dkg/history/a9d2/CONTEXT.md` preserves the detached design
  worktree's terminology snapshot. Its three untracked ADRs were byte-identical
  to active ADRs 0001 through 0003 and were not duplicated here.
- `.scratch/golden-proof-stream-cleanup/` is a byte-for-byte copy of the complete
  15-file scratch tree from the original checkout.
- `resources/notes/` contains the three unique Onyx Falcon Golden research
  notes.
- The ignored Onyx Falcon `AGENTS.md` was copied to the repository root.
- `.scratch/batch-dkg/history/legacy-worktrees/AGENTS.md` preserves the older
  ignored instruction file shared byte-for-byte by the original checkout,
  Able Bay, and PR-12.

## Dirty worktree snapshots

Each `tracked.patch` was produced with `git diff --binary` at the stated tip.
Apply it to a checkout of that exact tip with `git apply --index` or inspect it
as ordinary patch text. Untracked files are copied beneath `untracked/` using
their original repository-relative paths.

- `5a35`: branch `adr1anh/codex/batch-dkg-option-constant-term` at `9844798`;
  includes the tracked patch and `paper-batched-dealer-v8.bin`.
- `a9d2`: detached at `a9ca230`; tracked `CONTEXT.md` patch. Its untracked ADRs
  are preserved by the active byte-identical copies.
- `onyx-falcon`: branch `adr1anh/batch-dkg` at `a9ca230`; tracked `CONTEXT.md`
  patch. Its untracked ADRs are preserved by the active byte-identical copies.
- `pr-9`: branch `review/pr-9` at `f4ceb5a`; two review-note additions.
- `pr-12`: branch `pr/12` at `98194ef`; manifest patch plus the untracked
  `threshold_records_v2.rs` example.
- `stash/stash-8d62fde.patch`: binary-capable export of the shared stash named
  `backup/batch-dkg uncommitted benchmark work before clean implementation`.

Clean worktrees had no filesystem-only state. Their named branch refs remain in
the common repository after worktree removal. Detached review tips are recorded
here: `main-baseline` at `9892021` and `a9d2` at `a9ca230`.

The only other ignored entries in the removable worktrees were `.memory`
symlinks to `/Users/adrian/.memory/repos/github.com/0xMiden/golden-dkg`; the
target vault is external to the worktrees and the links are recreatable.

## Known incomplete artifacts

The active code expects these proof vectors, but neither file existed in any
registered worktree at capture time:

- `crates/golden-evrf/tests/vectors/main-golden-one-receiver-v1.bin`
- `crates/golden-evrf/tests/vectors/main-golden-two-receiver-v1.bin`

The regenerated `t2-n2`, `t2-n10`, `t2-n50`, and `t2-n100` benchmark fixtures
matched their checked-in SHA-256 sidecars before this checkpoint.

This is a recoverability snapshot, not evidence that the consolidated WIP
builds, passes tests, or is ready to merge or release.
