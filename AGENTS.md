# Local Research Audit Workflow

This repository has a local, non-committed research corpus under `resources/` for audit work.

For questions about cryptography, protocol design, paper comparisons, security assumptions, or audit findings:

1. Read `resources/context/INDEX.md` for broad orientation and `resources/context/REPO_CONTEXT.md` for the paper-to-code map.
2. Search the local corpus before opening whole PDFs:

   ```sh
   python3 resources/scripts/search_index.py "<question or concepts>" --limit 8 --full
   ```

3. Read only the returned chunks first. Open or extract from the original PDF when exact equations, notation, figures, or surrounding qualifications matter.
4. Cite the document id and PDF page number in research-backed answers.
5. Treat summaries and topic maps as routing aids, not primary evidence; the source paper controls when they disagree.
6. Add only evidence-backed or explicitly confirmed durable conclusions to `resources/AUDIT_CONTEXT.md`. Keep hypotheses and unresolved issues under open questions.

If the corpus changes, rebuild it with the bundled Python runtime:

```sh
/Users/adrian/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 resources/scripts/build_index.py
```

The generated database and extracted chunks live under `resources/.index/` and are disposable.

## Agent skills

### Issue tracker

Issues and specs are tracked as local Markdown under `.scratch/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Triage uses the default canonical label vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository using root `CONTEXT.md` and `docs/adr/`. See `docs/agents/domain.md`.
