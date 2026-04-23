# Issuer Backend Repo Guidance

- Use GPT-5.4 by default for protocol-facing work in this repo.
- Treat `project-docs/docs/EIDAS_ARF_Implementation_Brief.md` and `project-docs/docs/AI_Working_Agreement.md` as mandatory constraints.
- This repo owns the issuer backend used by the current local reference flow.
- Keep backend changes minimal unless verifier delivery or end-to-end interoperability requires them.
- When issuer metadata, credential issuance behaviour, env contracts, or local interoperability rules change, update `project-docs` in the same task.
- Default Git flow in this workspace is local `wip/<stream>` commits promoted into protected default branches through reviewed pull requests; do not publish remote `wip/<stream>` branches unless explicitly requested.

## Local Checks

- `.venv/bin/python -m pytest -q` when `.venv` exists, otherwise `python3 -m pytest -q`

## Sensitive Areas

- Do not casually mutate canonical metadata or JWKS assets for local runtime convenience.
- Keep local-only keys, JWKS files, and runtime artifacts out of version control.