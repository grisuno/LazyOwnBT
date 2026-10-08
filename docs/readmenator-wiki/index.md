# Second Brain

*Last synthesized: 2026-10-07 | 24 files | 4 concept pages | offline, zero tokens*

> Raw sources -> readmenator wiki -> links (Karpathy LLM Wiki Pattern, deterministic).
> Start here, then open one community page. Prefer grep over full reads.

## Vault Overview

The codebase centres on `web.py`, `app.py`, `conftest.py`. Architecturally it is 4 layers, dominant utility (10 files) across 4 import-based communities. Recorded risk surface: 0 security findings and 0 dependency cycles.

Surprising tissue lives between lazyownbt: web, lazyownbt: main, lazyownbt: security: 3 extracted cross-community imports and 8 inferred bridges. Follow `connections.json` sorted by strength before refactoring.

Open work clusters around documentation (96% file coverage), 0 security findings, 6 taint paths, and 5 suggested exploration questions in `queries.md`.

## Stats

| Metric | Value |
|--------|-------|
| Files | 24 |
| Symbols | 419 |
| Resolved imports | 30 |
| Languages | js, py, sh |
| Communities | 4 |
| Doc coverage | 96% (23/24 files) |
| Security findings | 0 |
| Estimated read cost | ~7445 tokens (chars/4, offline so $0) |

## Reading Order

1. Skim Stats and God Nodes below for blast radius.
2. Open the largest community page first, then follow Connections.
3. Use `queries.md` for the next question; log the answer there.

```
grep -rn '<keyword>' index.md community_*.md
readmenator query "<question>" --target readmenator_LazyOwnBT_bnv963_o
```

## Concept Wiki

- [lazyownbt: web (5 files, cohesion 0.55)](./community_0_lazyownbt_web.md)
- [lazyownbt: main (4 files, cohesion 0.38)](./community_1_lazyownbt_main.md)
- [lazyownbt: security (3 files, cohesion 0.33)](./community_2_lazyownbt_security.md)
- [orphans (12 files, cohesion 0.00)](./community_3_orphans.md)

## God Nodes

| File | Score |
|------|-------|
| `lazyownbt/web.py` | 19.5 |
| `app.py` | 19.3 |
| `tests/conftest.py` | 13.7 |
| `lazyownbt/config.py` | 12.8 |
| `lazyownbt/actions.py` | 7.0 |

## Strongest Connections

- 0 -> 1: depends_on (strength 0.9, EXTRACTED)
- 0 -> 2: depends_on (strength 0.9, EXTRACTED)
- 2 -> 1: depends_on (strength 0.9, EXTRACTED)
- 0 -> 1: bridges (strength 0.7, INFERRED)
- 0 -> 2: bridges (strength 0.7, INFERRED)
- 0 -> 1: bridges (strength 0.7, INFERRED)
- 0 -> 2: bridges (strength 0.7, INFERRED)
- 0 -> 1: bridges (strength 0.7, INFERRED)
- 0 -> 3: shares_context (strength 0.5, INFERRED)
- 1 -> 3: shares_context (strength 0.5, INFERRED)

## Navigation Tips

- Obsidian Graph View works: every community page links back here.
- `connections.json` is machine-readable for GraphRAG pipelines.
- `REPORT.md` states what was extracted vs inferred and current limits.
- Regenerate offline: `readmenator . --rebuild` (no network, no tokens).
