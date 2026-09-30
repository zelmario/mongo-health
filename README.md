# Big Hole collector

Keeps your MongoDB FTDC past Atlas's 3–10 day retention, watches it with the Big Hole rules,
and emails you when something happens.

Work in progress: the README, configuration and packaging are being rewritten for the first
public release.

- `collector/` — capture, analysis, reports and email (Python)
- `big-hole/` — FTDC decoder, rules engine and viewer (TypeScript)

Apache 2.0; `big-hole/` is MIT. See `NOTICE`.
