# mongo-health

Is my MongoDB cluster healthy? Keeps your FTDC past Atlas's 3–10 day retention, checks it with
the [Big Hole](https://github.com/zelmario/Big-hole) rules,
and emails you when something happens.

Work in progress: the README, configuration and packaging are being rewritten for the first
public release.

- `collector/` — capture, analysis, reports and email (Python)
- `big-hole/` — FTDC decoder, rules engine and viewer (TypeScript)

Apache 2.0; `big-hole/` is MIT. See `NOTICE`.
