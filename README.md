## About this project

A **self-contained security & structure playbook for Flarum v2 extensions**, distributed as a single [`CLAUDE.md`](./CLAUDE.md) file. Drop it into any Flarum v2 extension repository and AI coding agents (Claude Code) will auto-load it as the canonical reference for writing, reviewing, and hardening that extension.

The playbook spans 35 sections covering authorization, IDOR, XSS, path traversal, SSRF, CSRF, token management, upload validation, CI/CD hardening, and the canonical patterns from official Flarum v2 extensions (`tags`, `likes`, `mentions`, `subscriptions`, `suspend`, `gdpr`, `flags`, `nicknames`).

Use it to:

- Review pull requests against objective criteria (100+ item checklist in §32).
- Calibrate finding severity (🔴 critical / 🟠 important / 🟡 recommended / ⚪ informational).
- Mirror official Flarum extension patterns instead of reinventing security primitives.
- Keep CI/CD pipelines aligned with SHA pinning, least-privilege permissions, and supply-chain hardening lessons from the 2025 incidents (`tj-actions/changed-files`, `reviewdog/action-setup`).

**How to use:** copy `CLAUDE.md` into the root of your Flarum v2 extension. Read §0 (self-audit prompts) before writing code and §32 (pre-commit checklist) before merging.