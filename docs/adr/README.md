# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Auths project.

## What is an ADR?

An ADR captures an important architectural decision made during the project's development, along with its context and consequences. The format is based on [Michael Nygard's original ADR template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).

## Format

Each ADR is a Markdown file named `ADR-NNN-short-title.md`. It contains:

1. **Title** — short imperative phrase
2. **Status** — `Proposed`, `Accepted`, `Deprecated`, or `Superseded by ADR-NNN`
3. **Context** — the situation that motivated the decision
4. **Decision** — what was decided and why
5. **Consequences** — positive and negative outcomes

## Adding a new ADR

1. Copy the structure from an existing ADR.
2. Use the next sequential number (e.g. `ADR-002-...`).
3. Start with `Status: Proposed` while gathering feedback.
4. Change to `Accepted` once the decision is finalised.
5. If a later decision supersedes this one, mark it `Superseded by ADR-NNN` rather than deleting it.

## Index

| Number | Title | Status |
|--------|-------|--------|
| [ADR-001](ADR-001-repo-per-tenant-isolation.md) | Repo-per-tenant isolation for multi-tenant SaaS registry | Accepted |
