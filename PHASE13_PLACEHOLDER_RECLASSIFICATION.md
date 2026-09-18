# Phase 13 Placeholder Reclassification — 2026-09-18

Status: `PLANNED`

Nineteen files in Phase 13 directories were design/reference placeholders stored
with a `.py` extension. Twelve contained prose that directly broke compilation;
the remainder were constant/reference stubs (and one unbound-name event list)
that still did not constitute usable runtime implementation.

All nineteen have been reclassified as Markdown `*_REFERENCE.md` files. This is a
source-truth repair only: it does **not** promote Alert Lifecycle, Case
Management, Investigation Workspace, Entity Context, Detection Rule Management,
or SOC Metrics to implemented status.

Real Phase 13 implementation must add runtime schema/API/UI/tests before any
scope can move from `PLANNED`.
