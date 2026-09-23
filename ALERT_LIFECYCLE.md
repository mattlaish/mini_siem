# Alert Lifecycle

Status: `IMPLEMENTED_TESTING_DEFERRED`

mini-SIEM owns lightweight alert triage state. It does **not** become a full
case-management or SOAR system; external ticket/SOAR systems remain the incident
system of record when configured.

## State model

```text
new -> acknowledged -> investigating -> resolved -> closed
                         ^                |
                         |________________|

closed -> investigating   (controlled reopen)
```

Allowed shortcuts are intentionally limited by `alert_workflow.py`. A new alert
may be acknowledged, investigated, or resolved; it cannot jump directly to
closed. Resolved/closed alerts may be reopened to `investigating`.

## Durable fields

`alerts` stores:

- `workflow_status`
- `workflow_assignee`
- `workflow_updated_at`
- `workflow_updated_by`
- `workflow_resolution_note`

`alert_workflow_events` is the append-only workflow history containing actor,
from/to state, assignee and note. PostgreSQL uses a dialect-aware `BIGSERIAL`
identifier; SQLite uses `INTEGER PRIMARY KEY AUTOINCREMENT`.

## API and UI

- `GET /api/alerts/<id>/workflow` returns the alert plus workflow history.
- `POST /api/alerts/<id>/workflow` is analyst-protected and updates status,
  assignee and optional resolution/closure note.
- The Live logs & alerts table exposes workflow state and assignment controls.
- Every workflow change also emits the existing application audit event
  `alert_workflow_updated`.

## Boundary

Alert Lifecycle ends at alert triage and ticket/SOAR handoff. mini-SIEM does not
implement a separate internal case engine, approval workflow, evidence clone, or
destructive SOAR action plane in this scope.
