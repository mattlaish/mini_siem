# AI Development Instructions

## Before starting work
- Read this file.
- Read AI_HANDOFF.md.
- Read patch.md.
- Inspect git status and recent commits.
- Review relevant existing code before modifying it.
- Do not redo completed work unless necessary.

## Development rules
- Keep changes focused.
- Preserve existing functionality unless explicitly changing it.
- Follow the existing project architecture and coding conventions.
- Consider security implications of all changes.
- Never commit real credentials, API keys, or private keys.
- Run relevant tests after changes.
- Update patch.md in the same work session for every material code,
  configuration, schema, test, deployment, or documentation change. Record the
  intent, files changed, important decisions, validation results, deployment or
  migration notes, and remaining work. Never place secrets in patch.md.

## Handoff rules
Before handing development to another AI:
- Update AI_HANDOFF.md.
- Update patch.md with the concrete changes and validation from the session.
- Record what was completed.
- Record what remains unfinished.
- Record important technical decisions.
- Record known bugs or failed approaches.
- Record relevant test/build results.
- Identify the recommended next step.

## Git
- Prefer small meaningful commits.
- Do not overwrite unrelated changes.
- Do not force-push unless explicitly instructed.
