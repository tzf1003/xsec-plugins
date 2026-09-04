---
name: asset-discovery
description: Query an explicitly authorized network scope through the asset-discovery plugin, then normalize and deduplicate candidate assets without importing them into an XSec project.
---

# Asset discovery portable workflow

Use this Skill only for a scope the user explicitly authorizes. This portable
workflow accepts direct network scopes: a wildcard domain such as
`*.example.com`, or one fixed host/domain/IP/URL. It does not expand company
names, HackerOne programs, local files, browser state, project records, or
proxy traffic.

## Available tools

- `asset_hunter_query` and `asset_fofa_query` each query one authorized direct
  scope. They read their configured provider credential from the host-injected
  environment; credentials are never Tool arguments or output fields.
- `asset_candidates_normalize` validates and deduplicates candidate asset
  values. It does not persist data and does not import assets into XSec.

Start with a small `limit`, inspect the returned `items` and explicit
`rejected` values, and state the provider and authorized scope in the result.
Do not pass a provider query expression, a credential, an internal URL, or an
unbounded range as a scope.

## XSec handoff

In XSec, candidate import, project association, collection-run lifecycle, and
audit records remain Host operations. Present the normalized candidates for an
explicit Host-owned import step; this MCP server must not call an import API or
accept a project, assignment, session, or account identifier.
