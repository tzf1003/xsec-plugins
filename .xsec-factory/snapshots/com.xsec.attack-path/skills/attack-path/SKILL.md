---
name: attack-path
description: Manage attack-path nodes and findings for the active task.
---

# Attack Path

Use the attack-path MCP server to record the evidence-backed steps of the
active task. Tool descriptions and input schemas come from `tools/list`.

Start with `attack_path_list`. Create a node with `attack_path_node_create`
only when it represents a concrete next step or confirmed observation. Use
`attack_path_node_update` to record validation status, evidence or a final
conclusion. Read a single node with `attack_path_node_get` before an update
when the current state matters.

Pass the top-level `revision` returned by `attack_path_node_get` or
`attack_path_list` as `expectedRevision` for update/delete; do not use a
node's `updatedAt` timestamp.

`kind` is an open classification string. State-like fields such as `status`,
`testValue`, and `severity` use the finite values advertised by `tools/list`.

Use `attack_path_finding_add` only for a supported security finding. Provide a
stable fingerprint, concise title, and structured supporting data. Inspect the
current finding set with `attack_path_findings_list` before adding a duplicate.
Delete an obsolete finding with `attack_path_finding_delete`; only the parent
Agent may delete findings.

In xSec, task identity and permissions are supplied by the MCP Fabric. Do not
add assignment, project, session, role, authorization, or context fields to a
Tool call. The server rejects calls outside the active task scope.

Keep domain data in the plugin runtime store. Use xSec Host Tools for browser,
proxy, evidence, report, terminal, audit, and sub-agent operations; those are
not attack-path plugin Tools.
