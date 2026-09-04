---
name: attack-path
description: Maintain the current assignment attack path through the XSec host domain API.
---

Use the attack-path MCP tools for node and finding changes. Keep assignment, project,
lease, and revision fields supplied by the host; never invent scope identifiers or
write to the plugin directory. Treat revision conflicts as a user-visible conflict
that requires rereading the path before retrying.
