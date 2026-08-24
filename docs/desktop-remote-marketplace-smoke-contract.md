# Desktop remote marketplace smoke-test contract (v1)

This is the repository-side hand-off for the Desktop release workflow. It is a
contract only: this repository does not invoke the Desktop repository or modify
its workflows.

After a signed marketplace commit passes `validate_market.py published`, a
maintainer or trusted workflow may trigger the Desktop workflow with a GitHub
`repository_dispatch` event named `xsec_marketplace_smoke`. The payload is:

```json
{
  "contract_version": 1,
  "marketplace_url": "https://raw.githubusercontent.com/tzf1003/xsec-plugins/<immutable-commit>/.agents/plugins/marketplace.json",
  "marketplace_public_key_b64": "KLOHLCxQiEgPiGLwX2RJh/DlkGT/4dLr0z8y9WQrIPI=",
  "source_revision": "<40-character Git commit SHA>",
  "expected_default_plugin_ids": [
    "com.xsec.asset-discovery",
    "com.xsec.attack-path",
    "com.xsec.project-workspace",
    "com.xsec.system-terminal",
    "com.xsec.workspace.approvals",
    "com.xsec.workspace.browser",
    "com.xsec.workspace.conversation-tree",
    "com.xsec.workspace.files",
    "com.xsec.workspace.project-outcomes",
    "com.xsec.workspace.sub-agent",
    "com.xsec.workspace.traffic"
  ]
}
```

`marketplace_url` must use an immutable commit SHA, never a branch name. The
public key is public trust metadata and must equal the Desktop-pinned official
marketplace key. A receiver must reject unknown fields, a different key, a
non-40-character revision, an HTTPS URL outside the official GitHub raw-content
origin, or a default plugin set other than the eleven IDs above.

The Desktop implementation runs this request on Windows, macOS and Linux using
a fresh temporary profile. Each platform must: refresh the remote index; verify
the index and release signatures; download, hash, inspect and install all
eleven default plugins; verify that they can be disabled and enabled; reload the
profile; and delete the temporary profile. It must not use an operator profile,
marketplace cache or user plugin directory.

The workflow result should include `source_revision`, platform, installed IDs,
per-plugin failures and elapsed time. A failure blocks a Desktop release but
does not change this marketplace's published artifacts. Any dispatcher token is
stored only as a protected CI secret in the repository that sends the dispatch;
it is never placed in this payload or a plugin package.
