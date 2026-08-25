# Desktop remote marketplace smoke-test contract (v2)

This is the repository-side hand-off for the Desktop release workflow. After a
successful protected publication, this repository invokes the Desktop workflow
with a GitHub `repository_dispatch` event. The event name and payload below are
the exact receiver contract.

After a signed marketplace commit is merged, the protected publisher triggers
the Desktop workflow with a GitHub `repository_dispatch` event named
`xsec_official_marketplace_published`. The payload is:

```json
{
  "source_repository": "tzf1003/xsec-plugins",
  "source_ref": "refs/heads/main",
  "source_sha": "<40-character protected-main source SHA>",
  "marketplace_revision": "<40-character immutable generated-commit SHA>",
  "channel": "beta"
}
```

`source_repository` and `source_ref` identify the compiled official publisher.
`source_sha` is the protected `main` revision from which the publishing job
built and KMS-signed the documents. `marketplace_revision` is the immutable
merge commit that contains those sidecars. Both must be canonical lowercase
40-character Git commit SHAs, must be reachable from `xsec-plugins/main`, and
`source_sha` must be an ancestor of `marketplace_revision`. A receiver must
reject any different repository/ref, malformed revision, or ancestry failure.
It constructs the raw GitHub content URL itself; a dispatch payload never
supplies a URL, a public key, or a plugin list.

`channel` is exactly `beta` or `stable`. A normal protected-main publication
appends immutable release records as needed and dispatches `beta`; the separate
manual stable-promotion workflow changes only a v2 release index's
`channels.stable.releaseId` and dispatches `stable`. Desktop must select the
matching channel pointer after verifying the release-index sidecar. Its normal
user update policy remains stable; beta installation/update requires explicit
user opt-in. For a stable promotion or rollback, Desktop must download the
already-published artifact whose SHA-256 is in the selected immutable record;
it must never expect a newly rebuilt package.

The Desktop implementation runs this request on Windows, macOS and Linux using
a fresh temporary profile. Each platform must: refresh the remote index; verify
the index and release signatures; resolve the dispatched channel; download,
hash, inspect and install all eleven default plugins; verify that they can be
disabled and enabled; reload the profile; and delete the temporary profile. It
must not use an operator profile, marketplace cache or user plugin directory.

The workflow result should include `marketplace_revision`, platform, installed
IDs, per-plugin failures and elapsed time. A failure blocks a Desktop release
but does not change this marketplace's published artifacts. Any dispatcher
token is stored only as a protected CI secret in the repository that sends the
dispatch; it is never placed in this payload or a plugin package.
