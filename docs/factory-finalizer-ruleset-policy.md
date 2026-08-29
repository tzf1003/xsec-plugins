# Factory finalizer Ruleset policy

`factory-final-merge-gate` is not a normal product pull-request check. The
trusted arm workflow writes it as `pending` for a Factory candidate and it
remains pending through final revalidation and merge; the finalizer never
writes a success status or relies on a cleanup trap. It is therefore maintained
separately from the classic `main` branch-protection document.

The manual protected workflow `enforce-factory-main-protection.yml` owns one
repository Ruleset only: `xsec-marketplace-final-exact-head`.  That Ruleset is
active only for `refs/heads/main`, requires the strict
`factory-final-merge-gate` status from GitHub Actions integration `15368`, and
has exactly one bypass actor: the numeric GitHub App integration ID supplied as
`XSEC_MARKETPLACE_FINALIZER_APP_ID`.  Its bypass mode is `pull_request`, so the
App can complete the already-reviewed exact-head merge but cannot bypass a
direct update. The final workflow creates a short-lived, repository-scoped App
token only after all revalidation and uses it only for that exact-head merge
API request. Missing App credentials or a failed merge leaves the candidate
pending and requires a fresh protected revalidation.

`production` is itself a required review boundary: both the policy workflow
and final merge query its server-side Environment policy and require at least
one `required_reviewers` rule with administrator bypass disabled. A missing or
weaker Environment fails closed before a Ruleset or merge is attempted.

The enforcing workflow first creates or verifies this Ruleset.  Only after the
returned Ruleset passes local validation does it remove the finalizer check
from classic branch protection.  Classic protection continues to require
strict GitHub-Actions `source-gate`, applies to administrators, requires
resolved conversations, and disallows force-push/deletion.  Missing credentials
or App configuration, duplicate rulesets, or any same-name Ruleset that differs
from the exact allowed shape fails closed; the workflow does not update or
delete unrelated rulesets.

Run the policy test locally with:

```text
python -m unittest discover -s tests -p test_factory_finalizer_ruleset_policy.py
```
