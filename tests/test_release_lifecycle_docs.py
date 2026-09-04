from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
LIFECYCLE = ROOT / "docs" / "plugin-development-release-lifecycle.md"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
REFRESH_SIDECAR_WORKFLOW = ROOT / ".github" / "workflows" / "refresh-retained-sidecars.yml"
ADOPTION_WORKFLOW = ROOT / ".github" / "workflows" / "adopt-first-party.yml"
STAGE_ADOPTION_WORKFLOW = ROOT / ".github" / "workflows" / "stage-first-party-adoption.yml"
POST_MERGE_DISPATCHER = ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml"
MERGE_GUARD_WORKFLOW = ROOT / ".github" / "workflows" / "verify-generated-marketplace-publication.yml"
ARM_FINAL_GATE_WORKFLOW = ROOT / ".github" / "workflows" / "arm-generated-marketplace-final-merge.yml"
FINAL_MERGE_WORKFLOW = ROOT / ".github" / "workflows" / "final-merge-generated-marketplace-pr.yml"
PROTECTION_WORKFLOW = ROOT / ".github" / "workflows" / "enforce-factory-main-protection.yml"
FINALIZER_RULESET_DOCUMENT = ROOT / "docs" / "factory-finalizer-ruleset-policy.md"


class ReleaseLifecycleDocumentationTests(unittest.TestCase):
    def test_marketplace_readme_links_to_the_lifecycle_contract(self) -> None:
        self.assertIn(
            "docs/plugin-development-release-lifecycle.md",
            README.read_text(encoding="utf-8"),
        )

    def test_lifecycle_contract_keeps_local_and_cloud_identities_distinct(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        for required_rule in (
            "`dev_revision`",
            "`releaseId`",
            "一个 `plugin.json.version`（SemVer）只能对应一个不可变 release",
            "必须先提高 `plugin.json.version`",
            "上传到 Marketplace 或任何云端 preview",
            "规范 JSON 重新计算 `releaseId`",
        ):
            with self.subTest(required_rule=required_rule):
                self.assertIn(required_rule, document)

    def test_lifecycle_contract_explains_the_publication_queue(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        for required_rule in (
            "发布队列",
            "取得队列槽位后",
            "`source_sha`",
            "过期 release index",
        ):
            with self.subTest(required_rule=required_rule):
                self.assertIn(required_rule, document)
        self.assertIn("Publication queue and Agent evidence", readme)
        self.assertIn("event SHA", readme)

    def test_external_source_transport_boundary_is_documented(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("Git transport", document)
        self.assertIn("verified ref", document)
        self.assertIn("https://github.com", readme)
        self.assertIn("insteadOf", readme)
        self.assertIn("local verified ref", readme)

    def test_disabled_external_history_requires_cryptographic_sidecar_verification(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("pinned Vercel KMS issuer JWKS", readme)
        self.assertIn("cryptographically verifies", readme)
        self.assertIn("Ed25519", document)
        self.assertIn("密码学验证 sidecar", document)

    def test_published_external_registry_removal_is_blocked_against_the_trusted_baseline(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("trusted pre-change\nFactory revision", readme)
        self.assertIn("同一 PR 同时删除 registry、快照和证据", document)
        self.assertIn("设为 `disabled`", document)

    def test_duplicate_beta_delivery_never_dispatches_before_the_reviewed_merge(self) -> None:
        workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
        dispatcher = POST_MERGE_DISPATCHER.read_text(encoding="utf-8")
        self.assertIn("A duplicate source delivery", workflow)
        self.assertIn("separately audited smoke recovery path", workflow)
        self.assertNotIn("XSEC_DESKTOP_REPOSITORY_DISPATCH_TOKEN", workflow)
        self.assertIn("Dispatch the validated Beta or Stable revision to Desktop smoke", dispatcher)
        self.assertIn("All registered Stable completions are bound to their KMS-authenticated Beta Desktop smoke callbacks", dispatcher)

    def test_status_smoke_gate_is_kms_bound_and_cloud_deployment_is_explicit(self) -> None:
        readme = README.read_text(encoding="utf-8")
        publisher = (ROOT / "scripts" / "kms_marketplace_publisher.py").read_text(encoding="utf-8")
        verifier = (ROOT / "scripts" / "verify_merged_stable_promotion.py").read_text(encoding="utf-8")
        dispatcher = POST_MERGE_DISPATCHER.read_text(encoding="utf-8")
        for required_rule in (
            "xsec.plugin-marketplace.official-status",
            "official-status-proofs/<plugin-id>.json",
            "paired `xsec-cloud` broker allowlist",
            "unsigned `waiting_for_smoke`",
        ):
            with self.subTest(readme_rule=required_rule):
                self.assertIn(required_rule, readme)
        self.assertIn("OFFICIAL_STATUS_PURPOSE", publisher)
        self.assertIn("OFFICIAL_STATUS_PROOFS_RELATIVE_PATH", publisher)
        self.assertIn("STATUS_PROOF_PATTERN", verifier)
        self.assertIn("status KMS proof", verifier)
        self.assertIn("--verify-active-marketplace-signatures", dispatcher)

    def test_merge_dispatcher_requires_signed_diff_source_gate_and_fresh_sources(self) -> None:
        dispatcher = POST_MERGE_DISPATCHER.read_text(encoding="utf-8")
        merge_guard = MERGE_GUARD_WORKFLOW.read_text(encoding="utf-8")
        publisher = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
        for rule in (
            "verify_merged_stable_promotion.py",
            "--verify-active-marketplace-signatures",
            "successful immutable Factory source gate",
            "Require the merged generated PR and source gate",
            "Revalidate each registered source branch at the exact merge boundary",
            'event_type:"xsec_official_marketplace_published"',
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, dispatcher)
        self.assertNotIn("github.ref_protected", dispatcher)
        self.assertNotIn("head_commit.message", dispatcher)
        self.assertNotIn("coderabbit", dispatcher.lower())
        self.assertNotIn("reviewThreads", dispatcher)
        self.assertIn("ref: ${{ inputs.marketplace_revision || github.sha }}", dispatcher)
        self.assertIn("merge_group:", merge_guard)
        self.assertEqual(
            merge_guard.count('git diff --quiet "$BEFORE" "$AFTER" -- .agents/plugins .xsec-factory plugins .gitmodules'),
            2,
        )
        self.assertIn("Registered ${repository} ${ref} advanced", merge_guard)
        self.assertIn("Refuse to sign while this plugin has a generated Factory PR awaiting final merge", publisher)
        self.assertNotIn("github.event.head_commit.message", publisher)

    def test_final_merge_gate_is_trusted_revalidating_and_does_not_deadlock_normal_prs(self) -> None:
        arm = ARM_FINAL_GATE_WORKFLOW.read_text(encoding="utf-8")
        final_merge = FINAL_MERGE_WORKFLOW.read_text(encoding="utf-8")
        protection = PROTECTION_WORKFLOW.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        factory_document = (ROOT / "docs" / "first-party-plugin-factory.md").read_text(encoding="utf-8")
        finalizer_ruleset_document = FINALIZER_RULESET_DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("pull_request_target:", arm)
        self.assertNotIn("actions/checkout", arm)
        self.assertIn("factory_generated=true", arm)
        self.assertIn("factory_generated=false", arm)
        self.assertIn("xsec-marketplace/adopt-first-party-", arm)
        self.assertIn("xsec-marketplace/stage-first-party-adoption-", arm)
        self.assertIn("pulls?state=all&base=main&per_page=100", arm)
        self.assertIn("factory_for_sha", arm)
        self.assertNotIn("commits/${PR_HEAD_SHA}/pulls", arm)
        self.assertIn("state=pending", arm)
        self.assertIn("state=success", arm)
        self.assertIn("Not a Factory-generated Marketplace publication PR.", arm)
        self.assertIn("context=factory-final-merge-gate", arm)
        self.assertIn("workflow_dispatch:", final_merge)
        self.assertIn("environment: production", final_merge)
        self.assertIn("XSEC_MARKETPLACE_FINALIZER_APP_ID", final_merge)
        self.assertIn("XSEC_MARKETPLACE_FINALIZER_APP_PRIVATE_KEY", final_merge)
        self.assertIn("actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349", final_merge)
        self.assertIn("actions/checkout@11d5960a326750d5838078e36cf38b85af677262", final_merge)
        self.assertIn("actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1", final_merge)
        self.assertNotIn("XSEC_MARKETPLACE_PUBLISH_TOKEN", final_merge)
        self.assertNotIn("statuses: write", final_merge)
        self.assertIn("Recheck the live PR/source boundary", final_merge)
        self.assertIn("PR head/base changed while final revalidation ran", final_merge)
        self.assertIn("factory-final-merge-gate", final_merge)
        self.assertIn("stable-maintenance", final_merge)
        self.assertIn("beta-smoke-ready", final_merge)
        self.assertIn("external-stable-*", final_merge)
        self.assertIn("adopt-first-party-*", final_merge)
        self.assertIn("validate --baseline-root .", final_merge)
        self.assertIn("factory-publication-sources.json", final_merge)
        self.assertIn("-f sha=\"$HEAD_SHA\"", final_merge)
        self.assertIn("XSEC_MARKETPLACE_SOURCE_APP_ID", final_merge)
        self.assertIn("XSEC_MARKETPLACE_SOURCE_APP_PRIVATE_KEY", final_merge)
        self.assertIn("Create a narrowly scoped read-only Source App token", final_merge)
        self.assertIn("permission-contents: read", final_merge)
        self.assertNotIn("state=success -f context=factory-final-merge-gate", final_merge)
        self.assertNotIn("trap ", final_merge)
        self.assertIn("The arm workflow owns factory-final-merge-gate", final_merge)
        self.assertIn("the Factory gate remains pending", final_merge)
        self.assertIn("Merge the exact revalidated head with the isolated Finalizer App", final_merge)
        self.assertNotIn("deployment_branch_policy.protected_branches", final_merge)
        self.assertNotIn('any(.protection_rules[]?; .type == "branch_policy")', final_merge)
        self.assertIn("Require source-gated automatic finalization", final_merge)
        self.assertIn("require_current_review_state() {\n            :", final_merge)
        self.assertIn("XSEC_MARKETPLACE_ADMIN_TOKEN", protection)
        self.assertIn("can_admins_bypass == false", protection)
        self.assertIn("deployment_branch_policy.protected_branches == true", protection)
        self.assertIn("deployment_branch_policy.custom_branch_policies == false", protection)
        self.assertIn('any(.protection_rules[]?; .type == "branch_policy")', protection)
        self.assertIn('select(.type == "required_reviewers")', protection)
        self.assertIn("length == 0", protection)
        self.assertIn("branches/main/protection", protection)
        self.assertIn("factory_main_protection_policy.py", protection)
        self.assertIn("XSEC_MARKETPLACE_ADMIN_TOKEN", readme)
        self.assertIn("factory-final-merge-gate", readme)
        self.assertIn("验证 release diff、全部 KMS sidecar、注册来源当前 ref 与 source gate", factory_document)
        self.assertIn("绝不写 success", factory_document)
        self.assertIn("xsec-marketplace-final-exact-head", factory_document)
        self.assertIn("remains pending through final revalidation and merge", finalizer_ruleset_document)
        self.assertIn("never\nwrites a success status", finalizer_ruleset_document)
        self.assertNotIn("short-lived exact-head approval", finalizer_ruleset_document)
        self.assertNotIn("requiring that check and GitHub merge queue", readme)

    def test_final_and_post_merge_source_proofs_use_the_separate_reader_app(self) -> None:
        final_merge = FINAL_MERGE_WORKFLOW.read_text(encoding="utf-8")
        dispatcher = POST_MERGE_DISPATCHER.read_text(encoding="utf-8")
        untrusted_pr_gate = MERGE_GUARD_WORKFLOW.read_text(encoding="utf-8")

        for workflow in (final_merge, dispatcher):
            with self.subTest(workflow="final" if workflow == final_merge else "dispatcher"):
                self.assertIn("XSEC_MARKETPLACE_SOURCE_APP_ID", workflow)
                self.assertIn("XSEC_MARKETPLACE_SOURCE_APP_PRIVATE_KEY", workflow)
                self.assertIn("Create a narrowly scoped read-only Source App token", workflow)
                self.assertIn("permission-contents: read", workflow)
                self.assertIn("GIT_TERMINAL_PROMPT=0", workflow)
                self.assertIn(
                    '-c http.https://github.com/.extraheader= \\\n              -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $token_header"',
                    workflow,
                )
                self.assertIn('http.https://github.com/.extraheader=AUTHORIZATION: basic $token_header', workflow)
        self.assertEqual(
            final_merge.count(
                '-c http.https://github.com/.extraheader= \\\n              -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $token_header"'
            ),
            3,
        )
        self.assertEqual(
            dispatcher.count(
                '-c http.https://github.com/.extraheader= \\\n              -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $token_header"'
            ),
            1,
        )
        self.assertIn("SOURCE_TOKEN: ${{ steps.source-token.outputs.token }}", final_merge)
        self.assertIn("SOURCE_TOKEN: ${{ steps.source-token.outputs.token }}", dispatcher)
        self.assertNotIn("steps.finalizer.outputs.token", dispatcher)
        # A pull_request runner executes the candidate workflow definition,
        # so it must not receive the protected Source App key. It can report
        # an authenticated public head early, but private access is deferred
        # to the production-gated final workflow above.
        self.assertNotIn("XSEC_MARKETPLACE_SOURCE_APP_PRIVATE_KEY", untrusted_pr_gate)
        self.assertIn("defer private-source proof to the final gate", untrusted_pr_gate)
        self.assertIn(')" || actual_sha=""', untrusted_pr_gate)

    def test_pending_generated_pr_scan_is_paginated_before_every_kms_call(self) -> None:
        workflows = (
            PUBLISH_WORKFLOW,
            ROOT / ".github" / "workflows" / "promote-stable.yml",
            REFRESH_SIDECAR_WORKFLOW,
            ADOPTION_WORKFLOW,
        )
        for workflow_path in workflows:
            workflow = workflow_path.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow_path.name):
                self.assertIn('gh api --paginate', workflow)
                self.assertIn('"repos/${GITHUB_REPOSITORY}/pulls?state=open&base=main&per_page=100"', workflow)
                self.assertIn('--arg repository "$GITHUB_REPOSITORY"', workflow)
                self.assertIn('select(.head.repo.full_name == $repository)', workflow)
                self.assertNotIn('.[] | .head.ref | select(startswith("xsec-marketplace/"))', workflow)
                self.assertNotIn('gh pr list --repo "$GITHUB_REPOSITORY" --base main --state open', workflow)
                if workflow_path in (PUBLISH_WORKFLOW, ROOT / ".github" / "workflows" / "promote-stable.yml"):
                    self.assertIn('.head.ref | startswith("xsec-marketplace/")', workflow)
                    self.assertIn('--paginate --slurp "repos/${GITHUB_REPOSITORY}/pulls/${number}/files?per_page=100"', workflow)
                    self.assertIn('Cannot completely inspect generated Factory PR', workflow)
                    self.assertIn('.xsec-factory/official-status/', workflow)
                    guard_start = workflow.index("Refuse to sign while this plugin has a generated Factory PR awaiting final merge")
                    guard_end = workflow.index("\n      - uses:", guard_start)
                    guard = workflow[guard_start:guard_end]
                    self.assertIn('/.xsec-market/releases.json', guard)
                    self.assertNotIn('/.xsec-market/releases.json.sig.jws.json', guard)
                    self.assertNotIn('.xsec-factory/official-publication-proofs/', guard)
                    self.assertNotIn('.xsec-factory/official-status-proofs/', guard)
                else:
                    self.assertIn('select(startswith("xsec-marketplace/"))', workflow)

    def test_retained_sidecar_refresh_is_manual_narrow_and_never_auto_merges(self) -> None:
        workflow = REFRESH_SIDECAR_WORKFLOW.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        for required_rule in (
            "workflow_dispatch:",
            "refs/heads/main",
            "environment: production",
            "XSEC_MARKETPLACE_PUBLISH_TOKEN",
            "id-token: write",
            "xsec-marketplace-publish-main",
            "validate_market.py source --source-root . --built-root .",
            "--retained-release-plugin-id",
            "--validate-only --retained-release-plugin-id",
            "--verify-retained-release-signature --retained-release-plugin-id",
            "external_source_factory.py validate",
            "git ls-files --others --exclude-standard",
            "The source gate passed. The final merge may now run.",
        ):
            with self.subTest(required_rule=required_rule):
                self.assertIn(required_rule, workflow)
        self.assertNotIn("github.ref_protected", workflow)
        self.assertNotIn('pulls/${pull_number}/merge', workflow)
        self.assertNotIn("XSEC_DESKTOP_REPOSITORY_DISPATCH_TOKEN", workflow)
        self.assertNotIn("@coderabbitai review", workflow)
        self.assertNotIn("review_body=", workflow)
        self.assertNotIn("\n\nThis PR was generated", workflow)
        self.assertIn("Retained KMS sidecar repair", readme)
        self.assertIn("refresh-retained-sidecars.yml", readme)
        self.assertIn("intentionally **never merges**\n", readme)

    def test_adoption_workflows_do_not_request_bot_review(self) -> None:
        workflow = ADOPTION_WORKFLOW.read_text(encoding="utf-8")
        stage = STAGE_ADOPTION_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("workflow_dispatch:", stage)
        self.assertIn("group: xsec-marketplace-publish-main", stage)
        self.assertIn("Stage only the immutable unsigned adoption proof", stage)
        self.assertIn("The Registry remains pending-adoption", stage)
        self.assertNotIn("@coderabbitai review", workflow)
        self.assertNotIn("@coderabbitai review", stage)
        self.assertNotIn("review_body=", workflow)
        self.assertNotIn("review_body=", stage)
        self.assertNotIn("\n\nThis is an immutable first-party adoption", workflow)

    def test_final_gate_arms_shared_commit_status_only_after_slurping_all_main_pr_pages(self) -> None:
        workflow = ARM_FINAL_GATE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('gh api --paginate --slurp "repos/${REPOSITORY}/pulls?state=all&base=main&per_page=100"', workflow)
        self.assertIn("any(.[][]; .head.sha == $sha and .head.repo.full_name == $repo", workflow)
        self.assertNotIn("commits/${PR_HEAD_SHA}/pulls", workflow)

    def test_main_protection_ruleset_inventory_paginates_and_flattens_every_page(self) -> None:
        workflow = PROTECTION_WORKFLOW.read_text(encoding="utf-8")
        inventory_call = 'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/rulesets?per_page=100"'

        # Both the pre-write create/update plan and the post-write uniqueness
        # check must see every inventory page. ``--slurp`` preserves page
        # boundaries, so the jq aggregation is part of the security boundary.
        self.assertEqual(workflow.count(inventory_call), 2)
        self.assertEqual(workflow.count("| jq -e '[.[][]]'"), 2)
        self.assertIn('| jq -e \'[.[][]]\' > "$rulesets"', workflow)
        self.assertIn('| jq -e \'[.[][]]\' > "$post_rulesets"', workflow)
        self.assertNotIn('gh api "repos/${GITHUB_REPOSITORY}/rulesets" > "$rulesets"', workflow)
        self.assertNotIn('gh api "repos/${GITHUB_REPOSITORY}/rulesets" > "$post_rulesets"', workflow)

    def test_post_merge_dispatcher_slurps_all_associated_pr_pages_before_selecting_factory_pr(self) -> None:
        workflow = POST_MERGE_DISPATCHER.read_text(encoding="utf-8")
        self.assertIn(
            'gh api --paginate --slurp -H \'Accept: application/vnd.github+json\' "repos/${GITHUB_REPOSITORY}/commits/${AFTER}/pulls?per_page=100"',
            workflow,
        )
        self.assertIn('[.[][] | select(.merged_at != null and .base.ref == "main"', workflow)
        self.assertIn('error("expected exactly one merged Factory generated PR")', workflow)
        self.assertNotIn('gh api -H \'Accept: application/vnd.github+json\' "repos/${GITHUB_REPOSITORY}/commits/${AFTER}/pulls?per_page=100"', workflow)

    def test_final_gate_uses_source_gates_without_review_state(self) -> None:
        workflow = FINAL_MERGE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Require a current source gate", workflow)
        self.assertIn("Require source-gated automatic finalization", workflow)
        self.assertIn("require_current_review_state() {\n            :", workflow)


if __name__ == "__main__":
    unittest.main()
