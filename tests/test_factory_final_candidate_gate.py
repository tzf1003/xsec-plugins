from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARM_WORKFLOW = ROOT / ".github" / "workflows" / "arm-generated-marketplace-final-merge.yml"
FINAL_WORKFLOW = ROOT / ".github" / "workflows" / "final-merge-generated-marketplace-pr.yml"
ADOPTION_WORKFLOW = ROOT / ".github" / "workflows" / "adopt-first-party.yml"


class FactoryFinalCandidateGateWorkflowTests(unittest.TestCase):
    def test_retained_sidecar_refresh_is_a_pending_factory_candidate(self) -> None:
        workflow = ARM_WORKFLOW.read_text(encoding="utf-8")
        # Both the event branch and every same-repository Factory PR with a
        # shared head SHA must identify the generated repair, even if that
        # Factory PR was closed without merging. The commit-association API
        # omits such closed PRs before default-branch inclusion, so this must
        # use the complete main-targeting PR inventory. Otherwise an ordinary
        # same-SHA PR could overwrite its required pending status with success.
        self.assertGreaterEqual(workflow.count("xsec-marketplace/refresh-retained-sidecar-"), 2)
        self.assertIn('pulls?state=all&base=main&per_page=100', workflow)
        self.assertIn('any(.[][]; .head.sha == $sha and .head.repo.full_name == $repo', workflow)
        self.assertNotIn('commits/${PR_HEAD_SHA}/pulls', workflow)
        self.assertIn("factory_generated=true", workflow)
        self.assertIn("state=pending", workflow)
        # Both stages are privileged, review-gated Factory changes. The arm
        # workflow must keep an ordinary same-SHA PR from overwriting either
        # candidate's required pending finalizer status.
        self.assertGreaterEqual(workflow.count("xsec-marketplace/stage-first-party-adoption-"), 2)

    def test_release_shaped_content_is_pending_even_on_an_ordinary_branch(self) -> None:
        workflow = ARM_WORKFLOW.read_text(encoding="utf-8")
        # A Factory change may be cherry-picked and followed by an empty commit
        # on a normally named branch, producing a new SHA with no historical
        # Factory PR association. The trusted pull_request_target workflow may
        # read GitHub's authenticated file inventory, but must never check out
        # or execute that PR's files merely to make this safety classification.
        self.assertIn('pulls/${PR_NUMBER}/files?per_page=100', workflow)
        self.assertIn('repos/${REPOSITORY}/pulls/${PR_NUMBER}', workflow)
        self.assertIn('changed_file_count=', workflow)
        self.assertIn('returned_file_count=', workflow)
        self.assertIn('factory_content=true', workflow)
        self.assertIn('def release_index:', workflow)
        self.assertIn('def release_sidecar:', workflow)
        self.assertIn('def factory_document:', workflow)
        self.assertIn('any(.[][]; .filename | if type == "string" then', workflow)
        self.assertIn('|| [ "$factory_content" = "true" ]', workflow)
        self.assertIn("never checks out or executes PR content", workflow)
        self.assertNotIn("actions/checkout", workflow)

    def test_final_gate_revalidates_narrow_adoption_and_sidecar_candidates(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("xsec-marketplace/stage-first-party-adoption-*", workflow)
        self.assertIn("Adoption is a two-step non-release transition", workflow)
        self.assertIn("staging PR adds one unsigned assertion", workflow)
        self.assertIn("activation PR later adds only the matching sidecar", workflow)
        self.assertIn("xsec-marketplace/refresh-retained-sidecar-*", workflow)
        self.assertIn("beta-smoke-ready", workflow)
        self.assertIn("Only external Beta branches may reopen a no-pointer Desktop smoke cycle", workflow)
        self.assertIn("--verify-first-party-adoption-candidate", workflow)
        self.assertIn("--verify-retained-sidecar-refresh-candidate", workflow)
        self.assertIn("--verify-retained-release-signature --retained-release-plugin-id", workflow)
        self.assertIn("exact PR head has no successful Factory source gate", workflow)
        self.assertIn("latest @codex review request", workflow)
        self.assertIn(".state == \"APPROVED\" or .state == \"COMMENTED\"", workflow)
        self.assertIn("terminal Codex review", workflow)
        self.assertIn("codex-pull-request-review-summary", workflow)
        self.assertIn("Code Review", workflow)
        self.assertIn("Completed", workflow)
        self.assertIn("chatgpt-codex-connector[bot]", workflow)
        self.assertIn("short_head", workflow)
        self.assertIn("unresolved Codex review thread", workflow)

    def test_adoption_signer_uses_the_retained_protected_pre_staging_revision(self) -> None:
        workflow = ADOPTION_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(".legacy.factoryRevision", workflow)
        self.assertIn('git merge-base --is-ancestor "$baseline_revision" HEAD', workflow)
        self.assertIn('git cat-file -e "${baseline_revision}^{commit}"', workflow)
        self.assertNotIn("git log --diff-filter=A", workflow)

    def test_final_gate_never_turns_the_arm_owned_candidate_status_green(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("The arm workflow owns factory-final-merge-gate", workflow)
        self.assertNotIn("state=success -f context=factory-final-merge-gate", workflow)
        self.assertNotIn("statuses: write", workflow)
        self.assertNotIn("trap ", workflow)
        self.assertNotIn("XSEC_MARKETPLACE_PUBLISH_TOKEN", workflow)
        self.assertIn("XSEC_MARKETPLACE_FINALIZER_APP_ID", workflow)
        self.assertIn("XSEC_MARKETPLACE_FINALIZER_APP_PRIVATE_KEY", workflow)
        self.assertIn("permission-contents: write", workflow)
        # GitHub's merge endpoint needs Contents:write. Requesting a separate
        # Pull requests:write grant would widen the short-lived bypass token
        # without enabling its one exact-head merge call.
        self.assertNotIn("permission-pull-requests: write", workflow)
        self.assertIn("-f sha=\"$HEAD_SHA\"", workflow)

    def test_finalizer_token_follows_the_last_external_source_sha_check(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        merge_step = workflow.split(
            "- name: Merge the exact revalidated head with the isolated Finalizer App", 1
        )[1]
        source_check = "while IFS= read -r source; do"
        token_assignment = 'GH_TOKEN="${{ steps.finalizer.outputs.token }}" gh api --method PUT'

        # The short-lived bypass token must not exist in the source-read loop.
        # A source beta/main push while the token action runs is therefore
        # detected by this second proof, immediately before the only PUT that
        # receives the token. Private registered sources use the separate
        # exact-repository Source App reader; the Finalizer App never crosses
        # that repository boundary.
        self.assertNotIn("GH_TOKEN: ${{ steps.finalizer.outputs.token }}", workflow)
        self.assertIn("XSEC_MARKETPLACE_SOURCE_APP_ID", workflow)
        self.assertIn("XSEC_MARKETPLACE_SOURCE_APP_PRIVATE_KEY", workflow)
        self.assertIn("permission-contents: read", workflow)
        self.assertIn("SOURCE_TOKEN: ${{ steps.source-token.outputs.token }}", merge_step)
        self.assertIn(
            '-c http.https://github.com/.extraheader= \\\n              -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $token_header"',
            merge_step,
        )
        self.assertIn('http.https://github.com/.extraheader=AUTHORIZATION: basic $token_header', merge_step)
        self.assertEqual(
            workflow.count(
                '-c http.https://github.com/.extraheader= \\\n              -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $token_header"'
            ),
            3,
        )
        self.assertIn(source_check, merge_step)
        self.assertIn('factory-publication-sources.json', merge_step)
        self.assertIn(token_assignment, merge_step)
        self.assertIn(
            "advanced or could not be read immediately before the Finalizer merge; it remains pending.",
            merge_step,
        )
        self.assertLess(merge_step.index(source_check), merge_step.index(token_assignment))
        self.assertNotIn("GH_TOKEN", merge_step[: merge_step.index(token_assignment)])
        self.assertEqual(merge_step.count("GH_TOKEN="), 1)
        self.assertEqual(merge_step.count("gh api"), 1)

    def test_final_gate_scopes_source_reader_to_exact_owner_repositories(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        source_token = workflow.split("- name: Create a narrowly scoped read-only Source App token", 1)[1].split(
            "- name: Authenticate each registered source branch before review completion", 1
        )[0]

        self.assertIn("one Factory candidate cannot span multiple source owners", workflow)
        self.assertIn("repositories:($repositories | map(split(\"/\")[1]) | unique | join(\",\"))", workflow)
        self.assertIn("owner: ${{ steps.publication.outputs.source_owner }}", source_token)
        self.assertIn("repositories: ${{ steps.publication.outputs.source_repositories }}", source_token)
        self.assertIn("permission-contents: read", source_token)
        self.assertNotIn("permission-contents: write", source_token)

    def test_beta_smoke_gate_rechecks_both_registered_branch_heads(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        freshness = (ROOT / ".github" / "workflows" / "verify-generated-marketplace-publication.yml").read_text(encoding="utf-8")
        dispatcher = (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8")

        # Beta provenance alone is insufficient: each generated Beta candidate
        # binds the compared source-main head, and both unprotected early gate
        # and protected finalizer read it as an independently exact source ref.
        self.assertIn("(.main_source // empty)", workflow)
        self.assertIn("(.main_source // empty)", freshness)
        self.assertIn("(.main_source // empty)", dispatcher)
        self.assertIn("mainGateSha", dispatcher)

    def test_finalizer_and_dispatcher_require_the_exact_pr_source_gate(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        dispatcher = (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8")

        # The candidate source gate runs on pull_request. Accepting a
        # workflow_dispatch run would not prove that the exact PR content
        # received the reviewed Factory gate.
        for protected_workflow in (workflow, dispatcher):
            self.assertIn(
                "actions/workflows/validate.yml/runs?head_sha=${",
                protected_workflow,
            )
            self.assertIn("&event=pull_request&per_page=100", protected_workflow)
            self.assertNotIn("&event=workflow_dispatch&per_page=100", protected_workflow)
            self.assertIn("--argjson pull_number", protected_workflow)
            self.assertIn("any(.pull_requests[]?; .number == $pull_number)", protected_workflow)


if __name__ == "__main__":
    unittest.main()
