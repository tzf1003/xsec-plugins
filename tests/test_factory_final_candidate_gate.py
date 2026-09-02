from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARM_WORKFLOW = ROOT / ".github" / "workflows" / "arm-generated-marketplace-final-merge.yml"
FINAL_WORKFLOW = ROOT / ".github" / "workflows" / "final-merge-generated-marketplace-pr.yml"
SELECTED_FINALIZER_WORKFLOW = ROOT / ".github" / "workflows" / "finalize-selected-generated-marketplace-pr.yml"
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
        # Both stages are privileged Factory changes. The arm
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
        self.assertIn('any(.[][]; [.filename, (.previous_filename? // "")]', workflow)
        self.assertIn("git/trees/" + "$" + "{PR_BASE_SHA}?recursive=1", workflow)
        self.assertIn("gitlink_changed", workflow)
        self.assertIn('|| [ "$factory_content" = "true" ]', workflow)
        self.assertIn('|| [ "$gitlink_changed" = "true" ]', workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("never checks out or executes PR content", workflow)
        self.assertNotIn("actions/checkout", workflow)

    def test_final_gate_revalidates_narrow_adoption_and_sidecar_candidates(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("xsec-marketplace/stage-first-party-adoption-*", workflow)
        self.assertIn("Adoption is a two-step non-release transition", workflow)
        self.assertIn("staging PR adds one unsigned assertion", workflow)
        self.assertIn("activation PR later adds only the matching sidecar", workflow)
        self.assertIn("xsec-marketplace/refresh-retained-sidecar-*", workflow)
        self.assertIn('elif [ "$kind" = "maintenance" ]; then', workflow)
        self.assertIn("The ordinary publisher can renew all immutable KMS sidecars", workflow)
        self.assertIn("(.promotions // [])[]", workflow)
        self.assertIn("beta-smoke-ready", workflow)
        self.assertIn("Only external Beta or signed batch branches may reopen a no-pointer Desktop smoke cycle", workflow)
        self.assertIn("--verify-first-party-adoption-candidate", workflow)
        self.assertIn("--verify-retained-sidecar-refresh-candidate", workflow)
        self.assertIn("--verify-retained-release-signature --retained-release-plugin-id", workflow)
        self.assertIn("exact PR head has no successful Factory source gate", workflow)
        self.assertIn("Require a current source gate", workflow)
        self.assertIn("Require source-gated automatic finalization", workflow)
        self.assertIn(
            "require_current_review_state() {\n"
            "            require_current_coderabbit_status\n"
            "            require_all_review_threads_resolved",
            workflow,
        )

    def test_every_generated_candidate_skips_bot_review_requests(self) -> None:
        workflows = (
            "publish.yml",
            "publish-marketplace-batch.yml",
            "promote-stable.yml",
            "stage-first-party-adoption.yml",
            "adopt-first-party.yml",
            "refresh-retained-sidecars.yml",
            "migrate-factory-layout-sidecars.yml",
        )
        for workflow_name in workflows:
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            with self.subTest(workflow=workflow_name):
                self.assertNotIn("@coderabbitai review", workflow)

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
        review_check = "require_current_review_state"
        self.assertIn(review_check, merge_step)
        self.assertLess(merge_step.rindex(review_check), merge_step.index(token_assignment))
        self.assertNotIn("steps.finalizer.outputs.token", merge_step[: merge_step.index(token_assignment)])
        self.assertEqual(merge_step.count('GH_TOKEN="${{ github.token }}"'), 4)
        self.assertEqual(merge_step.count('GH_TOKEN="${{ steps.finalizer.outputs.token }}"'), 1)
        self.assertEqual(merge_step.count("gh api graphql --paginate --slurp"), 2)
        self.assertEqual(merge_step.count("statuses?per_page=100"), 1)
        self.assertEqual(merge_step.count("gh api --method PUT"), 1)

    def test_final_gate_scopes_source_reader_to_exact_owner_repositories(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        source_token = workflow.split("- name: Create a narrowly scoped read-only Source App token", 1)[1].split(
            "- name: Authenticate each registered source branch before final merge", 1
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

        # The Finalizer runs while the candidate remains open, when GitHub
        # returns its pull_requests association.
        self.assertIn("--argjson pull_number", workflow)
        self.assertIn("any(.pull_requests[]?; .number == $pull_number)", workflow)

        # GitHub removes that association once a PR is merged. The post-merge
        # dispatcher therefore binds a pull_request run to the unique reviewed
        # generated branch and exact candidate head instead of accepting a
        # manual validation run.
        self.assertIn('head_ref="$(printf \'%s\' "$pr" | jq -er .head.ref)"', dispatcher)
        self.assertIn('--arg head_sha "$head_sha" --arg head_ref "$head_ref"', dispatcher)
        self.assertIn(".event == \"pull_request\"", dispatcher)
        self.assertIn(".head_sha == $head_sha", dispatcher)
        self.assertIn(".head_branch == $head_ref", dispatcher)
        self.assertNotIn("any(.pull_requests[]?; .number == $pull_number)", dispatcher)

    def test_dispatcher_manual_recovery_rechecks_current_waiting_beta(self) -> None:
        dispatcher = (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8")

        # Retrying a lost Desktop dispatch must not turn an arbitrary old
        # Factory revision into a release. The manual route accepts one exact
        # protected-main ancestor and rechecks the live status tuple first.
        for rule in (
            "workflow_dispatch:",
            "marketplace_revision:",
            "Manual Desktop smoke recovery requires an exact Factory revision SHA.",
            "git merge-base --is-ancestor \"$AFTER\" origin/main",
            "needs-smoke-redispatch",
            "manual Desktop smoke recovery requires every promotion to have a registered source",
            "manual_recovery: ${{ steps.classify.outputs.manual_recovery }}",
            "recovery_tuples: ${{ steps.classify.outputs.recovery_tuples }}",
            "Revalidate current Factory recovery tuple immediately before dispatch",
            "--verify-active-marketplace-signatures",
            "--json needs-smoke-redispatch",
            "--beta-release-id \"$beta_release_id\"",
            "MARKETPLACE_REVISION: ${{ needs.verify-reviewed-publication.outputs.marketplace_revision }}",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, dispatcher)

    def test_dispatcher_recovers_only_the_current_signed_registered_plugin_beta(self) -> None:
        dispatcher = (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8")

        for rule in (
            "plugin_id:",
            "INPUT_PLUGIN_ID: ${{ inputs.plugin_id }}",
            '[[ "$INPUT_PLUGIN_ID" =~ ^[a-z0-9]([a-z0-9.-]{0,62}[a-z0-9])?$ ]]',
            'Manual registered-plugin smoke recovery requires the current protected Factory revision.',
            "python scripts/external_source_factory.py validate",
            'expected one active registered plugin',
            '"waiting_for_smoke"',
            "Registered plugin recovery status is not bound to the active signed Beta tuple",
            'kind:"beta-smoke-ready"',
            "registered_recovery: ${{ steps.classify.outputs.registered_recovery }}",
            'REGISTERED_RECOVERY: ${{ steps.classify.outputs.registered_recovery }}',
            '$registered_recovery == "true"',
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, dispatcher)

    def test_dispatcher_smokes_only_the_ready_subset_of_a_mixed_beta_batch(self) -> None:
        dispatcher = (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8")

        # A later source-main event may make one sibling reproducible while
        # another remains waiting_for_beta. The ready tuple still needs an
        # exact status binding, but the waiting sibling must never widen the
        # Source App token, source revalidation, manual recovery tuple, or
        # Desktop request.
        for rule in (
            "selected_promotions=\"$(printf '%s' \"$result\" | jq -cer '[.promotions[] | select(.source != null)]')\"",
            'waiting_for_smoke) smoke_promotions+=("$promotion") ;;',
            "done < <(printf '%s' \"$selected_promotions\" | jq -rc '.[]')",
            'selected_promotions="$(printf \'%s\\n\' "${smoke_promotions[@]}" | jq -sc \'.\')"',
            'sources="$(printf \'%s\' "$selected_promotions" | jq -c \'[.[] | .source, (.main_source // empty)]\')"',
            "No registered Beta promotion is currently waiting for Desktop smoke",
            "Use only the already-selected smoke subset",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, dispatcher)

    def test_dispatcher_skips_only_kms_authenticated_callback_bound_registered_stable_smoke(self) -> None:
        dispatcher = (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8")
        self.assertIn('elif (.promotions | type) != "array" or (.promotions | length) == 0 then false', dispatcher)
        self.assertIn('all(.promotions[];', dispatcher)
        self.assertIn("Do not use jq -e here: false is the expected result", dispatcher)
        self.assertIn('[ "$kind" != "beta" ] && [ "$kind" != "beta-smoke-ready" ] && [ "$kind" != "stable" ]', dispatcher)
        for required_status_binding in (
            'status_path=".xsec-factory/official-status/${plugin_id}.json"',
            '.publication.state == "published"',
            '.source.stableSha == $stable_sha',
            '.release.betaReleaseId == $release_id',
            '.release.stableReleaseId == $release_id',
            '.publication.smokeRunUrl | type == "string"',
            '.publication.marketplaceRevision | type == "string"',
            'All registered Stable completions are bound to their KMS-authenticated Beta Desktop smoke callbacks',
        ):
            with self.subTest(required_status_binding=required_status_binding):
                self.assertIn(required_status_binding, dispatcher)

        stable_skip = 'if [ "$callback_bound_stable" = "true" ]; then'
        self.assertIn(stable_skip, dispatcher)
        self.assertIn("done < <(printf '%s' \"$result\" | jq -rc '.promotions[]')", dispatcher)
        # A legacy pointer-only stable promotion has no registered source and
        # a manual external Stable recovery has no terminal smoke status, so
        # both remain eligible for the independent Stable smoke contract.
        self.assertIn("Dispatch the validated Beta or Stable revision to Desktop smoke", dispatcher)
        self.assertNotIn("Dispatch the validated Beta revision to Desktop smoke", dispatcher)
        # KMS verification must precede the callback-status no-op, while the
        # no-op still occurs before source tokens and Desktop dispatch quota.
        self.assertLess(
            dispatcher.index("verification=\"$(python scripts/kms_marketplace_publisher.py"),
            dispatcher.index("callback_bound_stable=\"$(printf '%s' \"$result\""),
        )
        self.assertLess(dispatcher.index(stable_skip), dispatcher.index("source_scope=\"$(printf '%s' \"$sources\""))

    def test_finalizer_requires_exact_head_review_state(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Require a current source gate", workflow)
        self.assertIn("Require source-gated automatic finalization", workflow)
        review_gate = workflow.split("- name: Require source-gated automatic finalization", 1)[1].split(
            "- name: Recheck the live PR/source boundary before the isolated final merge", 1
        )[0]
        self.assertNotIn("exit 0", review_gate)
        self.assertIn('description == "Review completed"', review_gate)
        self.assertIn("reviewThreads(first:100", review_gate)
        self.assertIn(
            "require_current_review_state() {\n"
            "            require_current_coderabbit_status\n"
            "            require_all_review_threads_resolved",
            workflow,
        )

    def test_protected_finalizer_runs_after_the_unprivileged_selector(self) -> None:
        selector = (ROOT / ".github" / "workflows" / "auto-finalize-generated-marketplace-pr.yml").read_text(encoding="utf-8")
        workflow = SELECTED_FINALIZER_WORKFLOW.read_text(encoding="utf-8")

        # The selector has no reusable final-merge job; a workflow_run from
        # protected default-branch configuration finds one current-baseline
        # candidate before handing it to the production finalizer.
        self.assertNotIn("final-revalidate-and-merge:", selector)
        self.assertIn("workflows: [Automatically finalize generated Marketplace PR]", workflow)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", workflow)
        self.assertNotIn("github.event.workflow_run.head_branch", workflow)
        self.assertIn("Require the preceding unprivileged selector to have run", workflow)
        self.assertIn("actions/runs/${UPSTREAM_RUN_ID}/jobs?per_page=100", workflow)
        self.assertIn('git/ref/heads/main" --jq .object.sha', workflow)
        self.assertIn('.base.sha == $main_sha', workflow)
        self.assertIn('test("^xsec-marketplace/(publish-|batch-|default-set-|external-beta-', workflow)
        self.assertIn("ready_matches='[]'", workflow)
        self.assertIn("done < <(printf '%s' \"$matches\" | jq -rc '.[]')", workflow)
        self.assertIn("expected one ready current-baseline generated PR", workflow)
        self.assertIn("refs/heads/main", FINAL_WORKFLOW.read_text(encoding="utf-8"))
        self.assertIn("source-freshness-gate", workflow)


if __name__ == "__main__":
    unittest.main()
