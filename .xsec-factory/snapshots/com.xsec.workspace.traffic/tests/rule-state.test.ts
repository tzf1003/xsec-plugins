import assert from "node:assert/strict";
import { test } from "node:test";
import { samePassiveRule } from "../src/settings/rule-state";
import type { PassiveRule } from "../src/types";

const submitted: PassiveRule = {
  rule_id: "token-leak",
  severity: "high",
  pattern: "token=",
  enabled: true,
};

test("passive rule comparison detects edits made during an in-flight save", () => {
  assert.equal(samePassiveRule({ ...submitted }, submitted), true);
  assert.equal(samePassiveRule({ ...submitted, pattern: "secret=" }, submitted), false);
  assert.equal(samePassiveRule({ ...submitted, enabled: false }, submitted), false);
});
