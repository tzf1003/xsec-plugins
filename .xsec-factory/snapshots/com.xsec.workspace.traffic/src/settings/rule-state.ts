import type { PassiveRule } from "../types";

/** Determine whether passive rule values are equivalent. */
export function samePassiveRule(left: PassiveRule, right: PassiveRule): boolean {
  return left.rule_id === right.rule_id
    && left.severity === right.severity
    && left.pattern === right.pattern
    && left.enabled === right.enabled;
}
