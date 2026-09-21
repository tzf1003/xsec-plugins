import assert from "node:assert/strict";
import { test } from "node:test";
import { activeFilterCount, defaultFilterSettings, extensionList, filterInput, parseFilterSettings, sameFilterSettings } from "../src/filter";

test("default filter preserves the accepted HTTP history categories", () => {
  const defaults = defaultFilterSettings();
  assert.equal(activeFilterCount(defaults), 1);
  assert.deepEqual(defaults.mimeCategories, ["html", "script", "xml", "otherText", "unknown"]);
  assert.deepEqual(extensionList(".JPG， png;js js"), ["jpg", "png", "js"]);
});

test("filter input retains search flags and normalized extensions", () => {
  const value = defaultFilterSettings();
  value.searchTerm = "  api.example  ";
  value.searchRegex = true;
  value.searchNegative = true;
  value.showOnlyExtensionsEnabled = true;
  value.showOnlyExtensionsText = ".php, JSP";
  const result = filterInput(value);
  assert.deepEqual(result.search, { term: "api.example", regex: true, caseSensitive: false, negative: true });
  assert.deepEqual(result.extensions.showOnly, ["php", "jsp"]);
});

test("stored defaults fail closed on invalid enum values", () => {
  const value = defaultFilterSettings() as unknown as Record<string, unknown>;
  value.sources = ["proxy", "external"];
  assert.throws(() => parseFilterSettings(value), /来源筛选格式无效/);
});

test("filter equality distinguishes unchanged and request-changing values", () => {
  const original = defaultFilterSettings();
  const copy = { ...original, mimeCategories: [...original.mimeCategories] };
  assert.equal(sameFilterSettings(original, copy), true);
  assert.equal(sameFilterSettings(original, { ...copy, searchTerm: "api" }), false);
  assert.equal(sameFilterSettings(original, { ...copy, sources: ["replay", "proxy"] }), false);
});
