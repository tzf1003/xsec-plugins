import assert from "node:assert/strict";
import { test } from "node:test";
import { ensureHost, prettyBody, renderSection, requiresSensitiveHostConfirmation } from "../src/proxy";

test("raw request adds an authority without replacing an existing Host", () => {
  const raw = "GET /login HTTP/1.1\r\nAccept: */*\r\n\r\n";
  assert.match(ensureHost(raw, { host: "2001:db8::1", port: 8443, scheme: "https" }), /Host: \[2001:db8::1\]:8443/);
  const existing = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
  assert.equal(ensureHost(existing, { host: "other.test", port: 443, scheme: "https" }), existing);
});

test("message rendering preserves start line, headers, body and JSON pretty view", () => {
  assert.equal(renderSection({ line: "HTTP/1.1 200 OK", headers: [["Content-Type", "application/json"]], body: "{\"ok\":true}" }), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}");
  assert.equal(prettyBody("{\"ok\":true}"), "{\n  \"ok\": true\n}");
});

/** Build replay-confirmation inputs with focused test overrides. */
function confirmationOptions(overrides: Partial<Parameters<typeof requiresSensitiveHostConfirmation>[0]>) {
  return {
    sourceHost: "old.test", sourcePort: 443, sourceScheme: "https",
    targetHost: "old.test", targetPort: 443, targetScheme: "https" as const,
    rawRequest: "",
    ...overrides,
  };
}

test("replay confirmation compares complete origins when sensitive headers are present", () => {
  const raw = "GET / HTTP/1.1\r\nHost: old.test\r\nCookie: session=1\r\n\r\n";
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ targetHost: "new.test", rawRequest: raw })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ targetHost: "OLD.TEST", rawRequest: raw })), false);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ targetHost: "new.test", rawRequest: raw.replace("Cookie", "X-Test") })), false);
  const editedHost = raw.replace("old.test", "other.test");
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: editedHost })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: raw })), false);
  const ipv6 = "GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\nCookie: session=1\r\n\r\n";
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ sourceHost: "2001:db8::1", targetHost: "2001:db8::1", rawRequest: ipv6 })), false);
  const authority = "GET / HTTP/1.1\r\nHost: OTHER.test:8443\r\nAuthorization: Bearer 1\r\n\r\n";
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: authority })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ sourceHost: "other.test", targetHost: "other.test", sourcePort: 8443, targetPort: 8443, rawRequest: authority })), false);
  const absoluteForeign = "GET https://other.test/path HTTP/1.1\r\nHost: old.test\r\nCookie: session=1\r\n\r\n";
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: absoluteForeign })), true);
  const absoluteSame = "GET https://old.test/path HTTP/1.1\r\nHost: old.test\r\nCookie: session=1\r\n\r\n";
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: absoluteSame })), false);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ targetScheme: "http", targetPort: 80, rawRequest: raw })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ targetPort: 8443, rawRequest: raw })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: absoluteSame.replace("https://", "http://") })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: raw.replace("Host: old.test", "Host:") })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: raw.replace("old.test", "old.test\\other.test") })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: absoluteSame.replace("old.test", "old.test\\other.test") })), true);
  assert.equal(requiresSensitiveHostConfirmation(confirmationOptions({ rawRequest: raw.replace("GET /", "GET https://[::1") })), true);
});
