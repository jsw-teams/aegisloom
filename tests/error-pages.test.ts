import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createErrorPageResponse,
  createErrorPages,
  wantsHtml,
} from "../packages/runtime/error-pages.js";
import { context, fixture, request } from "./helpers.js";

const page = {
  html: "<!doctype html><html><body><h1>Access denied.</h1></body></html>",
  contentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'",
};
test("trusted pages preserve status, HEAD and privacy without reflecting the request", async () => {
  const req = new Request("https://api.test/private?secret=sensitive", { method: "HEAD" });
  const response = createErrorPageResponse(req, 403, page);
  assert.equal(response.status, 403);
  assert.equal(await response.text(), "");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("vary"), "Accept");
  assert.throws(() => createErrorPages({ 403: { ...page, html: "x".repeat(262145) } }));
  assert.throws(() =>
    createErrorPages({ 403: { ...page, contentSecurityPolicy: "bad\r\nInjected: yes" } }),
  );
  assert.equal(
    wantsHtml(new Request("https://api.test", { headers: { accept: "text/html;q=0, */*" } })),
    false,
  );
  assert.equal(
    wantsHtml(
      new Request("https://api.test", { headers: { accept: "application/json, text/html;q=0.5" } }),
    ),
    false,
  );
});
test("rule and cached blocks use HTML for browsers and retain JSON APIs and enforcement", async () => {
  const f = await fixture({ errorPages: { 403: page, 404: page } });
  const browser = () => request("?q=attack", { headers: { accept: "text/html" } });
  for (let i = 0; i < 2; i++) {
    const response = await f.handle(browser(), context);
    assert.equal(response.status, 403);
    assert.equal(await response.text(), page.html);
  }
  assert.equal(f.events.at(-1)?.source, "l1");
  assert.equal(f.forwarded.length, 0);
  const api = await f.handle(
    request("?q=attack", { headers: { accept: "application/json" } }),
    context,
  );
  assert.equal(api.status, 403);
  assert.equal((await api.json()).error, "request_rejected");
  const missing = await f.handle(
    new Request("https://api.test/missing?private=value", { headers: { accept: "text/html" } }),
    context,
  );
  assert.equal(missing.status, 404);
  assert.equal(await missing.text(), page.html);
});
