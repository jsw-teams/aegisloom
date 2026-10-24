import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";
import { createEdgeOneGateway } from "../adapters/edgeone/index.js";
import { signTc3 } from "../adapters/edgeone/sign.js";

const require = createRequire(import.meta.url);
const sdkSign = require("tencentcloud-sdk-nodejs-common/tencentcloud/common/sign.js").default;

test("portable TC3 signer matches the official SDK for UTC scope, Unicode and both regional endpoints", async () => {
  for (const host of ["teo.tencentcloudapi.com", "teo.intl.tencentcloudapi.com"]) {
    const payload = { ZoneId: "zone-test", Name: "未命名", SecurityConfig: {} };
    const timestamp = 1551113065;
    const expected = sdkSign.sign3({
      url: `https://${host}/`,
      payload,
      timestamp,
      service: "teo",
      secretId: "offline-id",
      secretKey: "offline-secret",
      headers: { "Content-Type": "application/json; charset=utf-8" },
    });
    const actual = await signTc3({
      host,
      service: "teo",
      body: JSON.stringify(payload),
      timestamp,
      secretId: "offline-id",
      secretKey: "offline-secret",
    });
    assert.equal(actual, expected);
    assert.match(actual, /2019-02-25\/teo\/tc3_request/);
  }
});
test("EdgeOne production transport signs only fixed official actions/endpoints and surfaces API errors", async () => {
  let failed = false;
  const gateway = createEdgeOneGateway({
    secretId: "offline-id",
    secretKey: "offline-secret",
    token: "offline-sts-token",
    zoneId: "zone-test",
    templateId: "template-test",
    endpoint: "teo.intl.tencentcloudapi.com",
    fetch: async (url, init) => {
      assert.equal(String(url), "https://teo.intl.tencentcloudapi.com/");
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("x-tc-action"), "DescribeSecurityPolicy");
      assert.equal(headers.get("x-tc-version"), "2022-09-01");
      assert.equal(headers.get("x-tc-token"), "offline-sts-token");
      const payload = JSON.parse(String(init?.body));
      const expected = sdkSign.sign3({
        url: String(url),
        payload,
        timestamp: Number(headers.get("x-tc-timestamp")),
        service: "teo",
        secretId: "offline-id",
        secretKey: "offline-secret",
        headers: { "Content-Type": "application/json; charset=utf-8" },
      });
      assert.equal(headers.get("authorization"), expected);
      return Response.json(
        failed
          ? { Response: { Error: { Code: "AuthFailure", Message: "sensitive omitted" } } }
          : { Response: { SecurityPolicy: { CustomRules: { Rules: [] } } } },
      );
    },
  });
  assert.deepEqual(await gateway.list(), []);
  assert.ok(gateway.target.includes("teo.intl.tencentcloudapi.com"));
  failed = true;
  await assert.rejects(gateway.list(), /sensitive response omitted/);
});
