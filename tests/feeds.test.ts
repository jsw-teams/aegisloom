import assert from "node:assert/strict";
import { test } from "node:test";
import {
  fetchOfficialFeed,
  importCve5,
  importEpss,
  importKev,
} from "../packages/vulnerability/index.js";

test("official feed conditional fetching preserves checkpoints and denies arbitrary destinations", async () => {
  const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  const result = await fetchOfficialFeed(url, {}, async () =>
    Response.json({ count: 0, vulnerabilities: [] }, { headers: { etag: '"v1"' } }),
  );
  assert.equal(result.changed, true);
  const unchanged = await fetchOfficialFeed(url, result.checkpoint, async (_, init) => {
    assert.equal(new Headers(init?.headers).get("if-none-match"), '"v1"');
    return new Response(null, { status: 304 });
  });
  assert.equal(unchanged.changed, false);
  await assert.rejects(fetchOfficialFeed("https://attacker.test/"), /Unsupported/);
});
test("CVE5 vendor semantics are preserved while KEV/EPSS are priority signals", () => {
  const cve = importCve5({
    dataType: "CVE_RECORD",
    dataVersion: "5.1",
    cveMetadata: {
      cveId: "CVE-2024-12345",
      state: "PUBLISHED",
      dateUpdated: "2024-01-01T00:00:00Z",
    },
    containers: {
      cna: {
        affected: [
          {
            vendor: "vendor",
            product: "product",
            versions: [{ version: "vendor-build", status: "affected", versionType: "custom" }],
          },
        ],
      },
    },
  });
  assert.deepEqual(cve.affected[0]?.versions, [
    { version: "vendor-build", status: "affected", versionType: "custom" },
  ]);
  assert.equal(
    importKev({
      count: 1,
      vulnerabilities: [
        {
          cveID: cve.id,
          requiredAction: "upgrade",
          dateAdded: "2024-01-01",
          dueDate: "2024-01-21",
        },
      ],
    }).get(cve.id)?.requiredAction,
    "upgrade",
  );
  assert.equal(
    importEpss({
      total: 1,
      data: [{ cve: cve.id, epss: "0.9", percentile: "0.99", date: "2024-01-01" }],
    }).get(cve.id)?.probability,
    0.9,
  );
  assert.throws(() => importEpss({ total: 2, data: [] }), /Incomplete/);
});
