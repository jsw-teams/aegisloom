import { randomBytes, timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { importConfiguredSource, readSources } from "../../packages/cli/sources.js";
import { SqliteAuthority } from "../../packages/control-plane/sqlite.js";
import { loadPolicy, type Policy } from "../../packages/rule-ir/index.js";
import { createShield, type SecurityEvent } from "../../packages/runtime/index.js";
import { createNodeServer } from "../../packages/runtime/node.js";

export async function startDemo() {
  const directory = await mkdtemp(join(tmpdir(), "shield-recording-"));
  const authority = new SqliteAuthority(join(directory, "authority.db"));
  const token = randomBytes(32).toString("hex"),
    csrf = randomBytes(32).toString("hex");
  const servers: ReturnType<typeof createNodeServer>[] = [];
  let originHits = 0,
    engines: Awaited<ReturnType<typeof createShield>>[] = [];
  let events: SecurityEvent[] = [],
    policy: Policy = loadPolicy({ version: "1", rules: [] });
  const listen = async (server: ReturnType<typeof createNodeServer>) => {
    servers.push(server);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No TCP listener");
    return `http://127.0.0.1:${address.port}`;
  };
  const origin = await listen(
    createNodeServer(
      async (request) => {
        const given = Buffer.from(request.headers.get("x-shield-origin-auth") ?? ""),
          expected = Buffer.from(token);
        if (given.length !== expected.length || !timingSafeEqual(given, expected))
          return new Response(null, { status: 403 });
        originHits++;
        return Response.json({ origin: "isolated-local-api", accepted: true });
      },
      () => new URL(origin).host,
    ),
  );
  const rebuild = async (next: Policy) => {
    policy = loadPolicy(next);
    events = [];
    engines = await Promise.all(
      [0, 1].map(() =>
        createShield({
          tenant: "recording",
          service: "api",
          publicHosts: ["api.demo.test"],
          policy,
          decisions: authority,
          revocationPollMs: 0,
          routes: [{ path: "/api/echo", methods: ["GET", "DELETE"], authenticated: false }],
          proxy: { origin, allowedOrigins: [origin], originToken: token, allowLoopbackHttp: true },
          event: (event) => {
            events.push(event);
            if (events.length > 50) events.shift();
          },
        }),
      ),
    );
  };
  await rebuild(policy);
  const edges = await Promise.all(
    [0, 1].map(async (index) =>
      listen(
        createNodeServer(
          (request, incoming) =>
            engines[index]!.handle(
              request,
              { tenant: "recording", verifiedClientIp: "127.0.0.1" },
              incoming.url,
            ),
          "api.demo.test",
        ),
      ),
    ),
  );
  const configPath = fileURLToPath(new URL("./sources.yaml", import.meta.url));
  const config = await readSources(configPath);
  const actions: Record<string, () => Promise<unknown>> = {
    config: async () => ({
      configuration: await readFile(configPath, "utf8"),
      summary: [
        "examples/demo/sources.yaml · JSON Schema validated",
        "",
        ...config.upstreams.map((s) => `${s.id} [${s.kind}] → ${s.origin}`),
        "",
        ...config.ruleSources.map(
          (s) =>
            `${s.id} [${s.format}] ${s.version} / ${s.license}\n  location: ${s.location} · SHA-256 prefix: ${s.sha256.slice(0, 16)}…`,
        ),
        "",
        "Secrets: environment references only. Full SHA-256 checked on import.",
      ].join("\n"),
      validated: true,
      note: "Cloud/VPS HTTPS profiles validated; recording uses a separate loopback-only origin.",
    }),
    import: async () => {
      const imported = await importConfiguredSource(configPath, "local-ir");
      await rebuild(imported);
      return {
        imported: "local-ir",
        schema: "valid",
        checksum: "verified",
        license: "Apache-2.0",
        rules: imported.rules.length,
        activation: "isolated recording runtime only",
      };
    },
    convert: async () => {
      // This is the independent converter package, never a parser bundled into Shield Core.
      const { convert } = await import(
        pathToFileURL(
          fileURLToPath(new URL("../../api-shield-convert/src/index.mjs", import.meta.url)),
        ).href
      );
      const source = config.ruleSources.find((s) => s.id === "seclang-method")!;
      const original = await readFile(new URL("./method.conf", import.meta.url), "utf8");
      const report = convert(original, {
        format: source.format,
        url: source.location,
        version: source.version,
        sha256: source.sha256,
        license: source.license,
        service: source.service,
      });
      const imported = await importConfiguredSource(configPath, source.id, report);
      await rebuild({ version: "1", rules: [...policy.rules, ...imported.rules] });
      return {
        converter: "api-shield-convert (independent package)",
        status: report.status,
        rules: imported.rules.length,
        provenance: imported.rules[0]?.provenance,
        limitation: "Strict method-only SecLang subset. Full CRS is not supported.",
      };
    },
    tamper: async () => {
      const { importSource } = await import("../../integrations/rule-converter/sources.js");
      try {
        await importSource(config, "local-ir", new TextEncoder().encode("tampered"));
      } catch (error) {
        return { rejected: true, reason: (error as Error).message, activated: false };
      }
      throw new Error("Tampered source was accepted");
    },
    revoke: async () => {
      const id = [...events].reverse().find((event) => event.decisionId)?.decisionId;
      if (!id) throw new Error("Create an attack decision first");
      return {
        revoked: id,
        generation: await authority.revoke("recording", id, Date.now()),
        note: "Cached decision revoked. The active detection rule still blocks a new matching attack.",
      };
    },
    rollback: async () => {
      await rebuild({ version: "1", rules: [] });
      return {
        rules: 0,
        policy: engines[0]!.version,
        note: "Explicit policy replacement in isolated runtime; identity and origin authentication remain enabled.",
      };
    },
    isolation: async () => {
      const response = await fetch(`${origin}/api/echo`);
      await response.arrayBuffer();
      return {
        directOriginStatus: response.status,
        originHits,
        note: "Origin token enforced locally; production must also restrict network ingress.",
      };
    },
  };
  for (const [name, instance, attack, method] of [
    ["legal", 0, false, "GET"],
    ["attack", 0, true, "GET"],
    ["l1", 0, true, "GET"],
    ["l2", 1, true, "GET"],
    ["delete", 0, false, "DELETE"],
  ] as const)
    actions[name] = async () => {
      const before = events.length;
      const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        const outgoing = httpRequest(
          `${edges[instance]}/api/echo${attack ? "?q=shield-demo-attack" : ""}`,
          { method, headers: { host: "api.demo.test" } },
          (incoming) => {
            let body = "";
            incoming.setEncoding("utf8");
            incoming.on("data", (chunk) => {
              body += chunk;
            });
            incoming.on("end", () => resolve({ status: incoming.statusCode!, body }));
            incoming.on("error", reject);
          },
        );
        outgoing.on("error", reject);
        outgoing.setTimeout(5000, () => outgoing.destroy(new Error("Local request timed out")));
        outgoing.end();
      });
      const body = response.body;
      return {
        instance: instance ? "B" : "A",
        request: `${method} /api/echo${attack ? "?q=shield-demo-attack" : ""}`,
        status: response.status,
        body,
        originHits,
        event: events.length > before ? events.at(-1) : null,
        stats: engines[instance]!.stats,
      };
    };
  let uiOrigin = "";
  const ui = createNodeServer(
    async (request) => {
      const url = new URL(request.url);
      const expectedHost = new URL(uiOrigin).host;
      if (request.headers.get("host") !== expectedHost) return new Response(null, { status: 421 });
      if (request.method === "GET" && url.pathname === "/") {
        const html = (await readFile(new URL("./index.html", import.meta.url), "utf8")).replaceAll(
          "__CSRF__",
          csrf,
        );
        return new Response(html, {
          headers: {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "content-security-policy":
              "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" +
              csrf +
              "'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
          },
        });
      }
      const action = actions[url.pathname.slice(1)];
      if (
        request.method !== "POST" ||
        request.headers.get("origin") !== uiOrigin ||
        request.headers.get("x-demo-csrf") !== csrf ||
        !action
      )
        return new Response(null, { status: 403 });
      try {
        return Response.json(await action(), { headers: { "cache-control": "no-store" } });
      } catch (error) {
        return Response.json({ error: (error as Error).message }, { status: 400 });
      }
    },
    () => new URL(uiOrigin).host,
  );
  uiOrigin = await listen(ui);
  const stop = async () => {
    for (const server of servers) server.closeAllConnections();
    await Promise.all(
      servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
    );
    authority.close();
    await rm(directory, { recursive: true, force: true });
  };
  return { url: uiOrigin, stop };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const demo = await startDemo();
  console.log(`Local recording console: ${demo.url}`);
  process.once("SIGINT", () => void demo.stop());
  process.once("SIGTERM", () => void demo.stop());
}
