/** Actual xterm input and X11 recording in the existing disposable recording VM. */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "../.."),
  recording = resolve(process.argv[2] ?? "../edgepress");
const require = createRequire(resolve(recording, "package.json")),
  { chromium } = require("playwright");
const { guest, openApp, typeCommand, activate, guestPath } = await import(
  pathToFileURL(resolve(recording, "tools/recordings/vm-desktop.mjs"))
);
const { recordingContext, record, closeRecording } = await import(
  pathToFileURL(resolve(recording, "tools/recordings/desktop-recording.mjs"))
);
const artifact = resolve(root, "tools/.cache/vm-routing-recording"),
  output = resolve(root, "tools/demo");
await mkdir(artifact, { recursive: true });
const mounted = root
  .replaceAll("\\", "/")
  .replace(/^([a-z]):/i, (_, drive) => `/mnt/${drive.toLowerCase()}`);
const version = JSON.parse(await readFile(resolve(root, "package.json"))).version;
const demo = "/opt/recording/edgeaegis-routing-demo",
  archive = `/opt/recording/packages/edgeaegis-${version}.tgz`;
await guest(["mkdir", "-p", "/opt/recording/packages"]);
await guest(["cp", `${mounted}/tools/.cache/edgeaegis-${version}.tgz`, archive]);
// The package and its dependencies are installed before recording; the visible commands operate the real CLI and server.
await guest([
  "bash",
  "-lc",
  `cd /opt/recording/edgeaegis-cli && npm install --offline --no-audit --no-fund '${archive}'`,
]);
await guest(["/opt/recording/edgeaegis-cli/node_modules/.bin/edgeaegis", "init", demo]);
await guest([
  "node",
  "--input-type=module",
  "-e",
  `import{readFileSync,writeFileSync}from'node:fs';const p='${demo}/package.json',j=JSON.parse(readFileSync(p));j.dependencies.edgeaegis='file:${archive}';writeFileSync(p,JSON.stringify(j));`,
]);
await guest(["bash", "-lc", `cd '${demo}' && npm install --offline --no-audit --no-fund`]);
await guest(["node", `${mounted}/tools/demo/prepare-lab.mjs`, demo, archive]);
const rc = resolve(artifact, "bashrc");
await writeFile(
  rc,
  `export PATH=/usr/local/bin:/usr/bin:/bin\ncd '${demo}'\nexport PS1='edgeaegis ❯ '\n`,
);
const browser = await chromium.connectOverCDP("http://127.0.0.1:9222");
const context = await recordingContext(browser, { locale: "en" }, artifact);
const server = "EdgeAegis server",
  terminal = "EdgeAegis curl verification",
  backend = "EdgeAegis TLS origins";
const term = async (title) =>
  openApp(
    [
      "xterm",
      "-T",
      title,
      "-fa",
      "Monospace",
      "-fs",
      "17",
      "-bg",
      "#17212c",
      "-fg",
      "#e8edf2",
      "-geometry",
      "90x32+20+20",
      "-e",
      "bash",
      "--rcfile",
      guestPath(rc),
    ],
    title,
  );
const wait = (ms) => new Promise((done) => setTimeout(done, ms));
try {
  await term(backend);
  await typeCommand(artifact, backend, "node tools/lab/origins.mjs");
  await term(server);
  await typeCommand(artifact, server, "npm run deploy:local");
  for (let n = 0; n < 40; n++) {
    try {
      const text = await guest([
        "curl",
        "-fsS",
        "-H",
        "Host: demo.test",
        "http://127.0.0.1:8787/app",
      ]);
      assert.equal(JSON.parse(text).business, "app");
      break;
    } catch (error) {
      if (n === 39) throw error;
      await wait(300);
    }
  }
  await term(terminal);
  const page = await context.newPage();
  const command = async (value, delay = 1700) => {
    const file = resolve(artifact, ".curl-command.txt");
    await writeFile(file, value);
    await activate(terminal);
    await guest([
      "xdotool",
      "type",
      "--clearmodifiers",
      "--delay",
      "15",
      "--file",
      guestPath(file),
    ]);
    await guest(["xdotool", "key", "Return"]);
    await wait(delay);
  };
  await record(
    page,
    "edgeaegis-routing",
    async () => {
      await command("cat origin/config.yml", 2800);
      await command("sed -E 's/(: ).{32,}/\\1[redacted]/' secret/credentials.yml", 2200);
      await command("clear; curl -si -H 'Host: demo.test' http://127.0.0.1:8787/app");
      await command("curl -si -H 'Host: demo.test' http://127.0.0.1:8787/shop");
      for (const name of ["vps", "balance", "external"])
        await command(`clear; curl -si -H 'Host: demo.test' http://127.0.0.1:8787/${name}`);
      await command("cat tools/origin-requests.log");
      await command(
        "clear; curl -si -H 'Host: demo.test' 'http://127.0.0.1:8787/vps?q=1%20UNION%20SELECT%20password%20FROM%20users'",
        2600,
      );
      await command("cat tools/origin-requests.log", 2200);
      // Make the configured native TTL protection visible through actual curl responses.
      await command(
        "curl -s -o /dev/null -H 'Host: demo.test' 'http://127.0.0.1:8787/vps?q=1%20UNION%20SELECT%20password%20FROM%20users'",
        200,
      );
      await command(
        "curl -s -o /dev/null -H 'Host: demo.test' 'http://127.0.0.1:8787/vps?q=1%20UNION%20SELECT%20password%20FROM%20users'",
        200,
      );
      await command("clear; curl -si -H 'Host: demo.test' http://127.0.0.1:8787/app", 1500);
      assert.equal(
        await guest([
          "curl",
          "-s",
          "-o",
          "/dev/null",
          "-w",
          "%{http_code}",
          "-H",
          "Host: demo.test",
          "http://127.0.0.1:8787/app",
        ]),
        "403",
      );
      await command("sleep 6; curl -si -H 'Host: demo.test' http://127.0.0.1:8787/app", 9900);
    },
    { foreground: () => activate(terminal) },
  );
  const lines = (await guest(["cat", `${demo}/tools/origin-requests.log`])).split("\n");
  assert.deepEqual(lines, ["vps GET /vps", "balance GET /balance", "external GET /external"]);
  const recovered = await guest([
    "curl",
    "-fsS",
    "-H",
    "Host: demo.test",
    "http://127.0.0.1:8787/app",
  ]);
  assert.equal(JSON.parse(recovered).business, "app");
  const entries = await closeRecording(context, {
    artifact,
    output,
    source: "tools/demo/record-vm.mjs",
    kind: "Actual VM xterm: curl HTTP responses; two functions; three authenticated TLS origins; complete CRS SQLi block; unchanged origin access log; demo-only 5s native TTL",
  });
  await writeFile(resolve(artifact, "result.json"), `${JSON.stringify(entries, null, 2)}\n`);
} finally {
  for (const title of [server, terminal, backend])
    try {
      const ids = await guest(["xdotool", "search", "--onlyvisible", "--name", title]);
      for (const id of ids.split(/\s+/)) {
        const pid = await guest(["xdotool", "getwindowpid", id]);
        if (/^\d+$/.test(pid)) await guest(["kill", "-TERM", pid]);
      }
    } catch {}
  await browser.close();
}
