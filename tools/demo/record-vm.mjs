/** Real X11 guest capture, using the shared EdgePress recording tools. No host input/capture. */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "../.."),
  recording = resolve(process.argv[2] ?? "../edgepress");
const require = createRequire(resolve(recording, "package.json"));
const { chromium } = require("playwright");
const { guest, openApp, typeCommand, activate, guestPath } = await import(
  pathToFileURL(resolve(recording, "tools/recordings/vm-desktop.mjs"))
);
const { recordingContext, record, closeRecording } = await import(
  pathToFileURL(resolve(recording, "tools/recordings/desktop-recording.mjs"))
);
const artifact = resolve(root, "tools/.cache/vm-recording"),
  output = resolve(root, "tools/demo");
await mkdir(artifact, { recursive: true });
await mkdir(output, { recursive: true });
const mounted = root
  .replaceAll("\\", "/")
  .replace(/^([a-z]):/i, (_, drive) => `/mnt/${drive.toLowerCase()}`);
await guest([
  "bash",
  "-lc",
  `test -e /opt/recording/workspace/api-shield || ln -s '${mounted}' /opt/recording/workspace/api-shield`,
]);
assert.equal(await guest(["readlink", "-f", "/opt/recording/workspace/api-shield"]), mounted);
const demo = "/opt/recording/edgeshield-native-demo",
  archive = `/opt/recording/packages/jsw-teams-edgeshield-${JSON.parse(await readFile(resolve(root, "package.json"))).version}.tgz`;
await guest(["/opt/recording/edgeshield-cli/node_modules/.bin/edgeshield", "init", demo]);
await guest([
  "node",
  "--input-type=module",
  "-e",
  `
import{readFileSync,writeFileSync,copyFileSync,rmSync}from'node:fs';const root=${JSON.stringify(demo)},archive=${JSON.stringify(archive)};
for(const file of ['setup.conf','emergency.conf'])copyFileSync('/opt/recording/edgeshield-cli/node_modules/@jsw-teams/edgeshield/rules/'+file,root+'/rules/'+file);
for(const file of ['.install-complete','.probe-complete'])rmSync(root+'/'+file,{force:true});
const p=JSON.parse(readFileSync(root+'/package.json'));p.dependencies['@jsw-teams/edgeshield']='file:'+archive;writeFileSync(root+'/package.json',JSON.stringify(p,null,2));
let c=readFileSync(root+'/config.yml','utf8').replace('publicHosts: [api.example]',"publicHosts: ['127.0.0.1:8787']");writeFileSync(root+'/config.yml',c);
let s=readFileSync(root+'/rules/setup.conf','utf8').replaceAll('expirevar:ip.edgeshield_blocked=300','expirevar:ip.edgeshield_blocked=5');writeFileSync(root+'/rules/setup.conf',s);
writeFileSync(root+'/origin/cloudflare/app/index.js','export default {async fetch(){return Response.json({ok:true,business:"demo"});}};');
writeFileSync(root+'/probe.mjs',${JSON.stringify(`import assert from 'node:assert/strict';import{writeFileSync}from'node:fs';
async function probe(label,path,expected,headers={}){const r=await fetch('http://127.0.0.1:8787'+path,{headers});await r.text();console.log(label+' -> '+r.status);assert.equal(r.status,expected);}
await probe('Normal traffic','/health',200);
await probe('Native CVE-2025-29927 patch','/api',403,{'x-middleware-subrequest':''});
await probe('Complete CRS: SQL injection','/api?q=1%20UNION%20SELECT%20password%20FROM%20users',403);
await probe('Repeated CRS attack','/api?q=1%20UNION%20SELECT%20password%20FROM%20users',403);
await probe('Temporary IP protection','/health',403);
console.log('Waiting for the demo TTL (5 seconds)...');await new Promise(r=>setTimeout(r,5500));
await probe('Automatic TTL recovery','/health',200);
writeFileSync('.probe-complete','all assertions passed');
`)});
`,
]);
const rc = resolve(artifact, "bashrc");
await writeFile(rc, `export PATH=/usr/local/bin:/usr/bin:/bin\ncd '${demo}'\nexport PS1='❯ '\n`);
const browser = await chromium.connectOverCDP("http://127.0.0.1:9222");
const context = await recordingContext(browser, { locale: "en" }, artifact);
const terminal = "EdgeShield native demo",
  probeTerminal = "EdgeShield verification";
try {
  await openApp(
    [
      "xterm",
      "-T",
      terminal,
      "-fa",
      "Monospace",
      "-fs",
      "17",
      "-bg",
      "#17212c",
      "-fg",
      "#e8edf2",
      "-geometry",
      "100x30+40+30",
      "-e",
      "bash",
      "--rcfile",
      guestPath(rc),
    ],
    terminal,
  );
  const page = await context.newPage();
  await record(
    page,
    "edgeshield-native",
    async () => {
      await typeCommand(
        artifact,
        terminal,
        "npm install --no-audit --no-fund && touch .install-complete",
      );
      for (let n = 0; n < 60; n++) {
        if (
          (await guest([
            "bash",
            "-lc",
            `test -f '${demo}/.install-complete' && echo ready || true`,
          ])) === "ready"
        )
          break;
        await new Promise((done) => setTimeout(done, 500));
      }
      await typeCommand(artifact, terminal, "npm run deploy:local");
      for (let n = 0; n < 60; n++) {
        try {
          if ((await fetch("http://127.0.0.1:8787/health")).status === 200) break;
        } catch {}
        if (n === 59) throw new Error("Actual guest engine did not start");
        await new Promise((done) => setTimeout(done, 300));
      }
      await openApp(["geany", "-i", `${demo}/rules/setup.conf`], "Geany");
      await new Promise((done) => setTimeout(done, 2000));
      await openApp(
        [
          "xterm",
          "-T",
          probeTerminal,
          "-fa",
          "Monospace",
          "-fs",
          "17",
          "-bg",
          "#17212c",
          "-fg",
          "#e8edf2",
          "-geometry",
          "100x30+40+30",
          "-e",
          "bash",
          "--rcfile",
          guestPath(rc),
        ],
        probeTerminal,
      );
      await typeCommand(artifact, probeTerminal, "node probe.mjs");
      await new Promise((done) => setTimeout(done, 6500));
      assert.equal(await guest(["cat", `${demo}/.probe-complete`]), "all assertions passed");
      // Independent assertion on the actual recovered engine, before showing its rejection page.
      assert.equal((await fetch("http://127.0.0.1:8787/health")).status, 200);
      await activate("Chromium");
      const response = await page.goto(
        "http://127.0.0.1:8787/api?q=1%20UNION%20SELECT%20password%20FROM%20users",
      );
      assert.equal(response.status(), 403);
      await new Promise((done) => setTimeout(done, 2200));
    },
    { foreground: () => activate(terminal) },
  );
  const entries = await closeRecording(context, {
    artifact,
    output,
    source: "tools/demo/record-vm.mjs",
    kind: "FFmpeg capture of real VM xterm, Geany and Chromium; actual complete CRS; demo-only ban TTL 5 seconds",
  });
  await writeFile(resolve(artifact, "result.json"), `${JSON.stringify(entries, null, 2)}\n`);
} finally {
  for (const title of [terminal, probeTerminal, "Geany"]) {
    try {
      const ids = await guest(["xdotool", "search", "--onlyvisible", "--name", title]);
      for (const id of ids.split(/\s+/)) {
        const pid = await guest(["xdotool", "getwindowpid", id]);
        if (/^\d+$/.test(pid)) await guest(["kill", "-TERM", pid]);
      }
    } catch {}
  }
  await browser.close();
}
