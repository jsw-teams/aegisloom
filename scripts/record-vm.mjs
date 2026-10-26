// Records the existing Linux guest's actual X11 desktop. No rendered terminal or HTML console.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { distro, guest, launch, mount, quote, shell, wsl } from "./recording/vm.mjs";

const root = fileURLToPath(new URL("../", import.meta.url)),
  artifact = resolve(root, "artifacts/vm-recording");
await mkdir(artifact, { recursive: true });
await mkdir(resolve(root, "docs/media"), { recursive: true });
const manifest = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
const version = manifest.version;
const lab = `/opt/recording/cloud-api-shield-${Date.now()}`;
const core = resolve(root, `artifacts/jsw-teams-shieldweave-${version}.tgz`);
const converterVersion = JSON.parse(
  await readFile(resolve(root, "api-shield-convert/package.json"), "utf8"),
).version;
const converter = resolve(root, `artifacts/api-shield-convert-${converterVersion}.tgz`);
const title = "ShieldWeave | CodexRecordingVM WSL2";
const runningBytes = execFileSync(wsl, ["--list", "--running", "--quiet"], { windowsHide: true });
const wasRunning = runningBytes
  .toString(runningBytes.includes(0) ? "utf16le" : "utf8")
  .split(/\r?\n/)
  .some((name) => name.trim() === distro);
const owned = (name, args, options) =>
  launch(
    ["bash", "-lc", `echo $$ > ${quote(`${lab}/${name}.pid`)}; exec ${args.map(quote).join(" ")}`],
    options,
  );
const wait = (ms) => new Promise((done) => setTimeout(done, ms));
const evidence = [],
  segments = [];
let recorder,
  terminal,
  desktop,
  wm,
  originProcess,
  recorded = false;
let transcriptOffset = 0,
  startedAt = 0;
const stamp = () => Math.round(((Date.now() - startedAt) / 1000) * 1000) / 1000;
async function currentStatus() {
  return shell(
    `test -s ${quote(`${lab}/command-status.jsonl`)} && tail -n 1 ${quote(`${lab}/command-status.jsonl`)}`,
  );
}
async function command(text, { exit = 0, check, hold = 1800 } = {}) {
  const previous = JSON.parse(await currentStatus()).step;
  await writeFile(resolve(artifact, "command.txt"), text);
  await guest(["xdotool", "search", "--onlyvisible", "--name", title, "windowactivate", "--sync"]);
  await guest([
    "xdotool",
    "type",
    "--clearmodifiers",
    "--delay",
    "22",
    "--file",
    mount(resolve(artifact, "command.txt")),
  ]);
  await guest(["xdotool", "key", "Return"]);
  let status;
  for (let i = 0; i < 600; i++) {
    const latest = JSON.parse(await currentStatus());
    if (latest.step > previous) {
      status = latest;
      break;
    }
    await wait(100);
  }
  assert.ok(status, `Real terminal command timed out: ${text}`);
  assert.equal(status.exit, exit, text);
  const transcript = await guest(["cat", `${lab}/terminal.typescript`]);
  const delta = transcript.slice(transcriptOffset);
  transcriptOffset = transcript.length;
  if (check) await check(delta);
  evidence.push({ command: text, exit: status.exit, atSeconds: stamp() });
  console.log(`VM terminal verified: ${text}`);
  await wait(process.env.RECORDING_FAST === "1" ? 80 : hold);
}
const lastEvent = async (instance) =>
  JSON.parse(await shell(`cd ${quote(lab)} && node event.mjs ${quote(instance)}`));
try {
  const system = await guest(["uname", "-r"]);
  assert.match(
    system,
    /microsoft.*WSL2/i,
    "Use the existing requested recording guest; do not simulate it",
  );
  await shell(
    `mkdir -p ${quote(lab)} && cp ${quote(mount(resolve(root, "scripts/recording")))}/* ${quote(lab)}/ && cd ${quote(lab)} && printf '{"private":true,"type":"module"}\n' > package.json && npm install --ignore-scripts --no-audit --no-fund ${quote(mount(core))} ${quote(mount(converter))}`,
    { timeout: 180000 },
  );
  console.log(`Installed the actual packed engine and independent converter in ${distro}`);
  await shell(`cd ${quote(lab)} && node prepare.mjs`, { timeout: 15000 });
  originProcess = launch([
    "bash",
    "-lc",
    `cd ${quote(lab)} && source private.env && exec node origin.mjs`,
  ]);
  originProcess.stdout.resume();
  originProcess.stderr.resume();
  for (let i = 0; i < 100; i++) {
    try {
      await guest(["test", "-s", `${lab}/origin-url.txt`]);
      break;
    } catch {
      await wait(100);
    }
  }
  await shell(`cd ${quote(lab)} && node configure.mjs`);
  // Same guest desktop stack as EdgePress's existing tools/recordings, without launching a browser.
  desktop = owned("xvfb", ["Xvfb", ":99", "-screen", "0", "1440x900x24", "-nolisten", "tcp"]);
  desktop.stdout.resume();
  desktop.stderr.resume();
  for (let i = 0; i < 50; i++) {
    try {
      await guest(["xdpyinfo"]);
      break;
    } catch {
      await wait(100);
    }
  }
  wm = owned("openbox", ["openbox"]);
  wm.stdout.resume();
  wm.stderr.resume();
  await wait(400);
  await guest(["xsetroot", "-solid", "#243343"]);
  const rc = `cd ${quote(lab)}\nsource private.env\nexport PATH="$PWD/node_modules/.bin:$PATH"\nexport PS1='shield-vm $ '\n__step=0\nPROMPT_COMMAND='__status=$?; printf "{\\"step\\":%d,\\"exit\\":%d}\\n" "$__step" "$__status" >> command-status.jsonl; __step=$((__step+1))'\n`;
  await writeFile(resolve(artifact, "bashrc"), rc);
  terminal = owned("xterm", [
    "xterm",
    "-T",
    title,
    "-fa",
    "DejaVu Sans Mono",
    "-fs",
    "18",
    "-bg",
    "#101b2b",
    "-fg",
    "#e4edf8",
    "-geometry",
    "118x34+35+30",
    "-e",
    "script",
    "-q",
    "-f",
    "-c",
    `bash --noprofile --rcfile ${quote(mount(resolve(artifact, "bashrc")))}`,
    `${lab}/terminal.typescript`,
  ]);
  terminal.stdout.resume();
  terminal.stderr.resume();
  for (let i = 0; i < 50; i++) {
    try {
      await currentStatus();
      break;
    } catch {
      await wait(100);
    }
  }
  const ids = (await guest(["xdotool", "search", "--onlyvisible", "--name", title])).split(/\s+/);
  assert.equal(ids.length, 1, "Only the owned recording terminal may be targeted");
  await guest([
    "xdotool",
    "windowsize",
    ids[0],
    "1370",
    "820",
    "windowmove",
    ids[0],
    "35",
    "30",
    "windowactivate",
    "--sync",
    ids[0],
  ]);
  const raw = resolve(artifact, "desktop.mkv");
  recorder = owned(
    "ffmpeg",
    [
      "ffmpeg",
      "-hide_banner",
      "-loglevel",
      "error",
      "-y",
      "-f",
      "x11grab",
      "-framerate",
      "20",
      "-video_size",
      "1440x900",
      "-i",
      ":99.0",
      "-c:v",
      "libx264",
      "-preset",
      "ultrafast",
      "-crf",
      "18",
      "-pix_fmt",
      "yuv420p",
      "-progress",
      "pipe:1",
      mount(raw),
    ],
    { inputOpen: true },
  );
  let progress = "",
    errors = "";
  recorder.stderr.on("data", (part) => (errors += part));
  const finished = new Promise((done, reject) => {
    recorder.once("exit", (code) =>
      code === 0 ? done() : reject(new Error(errors || "Guest recording failed")),
    );
    recorder.once("error", reject);
  });
  finished.catch(() => {});
  await new Promise((done, reject) => {
    const timer = setTimeout(() => reject(new Error(errors || "No X11 recording frame")), 15000);
    recorder.stdout.on("data", (part) => {
      progress += part;
      if (/frame=\s*[1-9]/.test(progress)) {
        clearTimeout(timer);
        done();
      }
    });
  });
  startedAt = Date.now();
  await wait(700);
  segments.push({ name: "sources", start: 0 });
  await command("clear; uname -r; node --version; shieldweave --version");
  await command("head -n 24 sources.yaml", { hold: 2500 });
  await command("sed -n '25,50p' sources.yaml", { hold: 2500 });
  await command("shieldweave sources-check sources.yaml", {
    check: (text) => assert.match(text, /"valid":true/),
  });
  await command("cat rules.yaml", { hold: 2500 });
  await command("shieldweave sources-import sources.yaml native candidate.json", {
    check: (text) => assert.match(text, /not-deployed/),
  });
  await command("shieldweave validate candidate.json", {
    check: (text) => assert.match(text, /"valid":true/),
  });
  segments[0].end = stamp();
  segments.push({ name: "blocking", start: stamp() });
  await command("clear; source ./start-lab.sh", {
    check: (text) => assert.match(text, /Runtime B:/),
  });
  await command('curl -si -H "$H" "$A/api/items?id=1"; echo', {
    check: (text) => assert.match(text, /HTTP\/1.1 200/),
  });
  const attack = `curl -si -G -H "$H" --data-urlencode "id=' OR 1=1--" "$A/api/items"; echo`;
  await command(attack, {
    check: async (text) => {
      assert.match(text, /HTTP\/1.1 403/);
      assert.equal((await lastEvent("a")).source, "rule");
    },
  });
  await command("node event.mjs a", { check: (text) => assert.match(text, /"source": "rule"/) });
  await command(attack, {
    check: async (text) => {
      assert.match(text, /HTTP\/1.1 403/);
      assert.equal((await lastEvent("a")).source, "l1");
    },
  });
  await command("node event.mjs a", { check: (text) => assert.match(text, /"source": "l1"/) });
  await command(attack.replace("$A/", "$B/"), {
    check: async (text) => {
      assert.match(text, /HTTP\/1.1 403/);
      assert.equal((await lastEvent("b")).source, "l2");
    },
  });
  await command("node event.mjs b; cat origin-hits.json; echo", {
    check: (text) => {
      assert.match(text, /"source": "l2"/);
      assert.match(text, /"hits":1/);
    },
  });
  await command('curl -si --cacert tls/cert.pem "$(cat origin-url.txt)/api/items?id=1"; echo', {
    check: (text) => assert.match(text, /HTTP\/1.1 403/),
  });
  await command('shieldweave revoke state.db recording "$(node event.mjs a --id)"; sleep 2', {
    check: (text) => assert.match(text, /"generation":1/),
  });
  await command(attack, {
    check: async (text) => {
      assert.match(text, /HTTP\/1.1 403/);
      assert.equal((await lastEvent("a")).source, "rule");
    },
  });
  await command("node event.mjs a", { check: (text) => assert.match(text, /"source": "rule"/) });
  segments[1].end = stamp();
  segments.push({ name: "converter", start: stamp() });
  await command("clear; cat method.conf");
  await command(
    "api-shield-convert method.conf seclang method.conf lab-1 Apache-2.0 api > report.json",
  );
  await command(
    "shieldweave sources-import sources.yaml method candidate-method.json report.json",
    {
      check: (text) => assert.match(text, /"rules":1/),
    },
  );
  await command("node merge.mjs; node activate.mjs merged-policy.json; source ./start-lab.sh");
  await command('curl -si -X DELETE -H "$H" "$A/api/items?id=1"; echo', {
    check: async (text) => {
      assert.match(text, /HTTP\/1.1 403/);
      assert.equal((await lastEvent("a")).source, "rule");
    },
  });
  await command("node activate.mjs candidate.json; source ./start-lab.sh");
  await command('curl -si -X DELETE -H "$H" "$A/api/items?id=1"; echo', {
    check: (text) => assert.match(text, /HTTP\/1.1 200/),
  });
  await command(
    "printf '\\n# changed after conversion\\n' >> method.conf; shieldweave sources-import sources.yaml method rejected.json report.json",
    { exit: 1, check: (text) => assert.match(text, /Conversion does not match configured source/) },
  );
  await command(
    "api-shield-convert unsupported.conf seclang unsupported.conf lab-1 Apache-2.0 api > unsupported-report.json",
    { exit: 2 },
  );
  await command(
    "shieldweave sources-import sources.yaml unsupported rejected-lossy.json unsupported-report.json",
    { exit: 1, check: (text) => assert.match(text, /Lossy\/unsupported/) },
  );
  segments[2].end = stamp();
  await wait(1000);
  recorder.stdin.write("q\n");
  await finished;
  recorder = null;
  recorded = true;
  const ff = process.env.FFMPEG_PATH || "ffmpeg";
  const encode = (args) =>
    execFileSync(ff, ["-hide_banner", "-loglevel", "error", "-y", ...args], { stdio: "pipe" });
  encode([
    "-i",
    raw,
    "-c:v",
    "libx264",
    "-crf",
    "22",
    "-preset",
    "medium",
    "-pix_fmt",
    "yuv420p",
    "-movflags",
    "+faststart",
    resolve(artifact, "api-shield-vm.mp4"),
  ]);
  for (const section of segments) {
    encode([
      "-ss",
      String(section.start),
      "-t",
      String(section.end - section.start),
      "-i",
      raw,
      "-filter_complex",
      "fps=5,scale=960:-2:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle",
      "-loop",
      "0",
      resolve(root, `docs/media/vm-${section.name}.gif`),
    ]);
  }
  await writeFile(
    resolve(artifact, "evidence.json"),
    JSON.stringify(
      {
        version,
        distro,
        kernel: system,
        desktop: "actual Xvfb/Openbox/xterm in the existing WSL2 guest; FFmpeg x11grab",
        sourceCommit: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
        engineTarballSha256: createHash("sha256")
          .update(await readFile(core))
          .digest("hex"),
        converterTarballSha256: createHash("sha256")
          .update(await readFile(converter))
          .digest("hex"),
        workingTree: execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim()
          ? "modified"
          : "clean",
        segments,
        commands: evidence,
        scope:
          "isolated HTTPS acceptance origin, CLI packages and shared SQLite; no cloud WAF or production traffic",
      },
      null,
      2,
    ),
  );
  console.log(
    "Recorded and asserted " +
      evidence.length +
      " actual VM terminal commands. GIFs are ready for inline READMEs.",
  );
} finally {
  if (recorder) {
    recorder.stdin.write("q\n");
    await wait(1000);
  }
  await shell(
    `cd ${quote(lab)} && for file in a.pid b.pid origin.pid xterm.pid openbox.pid xvfb.pid ffmpeg.pid; do if [ -f "$file" ]; then kill -TERM "$(cat "$file")" 2>/dev/null || true; fi; done`,
  ).catch(() => {});
  terminal?.kill();
  originProcess?.kill();
  wm?.kill();
  desktop?.kill();
  if (!wasRunning) execFileSync(wsl, ["--terminate", distro], { stdio: "pipe", windowsHide: true });
  if (!recorded) console.error("Recording failed; no success or synthetic GIF was published.");
}
