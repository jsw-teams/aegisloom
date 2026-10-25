import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { chromium } from "playwright";
import { startDemo } from "../examples/demo/server.ts";

const dir = resolve("artifacts/demo");
await mkdir(dir, { recursive: true });
const demo = await startDemo();
let browser, context, video;
const evidence = [];
const steps = [
  [
    "config",
    "两类防护源，都通过配置文件管理。",
    "云服务与第三方 VPS 使用固定 HTTPS 源站；规则来源必须固定版本、哈希和许可证。",
    (r) => assert.equal(r.validated, true),
  ],
  [
    "import",
    "先校验规则，再启用隔离测试策略。",
    "实际读取 YAML，验证 JSON Schema、SHA-256、许可证及业务作用域。",
    (r) => assert.equal(r.rules, 1),
  ],
  [
    "legal",
    "合法请求：HTTP 200，源站收到请求。",
    "这是真实 TCP 上游，并且必须通过独立源站令牌验证。",
    (r) => {
      assert.equal(r.status, 200);
      assert.equal(r.originHits, 1);
    },
  ],
  [
    "attack",
    "首次攻击：由规则识别，返回 HTTP 403。",
    "自编攻击标记仅用于验收；源站到达次数保持为 1。",
    (r) => {
      assert.equal(r.status, 403);
      assert.equal(r.event.source, "rule");
      assert.equal(r.originHits, 1);
    },
  ],
  [
    "l1",
    "同一攻击再次到达：直接命中 L1。",
    "实际判定来源为 l1；不会再次执行完整规则检测。",
    (r) => {
      assert.equal(r.event.source, "l1");
      assert.equal(r.stats.ruleEvaluations, 2);
    },
  ],
  [
    "l2",
    "另一运行实例：从共享 L2 获取有效决策。",
    "两个独立引擎共享 SQLite 权威决策存储；不是缓存 HTTP 403 页面。",
    (r) => {
      assert.equal(r.event.source, "l2");
      assert.equal(r.originHits, 1);
    },
  ],
  [
    "isolation",
    "绕过 Shield 直接访问源站：HTTP 403。",
    "这里只验证源站令牌；生产还必须设置源站网络隔离与正确 TLS 身份。",
    (r) => assert.equal(r.directOriginStatus, 403),
  ],
  [
    "revoke",
    "撤销决策，并推进撤销代际号。",
    "撤销缓存不等于删除防护规则；下一次相同攻击必须重新匹配规则。",
    (r) => assert.ok(r.generation > 0),
  ],
  [
    "attack",
    "旧缓存已失效：判定来源重新变为 RULE。",
    "规则仍然有效，因此继续返回 403；不会错误地把撤销解释为放行。",
    (r) => assert.equal(r.event.source, "rule"),
  ],
  [
    "convert",
    "独立转换器导入：保留来源和语义。",
    "实际导入 SecLang 方法匹配子集。完整 CRS、链式规则和有损转换不支持自动启用。",
    (r) => {
      assert.equal(r.status, "exact");
      assert.equal(r.rules, 1);
    },
  ],
  [
    "delete",
    "导入后的 DELETE 规则确实执行。",
    "正常样本与攻击样本的结果来自同一个 Shield IR 执行引擎。",
    (r) => {
      assert.equal(r.status, 403);
      assert.equal(r.event.source, "rule");
    },
  ],
  [
    "tamper",
    "防护源校验失败：拒绝导入和启用。",
    "SHA-256 不匹配时停止处理，不会静默忽略风险继续部署。",
    (r) => {
      assert.equal(r.rejected, true);
      assert.equal(r.activated, false);
    },
  ],
  [
    "rollback",
    "显式替换隔离策略，保留源站身份验证。",
    "真实策略版本已更新；本次没有发布云端规则，也没有改动生产域名。",
    (r) => assert.equal(r.rules, 0),
  ],
  [
    "legal",
    "替换后合法请求继续正常转发。",
    "全部步骤均有机器断言和 JSON 证据，可在本地重复运行、重新录制。",
    (r) => assert.equal(r.status, 200),
  ],
];
try {
  browser = await chromium.launch({ headless: true, args: ["--disable-extensions"] });
  context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    deviceScaleFactor: 1,
    recordVideo: { dir, size: { width: 1280, height: 720 } },
    reducedMotion: "reduce",
  });
  // The console, two Shield instances and authenticated origin are all loopback-only.
  await context.route("**/*", (route) =>
    new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort(),
  );
  const page = await context.newPage();
  video = page.video();
  await page.goto(demo.url);
  await page.waitForTimeout(1800);
  for (const [action, caption, subcaption, verify] of steps) {
    await page.evaluate(
      ({ caption, subcaption }) => {
        document.getElementById("caption").textContent = caption;
        document.getElementById("subcaption").textContent = subcaption;
        window.lastAction = null;
      },
      { caption, subcaption },
    );
    await page.locator(`[data-action="${action}"]`).click();
    await page.waitForFunction((action) => window.lastAction === action, action);
    const result = await page.evaluate(() => window.lastResult);
    assert.ok(!result.error, JSON.stringify(result));
    verify(result);
    evidence.push({ action, caption, result });
    await page.screenshot({
      path: resolve(dir, `${String(evidence.length).padStart(2, "0")}-${action}.png`),
    });
    await page.waitForTimeout(process.env.DEMO_FAST === "1" ? 50 : 5200);
  }
  await writeFile(
    resolve(dir, "evidence.json"),
    JSON.stringify(
      {
        recordedAt: new Date().toISOString(),
        sourceCommit: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
        workingTree: execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim()
          ? "modified"
          : "clean",
        scope: "isolated local recording; no live cloud or production verification",
        steps: evidence,
      },
      null,
      2,
    ),
  );
  await context.close();
  context = null;
  const input = await video.path();
  execFileSync(
    process.env.FFMPEG_PATH || "ffmpeg",
    [
      "-y",
      "-i",
      input,
      "-c:v",
      "libx264",
      "-preset",
      "medium",
      "-crf",
      "20",
      "-pix_fmt",
      "yuv420p",
      "-movflags",
      "+faststart",
      resolve(dir, "cloud-api-shield-demo.zh-CN.mp4"),
    ],
    { stdio: "pipe" },
  );
  console.log(
    `Verified ${evidence.length} real scenarios; recording: ${resolve(dir, "cloud-api-shield-demo.zh-CN.mp4")}`,
  );
} finally {
  await context?.close();
  await browser?.close();
  await demo.stop();
}
