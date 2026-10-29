/** Repository-import builds. Private code is written only to provider function directories. */
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { buildPlatform } from "./build-platform.mjs";

const platform = process.argv[2],
  root = resolve(process.argv[3] ?? resolve(import.meta.dirname, ".."));
if (!["vercel", "netlify", "edgeone"].includes(platform))
  throw Error("Select vercel, netlify or edgeone");
const built = await buildPlatform(platform, join(root, "config.yml"));
await mkdir(join(built.deployDirectory, "public"), { recursive: true });
if (platform === "vercel") {
  const output = join(root, ".vercel/output"),
    directory = join(output, "functions/edgeaegis.func");
  await mkdir(directory, { recursive: true });
  await copyFile(join(built.deployDirectory, "api/index.mjs"), join(directory, "engine.mjs"));
  await writeFile(
    join(directory, "index.mjs"),
    `import worker from './engine.mjs';import{Readable}from'node:stream';import{pipeline}from'node:stream/promises';
export default async function(req,res){try{const url=new URL(req.url,'https://'+req.headers.host),body=['GET','HEAD'].includes(req.method)?undefined:Readable.toWeb(req);const request=new Request(url,{method:req.method,headers:req.headers,...(body?{body,duplex:'half'}:{})});const response=await worker.fetch(request);res.statusCode=response.status;for(const[key,value]of response.headers)if(key!=='set-cookie')res.setHeader(key,value);const cookies=response.headers.getSetCookie();if(cookies.length)res.setHeader('set-cookie',cookies);if(response.body)await pipeline(Readable.fromWeb(response.body),res);else res.end();}catch{if(!res.headersSent){res.statusCode=503;res.setHeader('cache-control','no-store');res.end('Service unavailable');}else res.destroy();}}`,
  );
  await writeFile(
    join(directory, ".vc-config.json"),
    JSON.stringify({
      runtime: "nodejs24.x",
      handler: "index.mjs",
      launcherType: "Nodejs",
      supportsResponseStreaming: true,
    }),
  );
  await writeFile(
    join(output, "config.json"),
    JSON.stringify({ version: 3, routes: [{ src: "/(.*)", dest: "/edgeaegis" }] }),
  );
} else if (platform === "edgeone") {
  const directory = join(root, "edge-functions");
  await mkdir(directory, { recursive: true });
  const marker = join(directory, ".edgeaegis-generated");
  try {
    await readFile(join(directory, "[[default]].js"));
    await readFile(marker);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    try {
      await readFile(join(directory, "[[default]].js"));
      throw Error("Refusing to overwrite an operator EdgeOne function");
    } catch (missing) {
      if (missing.code !== "ENOENT") throw missing;
    }
  }
  await copyFile(
    join(built.deployDirectory, "edge-functions/[[default]].js"),
    join(directory, "[[default]].js"),
  );
  await writeFile(marker, "Generated private deployment output; never publish as static assets.\n");
}
console.log(`Built ${platform}; static output is empty; private engine is in its function entry.`);
