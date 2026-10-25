#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { convert } from "./index.mjs";
import manifest from '../package.json' with {type:'json'};
const [file, format, url, version, license, service] = process.argv.slice(2);
try {
  if(file==='--version'||file==='-v'){console.log(manifest.version);process.exit(0);}
  if (!file || !service) throw new Error("Usage: api-shield-convert <file> <format> <source-url> <version> <license> <service>");
  const report = convert(await readFile(file, "utf8"), { format, url, version, license, service });
  console.log(JSON.stringify(report, null, 2));
  if (["partial", "unsupported"].includes(report.status)) process.exitCode = 2;
} catch (error) { console.error(error.message); process.exitCode = 1; }
