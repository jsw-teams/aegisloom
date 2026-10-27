#!/usr/bin/env node
import { chmod, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const template = new URL("./gateway.conf.template", import.meta.url);
const [output] = process.argv.slice(2);
if (!output) throw new Error("Usage: node deploy/openresty/render.mjs /secure/path/gateway.conf");

function value(name, pattern) {
  const input = process.env[name];
  if (!input || !pattern.test(input)) throw new Error("Missing/invalid " + name);
  return input;
}
function port(name) {
  const raw = process.env[name];
  const n = Number(raw);
  if (!raw || !Number.isInteger(n) || n < 1 || n > 65535)
    throw new Error("Invalid " + name);
  return String(n);
}
function file(name) {
  const input = value(name, /^\/[a-zA-Z0-9_./-]+$/);
  if (input.includes("..")) throw new Error("Invalid path " + name);
  return input;
}
const values = {
  PID_FILE: file("EDGESHIELD_NGINX_PID"),
  ERROR_LOG: file("EDGESHIELD_NGINX_ERROR_LOG"),
  BRIDGE_PORT: port("EDGESHIELD_BRIDGE_PORT"),
  INGRESS_PORT: port("EDGESHIELD_INGRESS_PORT"),
  INGRESS_BIND: process.env.EDGESHIELD_INGRESS_BIND === "0.0.0.0" ? "0.0.0.0" : "127.0.0.1",
  ENGINE_PORT: port("EDGESHIELD_ENGINE_PORT"),
  ORIGIN_TOKEN: value("EDGESHIELD_ORIGIN_TOKEN", /^[A-Za-z0-9_-]{32,128}$/),
  UPSTREAM_HOST: value("EDGESHIELD_UPSTREAM_HOST", /^(?:[a-z0-9-]+\.)*[a-z0-9-]+$/),
  UPSTREAM_PORT: port("EDGESHIELD_UPSTREAM_PORT"),
  UPSTREAM_CA_FILE: file("EDGESHIELD_UPSTREAM_CA_FILE"),
  PUBLIC_HOST: value("EDGESHIELD_PUBLIC_HOST", /^(?:[a-z0-9-]+\.)*[a-z0-9-]+$/),
  TLS_CERT_FILE: file("EDGESHIELD_TLS_CERT_FILE"),
  TLS_KEY_FILE: file("EDGESHIELD_TLS_KEY_FILE"),
};
let body = await readFile(template, "utf8");
for (const [name, value] of Object.entries(values)) {
  const marker = "__" + name + "__";
  if (!body.includes(marker)) throw new Error("Missing template marker " + marker);
  body = body.replaceAll(marker, value);
}
if (/__[A-Z_]+__/.test(body)) throw new Error("Unrendered template variables");
const target = resolve(output);
await writeFile(target, body, { flag: "wx", mode: 0o600 });
if (process.platform !== "win32") await chmod(target, 0o600);
console.log("Wrote operator-owned OpenResty config: " + target);
