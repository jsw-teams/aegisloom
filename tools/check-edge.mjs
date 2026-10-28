import { parse } from "acorn";
import { build } from "esbuild";

function check(node) {
  if (!node || typeof node !== "object") return;
  if (
    ["CallExpression", "NewExpression"].includes(node.type) &&
    node.callee?.type === "Identifier" &&
    ["eval", "Function"].includes(node.callee.name)
  )
    throw new Error("Dynamic code evaluation found");
  if (
    ["ImportDeclaration", "ExportNamedDeclaration"].includes(node.type) &&
    node.source?.value?.startsWith("node:")
  )
    throw new Error("Node dependency found in portable runtime");
  for (const value of Object.values(node))
    if (Array.isArray(value)) for (const child of value) check(child);
    else if (value && typeof value === "object") check(value);
}
const result = await build({
  entryPoints: ["scr/runtime/index.ts"],
  bundle: true,
  platform: "browser",
  format: "esm",
  target: "es2022",
  write: false,
});
check(parse(result.outputFiles[0].text, { ecmaVersion: "latest", sourceType: "module" }));
console.log(
  `Portable native runtime: ${result.outputFiles[0].contents.length} bytes; no Node imports or dynamic code`,
);
