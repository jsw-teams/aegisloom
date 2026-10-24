/** Strict subset parser. Chains, macros, state, inherited transforms and scripts are rejected. */
export function parseSecLang(source) {
  const output = [];
  const unsupported = [];
  const lines = source.split(/\r?\n/);
  for (const [index, original] of lines.entries()) {
    const line = original.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^SecRule\s+([A-Z_]+)\s+"([^"\r\n]*)"\s+"([^"\r\n]*)"\s*$/.exec(line);
    if (!match) { unsupported.push(`line ${index + 1}: unsupported directive/selector/quoting/chain`); continue; }
    const [, variable, operator, actionsText] = match;
    // Quoted action values may contain commas; do not silently split away conditions.
    const actions = []; let start = 0; let quoted = false;
    for (let i = 0; i <= actionsText.length; i++) {
      if (actionsText[i] === "'") quoted = !quoted;
      if ((actionsText[i] === "," && !quoted) || i === actionsText.length) { actions.push(actionsText.slice(start, i).trim()); start = i + 1; }
    }
    if (quoted || actions.some((a) => !/^(?:id:[0-9]+|phase:1|deny|pass|log|nolog|t:none|msg:'[^']*'|ver:'[^']*'|severity:'?[^']*'?)$/.test(a))) { unsupported.push(`line ${index + 1}: action/inheritance/phase semantics unsupported`); continue; }
    const id = actions.find((a) => a.startsWith("id:"))?.slice(3);
    const transforms = actions.filter((a) => a.startsWith("t:"));
    const disruptive = actions.filter((a) => ["deny", "pass"].includes(a));
    if (!id || transforms.length !== 1 || transforms[0] !== "t:none" || disruptive.length !== 1 || !actions.includes("phase:1") || variable !== "REQUEST_METHOD") { unsupported.push(`line ${index + 1}: requires unique id, phase:1, t:none, explicit deny/pass and REQUEST_METHOD; other variable semantics are not equivalent`); continue; }
    const op = /^@streq ([A-Z]{1,20})$/.exec(operator);
    if (!op) { unsupported.push(`line ${index + 1}: only exact method equality supported; PCRE/CRS transformations need a native engine`); continue; }
    output.push({ id: `sec-${id}`, name: actions.find((a) => a.startsWith("msg:"))?.slice(5, -1) ?? `SecRule ${id}`, phase: "request-headers", when: { field: "method", op: "eq", value: op[1] }, then: { action: disruptive[0] === "deny" ? "block" : "detect" } });
  }
  return { rules: output, limitations: unsupported };
}
