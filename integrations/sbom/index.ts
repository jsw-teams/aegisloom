export interface Component {
  name: string;
  version: string;
  ecosystem: string;
  purl?: string;
}
function purl(input: string): Partial<Component> {
  const match = /^pkg:([^/]+)\/(.+?)(?:@([^?#]+))?(?:\?[^#]*)?(?:#.*)?$/.exec(input);
  if (!match) return {};
  const ecosystems: Record<string, string> = {
    npm: "npm",
    golang: "Go",
    pypi: "PyPI",
    composer: "Packagist",
    maven: "Maven",
    cargo: "crates.io",
    gem: "RubyGems",
  };
  return {
    name: decodeURIComponent(match[2] ?? ""),
    ...(match[3] ? { version: decodeURIComponent(match[3]) } : {}),
    ecosystem: ecosystems[match[1] ?? ""] ?? "unknown",
    purl: input,
  };
}
/** Accepts CycloneDX JSON, SPDX JSON, npm lock v2/v3, or an explicit inventory. */
export function importInventory(source: unknown): Component[] {
  if (!source || typeof source !== "object") throw new Error("Inventory object required");
  const raw = source as Record<string, any>;
  let items: any[];
  if (raw.bomFormat === "CycloneDX") items = raw.components ?? [];
  else if (typeof raw.spdxVersion === "string")
    items = (raw.packages ?? []).map((p: any) => ({
      name: p.name,
      version: p.versionInfo,
      purl: p.externalRefs?.find((r: any) => r.referenceType === "purl")?.referenceLocator,
    }));
  else if (raw.lockfileVersion >= 2 && raw.packages)
    items = Object.entries(raw.packages)
      .filter(([path]) => path.includes("node_modules/"))
      .map(([path, p]) => ({
        name: (p as any).name ?? path.split("node_modules/").at(-1),
        version: (p as any).version,
        ecosystem: "npm",
      }));
  else if (Array.isArray(raw.components)) items = raw.components;
  else throw new Error("Unsupported inventory; CycloneDX/SPDX JSON/npm lock v2-v3 required");
  if (items.length > 10000) throw new Error("Inventory exceeds 10000 components");
  const components = items.map((item) => {
    const parsed = item.purl ? purl(item.purl) : {};
    const component: Component = {
      name: parsed.name ?? item.name,
      version: parsed.version ?? item.version,
      ecosystem: parsed.ecosystem ?? item.ecosystem ?? "unknown",
      ...(item.purl ? { purl: item.purl } : {}),
    };
    if (
      typeof component.name !== "string" ||
      !component.name ||
      component.name.length > 512 ||
      typeof component.version !== "string" ||
      !component.version ||
      component.version.length > 128
    )
      throw new Error("Component name/version required; do not infer missing versions");
    return component;
  });
  return [...new Map(components.map((c) => [JSON.stringify(c), c])).values()];
}
