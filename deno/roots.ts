import { join, dirname, basename } from "./path.ts";

type DepGraph = Map<string, Set<string>>;

function safeReadJson(filePath: string): any | null {
  try {
    const raw = Deno.readTextFileSync(filePath);
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function collectDirectRootsFromPackageJson(projectRoot: string): string[] {
  const pkg = safeReadJson(join(projectRoot, "package.json"));
  if (!pkg || typeof pkg !== "object") return [];

  const out = new Set<string>();
  const addKeys = (obj: any) => {
    if (!obj || typeof obj !== "object") return;
    for (const k of Object.keys(obj)) {
      if (typeof k === "string" && k.trim()) out.add(k);
    }
  };
  addKeys(pkg.dependencies);
  addKeys(pkg.devDependencies);
  addKeys(pkg.optionalDependencies);
  addKeys(pkg.peerDependencies);
  return [...out].sort((a, b) => a.localeCompare(b));
}

function listNpmStylePackageJsonPaths(nodeModulesRoot: string, max: number): string[] {
  const out: string[] = [];
  try {
    if (!Deno.statSync(nodeModulesRoot).isDirectory) return out;
  } catch {
    return out;
  }

  try {
    const entries = [...Deno.readDirSync(nodeModulesRoot)].sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (out.length >= max) break;
      if (!e.isDirectory) continue;
      if (e.name === ".bin" || e.name === ".pnpm") continue;

      const full = join(nodeModulesRoot, e.name);
      if (e.name.startsWith("@")) {
        try {
          const scopedEntries = [...Deno.readDirSync(full)].sort((a, b) => a.name.localeCompare(b.name));
          for (const se of scopedEntries) {
            if (out.length >= max) break;
            if (!se.isDirectory) continue;
            out.push(join(full, se.name, "package.json"));
          }
        } catch {
          // ignore
        }
      } else {
        out.push(join(full, "package.json"));
      }
    }
  } catch {
    return out;
  }
  return out;
}

function listPnpmStylePackageJsonPaths(nodeModulesRoot: string, max: number): string[] {
  const out: string[] = [];
  const pnpmRoot = join(nodeModulesRoot, ".pnpm");
  try {
    if (!Deno.statSync(pnpmRoot).isDirectory) return out;
  } catch {
    return out;
  }

  try {
    const storeEntries = [...Deno.readDirSync(pnpmRoot)].sort((a, b) => a.name.localeCompare(b.name));
    for (const storeEntry of storeEntries) {
      if (out.length >= max) break;
      if (!storeEntry.isDirectory) continue;
      const nm = join(pnpmRoot, storeEntry.name, "node_modules");
      const paths = listNpmStylePackageJsonPaths(nm, max - out.length);
      for (const p of paths) {
        if (out.length >= max) break;
        out.push(p);
      }
    }
  } catch {
    return out;
  }
  return out;
}

function extractDependencyKeys(pkgJson: any): string[] {
  const out = new Set<string>();
  const add = (obj: any) => {
    if (!obj || typeof obj !== "object") return;
    for (const k of Object.keys(obj)) out.add(k);
  };
  add(pkgJson.dependencies);
  add(pkgJson.optionalDependencies);
  add(pkgJson.peerDependencies);
  return [...out];
}

function buildGraphFromNodeModules(projectRoot: string, maxPackages: number): DepGraph {
  const nodeModulesRoot = join(projectRoot, "node_modules");
  const graph: DepGraph = new Map();

  const pkgJsonPaths: string[] = [];
  const limit = maxPackages + 1;
  pkgJsonPaths.push(...listNpmStylePackageJsonPaths(nodeModulesRoot, limit));
  if (pkgJsonPaths.length < limit) {
    pkgJsonPaths.push(...listPnpmStylePackageJsonPaths(nodeModulesRoot, limit - pkgJsonPaths.length));
  }

  const toScan = pkgJsonPaths.slice(0, maxPackages);
  for (const p of toScan) {
    try {
      if (!Deno.statSync(p).isFile) continue;
    } catch {
      continue;
    }
    const json = safeReadJson(p);
    if (!json) continue;

    const name = typeof json.name === "string" ? json.name : basename(dirname(p));
    const deps = extractDependencyKeys(json);

    const set = graph.get(name) ?? new Set<string>();
    for (const d of deps) set.add(d);
    graph.set(name, set);
  }

  return graph;
}

export function computeRootByPackageFromNodeModules(
  projectRoot: string,
  packages: string[],
): Record<string, string | null> {
  const directRoots = collectDirectRootsFromPackageJson(projectRoot);
  const nodeModulesRoot = join(projectRoot, "node_modules");
  try {
    if (!Deno.statSync(nodeModulesRoot).isDirectory) {
      const out: Record<string, string | null> = {};
      for (const p of packages) out[p] = null;
      return out;
    }
  } catch {
    const out: Record<string, string | null> = {};
    for (const p of packages) out[p] = null;
    return out;
  }

  const graph = buildGraphFromNodeModules(projectRoot, 50_000);
  const targets = new Set(packages);
  const rootsFor = new Map<string, Set<string>>();

  const q: Array<{ pkg: string; root: string }> = [];
  for (const r of directRoots) q.push({ pkg: r, root: r });
  const seen = new Set<string>();

  while (q.length) {
    const item = q.shift()!;
    const key = `${item.root}\0${item.pkg}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const set = rootsFor.get(item.pkg) ?? new Set<string>();
    set.add(item.root);
    rootsFor.set(item.pkg, set);

    const children = graph.get(item.pkg);
    if (!children) continue;
    for (const child of children) q.push({ pkg: child, root: item.root });
  }

  const out: Record<string, string | null> = {};
  for (const p of packages) {
    if (p.startsWith("<")) {
      out[p] = null;
      continue;
    }
    const rs = rootsFor.get(p);
    if (!rs || rs.size === 0) out[p] = null;
    else out[p] = [...rs].sort((a, b) => a.localeCompare(b)).join("|");
  }

  // Prefer showing direct roots for themselves even if graph scan missed them.
  for (const r of directRoots) {
    if (targets.has(r) && !out[r]) out[r] = r;
  }

  return out;
}

