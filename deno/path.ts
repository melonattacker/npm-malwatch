// Minimal path helpers for macOS/Linux (POSIX-like).
// Avoids importing `node:path` so `deno test` doesn't require npm node typings.

export function isAbsolute(p: string): boolean {
  return p.startsWith("/");
}

export function join(...parts: string[]): string {
  const filtered = parts.filter((p) => p !== "");
  const raw = filtered.join("/");
  return normalize(raw);
}

export function normalize(p: string): string {
  // Collapse multiple slashes.
  let out = p.replaceAll(/\/+/g, "/");
  // Remove trailing slash (except root).
  if (out.length > 1 && out.endsWith("/")) out = out.slice(0, -1);
  return out;
}

export function dirname(p: string): string {
  const n = normalize(p);
  if (n === "/") return "/";
  const idx = n.lastIndexOf("/");
  if (idx <= 0) return "/";
  return n.slice(0, idx);
}

export function basename(p: string): string {
  const n = normalize(p);
  if (n === "/") return "/";
  const idx = n.lastIndexOf("/");
  return idx === -1 ? n : n.slice(idx + 1);
}

export function resolve(cwd: string, p: string): string {
  if (isAbsolute(p)) return normalize(p);
  return normalize(join(cwd, p));
}

