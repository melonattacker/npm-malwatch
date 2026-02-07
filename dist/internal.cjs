"use strict";

const path = require("node:path");

function truncateString(value, maxLen) {
  if (value.length <= maxLen) return value;
  return value.slice(0, Math.max(0, maxLen - 1)) + "…";
}

function toPosixPath(p) {
  return p.replaceAll("\\\\", "/");
}

function isProbablyFilePath(p) {
  if (!p) return false;
  if (p.startsWith("node:")) return false;
  if (p.startsWith("internal/")) return false;
  if (p.startsWith("<")) return false;
  return true;
}

function extractFilePathFromStackLine(line) {
  const trimmed = line.trim();
  const m1 = trimmed.match(/\((.*):(\d+):(\d+)\)$/);
  if (m1?.[1] && isProbablyFilePath(m1[1])) return m1[1];
  const m2 = trimmed.match(/at (.*):(\d+):(\d+)$/);
  if (m2?.[1] && isProbablyFilePath(m2[1])) return m2[1];
  return null;
}

function stackToCandidateFilePaths(stack) {
  if (!stack) return [];
  const lines = stack.split("\n");
  const out = [];
  for (const line of lines) {
    const fp = extractFilePathFromStackLine(line);
    if (!fp) continue;
    out.push(fp);
  }
  return out;
}

function packageNameFromFilePath(filePath) {
  const p = toPosixPath(filePath);
  const idx = p.lastIndexOf("/node_modules/");
  if (idx === -1) return null;

  const rest = p.slice(idx + "/node_modules/".length);
  if (!rest || rest.startsWith(".")) return null;

  const parts = rest.split("/").filter(Boolean);
  if (parts.length === 0) return null;

  if (parts[0]?.startsWith("@")) {
    if (!parts[1]) return null;
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0] ?? null;
}

function isPmPackageName(pkgName) {
  if (pkgName === "npm") return "npm";
  if (pkgName === "pnpm") return "pnpm";
  if (pkgName.startsWith("@npmcli/")) return "npm";
  if (pkgName.startsWith("@pnpm/")) return "pnpm";
  return null;
}

function classifyPackageDisplayName(pkgName) {
  const pm = isPmPackageName(pkgName);
  if (pm === "npm") return "<pm:npm>";
  if (pm === "pnpm") return "<pm:pnpm>";
  return pkgName;
}

function inferPackageFromStack(stack) {
  const candidates = stackToCandidateFilePaths(stack);
  for (const candidate of candidates) {
    const pkgName = packageNameFromFilePath(candidate);
    if (!pkgName) continue;
    if (pkgName === "npm-malwatch") continue;
    return classifyPackageDisplayName(pkgName);
  }

  const envPkg = process.env.npm_package_name;
  if (envPkg) return classifyPackageDisplayName(envPkg);

  const initCwd = process.env.INIT_CWD;
  const base = path.basename(initCwd || process.cwd());
  if (base) return base;

  return "<unknown>";
}

function shortenStack(stack, maxLines, maxChars) {
  if (!stack) return void 0;
  const lines = stack.split("\n").filter(Boolean);
  const kept = [];
  for (const line of lines) {
    if (line.includes("npm-malwatch") && line.includes("/dist/")) continue;
    kept.push(line);
    if (kept.length >= maxLines) break;
  }
  const joined = kept.join("\n");
  return truncateString(joined, maxChars);
}

function looksSensitiveKey(key) {
  return /(pass|token|secret|auth|cookie|session)/i.test(key);
}

function redactObject(value, maxDepth = 3) {
  if (maxDepth <= 0) return "<truncated>";
  if (value === null) return null;
  if (value === void 0) return void 0;
  if (typeof value === "string") return truncateString(value, 500);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redactObject(v, maxDepth - 1));
  if (typeof value === "object") {
    const obj = value;
    const out = {};
    const keys = Object.keys(obj).slice(0, 40);
    for (const key of keys) {
      if (looksSensitiveKey(key)) {
        out[key] = "<redacted>";
      } else {
        out[key] = redactObject(obj[key], maxDepth - 1);
      }
    }
    return out;
  }
  return "<unserializable>";
}

function safeToString(value) {
  if (typeof value === "string") return value;
  if (value instanceof URL) return value.toString();
  if (Buffer.isBuffer(value)) return "<buffer>";
  try {
    return String(value);
  } catch {
    return "<unstringifiable>";
  }
}

module.exports = {
  truncateString,
  toPosixPath,
  extractFilePathFromStackLine,
  stackToCandidateFilePaths,
  packageNameFromFilePath,
  isPmPackageName,
  classifyPackageDisplayName,
  inferPackageFromStack,
  shortenStack,
  redactObject,
  safeToString
};
