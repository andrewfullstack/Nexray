#!/usr/bin/env node
// Stamp a version string into every place the build pipeline reads it:
//
//   • package.json                  → top-level "version"
//   • src-tauri/tauri.conf.json     → top-level "version" (used by the
//                                     bundler for filenames + by the
//                                     `app_info` IPC command)
//   • Cargo.toml                    → [workspace.package].version (the
//                                     value `version.workspace = true`
//                                     resolves to in every crate)
//
// Used by the release workflow so a `v1.2.3` tag produces bundles
// labelled 1.2.3 without anyone having to remember to bump source first.
// On invalid input the script exits non-zero so a typo'd tag fails the
// pipeline early instead of silently shipping `0.0.0` builds.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const raw = process.argv[2];
if (!raw) {
  console.error("usage: node scripts/stamp-version.mjs <version|v-tag>");
  process.exit(1);
}
const version = raw.startsWith("v") ? raw.slice(1) : raw;
if (!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/.test(version)) {
  console.error(`refusing to stamp non-SemVer value: ${raw}`);
  process.exit(1);
}

function stampJson(path) {
  const text = readFileSync(path, "utf8");
  // Match the first top-level `"version": "..."` line. Anchored to start
  // of line + leading whitespace so we don't accidentally rewrite a
  // `"version"` key buried in a nested object (e.g. dependency version
  // hints in tauri.conf.json's plugin config).
  const updated = text.replace(
    /^(\s*"version"\s*:\s*")[^"]+(")/m,
    `$1${version}$2`,
  );
  if (updated === text) {
    console.error(`[stamp-version] no version line found in ${path}`);
    process.exit(1);
  }
  writeFileSync(path, updated);
  console.log(`✓ ${relative(root, path)} → ${version}`);
}

function stampCargoWorkspace(path) {
  const text = readFileSync(path, "utf8");
  // Replace the first `version = "..."` that appears inside the
  // [workspace.package] table. Matching `[workspace.package]` first
  // anchors the rewrite — won't touch the unrelated `version = "1.0"`
  // strings in `[workspace.dependencies]`.
  const updated = text.replace(
    /(\[workspace\.package\][^[]*?\nversion\s*=\s*")[^"]+(")/,
    `$1${version}$2`,
  );
  if (updated === text) {
    console.error(`[stamp-version] no [workspace.package].version in ${path}`);
    process.exit(1);
  }
  writeFileSync(path, updated);
  console.log(`✓ ${relative(root, path)} → ${version}`);
}

stampJson(join(root, "package.json"));
stampJson(join(root, "src-tauri", "tauri.conf.json"));
stampCargoWorkspace(join(root, "Cargo.toml"));
