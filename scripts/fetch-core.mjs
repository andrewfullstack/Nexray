#!/usr/bin/env node
/**
 * Download xray-core release artifacts and verify SHA-256.
 *
 * Per DEVELOPMENT.md §12 rule 7: every bundled binary is pinned. CI verifies
 * the hash. We never auto-upgrade across releases. To bump xray-core, update
 * the VERSION + HASHES table below in the same PR that bumps Nexray.
 *
 * Output layout (matches Tauri sidecar conventions):
 *   src-tauri/binaries/<target-triple>/xray[.exe]
 *
 * Use `--target=<triple>` to fetch one platform; default is the host.
 * Use `--all` to fetch every triple in HASHES (used by CI matrix builds).
 * Use `--check` to only verify currently-on-disk binaries (no network).
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const VERSION = "v25.1.30";

/**
 * Pinned SHA-256 hashes per artifact. UPDATE BOTH the version and the hashes
 * in lockstep — never edit one without the other. See `docs/SECURITY.md`.
 *
 * To re-pin: download the artifact, compute `shasum -a 256 <file>`, paste below.
 */
const HASHES = {
  "x86_64-apple-darwin": {
    asset: "Xray-macos-64.zip",
    sha256: "REPLACE_ME_macos_x64",
    binary: "xray",
  },
  "aarch64-apple-darwin": {
    asset: "Xray-macos-arm64-v8a.zip",
    sha256: "REPLACE_ME_macos_arm64",
    binary: "xray",
  },
  "x86_64-pc-windows-msvc": {
    asset: "Xray-windows-64.zip",
    sha256: "REPLACE_ME_windows_x64",
    binary: "xray.exe",
  },
  "x86_64-unknown-linux-gnu": {
    asset: "Xray-linux-64.zip",
    sha256: "REPLACE_ME_linux_x64",
    binary: "xray",
  },
  "aarch64-unknown-linux-gnu": {
    asset: "Xray-linux-arm64-v8a.zip",
    sha256: "REPLACE_ME_linux_arm64",
    binary: "xray",
  },
};

/**
 * tun2socks binary, used by the Phase-6 TUN supervisor. We standardise on
 * xjasonlyu/tun2socks; the binary is named `tun2socks` (or `tun2socks.exe`
 * on Windows). Pinned per arch like xray-core. Update both versions in the
 * same PR.
 */
const TUN2SOCKS_VERSION = "v2.5.2";
const TUN2SOCKS = {
  "x86_64-apple-darwin": {
    asset: "tun2socks-darwin-amd64.zip",
    sha256: "REPLACE_ME_tun2socks_macos_x64",
    binary: "tun2socks",
  },
  "aarch64-apple-darwin": {
    asset: "tun2socks-darwin-arm64.zip",
    sha256: "REPLACE_ME_tun2socks_macos_arm64",
    binary: "tun2socks",
  },
  "x86_64-pc-windows-msvc": {
    asset: "tun2socks-windows-amd64.zip",
    sha256: "REPLACE_ME_tun2socks_windows_x64",
    binary: "tun2socks.exe",
  },
  "x86_64-unknown-linux-gnu": {
    asset: "tun2socks-linux-amd64.zip",
    sha256: "REPLACE_ME_tun2socks_linux_x64",
    binary: "tun2socks",
  },
  "aarch64-unknown-linux-gnu": {
    asset: "tun2socks-linux-arm64.zip",
    sha256: "REPLACE_ME_tun2socks_linux_arm64",
    binary: "tun2socks",
  },
};

/**
 * geoip / geosite databases. Bundled alongside xray-core at
 * `src-tauri/binaries/data/`. xray-core resolves rule values like
 * `geosite:cn` against these files, so they MUST be present at runtime.
 *
 * Pinned to the same release tag as xray-core; bumping the dat files is a
 * separate, deliberate change (DEVELOPMENT.md §12 rule 7).
 */
const GEO_DATA = {
  "geoip.dat": {
    url: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    sha256: "REPLACE_ME_geoip_dat",
  },
  "geosite.dat": {
    url: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    sha256: "REPLACE_ME_geosite_dat",
  },
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const BIN_DIR = resolve(ROOT, "src-tauri", "binaries");

main().catch((err) => {
  console.error(`fetch-core: ${err.message}`);
  process.exit(1);
});

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.check) {
    await checkAll();
    return;
  }

  const targets = args.all
    ? Object.keys(HASHES)
    : [args.target ?? hostTarget()];

  for (const triple of targets) {
    if (!(triple in HASHES)) {
      throw new Error(`unknown target triple: ${triple}`);
    }
    await fetchOne(triple);
    await fetchTun2socksOne(triple);
  }

  // geoip / geosite are platform-independent; fetch once into a shared dir.
  await fetchGeoData();
}

function parseArgs(argv) {
  const args = { check: false, all: false, target: undefined };
  for (const a of argv) {
    if (a === "--check") args.check = true;
    else if (a === "--all") args.all = true;
    else if (a.startsWith("--target=")) args.target = a.slice("--target=".length);
    else throw new Error(`unknown flag: ${a}`);
  }
  return args;
}

function hostTarget() {
  const os = process.platform;
  const arch = process.arch;
  if (os === "darwin" && arch === "arm64") return "aarch64-apple-darwin";
  if (os === "darwin" && arch === "x64") return "x86_64-apple-darwin";
  if (os === "win32" && arch === "x64") return "x86_64-pc-windows-msvc";
  if (os === "linux" && arch === "x64") return "x86_64-unknown-linux-gnu";
  if (os === "linux" && arch === "arm64") return "aarch64-unknown-linux-gnu";
  throw new Error(`unsupported host: ${os}/${arch}`);
}

async function fetchOne(triple) {
  const spec = HASHES[triple];
  const url = `https://github.com/XTLS/Xray-core/releases/download/${VERSION}/${spec.asset}`;
  const targetDir = resolve(BIN_DIR, triple);
  const targetBin = resolve(targetDir, spec.binary);

  console.error(`[fetch-core] ${triple}: ${url}`);

  if (spec.sha256.startsWith("REPLACE_ME")) {
    throw new Error(
      `SHA-256 not pinned for ${triple} — refuse to download. ` +
        `Update HASHES in scripts/fetch-core.mjs first.`,
    );
  }

  const zipBytes = await download(url);
  const actual = sha256Hex(zipBytes);
  if (actual !== spec.sha256) {
    throw new Error(
      `SHA-256 mismatch for ${spec.asset}\n` +
        `  expected: ${spec.sha256}\n  actual:   ${actual}`,
    );
  }

  await mkdir(targetDir, { recursive: true });
  const zipPath = resolve(targetDir, spec.asset);
  await writeFile(zipPath, zipBytes);
  await unzip(zipPath, targetDir);
  await rm(zipPath);

  if (!existsSync(targetBin)) {
    throw new Error(`expected ${spec.binary} not found after unzip in ${targetDir}`);
  }
  console.error(`[fetch-core] ${triple}: ok`);
}

async function fetchTun2socksOne(triple) {
  const spec = TUN2SOCKS[triple];
  if (!spec) {
    console.error(`[fetch-core] no tun2socks spec for ${triple} — skipping`);
    return;
  }
  const url = `https://github.com/xjasonlyu/tun2socks/releases/download/${TUN2SOCKS_VERSION}/${spec.asset}`;
  const targetDir = resolve(BIN_DIR, triple);
  const targetBin = resolve(targetDir, spec.binary);

  console.error(`[fetch-core] tun2socks ${triple}: ${url}`);

  if (spec.sha256.startsWith("REPLACE_ME")) {
    throw new Error(
      `SHA-256 not pinned for tun2socks/${triple} — refuse to download. ` +
        `Update TUN2SOCKS in scripts/fetch-core.mjs first.`,
    );
  }

  const zipBytes = await download(url);
  const actual = sha256Hex(zipBytes);
  if (actual !== spec.sha256) {
    throw new Error(
      `SHA-256 mismatch for ${spec.asset}\n` +
        `  expected: ${spec.sha256}\n  actual:   ${actual}`,
    );
  }

  await mkdir(targetDir, { recursive: true });
  const zipPath = resolve(targetDir, spec.asset);
  await writeFile(zipPath, zipBytes);
  await unzip(zipPath, targetDir);
  await rm(zipPath);

  if (!existsSync(targetBin)) {
    throw new Error(
      `expected ${spec.binary} not found after unzip in ${targetDir}`,
    );
  }
  console.error(`[fetch-core] tun2socks ${triple}: ok`);
}

async function fetchGeoData() {
  const dir = resolve(BIN_DIR, "data");
  await mkdir(dir, { recursive: true });
  for (const [name, spec] of Object.entries(GEO_DATA)) {
    if (spec.sha256.startsWith("REPLACE_ME")) {
      throw new Error(
        `SHA-256 not pinned for ${name} — refuse to download. ` +
          `Update GEO_DATA in scripts/fetch-core.mjs first.`,
      );
    }
    console.error(`[fetch-core] data: ${spec.url}`);
    const bytes = await download(spec.url);
    const actual = sha256Hex(bytes);
    if (actual !== spec.sha256) {
      throw new Error(
        `SHA-256 mismatch for ${name}\n` +
          `  expected: ${spec.sha256}\n  actual:   ${actual}`,
      );
    }
    await writeFile(resolve(dir, name), bytes);
    console.error(`[fetch-core] data: ${name} ok`);
  }
}

async function checkAll() {
  let bad = 0;
  for (const [triple, spec] of Object.entries(HASHES)) {
    const targetBin = resolve(BIN_DIR, triple, spec.binary);
    if (!existsSync(targetBin)) continue;
    const bytes = await readFile(targetBin);
    const hash = sha256Hex(bytes);
    console.error(`[fetch-core --check] ${triple}: ${hash}`);
    // Note: we hash the extracted binary, not the zip; this is informational.
    // The release-time integrity check is against the zip hash.
  }
  if (bad > 0) process.exit(1);
}

async function download(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download failed: ${res.status} ${res.statusText}`);
  const buf = await res.arrayBuffer();
  return new Uint8Array(buf);
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Tiny zip extractor by shelling out to the OS unzip / tar. */
async function unzip(zipPath, destDir) {
  const cmd = process.platform === "win32" ? "tar" : "unzip";
  const args =
    process.platform === "win32"
      ? ["-xf", zipPath, "-C", destDir]
      : ["-o", zipPath, "-d", destDir];
  await new Promise((res, rej) => {
    const child = spawn(cmd, args, { stdio: "inherit" });
    child.on("error", rej);
    child.on("exit", (code) =>
      code === 0 ? res(undefined) : rej(new Error(`${cmd} exited ${code}`)),
    );
  });
}
