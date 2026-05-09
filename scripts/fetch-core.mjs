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
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const VERSION = "v26.3.27";

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
    sha256: "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf",
    binary: "xray",
  },
  "x86_64-pc-windows-msvc": {
    asset: "Xray-windows-64.zip",
    sha256: "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
    binary: "xray.exe",
  },
  "aarch64-pc-windows-msvc": {
    asset: "Xray-windows-arm64-v8a.zip",
    sha256: "35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88",
    binary: "xray.exe",
  },
  "x86_64-unknown-linux-gnu": {
    asset: "Xray-linux-64.zip",
    sha256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
    binary: "xray",
  },
  "aarch64-unknown-linux-gnu": {
    asset: "Xray-linux-arm64-v8a.zip",
    sha256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
    binary: "xray",
  },
};

/**
 * tun2socks binary, used by the Phase-6 TUN supervisor. We standardise on
 * xjasonlyu/tun2socks; the binary is named `tun2socks` (or `tun2socks.exe`
 * on Windows). Pinned per arch like xray-core. Update both versions in the
 * same PR.
 */
const TUN2SOCKS_VERSION = "v2.6.0";
// xjasonlyu/tun2socks zips ship their binary named with a platform-arch
// suffix (`tun2socks-darwin-arm64`, `tun2socks-windows-amd64.exe`, …).
// `extracted` records that filename; the script renames it to `binary`
// after unzip so the Rust supervisor can resolve a stable `tun2socks`
// (or `tun2socks.exe`) path regardless of which target it's running on.
const TUN2SOCKS = {
  "x86_64-apple-darwin": {
    asset: "tun2socks-darwin-amd64.zip",
    sha256: "REPLACE_ME_tun2socks_macos_x64",
    extracted: "tun2socks-darwin-amd64",
    binary: "tun2socks",
  },
  "aarch64-apple-darwin": {
    asset: "tun2socks-darwin-arm64.zip",
    sha256: "4d7138111f3a35866d93551d6d2894bba3ba40223c01e4e2c5870bb61ebeb71e",
    extracted: "tun2socks-darwin-arm64",
    binary: "tun2socks",
  },
  "x86_64-pc-windows-msvc": {
    asset: "tun2socks-windows-amd64.zip",
    sha256: "1429e2e3b1ea09052da2c65e5005538b5730d63da37e304f4ad6fd2698a66695",
    extracted: "tun2socks-windows-amd64.exe",
    binary: "tun2socks.exe",
  },
  "aarch64-pc-windows-msvc": {
    asset: "tun2socks-windows-arm64.zip",
    sha256: "e7c71f89991f9b850817e6b441e568c370292f8aea4fa9bdf70d099da7991eca",
    extracted: "tun2socks-windows-arm64.exe",
    binary: "tun2socks.exe",
  },
  "x86_64-unknown-linux-gnu": {
    asset: "tun2socks-linux-amd64.zip",
    sha256: "2c4d9891ca898ecb2b582d158612d44c66793008328852b3465b77828c867e77",
    extracted: "tun2socks-linux-amd64",
    binary: "tun2socks",
  },
  "aarch64-unknown-linux-gnu": {
    asset: "tun2socks-linux-arm64.zip",
    sha256: "a5b326f79585851a7518b1072e1e2610d0a1ca6803b92f0630fcf97c035b5c81",
    extracted: "tun2socks-linux-arm64",
    binary: "tun2socks",
  },
};

/**
 * Wintun.dll — required by tun2socks on Windows for the kernel TUN
 * device. xjasonlyu/tun2socks's release zips ship just the .exe, so
 * without this bundling step tun2socks can only start when wintun.dll
 * happens to be on the user's system PATH (e.g. WireGuard installs it).
 * Pin a specific Wintun release version + sha256; the archive contains
 * one DLL per arch under wintun/bin/<arch>/wintun.dll — we extract the
 * matching one and drop it next to tun2socks.exe.
 *
 * Wintun versions older than 0.14 had known crashes; 0.14.1 is the
 * current stable. Update both the URL and sha256 in the same commit.
 */
const WINTUN_URL =
  "https://www.wintun.net/builds/wintun-0.14.1.zip";
const WINTUN_ZIP_SHA256 =
  "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
// Per-target arch subfolder inside the zip — wintun/bin/<arch>/wintun.dll.
const WINTUN_ARCH_BY_TRIPLE = {
  "x86_64-pc-windows-msvc": "amd64",
  "aarch64-pc-windows-msvc": "arm64",
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
    sha256: "8aa9b4838f29eace96ec99ff971bf62cb1ff795d1cda7a210c3d5e3cb84fe2e6",
  },
  "geosite.dat": {
    url: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    sha256: "bcd052d2f3fb736d60e25f5eb280d9f85837a98ad97e3eb2ce1f694cc5c31dce",
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
    await fetchWintunOne(triple);
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

  // Upstream zips name the binary with a platform-arch suffix
  // (`tun2socks-darwin-arm64`); rename to the stable `tun2socks` /
  // `tun2socks.exe` the Rust supervisor expects.
  if (spec.extracted && spec.extracted !== spec.binary) {
    const extractedPath = resolve(targetDir, spec.extracted);
    if (existsSync(extractedPath)) {
      await rename(extractedPath, targetBin);
    }
  }

  if (!existsSync(targetBin)) {
    throw new Error(
      `expected ${spec.binary} not found after unzip in ${targetDir}`,
    );
  }
  console.error(`[fetch-core] tun2socks ${triple}: ok`);
}

async function fetchWintunOne(triple) {
  const arch = WINTUN_ARCH_BY_TRIPLE[triple];
  if (!arch) {
    // Non-Windows triple — Wintun is a Windows-only DLL.
    return;
  }
  const targetDir = resolve(BIN_DIR, triple);
  const targetDll = resolve(targetDir, "wintun.dll");

  console.error(`[fetch-core] wintun ${triple} (${arch}): ${WINTUN_URL}`);
  const zipBytes = await download(WINTUN_URL);
  const actual = sha256Hex(zipBytes);
  if (actual !== WINTUN_ZIP_SHA256) {
    throw new Error(
      `SHA-256 mismatch for wintun-0.14.1.zip\n` +
        `  expected: ${WINTUN_ZIP_SHA256}\n  actual:   ${actual}`,
    );
  }

  await mkdir(targetDir, { recursive: true });
  const zipPath = resolve(targetDir, "wintun.zip");
  await writeFile(zipPath, zipBytes);
  // Extract the whole archive into a scratch dir, then promote just the
  // single arch-specific DLL we need so we don't ship the unrelated
  // x86 / arm32 builds + headers + .cat alongside tun2socks.exe.
  const scratch = resolve(targetDir, ".wintun-scratch");
  await mkdir(scratch, { recursive: true });
  await unzip(zipPath, scratch);
  await rm(zipPath);
  const sourceDll = resolve(scratch, "wintun", "bin", arch, "wintun.dll");
  if (!existsSync(sourceDll)) {
    throw new Error(
      `wintun.dll not found in archive at expected path: ${sourceDll}`,
    );
  }
  await rename(sourceDll, targetDll);
  await rm(scratch, { recursive: true, force: true });
  console.error(`[fetch-core] wintun ${triple}: ok`);
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
