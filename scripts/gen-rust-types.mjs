#!/usr/bin/env node
/**
 * Generate `src-tauri/src/types.generated.rs` from the Zod profile schemas.
 *
 * The pipeline:
 *   1. Load Zod schemas via tsx (so we read TS at runtime).
 *   2. Walk the schema shapes and confirm they match the MANIFEST below.
 *   3. Emit a Rust file with serde-deserializable structs that mirror the
 *      schema field-for-field.
 *
 * `--check` mode runs the generation into a buffer and diffs against the
 * file on disk. CI invokes `pnpm verify-types`; if a Zod field changes
 * without a corresponding MANIFEST + regenerate, CI fails.
 *
 * Why a manifest instead of full Zod introspection? Zod's runtime metadata
 * is loose (defaults are wrapped, transforms hide shapes). A manifest is a
 * second source of truth that BOTH sides must agree with — the schema check
 * catches additions, the Rust file gets the precise types we want.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const RUST_OUT = resolve(
  ROOT,
  "crates",
  "nexray-core",
  "src",
  "types_generated.rs",
);

// ---------------------------------------------------------------------------
// MANIFEST — the contract between Zod and Rust.
//
// Field types map to Rust as follows:
//   "string"        -> String
//   "u16" / "u64"   -> u16 / u64
//   "bool"          -> bool
//   "Fingerprint"   -> Fingerprint enum
//   "ConnectionState" -> ConnectionState enum
//   "Profile"       -> Profile enum (defined here too)
//   "Vec<Alpn>"     -> Vec<Alpn>
//   "?T"            -> Option<T>, Zod `.optional()`     — skip_serializing_if = None
//   "T|null"        -> Option<T>, Zod `.nullable()`     — always serialized (null when None)
// Add a new variant only if both Zod and Rust gain support together.
// ---------------------------------------------------------------------------

const FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "edge", "random"];
const ALPNS = ["h2", "http/1.1"];
const CONNECTION_STATES = ["disconnected", "connecting", "connected", "crashed"];
const ROUTING_PRESETS = ["default", "direct", "global"];
const ROUTING_DESTINATIONS = ["direct", "proxy", "block"];
const ROUTING_MATCHER_TYPES = ["domain", "ip", "port", "network"];
const TUN_STATES = ["disabled", "starting", "active", "stopping", "failed"];

const PROFILE_STRUCTS = {
  CdnWsProfile: {
    kind: '"cdn-ws"',
    fields: [
      ["id", "string"],
      ["name", "string"],
      ["remark", "?string"],
      ["address", "string"],
      ["port", "u16"],
      ["uuid", "string"],
      ["host", "string"],
      ["path", "string"],
      ["sni", "string"],
      ["alpn", "Vec<Alpn>"],
      ["fingerprint", "Fingerprint"],
    ],
  },
  RealityProfile: {
    kind: '"reality"',
    fields: [
      ["id", "string"],
      ["name", "string"],
      ["remark", "?string"],
      ["address", "string"],
      ["port", "u16"],
      ["uuid", "string"],
      ["sni", "string"],
      ["publicKey", "string"],
      ["shortId", "string"],
      ["fingerprint", "Fingerprint"],
      ["flow", '"xtls-rprx-vision"'],
      ["spiderX", "string"],
    ],
  },
};

const IPC_STRUCTS = {
  ConnectionStatus: {
    fields: [
      ["state", "ConnectionState"],
      ["profileId", "string|null"],
      ["socksPort", "u16|null"],
      ["sinceMs", "u64|null"],
      ["lastError", "string|null"],
    ],
  },
  TrafficStats: {
    fields: [
      ["available", "bool"],
      ["uplinkBytes", "u64"],
      ["downlinkBytes", "u64"],
    ],
  },
  ConnectRequest: {
    fields: [
      ["profile", "Profile"],
      ["socksPort", "?u16"],
    ],
  },
  Subscription: {
    fields: [
      ["id", "string"],
      ["url", "string"],
      ["name", "string"],
      ["addedMs", "u64"],
      ["lastFetchedMs", "u64|null"],
      ["lastFetchError", "string|null"],
      ["acceptedCount", "u32"],
      ["skippedCount", "u32"],
      ["skippedSummary", "string|null"],
      ["profiles", "Vec<Profile>"],
    ],
  },
  PoolEntry: {
    fields: [
      ["subscriptionId", "string"],
      ["subscriptionName", "string"],
      ["profile", "Profile"],
      ["latencyMs", "u32|null"],
      ["lastProbeMs", "u64|null"],
    ],
  },
  AddSubscriptionRequest: {
    fields: [
      ["url", "string"],
      ["name", "?string"],
    ],
  },
  SubscriptionIdRequest: {
    fields: [["id", "string"]],
  },
  CustomRule: {
    fields: [
      ["id", "string"],
      ["matcherType", "RoutingMatcherType"],
      ["matcher", "string"],
      ["destination", "RoutingDestination"],
      ["enabled", "bool"],
    ],
  },
  DnsConfig: {
    fields: [
      ["domesticResolver", "string"],
      ["proxyResolver", "string"],
    ],
  },
  RoutingSettings: {
    fields: [
      ["preset", "RoutingPreset"],
      ["customRules", "Vec<CustomRule>"],
      ["dns", "DnsConfig"],
    ],
  },
  SetRoutingRequest: {
    fields: [["settings", "RoutingSettings"]],
  },
  TunStatus: {
    fields: [
      ["state", "TunState"],
      ["interfaceName", "string|null"],
      ["sinceMs", "u64|null"],
      ["lastError", "string|null"],
    ],
  },
  TunCapabilities: {
    fields: [
      ["supported", "bool"],
      ["platform", "string"],
      ["binaryPresent", "bool"],
      ["reason", "string|null"],
    ],
  },
  SystemProxyStatus: {
    fields: [
      ["enabled", "bool"],
      ["host", "string|null"],
      ["port", "u16|null"],
      ["service", "string|null"],
    ],
  },
  AppSettings: {
    fields: [
      ["autoUpdateOptIn", "bool"],
      ["telemetryOptIn", "bool"],
    ],
  },
  SetSettingsRequest: {
    fields: [["settings", "AppSettings"]],
  },
  AppInfo: {
    fields: [
      ["name", "string"],
      ["version", "string"],
      ["platform", "string"],
    ],
  },
};

// Combine all structs that participate in schema↔manifest drift detection.
const MANIFEST = { ...PROFILE_STRUCTS, ...IPC_STRUCTS };

main().catch((err) => {
  console.error(`gen-rust-types: ${err.message}`);
  process.exit(1);
});

async function main() {
  const check = process.argv.includes("--check");
  await ensureSchemaMatchesManifest();
  const rendered = renderRust();

  if (check) {
    if (!existsSync(RUST_OUT)) {
      throw new Error(
        `${RUST_OUT} missing. Run \`pnpm gen-types\` and commit the result.`,
      );
    }
    const onDisk = await readFile(RUST_OUT, "utf8");
    if (onDisk !== rendered) {
      throw new Error(
        `${RUST_OUT} is stale relative to MANIFEST. Run \`pnpm gen-types\`.`,
      );
    }
    console.error("[gen-rust-types --check] ok");
    return;
  }

  await mkdir(dirname(RUST_OUT), { recursive: true });
  await writeFile(RUST_OUT, rendered);
  console.error(`[gen-rust-types] wrote ${RUST_OUT}`);
}

/**
 * Load the Zod profile schemas via a child Node process running with --import
 * tsx, then verify shape against MANIFEST. Done in a child process to keep
 * this script's host environment unaffected by tsx's loader.
 */
async function ensureSchemaMatchesManifest() {
  const probePath = resolve(__dirname, "_zod-probe.mjs");
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx/esm", probePath],
    { stdio: ["ignore", "pipe", "inherit"], cwd: ROOT },
  );
  if (result.status !== 0) {
    throw new Error("zod probe child process failed");
  }
  const shapes = JSON.parse(result.stdout.toString("utf8"));

  for (const [name, spec] of Object.entries(MANIFEST)) {
    const got = shapes[name];
    if (!got) throw new Error(`schema not exported: ${name}`);
    const expectedFields = spec.fields.map(([k]) => k).sort();
    // The `kind` discriminator is implicit in the manifest's `kind` literal
    // and doesn't appear as a field row, so drop it from the comparison.
    const actualFields = [...got.keys].filter((k) => k !== "kind").sort();
    if (JSON.stringify(expectedFields) !== JSON.stringify(actualFields)) {
      throw new Error(
        `schema/manifest drift on ${name}\n` +
          `  manifest: ${expectedFields.join(", ")}\n` +
          `  schema:   ${actualFields.join(", ")}`,
      );
    }
  }
}

function renderRust() {
  const lines = [];
  lines.push("// AUTO-GENERATED. Do not edit by hand.");
  lines.push("// Source: scripts/gen-rust-types.mjs + src/lib/{profile,ipc}.ts");
  lines.push("// Regenerate with `pnpm gen-types`. CI checks via `pnpm verify-types`.");
  lines.push("");
  lines.push("#![allow(dead_code)]");
  lines.push("");
  lines.push("use serde::{Deserialize, Serialize};");
  lines.push("");

  // Fingerprint
  lines.push("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]");
  lines.push("#[serde(rename_all = \"lowercase\")]");
  lines.push("pub enum Fingerprint {");
  for (const fp of FINGERPRINTS) {
    lines.push(`    ${pascal(fp)},`);
  }
  lines.push("}");
  lines.push("");

  // Alpn
  lines.push("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]");
  lines.push("pub enum Alpn {");
  for (const a of ALPNS) {
    const variant = a === "http/1.1" ? "Http11" : pascal(a);
    lines.push(`    #[serde(rename = "${a}")]`);
    lines.push(`    ${variant},`);
  }
  lines.push("}");
  lines.push("");

  // ConnectionState
  lines.push("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]");
  lines.push("#[serde(rename_all = \"lowercase\")]");
  lines.push("pub enum ConnectionState {");
  for (const s of CONNECTION_STATES) {
    lines.push(`    ${pascal(s)},`);
  }
  lines.push("}");
  lines.push("");

  // RoutingPreset
  lines.push("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]");
  lines.push("#[serde(rename_all = \"lowercase\")]");
  lines.push("pub enum RoutingPreset {");
  for (const p of ROUTING_PRESETS) lines.push(`    ${pascal(p)},`);
  lines.push("}");
  lines.push("");

  // RoutingDestination
  lines.push("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]");
  lines.push("#[serde(rename_all = \"lowercase\")]");
  lines.push("pub enum RoutingDestination {");
  for (const d of ROUTING_DESTINATIONS) lines.push(`    ${pascal(d)},`);
  lines.push("}");
  lines.push("");

  // RoutingMatcherType
  lines.push("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]");
  lines.push("#[serde(rename_all = \"lowercase\")]");
  lines.push("pub enum RoutingMatcherType {");
  for (const m of ROUTING_MATCHER_TYPES) lines.push(`    ${pascal(m)},`);
  lines.push("}");
  lines.push("");

  // TunState
  lines.push("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]");
  lines.push("#[serde(rename_all = \"lowercase\")]");
  lines.push("pub enum TunState {");
  for (const s of TUN_STATES) lines.push(`    ${pascal(s)},`);
  lines.push("}");
  lines.push("");

  // Structs (profile + IPC). Order matters for forward references inside Rust.
  for (const [name, spec] of Object.entries(MANIFEST)) {
    lines.push("#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]");
    lines.push("#[serde(rename_all = \"camelCase\")]");
    lines.push(`pub struct ${name} {`);
    for (const [field, ty] of spec.fields) {
      const rustField = camelToSnake(field);
      const rustTy = mapType(ty);
      if (rustTy.optionalSkip) {
        lines.push(
          `    #[serde(default, skip_serializing_if = "Option::is_none")]`,
        );
      } else if (rustTy.nullable) {
        // Nullable: always serialize (as null when None). serde does this by
        // default for Option<T>; the tag is here only for documentation.
      }
      lines.push(`    pub ${rustField}: ${rustTy.text},`);
    }
    lines.push("}");
    lines.push("");
  }

  // Profile enum
  lines.push("#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]");
  lines.push('#[serde(tag = "kind")]');
  lines.push("pub enum Profile {");
  lines.push('    #[serde(rename = "cdn-ws")]');
  lines.push("    CdnWs(CdnWsProfile),");
  lines.push('    #[serde(rename = "reality")]');
  lines.push("    Reality(RealityProfile),");
  lines.push("}");
  lines.push("");

  return lines.join("\n");
}

function mapType(ty) {
  let optionalSkip = false; // Zod .optional() — serialize-elide when None
  let nullable = false; //   Zod .nullable() — always emit (as null when None)
  let inner = ty;
  if (inner.endsWith("|null")) {
    nullable = true;
    inner = inner.slice(0, -"|null".length);
  } else if (inner.startsWith("?")) {
    optionalSkip = true;
    inner = inner.slice(1);
  }

  let text;
  switch (inner) {
    case "string":
      text = "String";
      break;
    case "bool":
      text = "bool";
      break;
    case "u16":
      text = "u16";
      break;
    case "u32":
      text = "u32";
      break;
    case "u64":
      text = "u64";
      break;
    case "Fingerprint":
      text = "Fingerprint";
      break;
    case "ConnectionState":
      text = "ConnectionState";
      break;
    case "Profile":
      text = "Profile";
      break;
    case "Vec<Alpn>":
      text = "Vec<Alpn>";
      break;
    case "Vec<Profile>":
      text = "Vec<Profile>";
      break;
    case "Vec<CustomRule>":
      text = "Vec<CustomRule>";
      break;
    case "RoutingPreset":
      text = "RoutingPreset";
      break;
    case "RoutingDestination":
      text = "RoutingDestination";
      break;
    case "RoutingMatcherType":
      text = "RoutingMatcherType";
      break;
    case "DnsConfig":
      text = "DnsConfig";
      break;
    case "RoutingSettings":
      text = "RoutingSettings";
      break;
    case "TunState":
      text = "TunState";
      break;
    case "AppSettings":
      text = "AppSettings";
      break;
    default:
      if (inner.startsWith('"') && inner.endsWith('"')) {
        text = "String";
      } else {
        throw new Error(`unknown manifest type: ${ty}`);
      }
  }
  const wrapped = optionalSkip || nullable ? `Option<${text}>` : text;
  return { text: wrapped, optionalSkip, nullable };
}

function pascal(s) {
  return s
    .split(/[^A-Za-z0-9]/)
    .filter(Boolean)
    .map((w) => w[0].toUpperCase() + w.slice(1).toLowerCase())
    .join("");
}

function camelToSnake(s) {
  return s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}
