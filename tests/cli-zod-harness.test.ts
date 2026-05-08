/**
 * Phase 1 acceptance: `--json` output of `nexray-cli` validates against the
 * Phase-0 Zod schemas. This is the contract test that proves Rust↔TypeScript
 * parity at the wire-format boundary.
 *
 * Skipped automatically when `cargo` isn't available (e.g. JS-only CI jobs).
 */

import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ClassifyResultSchema } from "../src/lib/profile";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const FIXTURE = path.join(ROOT, "crates/nexray-cli/tests/fixtures/mixed.txt");

function hasCargo(): boolean {
  const r = spawnSync("cargo", ["--version"], { stdio: "ignore" });
  return r.status === 0;
}

const cargoAvailable = hasCargo();

describe.skipIf(!cargoAvailable)("nexray-cli --json ↔ Zod schema", () => {
  it("classifies the mixed fixture into Zod-valid shape", () => {
    const stdout = execFileSync(
      "cargo",
      [
        "run",
        "--quiet",
        "--package",
        "nexray-cli",
        "--",
        "classify",
        FIXTURE,
        "--json",
      ],
      { cwd: ROOT, encoding: "utf-8", stdio: ["ignore", "pipe", "inherit"] },
    );

    const parsed = ClassifyResultSchema.parse(JSON.parse(stdout));

    expect(parsed.accepted).toHaveLength(3);
    expect(parsed.skipped).toHaveLength(9);
    expect(parsed.accepted.map((p) => p.kind).sort()).toEqual([
      "cdn-ws",
      "reality",
      "trojan",
    ]);

    const cdnWs = parsed.accepted.find((p) => p.kind === "cdn-ws");
    expect(cdnWs).toBeDefined();
    if (cdnWs?.kind === "cdn-ws") {
      expect(cdnWs.address).toBe("104.16.0.1");
      expect(cdnWs.port).toBe(443);
      expect(cdnWs.host).toBe("cdn.example.com");
      expect(cdnWs.path).toBe("/?ed=2560");
    }

    const reality = parsed.accepted.find((p) => p.kind === "reality");
    expect(reality).toBeDefined();
    if (reality?.kind === "reality") {
      expect(reality.flow).toBe("xtls-rprx-vision");
      expect(reality.publicKey).toMatch(/^[A-Za-z0-9_-]{43}=?$/);
      expect(reality.shortId).toBe("abcd1234");
    }

    const trojan = parsed.accepted.find((p) => p.kind === "trojan");
    expect(trojan).toBeDefined();
    if (trojan?.kind === "trojan") {
      expect(trojan.address).toBe("198.51.100.42");
      expect(trojan.port).toBe(443);
      expect(trojan.password).toBe("secret-pwd");
      expect(trojan.sni).toBe("trojan.example.com");
    }
  }, 120_000);
});
