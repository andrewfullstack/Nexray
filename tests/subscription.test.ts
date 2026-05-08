import { describe, expect, it } from "vitest";
import {
  classifySubscription,
  summarizeSkipped,
} from "../src/lib/subscription";
import { MIXED_PLAIN_SUB, VALID_CDN_WS, VALID_REALITY } from "./corpus/links";

describe("classifySubscription", () => {
  it("classifies a mixed plaintext list", () => {
    const r = classifySubscription(MIXED_PLAIN_SUB);
    expect(r.accepted).toHaveLength(4);
    expect(r.accepted.map((p) => p.kind).sort()).toEqual([
      "cdn-ws",
      "reality",
      "trojan",
      "vmess",
    ]);

    expect(r.skipped).toHaveLength(9);
    const counts = new Map<string, number>();
    for (const s of r.skipped) counts.set(s.reason, (counts.get(s.reason) ?? 0) + 1);
    expect(counts.get("shadowsocks (legacy)")).toBe(1);
    expect(counts.get("trojan-go (legacy)")).toBe(1);
    expect(counts.get("trojan+ws (unsupported)")).toBe(1);
    expect(counts.get("vmess+ws (unsupported)")).toBe(1);
    expect(counts.get("reality+grpc (invalid combination)")).toBe(1);
    expect(counts.get("reality+ws (invalid combination)")).toBe(1);
    expect(counts.get("vless+tls direct (use reality instead)")).toBe(1);
    expect(counts.get("http (unsupported as outbound)")).toBe(1);
    expect(counts.get("vless+kcp (mKCP unsupported)")).toBe(1);
  });

  it("decodes a base64-wrapped subscription", () => {
    const wrapped = btoa(`${VALID_CDN_WS}\n${VALID_REALITY}\n`);
    const r = classifySubscription(wrapped);
    expect(r.accepted).toHaveLength(2);
    expect(r.skipped).toHaveLength(0);
  });

  it("decodes a base64url-wrapped subscription with padding stripped", () => {
    const std = btoa(`${VALID_CDN_WS}\n${VALID_REALITY}\n`);
    const url = std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const r = classifySubscription(url);
    expect(r.accepted).toHaveLength(2);
  });

  it("ignores blank and comment lines", () => {
    const body = `\n# a comment\n${VALID_CDN_WS}\n\n`;
    const r = classifySubscription(body);
    expect(r.accepted).toHaveLength(1);
    expect(r.skipped).toHaveLength(0);
  });

  it("does not crash on garbage input", () => {
    expect(() => classifySubscription(" junk")).not.toThrow();
  });
});

describe("summarizeSkipped", () => {
  it("formats a count summary in DEVELOPMENT.md §5.3 shape", () => {
    const r = classifySubscription(MIXED_PLAIN_SUB);
    const summary = summarizeSkipped(r.skipped);
    expect(summary).toMatch(/^9 servers skipped: /);
    expect(summary).toMatch(/1 shadowsocks \(legacy\)/);
    expect(summary).toMatch(/1 trojan-go \(legacy\)/);
    expect(summary).toMatch(/1 trojan\+ws \(unsupported\)/);
    expect(summary).toMatch(/1 vmess\+ws \(unsupported\)/);
  });

  it("returns empty string when nothing is skipped", () => {
    expect(summarizeSkipped([])).toBe("");
  });
});
