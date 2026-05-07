import { describe, expect, it } from "vitest";
import {
  CdnWsProfileSchema,
  ProfileSchema,
  RealityProfileSchema,
} from "../src/lib/profile";

const baseCdnWs = {
  kind: "cdn-ws" as const,
  id: "abcd1234",
  name: "edge",
  address: "104.16.0.1",
  port: 443,
  uuid: "550e8400-e29b-41d4-a716-446655440000",
  host: "cdn.example.com",
  path: "/?ed=2560",
  sni: "cdn.example.com",
  alpn: ["h2", "http/1.1"] as ("h2" | "http/1.1")[],
  fingerprint: "chrome" as const,
};

const baseReality = {
  kind: "reality" as const,
  id: "abcd1234",
  name: "vps",
  address: "198.51.100.7",
  port: 443,
  uuid: "550e8400-e29b-41d4-a716-446655440001",
  sni: "www.microsoft.com",
  publicKey: "zR9LQ8Z3J0xWlb5fK0p9X1m3T7v6yE2u8N4o0aB1cD0",
  shortId: "abcd1234",
  fingerprint: "chrome" as const,
  flow: "xtls-rprx-vision" as const,
  spiderX: "",
};

describe("ProfileSchema", () => {
  it("accepts a valid cdn-ws profile", () => {
    expect(CdnWsProfileSchema.safeParse(baseCdnWs).success).toBe(true);
  });

  it("accepts a valid reality profile", () => {
    expect(RealityProfileSchema.safeParse(baseReality).success).toBe(true);
  });

  it.each([
    ["bad uuid", { ...baseCdnWs, uuid: "not-a-uuid" }],
    ["port too low", { ...baseCdnWs, port: 0 }],
    ["port too high", { ...baseCdnWs, port: 70000 }],
    ["unknown fingerprint", { ...baseCdnWs, fingerprint: "hyperion" }],
    ["empty alpn", { ...baseCdnWs, alpn: [] }],
    ["unknown alpn entry", { ...baseCdnWs, alpn: ["h3"] }],
    ["empty host", { ...baseCdnWs, host: "" }],
    ["extra field", { ...baseCdnWs, allowInsecure: true }],
  ])("rejects cdn-ws: %s", (_label, candidate) => {
    expect(CdnWsProfileSchema.safeParse(candidate).success).toBe(false);
  });

  it.each([
    ["wrong flow", { ...baseReality, flow: "" }],
    ["wrong flow xtls-rprx-direct", { ...baseReality, flow: "xtls-rprx-direct" }],
    ["short publicKey", { ...baseReality, publicKey: "short" }],
    ["odd-length shortId", { ...baseReality, shortId: "abc" }],
    ["non-hex shortId", { ...baseReality, shortId: "ZZZZ" }],
    ["unknown fingerprint", { ...baseReality, fingerprint: "hyperion" }],
    ["bad uuid", { ...baseReality, uuid: "550e8400" }],
  ])("rejects reality: %s", (_label, candidate) => {
    expect(RealityProfileSchema.safeParse(candidate).success).toBe(false);
  });

  it("discriminates the union by kind", () => {
    expect(ProfileSchema.safeParse(baseCdnWs).success).toBe(true);
    expect(ProfileSchema.safeParse(baseReality).success).toBe(true);
    expect(
      ProfileSchema.safeParse({ ...baseCdnWs, kind: "trojan" }).success,
    ).toBe(false);
  });
});
