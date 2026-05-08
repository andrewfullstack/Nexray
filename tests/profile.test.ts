import { describe, expect, it } from "vitest";
import {
  CdnWsProfileSchema,
  ProfileSchema,
  RealityProfileSchema,
  TrojanProfileSchema,
  VmessProfileSchema,
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

const baseTrojan = {
  kind: "trojan" as const,
  id: "abcd1234",
  name: "trojan-vps",
  address: "198.51.100.42",
  port: 443,
  password: "secret-pwd",
  sni: "trojan.example.com",
  alpn: ["h2", "http/1.1"] as ("h2" | "http/1.1")[],
  fingerprint: "chrome" as const,
};

const baseVmess = {
  kind: "vmess" as const,
  id: "abcd1234",
  name: "vmess-vps",
  address: "198.51.100.77",
  port: 443,
  uuid: "550e8400-e29b-41d4-a716-446655440042",
  security: "auto" as const,
  sni: "vmess.example.com",
  alpn: ["h2", "http/1.1"] as ("h2" | "http/1.1")[],
  fingerprint: "chrome" as const,
};

describe("ProfileSchema", () => {
  it("accepts a valid cdn-ws profile", () => {
    expect(CdnWsProfileSchema.safeParse(baseCdnWs).success).toBe(true);
  });

  it("accepts a valid reality profile", () => {
    expect(RealityProfileSchema.safeParse(baseReality).success).toBe(true);
  });

  it("accepts a valid trojan profile", () => {
    expect(TrojanProfileSchema.safeParse(baseTrojan).success).toBe(true);
  });

  it("accepts a valid vmess profile", () => {
    expect(VmessProfileSchema.safeParse(baseVmess).success).toBe(true);
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

  it.each([
    ["empty password", { ...baseTrojan, password: "" }],
    ["missing password", { ...baseTrojan, password: undefined }],
    ["empty sni", { ...baseTrojan, sni: "" }],
    ["empty alpn", { ...baseTrojan, alpn: [] }],
    ["unknown alpn entry", { ...baseTrojan, alpn: ["h3"] }],
    ["unknown fingerprint", { ...baseTrojan, fingerprint: "hyperion" }],
    ["port too low", { ...baseTrojan, port: 0 }],
    ["extra field allowInsecure", { ...baseTrojan, allowInsecure: true }],
    ["uuid is not a trojan field", { ...baseTrojan, uuid: "550e8400" }],
  ])("rejects trojan: %s", (_label, candidate) => {
    expect(TrojanProfileSchema.safeParse(candidate).success).toBe(false);
  });

  it.each([
    ["bad uuid", { ...baseVmess, uuid: "not-a-uuid" }],
    ["empty sni", { ...baseVmess, sni: "" }],
    ["empty alpn", { ...baseVmess, alpn: [] }],
    ["unknown security cipher", { ...baseVmess, security: "rc4-md5" }],
    ["unknown fingerprint", { ...baseVmess, fingerprint: "hyperion" }],
    ["port too low", { ...baseVmess, port: 0 }],
    ["password is not a vmess field", { ...baseVmess, password: "x" }],
    ["extra field allowInsecure", { ...baseVmess, allowInsecure: true }],
  ])("rejects vmess: %s", (_label, candidate) => {
    expect(VmessProfileSchema.safeParse(candidate).success).toBe(false);
  });

  it("discriminates the union by kind", () => {
    expect(ProfileSchema.safeParse(baseCdnWs).success).toBe(true);
    expect(ProfileSchema.safeParse(baseReality).success).toBe(true);
    expect(ProfileSchema.safeParse(baseTrojan).success).toBe(true);
    expect(ProfileSchema.safeParse(baseVmess).success).toBe(true);
    expect(
      ProfileSchema.safeParse({ ...baseCdnWs, kind: "shadowsocks" }).success,
    ).toBe(false);
  });
});
