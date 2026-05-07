import { describe, expect, it } from "vitest";
import { decodeShadowrocketJson } from "../src/lib/import-json";

const SAMPLE_VLESS_WS_TLS = `{
  "host" : "example-edge.example.com",
  "obfsParam" : "example-edge.example.com",
  "alpn" : "",
  "cert" : "",
  "created" : 1778097692.9895759,
  "updated" : 1778098176.8837972,
  "mode" : "auto",
  "tls" : true,
  "mtu" : "",
  "flag" : "CDN",
  "privateKey" : "",
  "hpkp" : "",
  "uuid" : "EBF9FA78-D224-4B75-9784-0D7901056CC4",
  "path" : "\\/",
  "downmbps" : "",
  "type" : "VLESS",
  "user" : "",
  "ech" : "",
  "plugin" : "none",
  "method" : "",
  "data" : "",
  "udp" : 1,
  "filter" : "",
  "protoParam" : "",
  "reserved" : "",
  "alterId" : "",
  "upmbps" : "",
  "keepalive" : "",
  "port" : "443",
  "obfs" : "websocket",
  "dns" : "",
  "publicKey" : "",
  "peer" : "example-edge.example.com",
  "weight" : 1778097692,
  "title" : "",
  "proto" : "",
  "password" : "00000000-0000-0000-0000-000000000000",
  "shortId" : "",
  "chain" : "",
  "ip" : ""
}`;

describe("decodeShadowrocketJson", () => {
  it("decodes the sample VLESS+WS+TLS server into a cdn-ws profile", () => {
    const r = decodeShadowrocketJson(SAMPLE_VLESS_WS_TLS);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.profile.kind).toBe("cdn-ws");
    if (r.profile.kind !== "cdn-ws") return;

    expect(r.profile.address).toBe("example-edge.example.com");
    expect(r.profile.port).toBe(443);
    // VLESS user UUID lives in `password`. Lowercased.
    expect(r.profile.uuid).toBe("00000000-0000-0000-0000-000000000000");
    // WS Host header from obfsParam (or peer fallback).
    expect(r.profile.host).toBe("example-edge.example.com");
    expect(r.profile.path).toBe("/");
    expect(r.profile.sni).toBe("example-edge.example.com");
    // alpn empty in input → defaults to both.
    expect(r.profile.alpn).toEqual(["h2", "http/1.1"]);
    expect(r.profile.fingerprint).toBe("chrome");
    // No remark in input (title + flag are "" / "CDN"); flag wins as label.
    expect(r.profile.name).toBe("CDN");
  });

  it("rejects non-VLESS types", () => {
    const r = decodeShadowrocketJson(
      `{ "type": "VMESS", "host": "x", "port": "443", "password": "u" }`,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/only VLESS is supported/i);
  });

  it("rejects plain (non-TLS) VLESS over WebSocket", () => {
    const r = decodeShadowrocketJson(JSON.stringify({
      type: "VLESS",
      host: "x.example",
      port: "443",
      password: "00000000-0000-0000-0000-000000000000",
      obfs: "websocket",
      tls: false,
      peer: "x.example",
      path: "/",
    }));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/TLS must be enabled/i);
  });

  it("rejects missing port", () => {
    const r = decodeShadowrocketJson(
      `{ "type": "VLESS", "host": "x", "port": "", "password": "u" }`,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/invalid port/i);
  });

  it("rejects missing password / uuid", () => {
    const r = decodeShadowrocketJson(
      `{ "type": "VLESS", "host": "x", "port": "443", "obfs": "websocket", "tls": true }`,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/missing VLESS UUID/i);
  });

  it("decodes a REALITY config when publicKey is set", () => {
    const r = decodeShadowrocketJson(JSON.stringify({
      type: "VLESS",
      host: "1.2.3.4",
      port: "443",
      password: "00000000-0000-0000-0000-000000000000",
      peer: "www.microsoft.com",
      publicKey: "zR9LQ8Z3J0xWlb5fK0p9X1m3T7v6yE2u8N4o0aB1cD0",
      shortId: "abcd1234",
      title: "vps",
    }));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.profile.kind).toBe("reality");
    if (r.profile.kind !== "reality") return;
    expect(r.profile.sni).toBe("www.microsoft.com");
    expect(r.profile.publicKey).toMatch(/^[A-Za-z0-9_-]{43}=?$/);
    expect(r.profile.shortId).toBe("abcd1234");
    expect(r.profile.flow).toBe("xtls-rprx-vision");
    expect(r.profile.name).toBe("vps");
  });

  it("does not throw on garbage input", () => {
    const cases = ["", "  ", "not json", "[]", "null", "42"];
    for (const c of cases) {
      const r = decodeShadowrocketJson(c);
      expect(r.ok).toBe(false);
    }
  });
});
