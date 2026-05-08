import { describe, expect, it } from "vitest";
import { decodeShareLink, encodeShareLink } from "../src/lib/share-link";
import {
  HTTP_LINK,
  MALFORMED_BAD_FP,
  MALFORMED_NO_UUID,
  REALITY_BAD_PBK,
  REALITY_GRPC,
  REALITY_WS,
  SOCKS_LINK,
  SS_LINK,
  SSR_LINK,
  TROJAN_GO_LINK,
  TROJAN_WS_LINK,
  VALID_CDN_WS,
  VALID_REALITY,
  VALID_TROJAN,
  VALID_VMESS,
  VLESS_KCP,
  VLESS_TLS_DIRECT,
  VMESS_WS_LINK,
} from "./corpus/links";

describe("decodeShareLink", () => {
  it("accepts a clean cdn-ws link", () => {
    const r = decodeShareLink(VALID_CDN_WS);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.profile.kind).toBe("cdn-ws");
    if (r.profile.kind !== "cdn-ws") return;
    expect(r.profile.address).toBe("104.16.0.1");
    expect(r.profile.port).toBe(443);
    expect(r.profile.host).toBe("cdn.example.com");
    expect(r.profile.path).toBe("/?ed=2560");
    expect(r.profile.sni).toBe("cdn.example.com");
    expect(r.profile.fingerprint).toBe("chrome");
    expect(r.profile.alpn).toEqual(["h2", "http/1.1"]);
    expect(r.profile.remark).toBe("CDN-Edge");
  });

  it("accepts a clean reality link", () => {
    const r = decodeShareLink(VALID_REALITY);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.profile.kind).toBe("reality");
    if (r.profile.kind !== "reality") return;
    expect(r.profile.flow).toBe("xtls-rprx-vision");
    expect(r.profile.sni).toBe("www.microsoft.com");
    expect(r.profile.publicKey).toMatch(/^[A-Za-z0-9_-]{43}=?$/);
    expect(r.profile.shortId).toBe("abcd1234");
    expect(r.profile.spiderX).toBe("/");
  });

  it("accepts a clean trojan link", () => {
    const r = decodeShareLink(VALID_TROJAN);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.profile.kind).toBe("trojan");
    if (r.profile.kind !== "trojan") return;
    expect(r.profile.address).toBe("198.51.100.42");
    expect(r.profile.port).toBe(443);
    expect(r.profile.password).toBe("secret-pwd");
    expect(r.profile.sni).toBe("trojan.example.com");
    expect(r.profile.fingerprint).toBe("chrome");
    expect(r.profile.alpn).toEqual(["h2", "http/1.1"]);
    expect(r.profile.remark).toBe("Trojan-VPS");
  });

  it("accepts a clean vmess link", () => {
    const r = decodeShareLink(VALID_VMESS);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.profile.kind).toBe("vmess");
    if (r.profile.kind !== "vmess") return;
    expect(r.profile.address).toBe("198.51.100.77");
    expect(r.profile.port).toBe(443);
    expect(r.profile.uuid).toBe("550e8400-e29b-41d4-a716-446655440042");
    expect(r.profile.security).toBe("auto");
    expect(r.profile.sni).toBe("vmess.example.com");
    expect(r.profile.fingerprint).toBe("chrome");
    expect(r.profile.alpn).toEqual(["h2", "http/1.1"]);
    expect(r.profile.remark).toBe("VMess-VPS");
  });

  it("rejects a trojan link that asks for allowInsecure=1", () => {
    const r = decodeShareLink(
      "trojan://pwd@1.2.3.4:443?type=tcp&sni=x.example.com&allowInsecure=1",
    );
    expect(r.ok).toBe(false);
  });

  it("rejects a vmess link with alterId>0 (no AEAD)", () => {
    // {v:"2", add:"x", port:443, id:"550e8400-...0044", aid:1, scy:"auto",
    //  net:"tcp", type:"none", tls:"tls", sni:"x", alpn:"h2", fp:"chrome"}
    const aidNonZero = `vmess://${btoa(
      JSON.stringify({
        v: "2",
        add: "x.example.com",
        port: 443,
        id: "550e8400-e29b-41d4-a716-446655440044",
        aid: 1,
        scy: "auto",
        net: "tcp",
        type: "none",
        tls: "tls",
        sni: "x.example.com",
        alpn: "h2",
        fp: "chrome",
      }),
    )}`;
    const r = decodeShareLink(aidNonZero);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe("malformed");
  });

  it.each([
    [SS_LINK, "shadowsocks (legacy)"],
    [SSR_LINK, "shadowsocks (legacy)"],
    [TROJAN_GO_LINK, "trojan-go (legacy)"],
    [TROJAN_WS_LINK, "trojan+ws (unsupported)"],
    [VMESS_WS_LINK, "vmess+ws (unsupported)"],
    [HTTP_LINK, "http (unsupported as outbound)"],
    [SOCKS_LINK, "socks (unsupported as outbound)"],
    [REALITY_WS, "reality+ws (invalid combination)"],
    [REALITY_GRPC, "reality+grpc (invalid combination)"],
    [VLESS_TLS_DIRECT, "vless+tls direct (use reality instead)"],
    [VLESS_KCP, "vless+kcp (mKCP unsupported)"],
    [MALFORMED_NO_UUID, "malformed"],
    [MALFORMED_BAD_FP, "malformed"],
    [REALITY_BAD_PBK, "malformed"],
  ])("rejects %#", (link, reason) => {
    const r = decodeShareLink(link);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe(reason);
  });

  it("does not throw on garbage input", () => {
    for (const garbage of ["", "   ", " ", "://", "vless://"]) {
      const r = decodeShareLink(garbage);
      expect(r.ok).toBe(false);
    }
  });
});

describe("encodeShareLink", () => {
  it("round-trips a cdn-ws profile", () => {
    const r = decodeShareLink(VALID_CDN_WS);
    if (!r.ok) throw new Error("expected ok");
    const re = decodeShareLink(encodeShareLink(r.profile));
    expect(re.ok).toBe(true);
    if (!re.ok) return;
    expect(re.profile).toEqual(r.profile);
  });

  it("round-trips a reality profile", () => {
    const r = decodeShareLink(VALID_REALITY);
    if (!r.ok) throw new Error("expected ok");
    const re = decodeShareLink(encodeShareLink(r.profile));
    expect(re.ok).toBe(true);
    if (!re.ok) return;
    expect(re.profile).toEqual(r.profile);
  });

  it("round-trips a trojan profile", () => {
    const r = decodeShareLink(VALID_TROJAN);
    if (!r.ok) throw new Error("expected ok");
    const encoded = encodeShareLink(r.profile);
    expect(encoded.startsWith("trojan://")).toBe(true);
    const re = decodeShareLink(encoded);
    expect(re.ok).toBe(true);
    if (!re.ok) return;
    expect(re.profile).toEqual(r.profile);
  });

  it("round-trips a vmess profile", () => {
    const r = decodeShareLink(VALID_VMESS);
    if (!r.ok) throw new Error("expected ok");
    const encoded = encodeShareLink(r.profile);
    expect(encoded.startsWith("vmess://")).toBe(true);
    const re = decodeShareLink(encoded);
    expect(re.ok).toBe(true);
    if (!re.ok) return;
    expect(re.profile).toEqual(r.profile);
  });
});
