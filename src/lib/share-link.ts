import {
  CdnWsProfileSchema,
  FINGERPRINTS,
  RealityProfileSchema,
  TrojanProfileSchema,
  type CdnWsProfile,
  type Fingerprint,
  type Profile,
  type RealityProfile,
  type SkipReason,
  type TrojanProfile,
} from "./profile";

// ----------------------------------------------------------------------------
// Result type
// ----------------------------------------------------------------------------

export type DecodeResult =
  | { ok: true; profile: Profile }
  | { ok: false; reason: SkipReason; raw: string };

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

/**
 * Decode a single share-link. Pure: never performs IO. Always returns a
 * structured result — never throws on malformed input.
 *
 * Supports the modern VLESS shapes plus Trojan over TCP+TLS:
 *   - vless://<uuid>@<host>:<port>?type=ws&security=tls&...   -> cdn-ws
 *   - vless://<uuid>@<host>:<port>?type=tcp&security=reality&... -> reality
 *   - trojan://<password>@<host>:<port>?type=tcp&...           -> trojan
 *
 * Every other prefix or combination produces { ok: false, reason }.
 */
export function decodeShareLink(raw: string): DecodeResult {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: false, reason: "malformed", raw };

  const lower = trimmed.toLowerCase();
  if (lower.startsWith("vmess://")) return { ok: false, reason: "vmess (legacy)", raw };
  if (lower.startsWith("ss://")) return { ok: false, reason: "shadowsocks (legacy)", raw };
  if (lower.startsWith("ssr://")) return { ok: false, reason: "shadowsocks (legacy)", raw };
  // trojan-go is a separate, incompatible fork; we still refuse it. Plain
  // trojan:// is parsed below.
  if (lower.startsWith("trojan-go://")) {
    return { ok: false, reason: "trojan-go (legacy)", raw };
  }
  if (lower.startsWith("http://") || lower.startsWith("https://")) {
    return { ok: false, reason: "http (unsupported as outbound)", raw };
  }
  if (lower.startsWith("socks://") || lower.startsWith("socks5://")) {
    return { ok: false, reason: "socks (unsupported as outbound)", raw };
  }
  if (lower.startsWith("trojan://")) {
    return decodeTrojan(trimmed);
  }
  if (!lower.startsWith("vless://")) {
    return { ok: false, reason: "unknown protocol", raw };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { ok: false, reason: "malformed", raw };
  }

  const uuid = decodeURIComponent(url.username);
  const address = url.hostname;
  const port = url.port ? Number(url.port) : Number.NaN;
  const q = url.searchParams;
  const remark = url.hash ? decodeURIComponent(url.hash.slice(1)) : undefined;

  if (!uuid || !address || !Number.isFinite(port)) {
    return { ok: false, reason: "malformed", raw };
  }

  const network = q.get("type")?.toLowerCase() ?? "";
  const security = q.get("security")?.toLowerCase() ?? "";

  // -- Reject nonsense before classification --------------------------------
  if (network === "kcp") return { ok: false, reason: "vless+kcp (mKCP unsupported)", raw };
  if (network === "quic") return { ok: false, reason: "vless+quic (raw QUIC inbound unsupported)", raw };

  // -- REALITY --------------------------------------------------------------
  if (security === "reality") {
    if (network === "ws") return { ok: false, reason: "reality+ws (invalid combination)", raw };
    if (network === "grpc") return { ok: false, reason: "reality+grpc (invalid combination)", raw };
    if (network === "xhttp") return { ok: false, reason: "reality+xhttp (invalid combination)", raw };
    if (network === "httpupgrade") {
      return { ok: false, reason: "reality+httpupgrade (invalid combination)", raw };
    }
    if (network !== "tcp") return { ok: false, reason: "malformed", raw };
    return parseReality({ raw, uuid, address, port, q, remark });
  }

  // -- TLS direct (forbidden by §1.2) ---------------------------------------
  if (security === "tls" && network !== "ws") {
    return { ok: false, reason: "vless+tls direct (use reality instead)", raw };
  }
  if (security === "" || security === "none") {
    // Plain VLESS without TLS isn't usable; classify as "tls direct rejected".
    return { ok: false, reason: "vless+tls direct (use reality instead)", raw };
  }

  // -- CDN-WS ---------------------------------------------------------------
  if (network === "ws" && security === "tls") {
    return parseCdnWs({ raw, uuid, address, port, q, remark });
  }

  return { ok: false, reason: "malformed", raw };
}

/**
 * Encode a Profile back to a `vless://...` (or `trojan://...`) share link.
 * Round-trip for normalization and copy-to-clipboard. Pure.
 */
export function encodeShareLink(profile: Profile): string {
  const credential =
    profile.kind === "trojan" ? profile.password : profile.uuid;
  const userInfo = encodeURIComponent(credential);
  const host = profile.address;
  const port = profile.port;
  const params = new URLSearchParams();

  if (profile.kind === "cdn-ws") {
    params.set("type", "ws");
    params.set("security", "tls");
    params.set("encryption", "none");
    params.set("host", profile.host);
    params.set("path", profile.path);
    params.set("sni", profile.sni);
    params.set("fp", profile.fingerprint);
    params.set("alpn", profile.alpn.join(","));
  } else if (profile.kind === "reality") {
    params.set("type", "tcp");
    params.set("security", "reality");
    params.set("encryption", "none");
    params.set("flow", profile.flow);
    params.set("sni", profile.sni);
    params.set("pbk", profile.publicKey);
    params.set("sid", profile.shortId);
    params.set("fp", profile.fingerprint);
    if (profile.spiderX !== "") params.set("spx", profile.spiderX);
  } else {
    // trojan — userinfo is the password (raw, percent-encoded).
    params.set("type", "tcp");
    params.set("security", "tls");
    params.set("sni", profile.sni);
    params.set("fp", profile.fingerprint);
    params.set("alpn", profile.alpn.join(","));
  }

  const fragment = profile.remark
    ? `#${encodeURIComponent(profile.remark)}`
    : "";
  const scheme = profile.kind === "trojan" ? "trojan" : "vless";
  return `${scheme}://${userInfo}@${host}:${port}?${params.toString()}${fragment}`;
}

// ----------------------------------------------------------------------------
// Internals
// ----------------------------------------------------------------------------

interface ParseInput {
  raw: string;
  uuid: string;
  address: string;
  port: number;
  q: URLSearchParams;
  remark: string | undefined;
}

function parseCdnWs(input: ParseInput): DecodeResult {
  const { raw, uuid, address, port, q, remark } = input;

  const host = q.get("host") ?? address;
  const path = q.get("path") ?? "/";
  const sni = q.get("sni") ?? host;
  const encryption = (q.get("encryption") ?? "none").toLowerCase();
  if (encryption !== "none") return { ok: false, reason: "malformed", raw };

  const fingerprint = pickFingerprint(q.get("fp"));
  if (fingerprint === null) return { ok: false, reason: "malformed", raw };

  const alpn = parseAlpn(q.get("alpn"));

  const candidate: Omit<CdnWsProfile, "id"> & { id: string } = {
    kind: "cdn-ws",
    id: profileId("cdn-ws", address, port, uuid),
    name: remark && remark.length > 0 ? remark.slice(0, 64) : `${address}:${port}`,
    ...(remark !== undefined && remark.length > 0 ? { remark } : {}),
    address,
    port,
    uuid,
    host,
    path,
    sni,
    alpn,
    fingerprint,
  };

  const parsed = CdnWsProfileSchema.safeParse(candidate);
  if (!parsed.success) return { ok: false, reason: "malformed", raw };
  return { ok: true, profile: parsed.data };
}

function decodeTrojan(raw: string): DecodeResult {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "malformed", raw };
  }

  const password = decodeURIComponent(url.username);
  const address = url.hostname;
  const port = url.port ? Number(url.port) : Number.NaN;
  const q = url.searchParams;
  const remark = url.hash ? decodeURIComponent(url.hash.slice(1)) : undefined;

  if (!password || !address || !Number.isFinite(port)) {
    return { ok: false, reason: "malformed", raw };
  }

  // Phase-7 scope: TCP+TLS only. Reject ws / grpc / xhttp etc. with a
  // dedicated reason for the most common case (CDN-fronted trojan-WS) so
  // users see a clear "switch to TCP" message.
  const network = (q.get("type") ?? "tcp").toLowerCase();
  if (network === "ws") return { ok: false, reason: "trojan+ws (unsupported)", raw };
  if (network !== "tcp") return { ok: false, reason: "malformed", raw };

  // xray-core's trojan outbound is TLS-only. `security=tls` is the default
  // when omitted; `security=none` would be a misconfiguration we refuse.
  const security = (q.get("security") ?? "tls").toLowerCase();
  if (security !== "tls") return { ok: false, reason: "malformed", raw };

  // allowInsecure=1 means "accept any cert" — DEVELOPMENT.md §4.1 forbids it.
  // We never set the flag in our materialized config, so refuse to import a
  // share link that asked for it.
  const allowInsecure = (q.get("allowInsecure") ?? "0").toLowerCase();
  if (allowInsecure === "1" || allowInsecure === "true") {
    return { ok: false, reason: "malformed", raw };
  }

  const sni = q.get("sni") ?? q.get("peer") ?? address;
  if (!sni) return { ok: false, reason: "malformed", raw };

  const fingerprint = pickFingerprint(q.get("fp"));
  if (fingerprint === null) return { ok: false, reason: "malformed", raw };

  const alpn = parseAlpn(q.get("alpn"));

  const candidate: TrojanProfile = {
    kind: "trojan",
    id: profileId("trojan", address, port, password),
    name: remark && remark.length > 0 ? remark.slice(0, 64) : `${address}:${port}`,
    ...(remark !== undefined && remark.length > 0 ? { remark } : {}),
    address,
    port,
    password,
    sni,
    alpn,
    fingerprint,
  };

  const parsed = TrojanProfileSchema.safeParse(candidate);
  if (!parsed.success) return { ok: false, reason: "malformed", raw };
  return { ok: true, profile: parsed.data };
}

function parseReality(input: ParseInput): DecodeResult {
  const { raw, uuid, address, port, q, remark } = input;

  const sni = q.get("sni") ?? "";
  const publicKey = q.get("pbk") ?? "";
  const shortId = q.get("sid") ?? "";
  const flow = q.get("flow") ?? "";
  const encryption = (q.get("encryption") ?? "none").toLowerCase();
  const spiderX = q.get("spx") ?? "";

  if (encryption !== "none") return { ok: false, reason: "malformed", raw };
  if (flow !== "xtls-rprx-vision") return { ok: false, reason: "malformed", raw };

  const fingerprint = pickFingerprint(q.get("fp"));
  if (fingerprint === null) return { ok: false, reason: "malformed", raw };

  const candidate: RealityProfile = {
    kind: "reality",
    id: profileId("reality", address, port, uuid),
    name: remark && remark.length > 0 ? remark.slice(0, 64) : `${address}:${port}`,
    ...(remark !== undefined && remark.length > 0 ? { remark } : {}),
    address,
    port,
    uuid,
    sni,
    publicKey,
    shortId,
    fingerprint,
    flow: "xtls-rprx-vision",
    spiderX,
  };

  const parsed = RealityProfileSchema.safeParse(candidate);
  if (!parsed.success) return { ok: false, reason: "malformed", raw };
  return { ok: true, profile: parsed.data };
}

function pickFingerprint(value: string | null): Fingerprint | null {
  if (value === null || value.length === 0) return "chrome";
  const lower = value.toLowerCase();
  return (FINGERPRINTS as readonly string[]).includes(lower)
    ? (lower as Fingerprint)
    : null;
}

function parseAlpn(value: string | null): ("h2" | "http/1.1")[] {
  if (value === null || value.length === 0) return ["h2", "http/1.1"];
  const out: ("h2" | "http/1.1")[] = [];
  for (const part of value.split(",")) {
    const t = part.trim();
    if (t === "h2" || t === "http/1.1") out.push(t);
  }
  return out.length > 0 ? out : ["h2", "http/1.1"];
}

/** Deterministic 8-char hex id for a profile. FNV-1a 32-bit. */
function profileId(kind: string, address: string, port: number, uuid: string): string {
  const s = `${kind}:${address}:${port}:${uuid}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}
