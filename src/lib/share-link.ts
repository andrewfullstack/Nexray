import {
  CdnWsProfileSchema,
  FINGERPRINTS,
  RealityProfileSchema,
  TrojanProfileSchema,
  VMESS_SECURITIES,
  VmessProfileSchema,
  type CdnWsProfile,
  type Fingerprint,
  type Profile,
  type RealityProfile,
  type SkipReason,
  type TrojanProfile,
  type VmessProfile,
  type VmessSecurity,
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
 * Supports the modern shapes plus Trojan and VMess over TCP+TLS:
 *   - vless://<uuid>@<host>:<port>?type=ws&security=tls&...     -> cdn-ws
 *   - vless://<uuid>@<host>:<port>?type=tcp&security=reality&... -> reality
 *   - trojan://<password>@<host>:<port>?type=tcp&...            -> trojan
 *   - vmess://<base64(json)>                                    -> vmess
 *
 * Every other prefix or combination produces { ok: false, reason }.
 */
export function decodeShareLink(raw: string): DecodeResult {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: false, reason: "malformed", raw };

  const lower = trimmed.toLowerCase();
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
  if (lower.startsWith("vmess://")) {
    return decodeVmess(trimmed);
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
 * Encode a Profile back to a `vless://...`, `trojan://...`, or `vmess://...`
 * share link. Round-trip for normalization and copy-to-clipboard. Pure.
 */
export function encodeShareLink(profile: Profile): string {
  if (profile.kind === "vmess") return encodeVmess(profile);

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

/**
 * VMess emits the v2rayN `vmess://<base64(json)>` format. We always emit the
 * "v":"2", "net":"tcp", "type":"none", "tls":"tls", "aid":0 fixed fields —
 * those are the only combinations the parser accepts on the way back in.
 */
function encodeVmess(profile: VmessProfile): string {
  const json = {
    v: "2",
    ps: profile.remark ?? "",
    add: profile.address,
    port: profile.port,
    id: profile.uuid,
    aid: 0,
    scy: profile.security,
    net: "tcp",
    type: "none",
    host: "",
    path: "",
    tls: "tls",
    sni: profile.sni,
    alpn: profile.alpn.join(","),
    fp: profile.fingerprint,
  };
  // btoa needs ASCII; UTF-8-encode first via TextEncoder to handle Chinese
  // remarks etc. round-tripping cleanly.
  const utf8 = new TextEncoder().encode(JSON.stringify(json));
  let bin = "";
  for (let i = 0; i < utf8.length; i++) bin += String.fromCharCode(utf8[i]!);
  return `vmess://${btoa(bin)}`;
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

function decodeVmess(raw: string): DecodeResult {
  // Strip the scheme, then base64-decode (URL-safe or standard, padding
  // optional). v2rayN emits standard base64; v2rayNG sometimes emits the
  // URL-safe variant with padding stripped.
  const body = raw.slice("vmess://".length).trim();
  if (body.length === 0) return { ok: false, reason: "malformed", raw };
  // The fragment-after-base64 form is rare but legal — `vmess://...#remark`.
  // Strip it so the base64 alphabet check below doesn't reject the link.
  const hashIdx = body.indexOf("#");
  const b64Part = hashIdx === -1 ? body : body.slice(0, hashIdx);
  const fragmentPart = hashIdx === -1 ? null : body.slice(hashIdx + 1);
  let normalized = b64Part.replace(/-/g, "+").replace(/_/g, "/");
  normalized += "=".repeat((4 - (normalized.length % 4)) % 4);
  if (!/^[A-Za-z0-9+/]+=*$/.test(normalized)) {
    return { ok: false, reason: "malformed", raw };
  }

  let json: unknown;
  try {
    const bin = atob(normalized);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    json = JSON.parse(text);
  } catch {
    return { ok: false, reason: "malformed", raw };
  }

  if (typeof json !== "object" || json === null) {
    return { ok: false, reason: "malformed", raw };
  }
  const j = json as Record<string, unknown>;

  // VMess v2rayN field shorthand:
  //   add  = address           net  = transport (tcp/ws/grpc/...)
  //   port = port              type = header obfuscation type
  //   id   = uuid              tls  = "tls" | "none"
  //   aid  = alterId (must 0)  sni  = TLS SNI
  //   scy  = cipher            alpn = comma-joined list
  //   ps   = remark            fp   = uTLS fingerprint
  const address = typeof j.add === "string" ? j.add : "";
  // Some generators emit port as a string ("443"), others as a number.
  const portRaw = typeof j.port === "number" ? j.port : Number(j.port);
  const port = Number.isFinite(portRaw) ? Math.trunc(portRaw) : Number.NaN;
  const uuid = typeof j.id === "string" ? j.id : "";
  const aidRaw = typeof j.aid === "number" ? j.aid : Number(j.aid ?? 0);
  const aid = Number.isFinite(aidRaw) ? Math.trunc(aidRaw) : Number.NaN;

  if (!address || !uuid || !Number.isFinite(port)) {
    return { ok: false, reason: "malformed", raw };
  }
  // alterId>0 routes through MD5 auth, which xray-core no longer accepts.
  if (aid !== 0) return { ok: false, reason: "malformed", raw };

  const net = (typeof j.net === "string" ? j.net : "tcp").toLowerCase();
  if (net === "ws") return { ok: false, reason: "vmess+ws (unsupported)", raw };
  if (net !== "tcp") return { ok: false, reason: "malformed", raw };

  const headerType = (typeof j.type === "string" ? j.type : "none").toLowerCase();
  // type=http obfuscates the TCP stream as fake HTTP/1.1 — xray's vmess+tcp
  // outbound supports it but our scope is plain TCP only.
  if (headerType !== "none") return { ok: false, reason: "malformed", raw };

  const tlsField = (typeof j.tls === "string" ? j.tls : "").toLowerCase();
  if (tlsField !== "tls") return { ok: false, reason: "malformed", raw };

  const securityRaw = (typeof j.scy === "string" ? j.scy : "auto").toLowerCase();
  const security = (VMESS_SECURITIES as readonly string[]).includes(securityRaw)
    ? (securityRaw as VmessSecurity)
    : null;
  if (security === null) return { ok: false, reason: "malformed", raw };

  const sniField = typeof j.sni === "string" && j.sni.length > 0 ? j.sni : address;
  if (!sniField) return { ok: false, reason: "malformed", raw };

  const fingerprint = pickFingerprint(typeof j.fp === "string" ? j.fp : null);
  if (fingerprint === null) return { ok: false, reason: "malformed", raw };

  const alpn = parseAlpn(typeof j.alpn === "string" ? j.alpn : null);

  // remark precedence: explicit fragment override (rare) > "ps" field > none.
  const remarkSource = fragmentPart
    ? decodeURIComponent(fragmentPart)
    : typeof j.ps === "string"
    ? j.ps
    : "";
  const remark = remarkSource.length > 0 ? remarkSource.slice(0, 128) : undefined;

  const candidate: VmessProfile = {
    kind: "vmess",
    id: profileId("vmess", address, port, uuid),
    name: remark && remark.length > 0 ? remark.slice(0, 64) : `${address}:${port}`,
    ...(remark !== undefined ? { remark } : {}),
    address,
    port,
    uuid,
    security,
    sni: sniField,
    alpn,
    fingerprint,
  };

  const parsed = VmessProfileSchema.safeParse(candidate);
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
