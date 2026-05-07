import {
  CdnWsProfileSchema,
  RealityProfileSchema,
  type Profile,
} from "./profile";

/**
 * Decode a Shadowrocket-style JSON config into a Nexray `Profile`. Pure: no
 * IO, no exceptions on adversarial input.
 *
 * The Shadowrocket JSON shape is denormalized — a single object holds the
 * union of every supported protocol's fields. We dispatch on `type` +
 * `obfs` + presence of REALITY-specific fields to produce a strongly-typed
 * `cdn-ws` or `reality` profile, or a structured rejection.
 *
 * Field mapping (cdn-ws):
 *   host       -> address  (the CDN edge IP/host the client dials)
 *   port       -> port     (string in JSON; we parseInt)
 *   password   -> uuid     (VLESS user UUID; lowercased)
 *   obfsParam  -> host     (WS Host header; falls back to peer)
 *   peer       -> sni      (TLS SNI / WS Host fallback)
 *   path       -> path     ("/" if missing)
 *   alpn       -> alpn     ("h2,http/1.1" parsed; defaults to both)
 *   title|flag -> remarks  (optional label)
 *
 * Field mapping (reality): same base, plus publicKey + shortId from the
 * top-level fields, flow pinned to `xtls-rprx-vision`.
 */
export type ImportResult =
  | { ok: true; profile: Profile }
  | { ok: false; reason: string };

export function decodeShadowrocketJson(text: string): ImportResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, reason: "not valid JSON" };
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "JSON must be an object" };
  }
  const o = raw as Record<string, unknown>;

  const type = str(o.type).toUpperCase();
  if (type !== "VLESS") {
    return {
      ok: false,
      reason: `only VLESS is supported, got "${type || "<empty>"}"`,
    };
  }

  const host = str(o.host).trim();
  const portRaw = str(o.port).trim();
  const port = portRaw ? Number.parseInt(portRaw, 10) : Number.NaN;
  if (!host) return { ok: false, reason: "missing `host`" };
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return { ok: false, reason: `invalid port: "${portRaw}"` };
  }

  // VLESS user UUID lives in `password` in Shadowrocket; some tools also
  // duplicate it into `uuid`. We accept either, prefer `password`.
  const uuid = (str(o.password) || str(o.uuid)).trim().toLowerCase();
  if (!uuid) return { ok: false, reason: "missing VLESS UUID (`password`)" };

  const obfs = str(o.obfs).toLowerCase();
  const tls = Boolean(o.tls);
  const publicKey = str(o.publicKey).trim();
  const shortId = str(o.shortId).trim();
  const peer = str(o.peer).trim();
  const obfsParam = str(o.obfsParam).trim();
  const path = str(o.path).trim() || "/";
  const remark = str(o.title).trim() || str(o.flag).trim();

  // REALITY: detected by presence of publicKey (shortId is allowed to be empty).
  if (publicKey) {
    const candidate = {
      kind: "reality" as const,
      id: profileId("reality", host, port, uuid),
      name: remark || `${host}:${port}`,
      ...(remark ? { remark } : {}),
      address: host,
      port,
      uuid,
      sni: peer || host,
      publicKey,
      shortId: shortId.toLowerCase(),
      fingerprint: "chrome" as const,
      flow: "xtls-rprx-vision" as const,
      spiderX: "",
    };
    const parsed = RealityProfileSchema.safeParse(candidate);
    if (!parsed.success) {
      return { ok: false, reason: zodReason(parsed.error) };
    }
    return { ok: true, profile: parsed.data };
  }

  // cdn-ws: VLESS + WebSocket + TLS.
  if (obfs !== "websocket") {
    return {
      ok: false,
      reason: `only obfs "websocket" (with TLS) is supported, got "${obfs || "<empty>"}"`,
    };
  }
  if (!tls) {
    return {
      ok: false,
      reason: "TLS must be enabled (Nexray refuses plain VLESS over WS)",
    };
  }

  const wsHost = obfsParam || peer || host;
  const sni = peer || wsHost;
  const alpn = parseAlpn(str(o.alpn));

  const candidate = {
    kind: "cdn-ws" as const,
    id: profileId("cdn-ws", host, port, uuid),
    name: remark || `${host}:${port}`,
    ...(remark ? { remark } : {}),
    address: host,
    port,
    uuid,
    host: wsHost,
    path,
    sni,
    alpn,
    fingerprint: "chrome" as const,
  };
  const parsed = CdnWsProfileSchema.safeParse(candidate);
  if (!parsed.success) {
    return { ok: false, reason: zodReason(parsed.error) };
  }
  return { ok: true, profile: parsed.data };
}

// ----------------------------------------------------------------------------
// Internals
// ----------------------------------------------------------------------------

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function parseAlpn(value: string): ("h2" | "http/1.1")[] {
  const def: ("h2" | "http/1.1")[] = ["h2", "http/1.1"];
  if (!value) return def;
  const out: ("h2" | "http/1.1")[] = [];
  for (const part of value.split(",")) {
    const t = part.trim();
    if (t === "h2" || t === "http/1.1") out.push(t);
  }
  return out.length > 0 ? out : def;
}

function profileId(kind: string, address: string, port: number, uuid: string): string {
  const s = `${kind}:${address}:${port}:${uuid}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

function zodReason(err: { issues: { path: (string | number)[]; message: string }[] }): string {
  const first = err.issues[0];
  if (!first) return "validation failed";
  const path = first.path.length > 0 ? first.path.join(".") : "(root)";
  return `${path}: ${first.message}`;
}
