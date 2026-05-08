import { z } from "zod";

// Shared primitives ---------------------------------------------------------

/**
 * The full uTLS fingerprint whitelist supported by xray-core. Per
 * DEVELOPMENT.md §4.2: an unknown value is a hard failure, never a fallback.
 */
export const FINGERPRINTS = [
  "chrome",
  "firefox",
  "safari",
  "ios",
  "android",
  "edge",
  "random",
] as const;

export const FingerprintSchema = z.enum(FINGERPRINTS);
export type Fingerprint = z.infer<typeof FingerprintSchema>;

const PortSchema = z.number().int().min(1).max(65535);

const UuidSchema = z.string().uuid({
  message: "VLESS user ID must be a UUID",
});

// Trojan password: any non-empty printable string. xray-core SHA-224's it
// before sending, so length and alphabet are not protocol-constrained beyond
// "must not be empty". Cap at 256 to keep share-links sane.
const TrojanPasswordSchema = z
  .string()
  .min(1, "Trojan password required")
  .max(256, "Trojan password too long");

// reality publicKey is a Curve25519 key serialized as 43 base64url characters
// (32 bytes, no padding). Some servers emit 44 chars with a trailing '='.
const RealityPublicKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}=?$/, "publicKey must be 43-char base64url");

// reality shortId: 0–16 hex chars, even length.
const RealityShortIdSchema = z
  .string()
  .regex(/^([0-9a-f]{2}){0,8}$/i, "shortId must be 0–16 hex chars, even length")
  .transform((s) => s.toLowerCase());

const AlpnSchema = z.array(z.enum(["h2", "http/1.1"])).min(1);

// Profiles ------------------------------------------------------------------

/**
 * `cdn-ws`: VLESS + WebSocket + TLS, fronted by a CDN.
 *
 * Field mapping (this profile -> xray outbound shape, materialized in Phase 2):
 *   address  -> settings.vnext[0].address           (CDN edge IP or host)
 *   port     -> settings.vnext[0].port
 *   uuid     -> settings.vnext[0].users[0].id       (encryption pinned to "none")
 *   sni      -> streamSettings.tlsSettings.serverName
 *   alpn     -> streamSettings.tlsSettings.alpn
 *   fp       -> streamSettings.tlsSettings.fingerprint
 *   path     -> streamSettings.wsSettings.path      (preserve `?ed=` early-data)
 *   host     -> streamSettings.wsSettings.headers.Host
 *
 * Hard rules (DEVELOPMENT.md §4.1):
 *   - allowInsecure is never accepted. There is no schema field for it on
 *     purpose; the materializer always emits `allowInsecure: false`.
 */
export const CdnWsProfileSchema = z
  .object({
    kind: z.literal("cdn-ws"),
    id: z.string().min(1, "profile id required"),
    name: z.string().min(1).max(64),
    remark: z.string().max(128).optional(),

    address: z.string().min(1),
    port: PortSchema,
    uuid: UuidSchema,

    host: z.string().min(1, "ws Host header required"),
    path: z.string().min(1, "ws path required"),
    sni: z.string().min(1, "TLS SNI required"),
    alpn: AlpnSchema.default(["h2", "http/1.1"]),
    fingerprint: FingerprintSchema.default("chrome"),
  })
  .strict();

export type CdnWsProfile = z.infer<typeof CdnWsProfileSchema>;

/**
 * `reality`: VLESS + Vision flow + REALITY over raw TCP.
 *
 * Field mapping (this profile -> xray outbound shape):
 *   address    -> settings.vnext[0].address
 *   port       -> settings.vnext[0].port
 *   uuid       -> settings.vnext[0].users[0].id
 *   flow       -> settings.vnext[0].users[0].flow  (pinned to xtls-rprx-vision)
 *   sni        -> streamSettings.realitySettings.serverName  (BORROWED dest SNI)
 *   publicKey  -> streamSettings.realitySettings.publicKey
 *   shortId    -> streamSettings.realitySettings.shortId
 *   fingerprint-> streamSettings.realitySettings.fingerprint
 *   spiderX    -> streamSettings.realitySettings.spiderX
 *
 * Hard rules (DEVELOPMENT.md §4.2):
 *   - flow MUST equal "xtls-rprx-vision" (literal).
 *   - network is forced to "tcp"; reality+ws/grpc/xhttp/httpupgrade are rejected
 *     at parse time, not here (the share-link parser drops them).
 */
export const RealityProfileSchema = z
  .object({
    kind: z.literal("reality"),
    id: z.string().min(1, "profile id required"),
    name: z.string().min(1).max(64),
    remark: z.string().max(128).optional(),

    address: z.string().min(1),
    port: PortSchema,
    uuid: UuidSchema,

    sni: z.string().min(1, "REALITY borrowed SNI required"),
    publicKey: RealityPublicKeySchema,
    shortId: RealityShortIdSchema,
    fingerprint: FingerprintSchema.default("chrome"),
    flow: z.literal("xtls-rprx-vision").default("xtls-rprx-vision"),
    spiderX: z.string().default(""),
  })
  .strict();

export type RealityProfile = z.infer<typeof RealityProfileSchema>;

/**
 * `trojan`: Trojan over raw TCP + TLS. The simplest of the three protocols —
 * a SHA-224(password) preamble immediately followed by SOCKS-like address +
 * payload, all wrapped in a stock TLS 1.3 session. xray-core handles the
 * crypto; Nexray only marshals the credentials and the TLS knobs.
 *
 * Field mapping (this profile -> xray outbound shape):
 *   address    -> settings.servers[0].address
 *   port       -> settings.servers[0].port
 *   password   -> settings.servers[0].password
 *   sni        -> streamSettings.tlsSettings.serverName
 *   alpn       -> streamSettings.tlsSettings.alpn
 *   fingerprint-> streamSettings.tlsSettings.fingerprint
 *
 * Hard rules:
 *   - Transport is pinned to TCP. WebSocket / gRPC variants are rejected
 *     at parse time (Phase-7 scope is TCP+TLS only).
 *   - allowInsecure is never accepted. There is no schema field for it on
 *     purpose; the materializer always emits `allowInsecure: false`.
 */
export const TrojanProfileSchema = z
  .object({
    kind: z.literal("trojan"),
    id: z.string().min(1, "profile id required"),
    name: z.string().min(1).max(64),
    remark: z.string().max(128).optional(),

    address: z.string().min(1),
    port: PortSchema,
    password: TrojanPasswordSchema,

    sni: z.string().min(1, "TLS SNI required"),
    alpn: AlpnSchema.default(["h2", "http/1.1"]),
    fingerprint: FingerprintSchema.default("chrome"),
  })
  .strict();

export type TrojanProfile = z.infer<typeof TrojanProfileSchema>;

export const ProfileSchema = z.discriminatedUnion("kind", [
  CdnWsProfileSchema,
  RealityProfileSchema,
  TrojanProfileSchema,
]);
export type Profile = z.infer<typeof ProfileSchema>;

// Skipped-entry classification --------------------------------------------

/** The well-known reasons emitted by the subscription classifier. */
export const SKIP_REASONS = [
  "vmess (legacy)",
  "shadowsocks (legacy)",
  // trojan-go is a separate protocol from upstream Trojan and intentionally
  // unsupported. Plain `trojan://` over TCP+TLS IS supported and produces
  // an accepted Profile, so it does NOT appear in this list.
  "trojan-go (legacy)",
  "trojan+ws (unsupported)",
  "http (unsupported as outbound)",
  "socks (unsupported as outbound)",
  "reality+ws (invalid combination)",
  "reality+grpc (invalid combination)",
  "reality+xhttp (invalid combination)",
  "reality+httpupgrade (invalid combination)",
  "vless+tls direct (use reality instead)",
  "vless+kcp (mKCP unsupported)",
  "vless+quic (raw QUIC inbound unsupported)",
  "malformed",
  "unknown protocol",
] as const;

export type SkipReason = (typeof SKIP_REASONS)[number];

export const SkippedEntrySchema = z.object({
  raw: z.string(),
  reason: z.enum(SKIP_REASONS),
});
export type SkippedEntry = z.infer<typeof SkippedEntrySchema>;

export const ClassifyResultSchema = z.object({
  accepted: z.array(ProfileSchema),
  skipped: z.array(SkippedEntrySchema),
});
export type ClassifyResult = z.infer<typeof ClassifyResultSchema>;
