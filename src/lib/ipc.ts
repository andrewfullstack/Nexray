import { z } from "zod";
import { ProfileSchema } from "./profile";

// ----------------------------------------------------------------------------
// IPC contract: typed inputs / outputs for every Tauri command.
//
// Keep this file as the single TS-side source of truth. Rust mirrors live in
// `crates/nexray-core/src/types_generated.rs` (auto-generated from
// `scripts/gen-rust-types.mjs`). Adding a field here requires updating the
// gen-rust-types MANIFEST in the same PR; CI fails otherwise.
// ----------------------------------------------------------------------------

/**
 * Lifecycle states surfaced by the Rust shell. See `XraySidecar` in
 * `src-tauri/src/core.rs`.
 *
 * - `disconnected` — no xray child running, no profile active.
 * - `connecting`   — xray child spawned, waiting for the SOCKS listener.
 * - `connected`    — SOCKS listener up; `socksPort` is bound on 127.0.0.1.
 * - `crashed`      — xray child exited unexpectedly. We never auto-restart;
 *                    the user must call `connect` again. `lastError` holds
 *                    the trailing stderr line if any.
 */
export const ConnectionStateSchema = z.enum([
  "disconnected",
  "connecting",
  "connected",
  "crashed",
]);
export type ConnectionState = z.infer<typeof ConnectionStateSchema>;

export const ConnectionStatusSchema = z
  .object({
    state: ConnectionStateSchema,
    profileId: z.string().nullable(),
    socksPort: z.number().int().min(1).max(65535).nullable(),
    sinceMs: z.number().int().min(0).nullable(),
    lastError: z.string().nullable(),
  })
  .strict();
export type ConnectionStatus = z.infer<typeof ConnectionStatusSchema>;

/**
 * Live byte counters. `available: false` when xray is not running, or when
 * the Stats API call failed (e.g. xray's stats service was disabled). Bytes
 * are absolute since xray start; the UI computes deltas itself.
 */
export const TrafficStatsSchema = z
  .object({
    available: z.boolean(),
    uplinkBytes: z.number().int().min(0),
    downlinkBytes: z.number().int().min(0),
  })
  .strict();
export type TrafficStats = z.infer<typeof TrafficStatsSchema>;

/**
 * One-shot egress check. The Rust shell does an HTTPS GET to `ifconfig.me/ip`
 * through the running xray's SOCKS inbound, returning whatever IP the
 * destination saw — your visual confirmation that a server switch reached
 * the wire even when both endpoints share a CDN front.
 */
export const EgressCheckSchema = z
  .object({
    ok: z.boolean(),
    ip: z.string().nullable(),
    elapsedMs: z.number().int().min(0).nullable(),
    error: z.string().nullable(),
  })
  .strict();
export type EgressCheck = z.infer<typeof EgressCheckSchema>;

/** Input to the `connect` command. */
export const ConnectRequestSchema = z
  .object({
    profile: ProfileSchema,
    /** Override the local SOCKS listener port. Default: 10808. */
    socksPort: z.number().int().min(1).max(65535).optional(),
  })
  .strict();
export type ConnectRequest = z.infer<typeof ConnectRequestSchema>;

// ----------------------------------------------------------------------------
// Subscriptions / pool — Phase 4
// ----------------------------------------------------------------------------

/**
 * One 机场 subscription. The `profiles` array is the last successful classify
 * output; we keep it embedded so the pool view doesn't need a join. The
 * `lastFetchError` carries a short reason string when the most recent refresh
 * failed but the cached profiles are still being served.
 */
export const SubscriptionSchema = z
  .object({
    id: z.string().min(1),
    url: z.string().min(1),
    name: z.string().min(1).max(64),
    addedMs: z.number().int().min(0),
    lastFetchedMs: z.number().int().min(0).nullable(),
    lastFetchError: z.string().nullable(),
    acceptedCount: z.number().int().min(0),
    skippedCount: z.number().int().min(0),
    skippedSummary: z.string().nullable(),
    profiles: z.array(ProfileSchema),
  })
  .strict();
export type Subscription = z.infer<typeof SubscriptionSchema>;

/** Per-profile latency probe result returned by `probe_profiles`. */
export const ProbeResultSchema = z
  .object({
    profileId: z.string().min(1),
    /** TCP-connect latency in ms; null on timeout / DNS failure. */
    latencyMs: z.number().int().min(0).nullable(),
  })
  .strict();
export type ProbeResult = z.infer<typeof ProbeResultSchema>;

export const AddSubscriptionRequestSchema = z
  .object({
    url: z.string().min(1),
    /** Optional friendly label; default derived from the URL host. */
    name: z.string().min(1).max(64).optional(),
  })
  .strict();
export type AddSubscriptionRequest = z.infer<typeof AddSubscriptionRequestSchema>;

export const SubscriptionIdRequestSchema = z
  .object({ id: z.string().min(1) })
  .strict();
export type SubscriptionIdRequest = z.infer<typeof SubscriptionIdRequestSchema>;

// ----------------------------------------------------------------------------
// Routing — Phase 5
// ----------------------------------------------------------------------------

/**
 * Routing presets (DEVELOPMENT.md §6.1).
 *
 * - `default`: CN traffic + private IPs go direct, ads blocked, rest proxied.
 * - `direct`: everything direct (proxy disabled), ads blocked. Useful for
 *    troubleshooting or "tunnel only specific apps via custom rules".
 * - `global`: everything through the proxy, no CN exemption. Used when the
 *    user wants identical egress regardless of destination.
 */
export const RoutingPresetSchema = z.enum(["default", "direct", "global"]);
export type RoutingPreset = z.infer<typeof RoutingPresetSchema>;

export const RoutingDestinationSchema = z.enum(["direct", "proxy", "block"]);
export type RoutingDestination = z.infer<typeof RoutingDestinationSchema>;

export const RoutingMatcherTypeSchema = z.enum(["domain", "ip", "port", "network"]);
export type RoutingMatcherType = z.infer<typeof RoutingMatcherTypeSchema>;

/**
 * One user-defined routing rule. Prepended to the preset's rules so user
 * intent always wins (Xray's first-match-wins semantics).
 *
 * `matcher` is a free-form string passed through to xray. Examples:
 *   - `domain:youtube.com`
 *   - `geosite:google`
 *   - `regexp:.*\\.example\\.org$`
 *   - `1.2.3.0/24`
 *   - `80,443`
 */
export const CustomRuleSchema = z
  .object({
    id: z.string().min(1),
    matcherType: RoutingMatcherTypeSchema,
    matcher: z.string().min(1).max(256),
    destination: RoutingDestinationSchema,
    enabled: z.boolean(),
  })
  .strict();
export type CustomRule = z.infer<typeof CustomRuleSchema>;

export const DnsConfigSchema = z
  .object({
    /** Resolver used for `geosite:cn` traffic. Default: `223.5.5.5` (AliDNS). */
    domesticResolver: z.string().min(1).max(256),
    /** Resolver used for everything proxied. Default: `https://1.1.1.1/dns-query`. */
    proxyResolver: z.string().min(1).max(256),
  })
  .strict();
export type DnsConfig = z.infer<typeof DnsConfigSchema>;

export const RoutingSettingsSchema = z
  .object({
    preset: RoutingPresetSchema,
    customRules: z.array(CustomRuleSchema),
    dns: DnsConfigSchema,
  })
  .strict();
export type RoutingSettings = z.infer<typeof RoutingSettingsSchema>;

export const SetRoutingRequestSchema = z
  .object({ settings: RoutingSettingsSchema })
  .strict();
export type SetRoutingRequest = z.infer<typeof SetRoutingRequestSchema>;

export const DEFAULT_ROUTING_SETTINGS: RoutingSettings = {
  preset: "default",
  customRules: [],
  dns: {
    domesticResolver: "223.5.5.5",
    proxyResolver: "https://1.1.1.1/dns-query",
  },
};

// ----------------------------------------------------------------------------
// TUN — Phase 6
// ----------------------------------------------------------------------------

/**
 * Lifecycle states for the TUN/tun2socks subsystem.
 *
 * - `disabled` — TUN is off; no kernel interface, no tun2socks process.
 * - `starting` — interface being created, tun2socks spawning.
 * - `active`   — interface up, tun2socks alive, system traffic captured.
 * - `stopping` — tearing down; routes being restored, tun2socks dying.
 * - `failed`   — last enable attempt errored. `lastError` carries the reason
 *                (e.g. "needs admin", "tun2socks binary not bundled").
 */
export const TunStateSchema = z.enum([
  "disabled",
  "starting",
  "active",
  "stopping",
  "failed",
]);
export type TunState = z.infer<typeof TunStateSchema>;

export const TunStatusSchema = z
  .object({
    state: TunStateSchema,
    /** OS interface name (`utun5`, `nexray-tun`, etc.) when active. */
    interfaceName: z.string().nullable(),
    sinceMs: z.number().int().min(0).nullable(),
    lastError: z.string().nullable(),
  })
  .strict();
export type TunStatus = z.infer<typeof TunStatusSchema>;

export const TunCapabilitiesSchema = z
  .object({
    /** Platform supports TUN at all (i.e. compiled-in support). */
    supported: z.boolean(),
    /** `"macos"` / `"windows"` / `"linux"` / `"unknown"`. */
    platform: z.string(),
    /** Whether the bundled tun2socks binary is present at runtime. */
    binaryPresent: z.boolean(),
    /** When `supported` is false, why. Surfaced in the UI tooltip. */
    reason: z.string().nullable(),
  })
  .strict();
export type TunCapabilities = z.infer<typeof TunCapabilitiesSchema>;

// ----------------------------------------------------------------------------
// System proxy — Phase 7.5
// ----------------------------------------------------------------------------

/**
 * Status of the OS-level system proxy. When `enabled` is true, every
 * proxy-aware app on the system tunnels its SOCKS traffic through Nexray's
 * local listener. Toggling on macOS shells out to `networksetup` (admin
 * password may be required).
 */
export const SystemProxyStatusSchema = z
  .object({
    enabled: z.boolean(),
    host: z.string().nullable(),
    port: z.number().int().min(1).max(65535).nullable(),
    /** OS-specific identifier of the network service we mutated (e.g. "Wi-Fi"). */
    service: z.string().nullable(),
  })
  .strict();
export type SystemProxyStatus = z.infer<typeof SystemProxyStatusSchema>;

// ----------------------------------------------------------------------------
// Settings — Phase 7
// ----------------------------------------------------------------------------

/**
 * App-wide settings persisted across launches. The shape uses default
 * (non-strict) Zod parsing so any legacy fields written by older builds
 * (e.g. the deleted `telemetryOptIn` toggle) are silently dropped on
 * next read instead of raising a validation error.
 */
export const AppSettingsSchema = z.object({
  autoUpdateOptIn: z.boolean(),
});
export type AppSettings = z.infer<typeof AppSettingsSchema>;

export const SetSettingsRequestSchema = z
  .object({ settings: AppSettingsSchema })
  .strict();
export type SetSettingsRequest = z.infer<typeof SetSettingsRequestSchema>;

export const DEFAULT_APP_SETTINGS: AppSettings = {
  autoUpdateOptIn: false,
};

// ----------------------------------------------------------------------------
// Rules file (Shadowrocket .conf format)
// ----------------------------------------------------------------------------

/** Matcher type understood by both the structured editor and the rules file. */
export const RulesFileMatcherTypeSchema = z.enum([
  "domain",
  "domain-suffix",
  "domain-keyword",
  "domain-regex",
  "ip-cidr",
  "ip-cidr6",
  "geoip",
  "ip-asn",
  "user-agent",
  "final",
]);
export type RulesFileMatcherType = z.infer<typeof RulesFileMatcherTypeSchema>;

/** Input shape for the "Add rule" form, mirroring the Rust IPC. */
export const RulesFileAppendRequestSchema = z
  .object({
    matcherType: RulesFileMatcherTypeSchema,
    matcher: z.string().min(1).max(256),
    destination: RoutingDestinationSchema,
    noResolve: z.boolean(),
  })
  .strict();
export type RulesFileAppendRequest = z.infer<typeof RulesFileAppendRequestSchema>;

/** Build metadata exposed by `app_info`. */
export const AppInfoSchema = z
  .object({
    name: z.string(),
    version: z.string(),
    platform: z.string(),
  })
  .strict();
export type AppInfo = z.infer<typeof AppInfoSchema>;
