import type { ClassifyResult, SkippedEntry } from "./profile";
import { decodeShareLink } from "./share-link";

/**
 * Detect-and-decode wrapper. Accepts the three formats listed in
 * DEVELOPMENT.md §5.1 and emits `{ accepted, skipped }`.
 *
 *   1. Plain newline-separated share links
 *   2. Base64 (URL-safe or standard) of (1)
 *   3. A single share link
 *
 * Pure: never performs IO. Order is preserved.
 */
export function classifySubscription(body: string): ClassifyResult {
  const lines = splitEntries(decodeIfBase64(body));
  const accepted: ClassifyResult["accepted"] = [];
  const skipped: SkippedEntry[] = [];

  for (const raw of lines) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const result = decodeShareLink(line);
    if (result.ok) {
      accepted.push(result.profile);
    } else {
      skipped.push({ raw: result.raw, reason: result.reason });
    }
  }

  return { accepted, skipped };
}

/**
 * Format the skipped-list summary line per DEVELOPMENT.md §5.3, e.g.
 *   "5 servers skipped: 2 vmess (legacy), 1 shadowsocks (legacy), ..."
 *
 * Reasons are grouped, ordered by descending count, then alphabetical.
 */
export function summarizeSkipped(skipped: readonly SkippedEntry[]): string {
  if (skipped.length === 0) return "";
  const counts = new Map<string, number>();
  for (const s of skipped) counts.set(s.reason, (counts.get(s.reason) ?? 0) + 1);
  const parts = [...counts.entries()]
    .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0]))
    .map(([reason, n]) => `${n} ${reason}`);
  return `${skipped.length} servers skipped: ${parts.join(", ")}`;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/**
 * Heuristic: a body is base64 if (a) it doesn't already look like share links
 * (no `vless://` / `vmess://` / etc. prefix on any non-empty line) AND
 * (b) it decodes cleanly to UTF-8 that contains at least one share-link prefix.
 */
function decodeIfBase64(body: string): string {
  const stripped = body.replace(/\s+/g, "");
  if (stripped.length === 0) return body;

  // If the body already looks like share links, don't try base64.
  if (/^(vless|vmess|ss|ssr|trojan|trojan-go|http|https|socks|socks5):\/\//im.test(body)) {
    return body;
  }

  // Only attempt base64 if the alphabet matches.
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(stripped)) return body;

  try {
    const normalized = stripped.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const decoded = base64ToUtf8(padded);
    if (/(vless|vmess|ss|ssr|trojan|http|https|socks):\/\//i.test(decoded)) {
      return decoded;
    }
    return body;
  } catch {
    return body;
  }
}

function splitEntries(body: string): string[] {
  return body.split(/\r?\n/);
}

/**
 * UTF-8 base64 decoder. Routes the binary-string output of `atob` through
 * `Uint8Array` + `TextDecoder` so multi-byte UTF-8 (Chinese remarks etc.)
 * round-trips correctly. `atob` is a global in browsers and Node ≥ 16, which
 * matches our `engines.node`.
 */
function base64ToUtf8(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
