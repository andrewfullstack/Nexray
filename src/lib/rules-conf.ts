/**
 * Lightweight TS-side mirror of the Rust `rules_conf` parser. Used purely
 * for rendering the rules table in the UI; the source-of-truth parser still
 * lives in nexray-core and runs server-side every time we save.
 */

export type RuleMatcherType =
  | "domain"
  | "domain-suffix"
  | "domain-keyword"
  | "domain-regex"
  | "ip-cidr"
  | "ip-cidr6"
  | "geoip"
  | "ip-asn"
  | "user-agent"
  | "final"
  | "other";

export type RuleDestination = "direct" | "proxy" | "block";

export interface ParsedRule {
  /** Index among rules-only (matches the backend's rule_index). */
  index: number;
  matcherType: RuleMatcherType;
  matcher: string;
  destination: RuleDestination;
  noResolve: boolean;
  enabled: boolean;
  /** Original source line (with any leading `# ` for disabled rules). */
  raw: string;
}

const RULE_KEYWORDS: Record<string, RuleMatcherType> = {
  DOMAIN: "domain",
  "DOMAIN-SUFFIX": "domain-suffix",
  "DOMAIN-KEYWORD": "domain-keyword",
  "DOMAIN-REGEX": "domain-regex",
  "URL-REGEX": "domain-regex",
  "IP-CIDR": "ip-cidr",
  "IP-CIDR6": "ip-cidr6",
  GEOIP: "geoip",
  "IP-ASN": "ip-asn",
  "USER-AGENT": "user-agent",
  FINAL: "final",
};

export interface ParseStats {
  rules: ParsedRule[];
  totalRules: number;
  disabledCount: number;
  unsupportedCount: number;
}

/** Parse a `.conf` file and return only its `[Rule]` entries. */
export function parseRulesConf(text: string): ParseStats {
  const lines = text.split(/\r?\n/);
  let inRuleSection = false;
  const rules: ParsedRule[] = [];
  let disabled = 0;
  let unsupported = 0;

  for (const raw of lines) {
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      inRuleSection = trimmed.toLowerCase() === "[rule]";
      continue;
    }
    if (!inRuleSection) continue;

    let body = trimmed;
    let enabled = true;
    if (body.startsWith("#")) {
      const inner = body.replace(/^#\s*/, "");
      // Only treat commented lines as disabled rules if they parse as a rule.
      if (looksLikeRule(inner)) {
        body = inner;
        enabled = false;
      } else {
        continue;
      }
    }

    const parsed = parseRuleLine(body, enabled, raw, rules.length);
    if (parsed) {
      if (!enabled) disabled++;
      if (parsed.matcherType === "other" || parsed.matcherType === "ip-asn" || parsed.matcherType === "user-agent") {
        unsupported++;
      }
      rules.push(parsed);
    }
  }

  return {
    rules,
    totalRules: rules.length,
    disabledCount: disabled,
    unsupportedCount: unsupported,
  };
}

function looksLikeRule(s: string): boolean {
  const kw = s.split(",")[0]?.toUpperCase() ?? "";
  return (
    kw in RULE_KEYWORDS ||
    kw === "AND" ||
    kw === "OR" ||
    kw === "NOT" ||
    kw === "FINAL"
  );
}

function parseRuleLine(
  body: string,
  enabled: boolean,
  raw: string,
  index: number,
): ParsedRule | null {
  const parts = body.split(",").map((p) => p.trim());
  if (parts.length < 2) return null;
  const kw = parts[0]?.toUpperCase() ?? "";

  if (kw === "FINAL") {
    const dest = parsePolicy(parts[1] ?? "");
    if (!dest) return null;
    return {
      index,
      matcherType: "final",
      matcher: "",
      destination: dest,
      noResolve: false,
      enabled,
      raw,
    };
  }

  if (kw === "AND" || kw === "OR" || kw === "NOT") {
    const last = parts[parts.length - 1];
    const dest = last ? parsePolicy(last) : null;
    if (!dest) return null;
    return {
      index,
      matcherType: "other",
      matcher: body,
      destination: dest,
      noResolve: false,
      enabled,
      raw,
    };
  }

  if (parts.length < 3) return null;
  const value = parts[1] ?? "";
  const dest = parsePolicy(parts[2] ?? "");
  if (!dest) return null;
  const noResolve = parts.slice(3).some((p) => p.toLowerCase() === "no-resolve");
  const matcherType: RuleMatcherType = RULE_KEYWORDS[kw] ?? "other";

  return {
    index,
    matcherType,
    matcher: value,
    destination: dest,
    noResolve,
    enabled,
    raw,
  };
}

function parsePolicy(s: string): RuleDestination | null {
  switch (s.toUpperCase()) {
    case "DIRECT":
      return "direct";
    case "PROXY":
      return "proxy";
    case "REJECT":
    case "REJECT-NO-DROP":
    case "REJECT-DROP":
      return "block";
    default:
      return null;
  }
}
