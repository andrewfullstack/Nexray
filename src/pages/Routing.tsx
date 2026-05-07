import { useEffect, useMemo, useState } from "react";
import { FormattedMessage } from "react-intl";
import { type RoutingPreset } from "../lib/ipc";
import type { ParsedRule, RuleDestination, RuleMatcherType } from "../lib/rules-conf";
import { useRoutingStore } from "../stores/routing";
import { useRulesFileStore } from "../stores/rulesFile";

const PRESETS: { id: RoutingPreset; label: string; help: string }[] = [
  {
    id: "default",
    label: "Default",
    help: "Apply the rules file first, then fall back: CN sites + private IPs go direct, ads blocked, rest proxied.",
  },
  {
    id: "direct",
    label: "Direct",
    help: "Kill-switch: everything direct. Block rules in the rules file still fire (ad filtering); direct/proxy rules in the file are ignored.",
  },
  {
    id: "global",
    label: "Global proxy",
    help: "Kill-switch: everything through the proxy, including .cn domains. Block rules in the rules file still fire; direct/proxy rules in the file are ignored.",
  },
];

const DESTINATIONS: RuleDestination[] = ["direct", "proxy", "block"];
const MATCHER_TYPES: RuleMatcherType[] = [
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
];

export function Routing() {
  const {
    settings,
    loading,
    dirty,
    error,
    presetFlashAt,
    hydrate,
    applyPreset,
    setDns,
    reset,
    save,
  } = useRoutingStore();
  const rulesLoading = useRulesFileStore((s) => s.loading);
  const rulesHydrate = useRulesFileStore((s) => s.hydrate);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [savedFlash, setSavedFlash] = useState(false);
  const [presetFlashVisible, setPresetFlashVisible] = useState(false);

  useEffect(() => {
    if (presetFlashAt === null) return;
    setPresetFlashVisible(true);
    const t = window.setTimeout(() => setPresetFlashVisible(false), 1500);
    return () => window.clearTimeout(t);
  }, [presetFlashAt]);

  useEffect(() => {
    void hydrate();
    void rulesHydrate();
  }, [hydrate, rulesHydrate]);

  const handleSavePresetAndDns = async () => {
    setSavedFlash(false);
    try {
      await save();
      setSavedFlash(true);
      window.setTimeout(() => setSavedFlash(false), 2000);
    } catch {
      /* error in store */
    }
  };

  if (loading || rulesLoading) return <p className="dim">Loading routing…</p>;

  return (
    <>
      <div className="card">
        <h2 style={{ marginTop: 0 }}>
          <FormattedMessage id="routing.heading" defaultMessage="Routing" />
        </h2>

        <div className="field">
          <div
            className="row"
            style={{ justifyContent: "space-between", alignItems: "baseline" }}
          >
            <span className="label">Fallback preset</span>
            {presetFlashVisible && <span className="flash ok">Applied.</span>}
          </div>
          <p className="dim" style={{ margin: "0 0 0.5rem" }}>
            <small>
              Click a preset to apply it immediately — if a profile is
              connected, xray reloads in place. The fallback preset runs{" "}
              <em>after</em> all rules in <code>rules.conf</code>; Xray uses
              first-match-wins, so rules in the file take priority and the
              preset catches whatever they don&apos;t match.
            </small>
          </p>
          <div className="preset-grid">
            {PRESETS.map((p) => {
              const selected = settings.preset === p.id;
              return (
                <label
                  key={p.id}
                  className={`preset-card${selected ? " selected" : ""}`}
                >
                  <input
                    type="radio"
                    name="preset"
                    checked={selected}
                    onChange={() => {
                      void applyPreset(p.id);
                    }}
                    className="sr-only"
                  />
                  <strong>{p.label}</strong>
                  <span className="dim">
                    <small>{p.help}</small>
                  </span>
                </label>
              );
            })}
          </div>
        </div>
      </div>

      <RulesFileCard />

      <div className="card">
        <button
          type="button"
          onClick={() => setShowAdvanced((v) => !v)}
          style={{ width: "100%", textAlign: "left" }}
        >
          {showAdvanced ? "▾ Advanced (DNS)" : "▸ Advanced (DNS)"}
        </button>
        {showAdvanced && (
          <div style={{ marginTop: "1rem" }}>
            <div className="field">
              <label className="label" htmlFor="dns-domestic">
                Domestic resolver (geosite:cn)
              </label>
              <input
                id="dns-domestic"
                value={settings.dns.domesticResolver}
                onChange={(e) =>
                  setDns({ ...settings.dns, domesticResolver: e.target.value })
                }
              />
            </div>
            <div className="field">
              <label className="label" htmlFor="dns-proxy">
                Proxy resolver (everything else)
              </label>
              <input
                id="dns-proxy"
                value={settings.dns.proxyResolver}
                onChange={(e) =>
                  setDns({ ...settings.dns, proxyResolver: e.target.value })
                }
              />
            </div>
            <p className="dim">
              <small>
                System DNS leaks are blocked unconditionally — these resolvers
                are the only DNS servers xray-core consults.
              </small>
            </p>
          </div>
        )}
      </div>

      <div className="card row" style={{ justifyContent: "space-between" }}>
        <button onClick={() => reset()}>Reset preset + DNS</button>
        <div className="row">
          {savedFlash && <span className="flash ok">Saved.</span>}
          <button
            className="primary"
            onClick={() => void handleSavePresetAndDns()}
            disabled={!dirty}
          >
            Save DNS
          </button>
        </div>
      </div>

      {error && <div className="flash err">{error}</div>}
    </>
  );
}

function RulesFileCard() {
  const {
    contents,
    parsed,
    error,
    appendRule,
    toggleEnabled,
    setRuleDestination,
    deleteRule,
    resetToDefault,
    saveRaw,
  } = useRulesFileStore();

  const [matcherType, setMatcherType] = useState<RuleMatcherType>("domain-suffix");
  const [matcher, setMatcher] = useState("");
  const [destination, setDestination] = useState<RuleDestination>("proxy");
  const [showRaw, setShowRaw] = useState(false);
  const [draft, setDraft] = useState("");
  const [savedFlash, setSavedFlash] = useState(false);

  useEffect(() => {
    if (showRaw) setDraft(contents);
  }, [showRaw, contents]);

  const placeholder = useMemo(() => placeholderFor(matcherType), [matcherType]);

  const handleAdd = async () => {
    const trimmed = matcher.trim();
    if (matcherType !== "final" && trimmed.length === 0) return;
    await appendRule({
      matcherType,
      matcher: matcherType === "final" ? "" : trimmed,
      destination,
      noResolve: false,
    });
    setMatcher("");
  };

  const handleSaveRaw = async () => {
    setSavedFlash(false);
    await saveRaw(draft);
    setSavedFlash(true);
    window.setTimeout(() => setSavedFlash(false), 2000);
  };

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <strong>Rules file ({parsed.totalRules} rules)</strong>
        <div className="row" style={{ gap: "0.5rem" }}>
          <button onClick={() => setShowRaw((v) => !v)}>
            {showRaw ? "Hide editor" : "Edit raw"}
          </button>
          <button
            onClick={() => {
              if (window.confirm("Reset rules.conf to the bundled default?")) {
                void resetToDefault();
              }
            }}
          >
            Reset to default
          </button>
        </div>
      </div>

      <p className="dim" style={{ margin: "0.4rem 0 1rem" }}>
        <small>
          Stored at <code>~/Library/Application Support/dev.nexray.app/rules.conf</code>{" "}
          (path varies by OS). Disabled lines start with <code>#</code>.
          {parsed.disabledCount > 0 && ` ${parsed.disabledCount} disabled.`}
          {parsed.unsupportedCount > 0 && (
            <>
              {" "}
              <span style={{ color: "var(--yellow)" }}>
                {parsed.unsupportedCount} rules use unsupported types
                (IP-ASN / USER-AGENT / AND); they round-trip but won&apos;t
                be applied by xray.
              </span>
            </>
          )}
        </small>
      </p>

      {showRaw ? (
        <>
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            spellCheck={false}
            style={{ minHeight: "20rem", fontSize: "0.9em" }}
          />
          <div className="row" style={{ marginTop: "0.5rem", justifyContent: "flex-end" }}>
            {savedFlash && <span className="flash ok">Saved.</span>}
            <button
              className="primary"
              onClick={() => void handleSaveRaw()}
              disabled={draft === contents}
            >
              Save file
            </button>
          </div>
        </>
      ) : (
        <RulesTable
          rules={parsed.rules}
          onToggle={(idx, on) => void toggleEnabled(idx, on)}
          onDestinationChange={(idx, dest) => void setRuleDestination(idx, dest)}
          onDelete={(idx) => void deleteRule(idx)}
        />
      )}

      <div
        className="row"
        style={{
          marginTop: "1rem",
          gap: "0.5rem",
          flexWrap: "wrap",
          borderTop: "1px solid var(--border)",
          paddingTop: "0.85rem",
        }}
      >
        <select
          value={matcherType}
          onChange={(e) => setMatcherType(e.target.value as RuleMatcherType)}
        >
          {MATCHER_TYPES.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        {matcherType !== "final" && (
          <input
            value={matcher}
            onChange={(e) => setMatcher(e.target.value)}
            placeholder={placeholder}
            style={{ flex: 1, minWidth: "12rem" }}
          />
        )}
        <select
          value={destination}
          onChange={(e) => setDestination(e.target.value as RuleDestination)}
        >
          {DESTINATIONS.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
        <button
          onClick={() => void handleAdd()}
          disabled={matcherType !== "final" && matcher.trim().length === 0}
        >
          Add rule
        </button>
      </div>

      {error && <div className="flash err">{error}</div>}
    </div>
  );
}

interface RulesTableProps {
  rules: ParsedRule[];
  onToggle: (index: number, enabled: boolean) => void;
  onDestinationChange: (index: number, destination: RuleDestination) => void;
  onDelete: (index: number) => void;
}

function RulesTable({
  rules,
  onToggle,
  onDestinationChange,
  onDelete,
}: RulesTableProps) {
  if (rules.length === 0) {
    return (
      <p className="dim">
        <small>
          No rules. Add one below or click &ldquo;Edit raw&rdquo;.
        </small>
      </p>
    );
  }
  return (
    <div style={{ maxHeight: "26rem", overflow: "auto" }}>
      <table
        className="mono"
        style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.92em" }}
      >
        <thead
          style={{
            position: "sticky",
            top: 0,
            // Solid opaque fill so rules scrolling underneath don't bleed
            // through. The card body is translucent (frosted glass), but
            // the sticky header needs to actually occlude.
            background: "rgb(28, 34, 42)",
            zIndex: 1,
            boxShadow: "0 1px 0 var(--border)",
          }}
        >
          <tr style={{ textAlign: "left" }}>
            <th style={{ padding: "0.5rem 0.4rem", color: "var(--fg-2)", fontSize: "0.78rem", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>on</th>
            <th style={{ padding: "0.5rem 0.4rem", color: "var(--fg-2)", fontSize: "0.78rem", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>type</th>
            <th style={{ padding: "0.5rem 0.4rem", color: "var(--fg-2)", fontSize: "0.78rem", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>matcher</th>
            <th style={{ padding: "0.5rem 0.4rem", color: "var(--fg-2)", fontSize: "0.78rem", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>→</th>
            <th style={{ padding: "0.5rem 0.4rem" }}></th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={`${r.index}-${r.raw}`} style={{ borderTop: "1px solid var(--border)" }}>
              <td style={{ padding: "0.4rem" }}>
                <input
                  type="checkbox"
                  checked={r.enabled}
                  onChange={(e) => onToggle(r.index, e.target.checked)}
                />
              </td>
              <td style={{ padding: "0.4rem", color: typeColor(r.matcherType) }}>
                {r.matcherType}
              </td>
              <td style={{ padding: "0.4rem", wordBreak: "break-all" }}>
                {r.matcherType === "final" ? <em className="dim">(catch-all)</em> : r.matcher}
                {r.noResolve && (
                  <span className="dim" style={{ marginLeft: "0.4rem" }}>
                    no-resolve
                  </span>
                )}
              </td>
              <td style={{ padding: "0.4rem" }}>
                <select
                  value={r.destination}
                  onChange={(e) =>
                    onDestinationChange(r.index, e.target.value as RuleDestination)
                  }
                  style={{
                    color: destColor(r.destination),
                    background: "transparent",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius)",
                    padding: "0.2rem 0.4rem",
                    fontFamily: "inherit",
                    fontSize: "inherit",
                    fontWeight: 500,
                    cursor: "pointer",
                  }}
                >
                  {DESTINATIONS.map((d) => (
                    <option key={d} value={d}>
                      {d}
                    </option>
                  ))}
                </select>
              </td>
              <td style={{ padding: "0.4rem" }}>
                <button className="danger" onClick={() => onDelete(r.index)}>
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function placeholderFor(t: RuleMatcherType): string {
  switch (t) {
    case "domain":
      return "exact.example.com";
    case "domain-suffix":
      return "example.com  (matches subdomains)";
    case "domain-keyword":
      return "google";
    case "domain-regex":
      return ".*\\.example\\.com$";
    case "ip-cidr":
      return "1.2.3.0/24";
    case "ip-cidr6":
      return "2001:db8::/32";
    case "geoip":
      return "CN  /  US  /  private";
    case "ip-asn":
      return "13335  (xray won't match this)";
    case "user-agent":
      return "Line*  (xray won't match this)";
    case "final":
      return "(no value — only the destination)";
    case "other":
      return "raw rule";
  }
}

function typeColor(t: RuleMatcherType): string {
  if (t === "ip-asn" || t === "user-agent" || t === "other") return "var(--yellow)";
  return "var(--fg-2)";
}

function destColor(d: RuleDestination): string {
  switch (d) {
    case "direct":
      return "var(--green)";
    case "proxy":
      return "var(--accent)";
    case "block":
      return "var(--red)";
  }
}
