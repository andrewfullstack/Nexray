import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Trash2, Zap } from "lucide-react";
import { FormattedMessage, useIntl } from "react-intl";
import { IconButton } from "../components/IconButton";
import { useProfileStore } from "../stores/profile";
import { useSubscriptionsStore } from "../stores/subscriptions";
import { tauri } from "../lib/tauri";
import type { Profile } from "../lib/profile";

type Latency = number | null;

interface GroupBucket {
  /** Stable key for React lists. `null` for the manual/ungrouped bucket. */
  subscriptionId: string | null;
  /** Display name. Subscription's `name` for grouped, "Manual servers"
   *  otherwise. Falls back to a synthesized label if a profile is tagged
   *  with a subscription that no longer exists in the subs list (rare —
   *  happens during a brief window between subscription delete and the
   *  group untag finishing). */
  label: string;
  profiles: Profile[];
  /** True when this is a real subscription group (has auto-switch toggle
   *  + Pick best). */
  isSubscriptionGroup: boolean;
  /** Auto-switch toggle for this group (only meaningful when
   *  `isSubscriptionGroup`). */
  autoSwitch: boolean;
}

export function Servers() {
  const profiles = useProfileStore((s) => s.manualProfiles);
  const groups = useProfileStore((s) => s.groups);
  const groupSettings = useProfileStore((s) => s.groupSettings);
  const active = useProfileStore((s) => s.active);
  const setActive = useProfileStore((s) => s.setActive);
  const remove = useProfileStore((s) => s.remove);
  const setGroupAutoSwitch = useProfileStore((s) => s.setGroupAutoSwitch);
  const removeGroup = useProfileStore((s) => s.removeGroup);
  const loading = useProfileStore((s) => s.loading);
  const subs = useSubscriptionsStore((s) => s.subs);
  const intl = useIntl();
  // Per-profile latency cache, keyed by profile id. `undefined` = never
  // probed; `null` = probed and timed out; number = ms.
  const [latency, setLatency] = useState<Record<string, Latency>>({});
  const [probing, setProbing] = useState(false);
  const [pickingGroupId, setPickingGroupId] = useState<string | null>(null);
  // Subscription group headers start collapsed — clicking the title
  // flips the bit. Keys: subscription id, or "__manual__" for the
  // ungrouped bucket. The Manual servers bucket starts EXPANDED because
  // it's the user's hand-curated short list (typically a handful of
  // entries) and showing it on first paint matches the pre-grouping UX;
  // subscription groups can hold dozens of entries each, so they stay
  // collapsed.
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(
    () => new Set(["__manual__"]),
  );
  const toggleGroup = (key: string) =>
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const handleDelete = (id: string) => {
    void remove(id);
    setLatency((prev) => {
      const { [id]: _omit, ...rest } = prev;
      return rest;
    });
  };

  // Auto-probe once when the page mounts and the manual list has finished
  // hydrating. Saves the user a click for the most common workflow:
  // "open Servers, see which one is fastest, pick it." The ref guards
  // against a re-fire if `profiles.length` changes after the initial
  // probe (delete/add) — manual Probe latency is the only re-probe path
  // after the auto-fire to avoid hammering when the user is just
  // editing the list.
  const autoProbedRef = useRef(false);
  useEffect(() => {
    if (loading) return;
    if (autoProbedRef.current) return;
    if (profiles.length === 0) return;
    autoProbedRef.current = true;
    void handleProbe();
    // handleProbe closes over latency state on purpose; we want a clean
    // first-shot probe and rely on the ref to prevent re-runs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading, profiles.length]);

  const handleDeleteGroup = (subscriptionId: string) => {
    // Drop the cached latency rows for this group so the UI doesn't
    // briefly show stale numbers if the user re-imports the same
    // subscription afterwards.
    const removedIds = new Set(
      Object.entries(groups)
        .filter(([, sid]) => sid === subscriptionId)
        .map(([pid]) => pid),
    );
    setLatency((prev) => {
      const next: Record<string, Latency> = {};
      for (const [pid, l] of Object.entries(prev)) {
        if (!removedIds.has(pid)) next[pid] = l;
      }
      return next;
    });
    void removeGroup(subscriptionId);
  };

  // Bucket profiles by their subscription tag. Group order:
  //   1. Manual / ungrouped (always first when non-empty).
  //   2. Each subscription group, sorted by subscription name.
  // Insertion order within each bucket follows the manualProfiles list,
  // not the subscription's profiles list — that way a server keeps its
  // visual position even after a subscription refresh re-orders the
  // upstream list.
  const buckets = useMemo<GroupBucket[]>(() => {
    const subById = new Map(subs.map((s) => [s.id, s]));
    const groupedMap = new Map<string, Profile[]>();
    const ungrouped: Profile[] = [];
    for (const p of profiles) {
      const subId = groups[p.id];
      if (subId) {
        const arr = groupedMap.get(subId) ?? [];
        arr.push(p);
        groupedMap.set(subId, arr);
      } else {
        ungrouped.push(p);
      }
    }
    const subscriptionBuckets: GroupBucket[] = [];
    for (const [subId, list] of groupedMap.entries()) {
      const sub = subById.get(subId);
      subscriptionBuckets.push({
        subscriptionId: subId,
        label:
          sub?.name ??
          intl.formatMessage(
            { id: "servers.group_unknown" },
            { id: subId.slice(0, 8) },
          ),
        profiles: list,
        isSubscriptionGroup: true,
        autoSwitch: groupSettings[subId]?.autoSwitch ?? false,
      });
    }
    subscriptionBuckets.sort((a, b) => a.label.localeCompare(b.label));
    const out: GroupBucket[] = [];
    if (ungrouped.length > 0) {
      out.push({
        subscriptionId: null,
        label: intl.formatMessage({ id: "servers.group_manual" }),
        profiles: ungrouped,
        isSubscriptionGroup: false,
        autoSwitch: false,
      });
    }
    out.push(...subscriptionBuckets);
    return out;
  }, [profiles, groups, groupSettings, subs, intl]);

  // Look up which bucket the active profile belongs to so we can decide
  // whether a probe sweep should auto-pick.
  const activeSubscriptionId =
    active && groups[active.id] ? groups[active.id] : null;

  const handleProbe = async () => {
    if (probing || profiles.length === 0) return;
    setProbing(true);
    try {
      const results = await tauri.probeProfiles(profiles);
      const merged: Record<string, Latency> = { ...latency };
      for (const r of results) merged[r.profileId] = r.latencyMs;
      setLatency(merged);

      // After a global probe, if the active profile lives in a group with
      // auto-switch enabled, pick the lowest-latency member of that group
      // and switch to it. Restricting auto-switch to the active group
      // keeps the behaviour predictable when the user has multiple groups
      // with the toggle on — only the group they're currently routing
      // through gets re-tuned.
      if (activeSubscriptionId && active) {
        const settings = groupSettings[activeSubscriptionId];
        if (settings?.autoSwitch) {
          const bucket = buckets.find(
            (b) => b.subscriptionId === activeSubscriptionId,
          );
          if (bucket) {
            const best = pickLowestLatency(bucket.profiles, merged);
            if (best && best.id !== active.id) {
              await setActive(best);
            }
          }
        }
      }
    } finally {
      setProbing(false);
    }
  };

  const handlePickBest = async (bucket: GroupBucket) => {
    if (pickingGroupId || !bucket.subscriptionId) return;
    if (bucket.profiles.length === 0) return;
    setPickingGroupId(bucket.subscriptionId);
    try {
      const results = await tauri.probeProfiles(bucket.profiles);
      const merged: Record<string, Latency> = { ...latency };
      for (const r of results) merged[r.profileId] = r.latencyMs;
      setLatency(merged);
      const best = pickLowestLatency(bucket.profiles, merged);
      if (best && best.id !== active?.id) {
        await setActive(best);
      }
    } finally {
      setPickingGroupId(null);
    }
  };

  if (loading)
    return (
      <p className="dim">
        <FormattedMessage id="servers.loading" />
      </p>
    );

  return (
    <>
      <div className="card">
        <div
          className="row"
          style={{ justifyContent: "space-between", alignItems: "center" }}
        >
          <h2 style={{ margin: 0 }}>
            <FormattedMessage id="servers.heading" />
          </h2>
          <div className="row" style={{ gap: "0.5rem" }}>
            <button
              onClick={() => void handleProbe()}
              disabled={probing || profiles.length === 0}
              title={intl.formatMessage({ id: "servers.probe_latency_help" })}
            >
              <FormattedMessage
                id={probing ? "servers.probing" : "servers.probe_latency"}
              />
            </button>
            <Link to="/servers/new">
              <button className="primary">
                <FormattedMessage id="servers.add_server" />
              </button>
            </Link>
          </div>
        </div>
        <p className="dim" style={{ margin: "0.4rem 0 0" }}>
          <small>
            <FormattedMessage id="servers.help" />
          </small>
        </p>
      </div>

      {profiles.length === 0 ? (
        <div className="card">
          <p className="dim">
            <FormattedMessage id="servers.empty" />{" "}
            <Link to="/servers/new">
              <FormattedMessage id="servers.empty_add_first" />
            </Link>
            <FormattedMessage
              id="servers.empty_or_import"
              values={{
                link: (
                  <Link to="/subscriptions">
                    <FormattedMessage id="servers.empty_subscription_link" />
                  </Link>
                ),
              }}
            />
          </p>
        </div>
      ) : (
        buckets.map((bucket) => {
          const key = bucket.subscriptionId ?? "__manual__";
          return (
            <GroupCard
              key={key}
              bucket={bucket}
              latency={latency}
              activeId={active?.id ?? null}
              picking={pickingGroupId === bucket.subscriptionId}
              expanded={expandedGroups.has(key)}
              onToggleExpanded={() => toggleGroup(key)}
              onSelect={(p) => void setActive(p)}
              onDelete={handleDelete}
              onToggleAutoSwitch={(enabled) => {
                if (!bucket.subscriptionId) return;
                void setGroupAutoSwitch(bucket.subscriptionId, enabled);
                // Toggling Auto ON should also pick the best server right
                // away — the user just expressed "I want the fastest in
                // this group", waiting for the next manual probe to act
                // on that intent feels broken.
                if (enabled) void handlePickBest(bucket);
              }}
              onPickBest={() => void handlePickBest(bucket)}
              onDeleteGroup={() => {
                if (bucket.subscriptionId) {
                  handleDeleteGroup(bucket.subscriptionId);
                }
              }}
            />
          );
        })
      )}
    </>
  );
}

function GroupCard({
  bucket,
  latency,
  activeId,
  picking,
  expanded,
  onToggleExpanded,
  onSelect,
  onDelete,
  onToggleAutoSwitch,
  onPickBest,
  onDeleteGroup,
}: {
  bucket: GroupBucket;
  latency: Record<string, Latency>;
  activeId: string | null;
  picking: boolean;
  expanded: boolean;
  onToggleExpanded: () => void;
  onSelect: (p: Profile) => void;
  onDelete: (id: string) => void;
  onToggleAutoSwitch: (enabled: boolean) => void;
  onPickBest: () => void;
  onDeleteGroup: () => void;
}) {
  const intl = useIntl();
  const sorted = sortByLatency(bucket.profiles, latency);
  // Surface the active selection in the collapsed header so users can
  // tell at a glance which group holds their currently-active server
  // without having to expand every card.
  const activeProfile = activeId
    ? bucket.profiles.find((p) => p.id === activeId) ?? null
    : null;

  // Clicking nested controls (Mode toggle, Pick best) inside the header
  // must not also toggle the collapse state. We stop propagation on the
  // wrapper around those controls instead of pinning it to each button —
  // any future control added in the same slot inherits the behaviour.
  const stopHeaderClick = (e: React.MouseEvent | React.KeyboardEvent) => {
    e.stopPropagation();
  };

  return (
    <div className="card" style={{ padding: 0 }}>
      <div
        className="row"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={onToggleExpanded}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggleExpanded();
          }
        }}
        style={{
          justifyContent: "space-between",
          alignItems: "center",
          padding: "0.75rem 1rem",
          borderBottom: expanded ? "1px solid var(--border)" : undefined,
          gap: "0.75rem",
          flexWrap: "wrap",
          cursor: "pointer",
          userSelect: "none",
        }}
        title={intl.formatMessage({
          id: expanded ? "servers.collapse_title" : "servers.expand_title",
        })}
      >
        <div className="row" style={{ gap: "0.5rem", alignItems: "baseline", minWidth: 0 }}>
          <Chevron expanded={expanded} />
          <strong style={{ wordBreak: "break-word" }}>{bucket.label}</strong>
          <span className="dim mono" style={{ fontSize: "0.8em" }}>
            ({bucket.profiles.length})
          </span>
          {activeProfile && (
            <span
              className="mono"
              style={{
                color: "var(--green)",
                fontSize: "0.8em",
                minWidth: 0,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              title={intl.formatMessage(
                { id: "servers.active_title" },
                { name: activeProfile.name },
              )}
            >
              ● {activeProfile.name}
            </span>
          )}
        </div>
        {bucket.isSubscriptionGroup && (
          <div
            className="row"
            style={{ gap: "0.6rem", alignItems: "center" }}
            onClick={stopHeaderClick}
            onKeyDown={stopHeaderClick}
          >
            <ModeToggle
              value={bucket.autoSwitch ? "auto" : "manual"}
              onChange={(mode) => onToggleAutoSwitch(mode === "auto")}
            />
            <IconButton
              onClick={onPickBest}
              disabled={picking || bucket.profiles.length === 0}
              ariaLabel={intl.formatMessage({ id: "servers.pick_best_aria" })}
              title={intl.formatMessage({
                id: picking
                  ? "servers.pick_best_title_busy"
                  : "servers.pick_best_title_idle",
              })}
            >
              <Zap
                size={14}
                strokeWidth={2.2}
                className={picking ? "spin" : undefined}
              />
            </IconButton>
            <IconButton
              danger
              onClick={onDeleteGroup}
              ariaLabel={intl.formatMessage({ id: "servers.delete_group_aria" })}
              title={intl.formatMessage({ id: "servers.delete_group_title" })}
            >
              <Trash2 size={14} strokeWidth={2.2} />
            </IconButton>
          </div>
        )}
      </div>
      {expanded && (
        bucket.profiles.length === 0 ? (
          <p className="dim" style={{ padding: "0.75rem 1rem", margin: 0 }}>
            <small>
              <FormattedMessage id="servers.no_servers_in_group" />
            </small>
          </p>
        ) : (
          sorted.map((p) => (
            <ServerRow
              key={p.id}
              profile={p}
              isActive={activeId === p.id}
              latency={latency[p.id]}
              onSelect={() => onSelect(p)}
              onDelete={() => onDelete(p.id)}
            />
          ))
        )
      )}
    </div>
  );
}

/// Tiny CSS triangle so we don't pull in another lucide icon for one
/// place. Rotates 90° when expanded — same convention as macOS Finder
/// disclosure triangles.
function Chevron({ expanded }: { expanded: boolean }) {
  return (
    <span
      aria-hidden
      style={{
        display: "inline-block",
        width: 0,
        height: 0,
        borderTop: "5px solid transparent",
        borderBottom: "5px solid transparent",
        borderLeft: "6px solid var(--fg-2)",
        transform: expanded ? "rotate(90deg)" : "rotate(0deg)",
        transformOrigin: "3px 5px",
        transition: "transform 120ms ease",
        marginRight: "0.15rem",
      }}
    />
  );
}

function ModeToggle({
  value,
  onChange,
}: {
  value: "manual" | "auto";
  onChange: (mode: "manual" | "auto") => void;
}) {
  const intl = useIntl();
  return (
    <div
      className="row"
      role="radiogroup"
      aria-label={intl.formatMessage({ id: "servers.mode.aria" })}
      style={{
        gap: 0,
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm, 6px)",
        overflow: "hidden",
      }}
    >
      <ModeButton
        active={value === "manual"}
        label={intl.formatMessage({ id: "servers.mode.manual" })}
        title={intl.formatMessage({ id: "servers.mode.manual_help" })}
        onClick={() => onChange("manual")}
      />
      <ModeButton
        active={value === "auto"}
        label={intl.formatMessage({ id: "servers.mode.auto" })}
        title={intl.formatMessage({ id: "servers.mode.auto_help" })}
        onClick={() => onChange("auto")}
      />
    </div>
  );
}

function ModeButton({
  active,
  label,
  title,
  onClick,
}: {
  active: boolean;
  label: string;
  title: string;
  onClick: () => void;
}) {
  return (
    <button
      role="radio"
      aria-checked={active}
      onClick={onClick}
      title={title}
      style={{
        padding: "0.25rem 0.65rem",
        background: active
          ? "var(--accent-grad-soft, rgba(79, 138, 255, 0.18))"
          : "transparent",
        color: active ? "var(--fg)" : "var(--fg-2)",
        border: "none",
        borderRadius: 0,
        fontSize: "0.85em",
        cursor: "pointer",
      }}
    >
      {label}
    </button>
  );
}

function ServerRow({
  profile,
  isActive,
  latency,
  onSelect,
  onDelete,
}: {
  profile: Profile;
  isActive: boolean;
  latency: Latency | undefined;
  onSelect: () => void;
  onDelete: () => void;
}) {
  const intl = useIntl();
  return (
    <div
      className="row"
      style={{
        justifyContent: "space-between",
        alignItems: "center",
        padding: "0.75rem 1rem",
        borderTop: "1px solid var(--border)",
        background: isActive ? "rgba(47, 129, 247, 0.08)" : undefined,
        gap: "0.75rem",
      }}
    >
      <div
        onClick={onSelect}
        style={{ flex: 1, cursor: "pointer", minWidth: 0 }}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") onSelect();
        }}
      >
        <div className="row" style={{ gap: "0.5rem", alignItems: "baseline" }}>
          <strong>{profile.name}</strong>
          <span
            className="mono dim"
            style={{
              fontSize: "0.85em",
              padding: "0.1rem 0.4rem",
              borderRadius: "var(--radius)",
              background: "var(--bg-2)",
            }}
          >
            {profile.kind}
          </span>
          {isActive && (
            <span style={{ color: "var(--green)", fontSize: "0.85em" }}>
              <FormattedMessage id="servers.row.active" />
            </span>
          )}
        </div>
        <div className="mono dim" style={{ fontSize: "0.85em", marginTop: "0.2rem" }}>
          {profile.address}:{profile.port}
        </div>
      </div>
      <div className="row" style={{ gap: "0.6rem", alignItems: "center" }}>
        <PingPill latency={latency} />
        <Link to={`/servers/${profile.id}`}>
          <button>
            <FormattedMessage id="servers.row.edit" />
          </button>
        </Link>
        <IconButton
          danger
          onClick={onDelete}
          ariaLabel={intl.formatMessage({ id: "servers.delete_server_aria" })}
          title={intl.formatMessage({ id: "servers.delete_server_title" })}
        >
          <Trash2 size={14} strokeWidth={2.2} />
        </IconButton>
      </div>
    </div>
  );
}

function PingPill({ latency }: { latency: Latency | undefined }) {
  const intl = useIntl();
  if (latency === undefined) {
    return (
      <span
        className="mono dim"
        style={{ fontSize: "0.85em", minWidth: "4rem", textAlign: "right" }}
      >
        —
      </span>
    );
  }
  if (latency === null) {
    return (
      <span
        className="mono"
        style={{
          fontSize: "0.85em",
          minWidth: "4rem",
          textAlign: "right",
          color: "var(--red)",
        }}
        title={intl.formatMessage({ id: "servers.ping.timeout_title" })}
      >
        <FormattedMessage id="servers.ping.timeout" />
      </span>
    );
  }
  return (
    <span
      className="mono"
      style={{
        fontSize: "0.85em",
        minWidth: "4rem",
        textAlign: "right",
        color: pingColor(latency),
      }}
    >
      <FormattedMessage id="servers.ping.ms" values={{ ms: latency }} />
    </span>
  );
}

function pingColor(ms: number): string {
  if (ms < 100) return "var(--green)";
  if (ms < 300) return "var(--yellow)";
  return "var(--red)";
}

/// Sort: probed servers first (ascending latency), then unprobed,
/// then timeouts. Stable enough that the user's mental model
/// ("fastest at top after probe") holds without surprises.
function sortByLatency(
  profiles: Profile[],
  latency: Record<string, Latency>,
): Profile[] {
  const bucket = (id: string): number => {
    const v = latency[id];
    if (typeof v === "number") return v;
    if (v === undefined) return Number.POSITIVE_INFINITY - 1;
    return Number.POSITIVE_INFINITY; // null = timeout, sinks to bottom
  };
  return [...profiles].sort((a, b) => bucket(a.id) - bucket(b.id));
}

/// Pick the lowest-latency member of `profiles` using `latency` as the
/// score. Ignores entries with no measurement (undefined) and timeouts
/// (null). Returns `null` when no profile has a numeric latency yet —
/// callers must not switch active to a stale guess.
function pickLowestLatency(
  profiles: Profile[],
  latency: Record<string, Latency>,
): Profile | null {
  let best: Profile | null = null;
  let bestMs = Number.POSITIVE_INFINITY;
  for (const p of profiles) {
    const v = latency[p.id];
    if (typeof v !== "number") continue;
    if (v < bestMs) {
      bestMs = v;
      best = p;
    }
  }
  return best;
}
