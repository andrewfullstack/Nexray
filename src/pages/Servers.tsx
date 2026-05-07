import { useState } from "react";
import { Link } from "react-router-dom";
import { useProfileStore } from "../stores/profile";
import { tauri } from "../lib/tauri";
import type { Profile } from "../lib/profile";

type Latency = number | null;

export function Servers() {
  const profiles = useProfileStore((s) => s.manualProfiles);
  const active = useProfileStore((s) => s.active);
  const setActive = useProfileStore((s) => s.setActive);
  const remove = useProfileStore((s) => s.remove);
  const loading = useProfileStore((s) => s.loading);
  // Per-profile latency cache, keyed by profile id. `undefined` = never
  // probed; `null` = probed and timed out; number = ms.
  const [latency, setLatency] = useState<Record<string, Latency>>({});
  const [probing, setProbing] = useState(false);

  const handleDelete = (id: string, name: string) => {
    if (!window.confirm(`Delete "${name}"?`)) return;
    void remove(id);
    setLatency((prev) => {
      const { [id]: _omit, ...rest } = prev;
      return rest;
    });
  };

  const handleProbe = async () => {
    if (probing || profiles.length === 0) return;
    setProbing(true);
    try {
      const results = await tauri.probeProfiles(profiles);
      setLatency((prev) => {
        const next = { ...prev };
        for (const r of results) next[r.profileId] = r.latencyMs;
        return next;
      });
    } finally {
      setProbing(false);
    }
  };

  if (loading) return <p className="dim">Loading servers…</p>;

  const sorted = sortByLatency(profiles, latency);

  return (
    <>
      <div className="card">
        <div
          className="row"
          style={{ justifyContent: "space-between", alignItems: "center" }}
        >
          <h2 style={{ margin: 0 }}>Servers</h2>
          <div className="row" style={{ gap: "0.5rem" }}>
            <button
              onClick={() => void handleProbe()}
              disabled={probing || profiles.length === 0}
              title="TCP-connect to each server's address:port and report the round-trip latency."
            >
              {probing ? "Probing…" : "Probe latency"}
            </button>
            <Link to="/servers/new">
              <button className="primary">+ Add server</button>
            </Link>
          </div>
        </div>
        <p className="dim" style={{ margin: "0.4rem 0 0" }}>
          <small>
            Manually-saved profiles. Click a row to make it active. Probe
            latency runs a TCP-connect test (no traffic through the proxy)
            so you can pick the closest server before connecting.
          </small>
        </p>
      </div>

      {profiles.length === 0 ? (
        <div className="card">
          <p className="dim">
            No saved servers yet.{" "}
            <Link to="/servers/new">Add your first one</Link>.
          </p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          {sorted.map((p) => (
            <ServerRow
              key={p.id}
              profile={p}
              isActive={active?.id === p.id}
              latency={latency[p.id]}
              onSelect={() => void setActive(p)}
              onDelete={() => handleDelete(p.id, p.name)}
            />
          ))}
        </div>
      )}
    </>
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
            <span style={{ color: "var(--accent)", fontSize: "0.85em" }}>
              ● active
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
          <button>Edit</button>
        </Link>
        <button className="danger" onClick={onDelete}>
          Delete
        </button>
      </div>
    </div>
  );
}

function PingPill({ latency }: { latency: Latency | undefined }) {
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
        title="TCP connect timed out or DNS failed"
      >
        timeout
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
      {latency} ms
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
