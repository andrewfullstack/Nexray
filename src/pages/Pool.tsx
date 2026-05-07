import { useEffect, useMemo, useState } from "react";
import { FormattedMessage } from "react-intl";
import { useProfileStore } from "../stores/profile";
import { useSubscriptionsStore } from "../stores/subscriptions";
import type { PoolEntry } from "../lib/ipc";

type Sort = "ping-asc" | "name" | "kind";

export function Pool() {
  const { pool, refresh, probeAll } = useSubscriptionsStore();
  const setProfile = useProfileStore((s) => s.set);
  const activeProfile = useProfileStore((s) => s.profile);
  const [sort, setSort] = useState<Sort>("ping-asc");
  const [probing, setProbing] = useState(false);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const sorted = useMemo(() => sortPool(pool, sort), [pool, sort]);

  const handleProbe = async () => {
    setProbing(true);
    try {
      await probeAll();
    } finally {
      setProbing(false);
    }
  };

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0 }}>
          <FormattedMessage id="pool.heading" defaultMessage="Server pool" />
        </h2>
        <div className="row">
          <select value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
            <option value="ping-asc">Sort: lowest ping</option>
            <option value="name">Sort: subscription</option>
            <option value="kind">Sort: kind</option>
          </select>
          <button onClick={() => void handleProbe()} disabled={probing}>
            {probing ? "Probing…" : "Probe latency"}
          </button>
        </div>
      </div>

      {pool.length === 0 ? (
        <p className="dim" style={{ marginTop: "1rem" }}>
          The pool is empty. Add a subscription on the Subscriptions tab.
        </p>
      ) : (
        <table className="mono" style={{ width: "100%", marginTop: "1rem", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th style={{ padding: "0.4rem 0.6rem" }}>kind</th>
              <th style={{ padding: "0.4rem 0.6rem" }}>name</th>
              <th style={{ padding: "0.4rem 0.6rem" }}>endpoint</th>
              <th style={{ padding: "0.4rem 0.6rem" }}>sub</th>
              <th style={{ padding: "0.4rem 0.6rem", textAlign: "right" }}>ping</th>
              <th style={{ padding: "0.4rem 0.6rem" }}></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((entry) => {
              const isActive = activeProfile?.id === entry.profile.id;
              return (
                <tr
                  key={`${entry.subscriptionId}-${entry.profile.id}`}
                  style={{
                    borderTop: "1px solid var(--border)",
                    background: isActive ? "rgba(47, 129, 247, 0.08)" : undefined,
                  }}
                >
                  <td style={{ padding: "0.4rem 0.6rem" }}>{entry.profile.kind}</td>
                  <td style={{ padding: "0.4rem 0.6rem" }}>{entry.profile.name}</td>
                  <td style={{ padding: "0.4rem 0.6rem" }}>
                    {entry.profile.address}:{entry.profile.port}
                  </td>
                  <td style={{ padding: "0.4rem 0.6rem", color: "var(--fg-2)" }}>
                    {entry.subscriptionName}
                  </td>
                  <td style={{ padding: "0.4rem 0.6rem", textAlign: "right" }}>
                    {entry.latencyMs === null ? (
                      <span className="dim">—</span>
                    ) : (
                      <span style={{ color: pingColor(entry.latencyMs) }}>
                        {entry.latencyMs} ms
                      </span>
                    )}
                  </td>
                  <td style={{ padding: "0.4rem 0.6rem" }}>
                    <button
                      onClick={() => void setProfile(entry.profile)}
                      disabled={isActive}
                    >
                      {isActive ? "Active" : "Use"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function sortPool(pool: PoolEntry[], sort: Sort): PoolEntry[] {
  const copy = [...pool];
  switch (sort) {
    case "ping-asc":
      copy.sort((a, b) => {
        const av = a.latencyMs ?? Number.POSITIVE_INFINITY;
        const bv = b.latencyMs ?? Number.POSITIVE_INFINITY;
        return av - bv;
      });
      break;
    case "name":
      copy.sort((a, b) =>
        a.subscriptionName.localeCompare(b.subscriptionName) ||
        a.profile.name.localeCompare(b.profile.name),
      );
      break;
    case "kind":
      copy.sort((a, b) => a.profile.kind.localeCompare(b.profile.kind));
      break;
  }
  return copy;
}

function pingColor(ms: number): string {
  if (ms < 100) return "var(--green)";
  if (ms < 300) return "var(--yellow)";
  return "var(--red)";
}
