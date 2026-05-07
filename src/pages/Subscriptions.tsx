import { useEffect, useState } from "react";
import { FormattedMessage } from "react-intl";
import { useSubscriptionsStore } from "../stores/subscriptions";

export function Subscriptions() {
  const { subs, error, loading, refresh, add, remove, refreshOne } = useSubscriptionsStore();
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setBusy(true);
    try {
      await add({ url: url.trim(), ...(name.trim() ? { name: name.trim() } : {}) });
      setUrl("");
      setName("");
    } catch {
      /* error already in the store */
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="card">
        <h2 style={{ marginTop: 0 }}>
          <FormattedMessage
            id="subscriptions.heading"
            defaultMessage="Subscriptions"
          />
        </h2>
        <form onSubmit={handleAdd}>
          <div className="field">
            <label className="label" htmlFor="sub-url">
              Subscription URL (https://)
            </label>
            <input
              id="sub-url"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://your-airport.example/sub"
              autoComplete="off"
            />
          </div>
          <div className="field">
            <label className="label" htmlFor="sub-name">
              Name (optional)
            </label>
            <input
              id="sub-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="my airport"
              autoComplete="off"
            />
          </div>
          <button type="submit" className="primary" disabled={busy || !url.trim()}>
            {busy ? "Adding…" : "Add subscription"}
          </button>
          {error && <div className="flash err">{error}</div>}
        </form>
      </div>

      {loading && <p className="dim">Loading…</p>}
      {!loading && subs.length === 0 && (
        <p className="dim">No subscriptions yet. Add one above.</p>
      )}

      {subs.map((s) => (
        <div className="card" key={s.id}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <strong>{s.name}</strong>
            <div className="row">
              <button onClick={() => void refreshOne(s.id)}>Refresh</button>
              <button className="danger" onClick={() => void remove(s.id)}>
                Delete
              </button>
            </div>
          </div>
          <p className="muted mono" style={{ wordBreak: "break-all", margin: "0.4rem 0" }}>
            {s.url}
          </p>
          <div className="row" style={{ gap: "1.5rem", flexWrap: "wrap" }}>
            <span className="muted">
              <strong>Accepted:</strong> {s.acceptedCount}
            </span>
            <span className="muted">
              <strong>Skipped:</strong> {s.skippedCount}
            </span>
            <span className="dim">
              {s.lastFetchedMs
                ? `Fetched ${formatRelative(s.lastFetchedMs)}`
                : "Not fetched yet"}
            </span>
          </div>
          {s.skippedSummary && (
            <p className="dim mono" style={{ marginTop: "0.5rem" }}>
              <small>{s.skippedSummary}</small>
            </p>
          )}
          {s.lastFetchError && (
            <div className="flash err" style={{ marginTop: "0.5rem" }}>
              Last refresh failed: {s.lastFetchError}
            </div>
          )}
        </div>
      ))}
    </>
  );
}

function formatRelative(ms: number): string {
  const delta = Date.now() - ms;
  if (delta < 60_000) return "just now";
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h ago`;
  return new Date(ms).toLocaleString();
}
