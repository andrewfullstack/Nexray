import { FormattedMessage, useIntl } from "react-intl";
import { Link } from "react-router-dom";
import { StatusPill } from "../components/StatusPill";
import { SystemProxyToggle } from "../components/SystemProxyToggle";
import { TrafficSparkline } from "../components/TrafficSparkline";
import { TunToggle } from "../components/TunToggle";
import { useConnectionStore } from "../stores/connection";
import { useProfileStore } from "../stores/profile";
import { formatBytes } from "../lib/format";
import type { Profile } from "../lib/profile";

export function Home() {
  const intl = useIntl();
  const profile = useProfileStore((s) => s.profile);
  const status = useConnectionStore((s) => s.status);
  const stats = useConnectionStore((s) => s.stats);
  const spark = useConnectionStore((s) => s.spark);
  const busy = useConnectionStore((s) => s.busy);
  const actionError = useConnectionStore((s) => s.actionError);
  const clearActionError = useConnectionStore((s) => s.clearActionError);
  const connect = useConnectionStore((s) => s.connect);
  const disconnect = useConnectionStore((s) => s.disconnect);

  // Errors land in the store via the connect/disconnect actions; this
  // handler is just a thin call site so React doesn't need a try/catch.
  const handleConnect = async () => {
    if (!profile) return;
    await connect(profile);
  };
  const handleDisconnect = async () => {
    await disconnect();
  };

  const inflight = busy || status.state === "connecting";
  const isLive = status.state === "connected" || status.state === "connecting";
  const connectLabel = inflight ? "Connecting…" : intl.formatMessage({ id: "home.connect" });
  const disconnectLabel = busy ? "Disconnecting…" : intl.formatMessage({ id: "home.disconnect" });

  return (
    <>
      <div className="card">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>
            <FormattedMessage id="app.title" />
          </h2>
          <StatusPill state={status.state} />
        </div>
        {profile ? (
          <p className="muted mono" style={{ marginTop: "0.5rem" }}>
            {summarizeProfile(profile)}
          </p>
        ) : (
          <p className="muted">
            <Link to="/profile">
              <FormattedMessage id="home.no_profile" />
            </Link>
          </p>
        )}

        {status.lastError && (
          <div
            className="flash err"
            style={{ marginTop: "0.5rem", marginBottom: "0.5rem" }}
          >
            <strong>xray reported:</strong>{" "}
            <span className="mono" style={{ wordBreak: "break-word" }}>
              {status.lastError}
            </span>
          </div>
        )}

        {actionError && (
          <div
            className="flash err"
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-start",
              gap: "0.5rem",
              marginBottom: "0.5rem",
            }}
          >
            <span style={{ flex: 1, wordBreak: "break-word" }}>
              <strong>Connect failed:</strong> {actionError}
            </span>
            <button
              type="button"
              onClick={clearActionError}
              style={{
                background: "transparent",
                border: "none",
                color: "inherit",
                padding: "0 0.25rem",
                cursor: "pointer",
              }}
              aria-label="Dismiss"
            >
              ×
            </button>
          </div>
        )}

        {profile &&
          (isLive ? (
            <button
              type="button"
              className="bigbtn danger"
              onClick={handleDisconnect}
              disabled={busy}
            >
              {disconnectLabel}
            </button>
          ) : (
            <button
              type="button"
              className="bigbtn primary"
              onClick={handleConnect}
              disabled={inflight}
            >
              {connectLabel}
            </button>
          ))}

        <SystemProxyToggle canEnable={isLive} />
        <TunToggle canEnable={isLive} />
      </div>

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <strong>
            <FormattedMessage id="home.uplink" />
          </strong>
          <span className="mono">{formatBytes(stats.uplinkBytes)}</span>
        </div>
        <TrafficSparkline values={spark.up} stroke="var(--accent)" />

        <div
          className="row"
          style={{ justifyContent: "space-between", marginTop: "0.75rem" }}
        >
          <strong>
            <FormattedMessage id="home.downlink" />
          </strong>
          <span className="mono">{formatBytes(stats.downlinkBytes)}</span>
        </div>
        <TrafficSparkline values={spark.down} stroke="var(--green)" />

        {!stats.available && (
          <p className="dim" style={{ marginTop: "0.5rem" }}>
            <small>
              Stats API unreachable — Phase 2.5 will plumb the real
              <code> xray api statsquery</code> output.
            </small>
          </p>
        )}
      </div>
    </>
  );
}

function summarizeProfile(p: Profile): string {
  const endpoint = `${p.address}:${p.port}`;
  return `${p.kind} · ${endpoint}`;
}
