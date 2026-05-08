import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { Link } from "react-router-dom";
import { ArrowDown, ArrowUp, Power, RefreshCw } from "lucide-react";
import { StatusPill } from "../components/StatusPill";
import { SystemProxyToggle } from "../components/SystemProxyToggle";
import { TunToggle } from "../components/TunToggle";
import { useConnectionStore } from "../stores/connection";
import { useProfileStore } from "../stores/profile";
import { formatBytes, formatRate } from "../lib/format";
import type { Profile } from "../lib/profile";
import { tauri } from "../lib/tauri";
import type { EgressCheck } from "../lib/ipc";

export function Home() {
  const intl = useIntl();
  const profile = useProfileStore((s) => s.profile);
  const manualProfiles = useProfileStore((s) => s.manualProfiles);
  const setActiveById = useProfileStore((s) => s.setActiveById);
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
  const connectLabel = intl.formatMessage({
    id: inflight ? "home.connecting" : "home.connect",
  });
  const disconnectLabel = intl.formatMessage({
    id: busy ? "home.disconnecting" : "home.disconnect",
  });

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
          <>
            {manualProfiles.length > 1 ? (
              <div
                className="row"
                style={{
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginTop: "0.5rem",
                  gap: "0.5rem",
                }}
              >
                <select
                  value={
                    manualProfiles.some((p) => p.id === profile.id)
                      ? profile.id
                      : "__pool__"
                  }
                  onChange={(e) => {
                    if (e.target.value !== "__pool__") {
                      void setActiveById(e.target.value);
                    }
                  }}
                  style={{ flex: 1, minWidth: 0 }}
                  title={intl.formatMessage({ id: "home.profile.switch_aria" })}
                >
                  {manualProfiles.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} · {p.kind} · {p.address}:{p.port}
                    </option>
                  ))}
                  {!manualProfiles.some((p) => p.id === profile.id) && (
                    <option value="__pool__">
                      {intl.formatMessage(
                        { id: "home.profile.from_pool" },
                        { name: profile.name },
                      )}
                    </option>
                  )}
                </select>
                <Link to="/servers">
                  <small className="dim">
                    <FormattedMessage id="home.profile.manage" />
                  </small>
                </Link>
              </div>
            ) : (
              <p className="muted mono" style={{ marginTop: "0.5rem" }}>
                {summarizeProfile(profile)}
              </p>
            )}
            <ActiveServerStatus
              uiProfile={profile}
              backendProfileId={status.profileId}
              connectionState={status.state}
              socksPort={status.socksPort}
            />
          </>
        ) : (
          <p className="muted">
            <Link to="/servers">
              <FormattedMessage id="home.no_profile" />
            </Link>
          </p>
        )}

        {status.lastError && (
          <div
            className="flash err"
            style={{ marginTop: "0.5rem", marginBottom: "0.5rem" }}
          >
            <strong>
              <FormattedMessage id="home.error.xray_reported" />
            </strong>{" "}
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
              <strong>
                <FormattedMessage id="home.error.connect_failed" />
              </strong>{" "}
              {actionError}
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
              aria-label={intl.formatMessage({ id: "common.dismiss" })}
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
              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 8 }}
            >
              <Power size={16} strokeWidth={2.5} />
              {disconnectLabel}
            </button>
          ) : (
            <button
              type="button"
              className="bigbtn primary"
              onClick={handleConnect}
              disabled={inflight}
              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 8 }}
            >
              <Power size={16} strokeWidth={2.5} />
              {connectLabel}
            </button>
          ))}

        <SystemProxyToggle canEnable={isLive} />
        <TunToggle canEnable={isLive} />
      </div>

      <div className="card">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "1.5rem",
          }}
        >
          <SpeedColumn
            label={<FormattedMessage id="home.uplink" />}
            icon={<ArrowUp size={13} strokeWidth={2.5} />}
            rate={spark.up[spark.up.length - 1] ?? 0}
            total={stats.uplinkBytes}
            color="var(--accent)"
          />
          <SpeedColumn
            label={<FormattedMessage id="home.downlink" />}
            icon={<ArrowDown size={13} strokeWidth={2.5} />}
            rate={spark.down[spark.down.length - 1] ?? 0}
            total={stats.downlinkBytes}
            color="var(--green)"
          />
        </div>

        {!stats.available && isLive && (
          <p
            className="dim"
            style={{ margin: "1rem 0 0", textAlign: "center" }}
          >
            <small>
              <FormattedMessage id="home.stats.unavailable" />
            </small>
          </p>
        )}
      </div>

      {profile && (
        <EgressCheckCard
          isLive={status.state === "connected"}
          activeProfileId={profile.id}
          backendProfileId={status.profileId}
        />
      )}
    </>
  );
}

function summarizeProfile(p: Profile): string {
  const endpoint = `${p.address}:${p.port}`;
  return `${p.kind} · ${endpoint}`;
}

/// One half of the Up/Down speed card. Shows a small uppercase label, a
/// hero current-rate number, and the cumulative byte total below.
function SpeedColumn({
  label,
  icon,
  rate,
  total,
  color,
}: {
  label: ReactNode;
  icon: ReactNode;
  rate: number;
  total: number;
  color: string;
}) {
  return (
    <div style={{ minWidth: 0 }}>
      <div
        className="row"
        style={{
          alignItems: "center",
          gap: 6,
          color: "var(--fg-2)",
        }}
      >
        <span style={{ display: "inline-flex", color }}>{icon}</span>
        <span
          style={{
            textTransform: "uppercase",
            fontSize: "0.7rem",
            letterSpacing: "0.12em",
            fontWeight: 600,
          }}
        >
          {label}
        </span>
      </div>
      <div
        className="mono"
        style={{
          fontSize: "1.55rem",
          fontWeight: 600,
          color,
          marginTop: "0.35rem",
          lineHeight: 1.1,
          letterSpacing: "-0.01em",
          // Tabular-nums keeps the digit columns from jiggling as the
          // value changes once per second.
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {formatRate(rate)}
      </div>
      <div
        className="dim mono"
        style={{
          fontSize: "0.78rem",
          marginTop: "0.45rem",
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {formatBytes(total)} <FormattedMessage id="home.stats.total_suffix" />
      </div>
    </div>
  );
}

/// Shows whether the running xray's outbound actually points at the
/// currently-selected profile. The connection store exposes the backend's
/// `profile_id` (set when xray was last spawned/restarted) — if that
/// matches the UI's active id, we're routing through the chosen server.
function ActiveServerStatus({
  uiProfile,
  backendProfileId,
  connectionState,
  socksPort,
}: {
  uiProfile: Profile;
  backendProfileId: string | null;
  connectionState: string;
  socksPort: number | null;
}) {
  if (connectionState === "connecting") {
    return (
      <p className="dim mono" style={{ marginTop: "0.4rem", fontSize: "0.85em" }}>
        <span style={{ color: "var(--yellow)" }}>● </span>
        <FormattedMessage
          id="home.profile.switching"
          values={{ address: uiProfile.address, port: uiProfile.port }}
        />
      </p>
    );
  }
  if (connectionState !== "connected") {
    return (
      <p className="dim mono" style={{ marginTop: "0.4rem", fontSize: "0.85em" }}>
        <FormattedMessage
          id="home.profile.connect_to_route"
          values={{ address: uiProfile.address, port: uiProfile.port }}
        />
      </p>
    );
  }
  const inSync = backendProfileId === uiProfile.id;
  return (
    <p
      className="mono"
      style={{
        marginTop: "0.4rem",
        fontSize: "0.85em",
        color: inSync ? "var(--green)" : "var(--yellow)",
      }}
    >
      ●{" "}
      {inSync ? (
        <FormattedMessage
          id="home.profile.live_on"
          values={{
            address: uiProfile.address,
            port: uiProfile.port,
            // Loopback by design (DEVELOPMENT.md §12 rule 6 — the SOCKS
            // listener never binds anything other than 127.0.0.1).
            proxyHost: "127.0.0.1",
            proxyPort: socksPort ?? "—",
          }}
        />
      ) : (
        <FormattedMessage id="home.profile.reconnecting" />
      )}
    </p>
  );
}

/// Egress-check panel. Calls `egress_check` (which proxies an HTTPS GET
/// through the running xray to ifconfig.me) and shows the IP, with a
/// short history so the user can see when the egress changes after a
/// server switch — even when both servers share a CDN front and the
/// difference lives in a /48 prefix.
function EgressCheckCard({
  isLive,
  activeProfileId,
  backendProfileId,
}: {
  isLive: boolean;
  activeProfileId: string;
  backendProfileId: string | null;
}) {
  const [current, setCurrent] = useState<EgressCheck | null>(null);
  const [history, setHistory] = useState<{ ip: string; at: number }[]>([]);
  const [busy, setBusy] = useState(false);
  // Track the last (live, profileId) we successfully checked against, so
  // we don't re-fire on every render.
  const lastChecked = useRef<string | null>(null);
  // Cancellation handle so an in-flight retry chain can be aborted when
  // the user clicks Refresh manually or the connection drops.
  const cancelRef = useRef<{ cancelled: boolean } | null>(null);

  const recordResult = (r: EgressCheck) => {
    setCurrent(r);
    if (r.ok && r.ip) {
      setHistory((prev) => {
        const last = prev[0];
        if (last && last.ip === r.ip) return prev;
        return [{ ip: r.ip!, at: Date.now() }, ...prev].slice(0, 5);
      });
    }
  };

  // Single attempt — used by the manual Refresh button. The user
  // clicked; cancel any in-flight auto-retry and run one shot, surfacing
  // the actual error if it fails.
  const runCheck = async () => {
    if (cancelRef.current) cancelRef.current.cancelled = true;
    setBusy(true);
    try {
      recordResult(await tauri.egressCheck());
    } finally {
      setBusy(false);
    }
  };

  // Auto-run with backoff. xray's upstream TLS handshake to the VLESS
  // server takes 1-3s after the supervisor flips to `connected` — the
  // first egress check often races that and reports "request: error
  // sending request". Retry a few times so the user sees the IP without
  // having to click Refresh.
  const runAutoCheck = async () => {
    if (cancelRef.current) cancelRef.current.cancelled = true;
    const token = { cancelled: false };
    cancelRef.current = token;
    setBusy(true);
    try {
      // Schedule: try now, then 700ms, 2s, 4s. Stop on first success or
      // when cancelled (manual Refresh / disconnect / profile change).
      const delaysMs: number[] = [0, 700, 2000, 4000];
      for (const delay of delaysMs) {
        if (token.cancelled) return;
        if (delay > 0) {
          await new Promise<void>((resolve) =>
            window.setTimeout(resolve, delay),
          );
          if (token.cancelled) return;
        }
        const r = await tauri.egressCheck();
        if (token.cancelled) return;
        if (r.ok) {
          recordResult(r);
          return;
        }
        // Surface the most recent error so the panel doesn't look empty
        // mid-retry. Final attempt's error is what the user sees if all
        // retries fail.
        recordResult(r);
      }
    } finally {
      if (!token.cancelled) setBusy(false);
    }
  };

  // Auto-run when we're live AND the backend matches the UI selection
  // (so the check actually probes the chosen server), and the
  // (state, backend profile) tuple has changed since last run.
  useEffect(() => {
    if (!isLive || backendProfileId !== activeProfileId) return;
    const key = `${activeProfileId}@${backendProfileId}`;
    if (lastChecked.current === key) return;
    lastChecked.current = key;
    void runAutoCheck();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLive, activeProfileId, backendProfileId]);

  // Reset history when we go offline so a stale IP doesn't masquerade as
  // the current egress, and cancel any in-flight retry chain.
  useEffect(() => {
    if (!isLive) {
      if (cancelRef.current) cancelRef.current.cancelled = true;
      setCurrent(null);
      setBusy(false);
      lastChecked.current = null;
    }
  }, [isLive]);

  return (
    <div className="card">
      <div
        className="row"
        style={{ justifyContent: "space-between", alignItems: "baseline" }}
      >
        <strong>
          <FormattedMessage id="home.egress.heading" />
        </strong>
        <button
          onClick={() => void runCheck()}
          disabled={!isLive || busy}
          style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
        >
          <RefreshCw size={13} strokeWidth={2.4} className={busy ? "spin" : undefined} />
          <FormattedMessage
            id={busy ? "home.egress.checking" : "home.egress.refresh"}
          />
        </button>
      </div>
      <p className="dim" style={{ margin: "0.3rem 0 0.6rem" }}>
        <small>
          <FormattedMessage id="home.egress.help" />
        </small>
      </p>
      {!isLive ? (
        <p className="dim mono">
          <small>
            <FormattedMessage id="home.egress.placeholder_offline" />
          </small>
        </p>
      ) : current === null ? (
        <p className="dim mono">
          <small>
            {busy ? <FormattedMessage id="home.egress.checking" /> : "—"}
          </small>
        </p>
      ) : current.ok ? (
        <>
          <div
            className="mono"
            style={{
              fontSize: "1.1em",
              color: "var(--green)",
              wordBreak: "break-all",
            }}
          >
            {current.ip}
            {current.elapsedMs !== null && (
              <span className="dim" style={{ marginLeft: "0.5rem", fontSize: "0.8em" }}>
                ({current.elapsedMs} ms)
              </span>
            )}
          </div>
          {history.length > 1 && (
            <details style={{ marginTop: "0.5rem" }}>
              <summary className="dim" style={{ cursor: "pointer" }}>
                <small>
                  <FormattedMessage
                    id="home.egress.last_n"
                    values={{ n: history.length }}
                  />
                </small>
              </summary>
              <ul
                className="mono"
                style={{
                  margin: "0.4rem 0 0",
                  paddingLeft: "1.25rem",
                  fontSize: "0.85em",
                }}
              >
                {history.map((h, i) => (
                  <li key={`${h.at}-${h.ip}`} style={{ color: i === 0 ? "var(--fg)" : "var(--fg-2)" }}>
                    {h.ip}
                    <span className="dim" style={{ marginLeft: "0.5rem" }}>
                      {new Date(h.at).toLocaleTimeString()}
                    </span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      ) : (
        <div className="mono" style={{ color: "var(--yellow)", wordBreak: "break-all" }}>
          {current.error ?? <FormattedMessage id="home.egress.fail" />}
        </div>
      )}
    </div>
  );
}
