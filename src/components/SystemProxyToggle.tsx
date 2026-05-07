import { useEffect, useState } from "react";
import type { SystemProxyStatus } from "../lib/ipc";
import { tauri } from "../lib/tauri";

const initial: SystemProxyStatus = {
  enabled: false,
  host: null,
  port: null,
  service: null,
};

export function SystemProxyToggle({ canEnable }: { canEnable: boolean }) {
  const [status, setStatus] = useState<SystemProxyStatus>(initial);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void tauri.systemProxyStatus().then(setStatus).catch(() => {});
    const handle = window.setInterval(
      () => void tauri.systemProxyStatus().then(setStatus).catch(() => {}),
      3000,
    );
    return () => window.clearInterval(handle);
  }, []);

  const onToggle = async () => {
    setBusy(true);
    try {
      const next = status.enabled
        ? await tauri.systemProxyDisable()
        : await tauri.systemProxyEnable();
      setStatus(next);
    } catch (e) {
      alert(
        `System proxy failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setBusy(false);
    }
  };

  const subtitle = status.enabled
    ? `On — ${status.service ?? "active service"} → ${status.host}:${status.port}`
    : "Route every proxy-aware app's traffic through Nexray.";

  return (
    <div
      className="row"
      style={{
        justifyContent: "space-between",
        marginTop: "0.75rem",
        padding: "0.5rem 0",
        borderTop: "1px solid var(--border)",
      }}
    >
      <div>
        <strong>System proxy</strong>
        <span
          className="dim"
          style={{ marginLeft: "0.5rem" }}
          title="Sets the macOS SOCKS proxy to Nexray's listener via networksetup. Most apps (Safari, Chrome, curl) will route through it automatically. Real VPN-style 'Settings → VPN' integration needs an Apple Developer Program membership + Network Extension entitlement; see docs/MACOS_VPN.md."
        >
          ⓘ
        </span>
        <p className="dim" style={{ margin: "0.25rem 0 0" }}>
          <small>{subtitle}</small>
        </p>
      </div>
      <button
        type="button"
        className={status.enabled ? "danger" : "primary"}
        onClick={() => void onToggle()}
        disabled={busy || (!status.enabled && !canEnable)}
      >
        {status.enabled ? "Stop system proxy" : "Start system proxy"}
      </button>
    </div>
  );
}
