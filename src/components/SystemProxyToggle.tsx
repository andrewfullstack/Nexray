import { useEffect, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import type { SystemProxyStatus } from "../lib/ipc";
import { tauri } from "../lib/tauri";
import { useTunStore } from "../stores/tun";
import { InfoTip } from "./InfoTip";

const initial: SystemProxyStatus = {
  enabled: false,
  host: null,
  port: null,
  service: null,
};

export function SystemProxyToggle({ canEnable }: { canEnable: boolean }) {
  const intl = useIntl();
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
      if (status.enabled) {
        const next = await tauri.systemProxyDisable();
        setStatus(next);
        return;
      }
      // Mutual exclusion with TUN: if TUN is currently capturing all
      // system traffic at the IP layer, also pointing OS-level apps at
      // the SOCKS listener double-routes them (proxy-aware app → SOCKS →
      // xray, AND its packets go through utun → tun2socks → xray
      // anyway). Tear TUN down first.
      const tun = useTunStore.getState();
      if (tun.status.state === "active" || tun.status.state === "starting") {
        try {
          await tun.disable();
        } catch (e) {
          console.warn("could not disable TUN before system proxy:", e);
        }
      }
      const next = await tauri.systemProxyEnable();
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
    ? intl.formatMessage(
        { id: "systemproxy.subtitle_active" },
        {
          service:
            status.service ??
            intl.formatMessage({ id: "systemproxy.active_service_default" }),
          host: status.host ?? "",
          port: status.port ?? "",
        },
      )
    : intl.formatMessage({ id: "systemproxy.subtitle_off" });

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
        <strong>
          <FormattedMessage id="systemproxy.heading" />
        </strong>
        <span style={{ marginLeft: "0.4rem" }}>
          <InfoTip>
            <p className="heading">System proxy</p>
            <p>
              Points the operating system&rsquo;s SOCKS5 proxy setting at
              Nexray&rsquo;s loopback listener. Most proxy-aware apps
              (browsers, curl, package managers) automatically pick it up.
            </p>
            <p className="heading">Per platform</p>
            <ul>
              <li>
                <strong>macOS</strong>: writes via <code>networksetup</code>{" "}
                on the active network service.
              </li>
              <li>
                <strong>Windows</strong>: sets the WinINet proxy registry +
                broadcasts <code>InternetSetOptionW</code> so running apps
                pick it up immediately.
              </li>
              <li>
                <strong>Linux</strong>: writes the GNOME{" "}
                <code>org.gnome.system.proxy</code> keys via{" "}
                <code>gsettings</code>.
              </li>
            </ul>
            <p className="heading">Caveats</p>
            <ul>
              <li>
                Apps that ignore system proxy (games, custom DNS clients,
                native binaries) won&rsquo;t be routed — use TUN mode for
                whole-system capture.
              </li>
              <li>
                Settings restore automatically on app exit.
              </li>
            </ul>
          </InfoTip>
        </span>
        <p className="dim" style={{ margin: "0.25rem 0 0" }}>
          <small>{subtitle}</small>
        </p>
      </div>
      <button
        type="button"
        className={`toggle-btn ${status.enabled ? "danger" : "primary"}`}
        onClick={() => void onToggle()}
        disabled={busy || (!status.enabled && !canEnable)}
      >
        <FormattedMessage
          id={status.enabled ? "systemproxy.stop" : "systemproxy.start"}
        />
      </button>
    </div>
  );
}
