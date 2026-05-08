import { useEffect } from "react";
import { FormattedMessage, useIntl, type IntlShape } from "react-intl";
import { useTunStore } from "../stores/tun";
import { tauri } from "../lib/tauri";
import { InfoTip } from "./InfoTip";

export function TunToggle({ canEnable }: { canEnable: boolean }) {
  const intl = useIntl();
  const { status, capabilities, busy, hydrate, pollStatus, enable, disable } =
    useTunStore();

  useEffect(() => {
    void hydrate();
    const handle = window.setInterval(() => void pollStatus(), 2000);
    return () => window.clearInterval(handle);
  }, [hydrate, pollStatus]);

  const isOn = status.state === "active" || status.state === "starting";
  const supported = capabilities?.supported ?? false;
  const disabled = busy || !supported || (!isOn && !canEnable);

  const handleToggle = async () => {
    try {
      if (isOn) {
        await disable();
        return;
      }
      // Mutual exclusion with system proxy: if it's currently routing
      // OS-level traffic at the SOCKS listener, leaving it on while TUN
      // captures the same traffic at the IP layer creates double-routing
      // (apps point at SOCKS, kernel routes their packets via utun
      // anyway). Tear it down before starting TUN.
      const proxyStatus = await tauri.systemProxyStatus().catch(() => null);
      if (proxyStatus?.enabled) {
        await tauri.systemProxyDisable().catch((e) => {
          console.warn("could not disable system proxy before TUN:", e);
        });
      }
      await enable();
    } catch (e) {
      alert(`TUN failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

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
          <FormattedMessage id="tun.heading" />
        </strong>
        <span style={{ marginLeft: "0.4rem" }}>
          <InfoTip>
            <p className="heading">TUN mode</p>
            <p>
              Captures every packet from your machine — including UDP and
              apps that ignore system proxy settings (games, native
              binaries, custom DNS clients) — and routes it through the
              proxy via a virtual network interface.
            </p>
            <p className="heading">Privilege requirements</p>
            <ul>
              <li>
                <strong>macOS</strong>: prompts for sudo to bring up the{" "}
                <code>utun</code> interface.
              </li>
              <li>
                <strong>Windows</strong>: triggers UAC; bundles the{" "}
                <code>wintun</code> adapter.
              </li>
              <li>
                <strong>Linux</strong>: needs <code>CAP_NET_ADMIN</code> or
                sudo.
              </li>
            </ul>
            {!supported && capabilities?.reason && (
              <>
                <p className="heading">Currently disabled</p>
                <p>{capabilities.reason}</p>
              </>
            )}
            {status.state === "failed" && (
              <>
                <p className="heading">Last attempt failed</p>
                <p>
                  If you saw a permissions error, re-run the app with admin
                  rights or grant <code>CAP_NET_ADMIN</code>.
                </p>
              </>
            )}
          </InfoTip>
        </span>
        <p className="dim" style={{ margin: "0.25rem 0 0" }}>
          <small>{tunSubtitle(intl, status, capabilities)}</small>
        </p>
        {status.lastError && status.state === "failed" && (
          <p className="error mono" style={{ margin: "0.25rem 0 0" }}>
            <small>{status.lastError}</small>
          </p>
        )}
      </div>
      <button
        type="button"
        className={`toggle-btn ${isOn ? "danger" : "primary"}`}
        onClick={() => void handleToggle()}
        disabled={disabled}
      >
        <FormattedMessage id={isOn ? "tun.stop" : "tun.start"} />
      </button>
    </div>
  );
}

function tunSubtitle(
  intl: IntlShape,
  status: ReturnType<typeof useTunStore.getState>["status"],
  caps: ReturnType<typeof useTunStore.getState>["capabilities"],
): string {
  if (caps && !caps.supported)
    return (
      caps.reason ?? intl.formatMessage({ id: "tun.subtitle.unsupported_default" })
    );
  switch (status.state) {
    case "disabled":
      return intl.formatMessage({ id: "tun.subtitle.disabled" });
    case "starting":
      return intl.formatMessage({ id: "tun.subtitle.starting" });
    case "active":
      return intl.formatMessage(
        { id: "tun.subtitle.active" },
        {
          iface:
            status.interfaceName ??
            intl.formatMessage({ id: "tun.subtitle.iface_default" }),
        },
      );
    case "stopping":
      return intl.formatMessage({ id: "tun.subtitle.stopping" });
    case "failed":
      return intl.formatMessage({ id: "tun.subtitle.failed" });
  }
}

