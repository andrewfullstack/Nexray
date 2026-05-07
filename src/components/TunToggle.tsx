import { useEffect } from "react";
import { useTunStore } from "../stores/tun";

export function TunToggle({ canEnable }: { canEnable: boolean }) {
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
      if (isOn) await disable();
      else await enable();
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
        <strong>TUN mode</strong>
        <span
          className="dim"
          style={{ marginLeft: "0.5rem" }}
          title={tunTooltip(supported, capabilities?.reason ?? null, status.state)}
        >
          ⓘ
        </span>
        <p className="dim" style={{ margin: "0.25rem 0 0" }}>
          <small>{tunSubtitle(status, capabilities)}</small>
        </p>
        {status.lastError && status.state === "failed" && (
          <p className="error mono" style={{ margin: "0.25rem 0 0" }}>
            <small>{status.lastError}</small>
          </p>
        )}
      </div>
      <button
        type="button"
        className={isOn ? "danger" : "primary"}
        onClick={() => void handleToggle()}
        disabled={disabled}
      >
        {isOn ? "Stop TUN" : "Start TUN"}
      </button>
    </div>
  );
}

function tunSubtitle(
  status: ReturnType<typeof useTunStore.getState>["status"],
  caps: ReturnType<typeof useTunStore.getState>["capabilities"],
): string {
  if (caps && !caps.supported) return caps.reason ?? "TUN not supported";
  switch (status.state) {
    case "disabled":
      return "Capture all system traffic via the proxy.";
    case "starting":
      return "Starting tun2socks…";
    case "active":
      return `Active on ${status.interfaceName ?? "interface"}.`;
    case "stopping":
      return "Tearing down…";
    case "failed":
      return "Last attempt failed — see error below.";
  }
}

function tunTooltip(
  supported: boolean,
  reason: string | null,
  state: string,
): string {
  const lines: string[] = [];
  lines.push(
    "TUN mode captures every packet from your machine, including UDP and apps that don't honor system proxy settings.",
  );
  lines.push("");
  lines.push("Privilege requirements:");
  lines.push("  · macOS: prompts for sudo to bring up the utun interface.");
  lines.push("  · Windows: triggers UAC; bundles the wintun adapter.");
  lines.push("  · Linux: needs CAP_NET_ADMIN or sudo.");
  if (!supported && reason) {
    lines.push("");
    lines.push(`Currently disabled: ${reason}`);
  }
  if (state === "failed") {
    lines.push("");
    lines.push("If you saw a permissions error, re-run the app with admin rights or grant CAP_NET_ADMIN.");
  }
  return lines.join("\n");
}
