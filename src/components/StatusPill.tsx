import { FormattedMessage } from "react-intl";
import type { ConnectionState } from "../lib/ipc";

const LABEL_ID: Record<ConnectionState, string> = {
  disconnected: "status.disconnected",
  connecting: "status.connecting",
  connected: "status.connected",
  crashed: "status.crashed",
};

export function StatusPill({ state }: { state: ConnectionState }) {
  return (
    <span className={`pill ${state}`}>
      <span className="dot" />
      <FormattedMessage id={LABEL_ID[state]} />
    </span>
  );
}
