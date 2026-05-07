import { useEffect } from "react";
import { useSettingsStore } from "../stores/settings";

export function Settings() {
  const { settings, info, loading, error, hydrate, setAutoUpdate } =
    useSettingsStore();

  useEffect(() => {
    void hydrate();
  }, [hydrate]);

  if (loading) return <p className="dim">Loading…</p>;

  return (
    <>
      <div className="card">
        <h2 style={{ marginTop: 0 }}>Settings</h2>

        <Toggle
          label="Auto-update"
          on={settings.autoUpdateOptIn}
          onChange={(v) => void setAutoUpdate(v)}
          help="Check for new releases on startup and prompt to install. Off by default; the app never phones home unless you enable this."
        />

        {error && <div className="flash err">{error}</div>}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>About</h3>
        <dl
          className="mono"
          style={{
            display: "grid",
            gap: "0.4rem 1.5rem",
            gridTemplateColumns: "max-content 1fr",
            margin: 0,
          }}
        >
          <Field label="Name" value={info?.name ?? "—"} />
          <Field label="Version" value={info?.version ?? "—"} />
          <Field label="Platform" value={info?.platform ?? "—"} />
        </dl>
      </div>
    </>
  );
}

interface ToggleProps {
  label: string;
  help: string;
  on: boolean;
  onChange: (v: boolean) => void;
}

function Toggle({ label, help, on, onChange }: ToggleProps) {
  return (
    <div
      className="row"
      style={{
        justifyContent: "space-between",
        alignItems: "flex-start",
        padding: "0.85rem 0",
        borderTop: "1px solid var(--border)",
      }}
    >
      <div style={{ paddingRight: "1rem" }}>
        <strong>{label}</strong>
        <p className="dim" style={{ margin: "0.25rem 0 0" }}>
          <small>{help}</small>
        </p>
      </div>
      <input
        type="checkbox"
        checked={on}
        onChange={(e) => onChange(e.target.checked)}
        style={{ width: "auto" }}
      />
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="muted" style={{ margin: 0 }}>
        {label}
      </dt>
      <dd className="mono" style={{ margin: 0, wordBreak: "break-all" }}>
        {value}
      </dd>
    </>
  );
}
