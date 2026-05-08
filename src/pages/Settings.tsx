import { useEffect } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { useSettingsStore } from "../stores/settings";
import { useLocaleStore } from "../stores/locale";
import { LOCALE_LABELS, LOCALES, type Locale } from "../messages/catalogs";

export function Settings() {
  const { settings, info, loading, error, hydrate, setAutoUpdate } =
    useSettingsStore();
  const locale = useLocaleStore((s) => s.locale);
  const setLocale = useLocaleStore((s) => s.setLocale);
  const intl = useIntl();

  useEffect(() => {
    void hydrate();
  }, [hydrate]);

  if (loading)
    return (
      <p className="dim">
        <FormattedMessage id="settings.loading" />
      </p>
    );

  return (
    <>
      <div className="card">
        <h2 style={{ marginTop: 0 }}>
          <FormattedMessage id="settings.heading" />
        </h2>

        <LanguageRow
          label={intl.formatMessage({ id: "settings.language" })}
          help={intl.formatMessage({ id: "settings.language_help" })}
          value={locale}
          onChange={(next) => void setLocale(next)}
        />

        <Toggle
          label={intl.formatMessage({ id: "settings.auto_update" })}
          on={settings.autoUpdateOptIn}
          onChange={(v) => void setAutoUpdate(v)}
          help={intl.formatMessage({ id: "settings.auto_update_help" })}
        />

        {error && <div className="flash err">{error}</div>}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>
          <FormattedMessage id="settings.about" />
        </h3>
        <dl
          className="mono"
          style={{
            display: "grid",
            gap: "0.4rem 1.5rem",
            gridTemplateColumns: "max-content 1fr",
            margin: 0,
          }}
        >
          <Field
            label={intl.formatMessage({ id: "settings.field.name" })}
            value={info?.name ?? "—"}
          />
          <Field
            label={intl.formatMessage({ id: "settings.field.version" })}
            value={info?.version ?? "—"}
          />
          <Field
            label={intl.formatMessage({ id: "settings.field.platform" })}
            value={info?.platform ?? "—"}
          />
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

function LanguageRow({
  label,
  help,
  value,
  onChange,
}: {
  label: string;
  help: string;
  value: Locale;
  onChange: (next: Locale) => void;
}) {
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
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as Locale)}
        style={{ width: "auto" }}
        aria-label={label}
      >
        {LOCALES.map((loc) => (
          <option key={loc} value={loc}>
            {LOCALE_LABELS[loc]}
          </option>
        ))}
      </select>
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
