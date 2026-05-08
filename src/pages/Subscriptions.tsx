import { useEffect, useMemo, useState } from "react";
import { FormattedMessage, useIntl, type IntlShape } from "react-intl";
import { RefreshCw, Trash2 } from "lucide-react";
import { IconButton } from "../components/IconButton";
import { useSubscriptionsStore } from "../stores/subscriptions";
import { useProfileStore } from "../stores/profile";
import type { Subscription } from "../lib/ipc";
import type { Profile } from "../lib/profile";

export function Subscriptions() {
  const { subs, error, loading, refresh, add, remove, refreshOne } = useSubscriptionsStore();
  const intl = useIntl();
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
          <FormattedMessage id="subscriptions.heading" />
        </h2>
        <form onSubmit={handleAdd}>
          <div className="field">
            <label className="label" htmlFor="sub-url">
              <FormattedMessage id="subscriptions.url_label" />
            </label>
            <input
              id="sub-url"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={intl.formatMessage({
                id: "subscriptions.url_placeholder",
              })}
              autoComplete="off"
            />
          </div>
          <div className="field">
            <label className="label" htmlFor="sub-name">
              <FormattedMessage id="subscriptions.name_label" />
            </label>
            <input
              id="sub-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={intl.formatMessage({
                id: "subscriptions.name_placeholder",
              })}
              autoComplete="off"
            />
          </div>
          <button type="submit" className="primary" disabled={busy || !url.trim()}>
            <FormattedMessage
              id={busy ? "subscriptions.adding" : "subscriptions.add"}
            />
          </button>
          {error && <div className="flash err">{error}</div>}
        </form>
      </div>

      {loading && (
        <p className="dim">
          <FormattedMessage id="subscriptions.loading" />
        </p>
      )}
      {!loading && subs.length === 0 && (
        <p className="dim">
          <FormattedMessage id="subscriptions.empty" />
        </p>
      )}

      {subs.map((s) => (
        <SubscriptionCard
          key={s.id}
          sub={s}
          onRefresh={() => void refreshOne(s.id)}
          onDelete={() => void remove(s.id)}
        />
      ))}
    </>
  );
}

function SubscriptionCard({
  sub,
  onRefresh,
  onDelete,
}: {
  sub: Subscription;
  onRefresh: () => void;
  onDelete: () => void;
}) {
  const intl = useIntl();
  const manualProfiles = useProfileStore((s) => s.manualProfiles);
  const addProfile = useProfileStore((s) => s.add);
  const setActive = useProfileStore((s) => s.setActive);
  const [expanded, setExpanded] = useState(false);
  const [importing, setImporting] = useState(false);
  // Per-profile flash so the user gets feedback after Import. `"saved"`
  // means it was added in the most recent click; we still show the
  // "already in servers" badge afterwards via the manualProfiles check.
  const [flash, setFlash] = useState<Record<string, "saved" | "exists" | "error">>({});

  const importedIds = useMemo(
    () => new Set(manualProfiles.map((p) => p.id)),
    [manualProfiles],
  );

  const flashFor = (id: string, value: "saved" | "exists" | "error") => {
    setFlash((prev) => ({ ...prev, [id]: value }));
    window.setTimeout(() => {
      setFlash((prev) => {
        if (prev[id] !== value) return prev;
        const { [id]: _omit, ...rest } = prev;
        return rest;
      });
    }, 1800);
  };

  const handleImportOne = async (profile: Profile) => {
    try {
      const added = await addProfile(profile, { subscriptionId: sub.id });
      flashFor(profile.id, added ? "saved" : "exists");
    } catch {
      flashFor(profile.id, "error");
    }
  };

  const handleImportAll = async () => {
    if (importing) return;
    setImporting(true);
    try {
      for (const p of sub.profiles) {
        try {
          const added = await addProfile(p, { subscriptionId: sub.id });
          flashFor(p.id, added ? "saved" : "exists");
        } catch {
          flashFor(p.id, "error");
        }
      }
    } finally {
      setImporting(false);
    }
  };

  const handleUseProfile = async (profile: Profile) => {
    try {
      // Make sure the profile lives in the manual list before activating it,
      // otherwise switching subscriptions away later would orphan the active
      // selection (active points at a pool entry that no longer exists).
      await addProfile(profile, { subscriptionId: sub.id });
      await setActive(profile);
      flashFor(profile.id, "saved");
    } catch {
      flashFor(profile.id, "error");
    }
  };

  const remainingToImport = sub.profiles.filter((p) => !importedIds.has(p.id)).length;

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <strong>{sub.name}</strong>
        <div className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <IconButton
            onClick={onRefresh}
            ariaLabel={intl.formatMessage({ id: "subscriptions.refresh_aria" })}
            title={intl.formatMessage({ id: "subscriptions.refresh_title" })}
          >
            <RefreshCw size={14} strokeWidth={2.2} />
          </IconButton>
          <IconButton
            danger
            onClick={onDelete}
            ariaLabel={intl.formatMessage({ id: "subscriptions.delete_aria" })}
            title={intl.formatMessage({ id: "subscriptions.delete_title" })}
          >
            <Trash2 size={14} strokeWidth={2.2} />
          </IconButton>
        </div>
      </div>
      <p className="muted mono" style={{ wordBreak: "break-all", margin: "0.4rem 0" }}>
        {sub.url}
      </p>
      <div className="row" style={{ gap: "1.5rem", flexWrap: "wrap" }}>
        <span className="muted">
          <strong>
            <FormattedMessage id="subscriptions.accepted_label" />
          </strong>{" "}
          {sub.acceptedCount}
        </span>
        <span className="muted">
          <strong>
            <FormattedMessage id="subscriptions.skipped_label" />
          </strong>{" "}
          {sub.skippedCount}
        </span>
        <span className="dim">
          {sub.lastFetchedMs ? (
            <FormattedMessage
              id="subscriptions.fetched_relative"
              values={{ when: formatRelative(intl, sub.lastFetchedMs) }}
            />
          ) : (
            <FormattedMessage id="subscriptions.not_fetched" />
          )}
        </span>
      </div>
      {sub.skippedSummary && (
        <p className="dim mono" style={{ marginTop: "0.5rem" }}>
          <small>{sub.skippedSummary}</small>
        </p>
      )}
      {sub.lastFetchError && (
        <div className="flash err" style={{ marginTop: "0.5rem" }}>
          <FormattedMessage
            id="subscriptions.refresh_failed"
            values={{ error: sub.lastFetchError }}
          />
        </div>
      )}

      {sub.profiles.length > 0 && (
        <div style={{ marginTop: "0.75rem" }}>
          <div
            className="row"
            style={{
              justifyContent: "space-between",
              alignItems: "center",
              gap: "0.5rem",
              flexWrap: "wrap",
            }}
          >
            <button
              onClick={() => setExpanded((v) => !v)}
              title={intl.formatMessage({
                id: expanded
                  ? "subscriptions.hide_servers_title"
                  : "subscriptions.show_servers_title",
              })}
            >
              <FormattedMessage
                id={
                  expanded
                    ? "subscriptions.hide_servers_button"
                    : "subscriptions.show_servers_button"
                }
                values={{ count: sub.profiles.length }}
              />
            </button>
            <button
              className="primary"
              onClick={() => void handleImportAll()}
              disabled={importing || remainingToImport === 0}
              title={
                remainingToImport === 0
                  ? intl.formatMessage({
                      id: "subscriptions.import_all_title_done",
                    })
                  : intl.formatMessage(
                      { id: "subscriptions.import_all_title" },
                      { count: remainingToImport },
                    )
              }
            >
              {importing ? (
                <FormattedMessage id="subscriptions.importing" />
              ) : remainingToImport === 0 ? (
                <FormattedMessage id="subscriptions.import_all_done" />
              ) : (
                <FormattedMessage
                  id="subscriptions.import_all"
                  values={{ count: remainingToImport }}
                />
              )}
            </button>
          </div>

          {expanded && (
            <div
              style={{
                marginTop: "0.5rem",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm, 6px)",
                overflow: "hidden",
              }}
            >
              {sub.profiles.map((p) => (
                <PoolProfileRow
                  key={p.id}
                  profile={p}
                  alreadyImported={importedIds.has(p.id)}
                  flashState={flash[p.id]}
                  onImport={() => void handleImportOne(p)}
                  onUse={() => void handleUseProfile(p)}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function PoolProfileRow({
  profile,
  alreadyImported,
  flashState,
  onImport,
  onUse,
}: {
  profile: Profile;
  alreadyImported: boolean;
  flashState: "saved" | "exists" | "error" | undefined;
  onImport: () => void;
  onUse: () => void;
}) {
  const intl = useIntl();
  return (
    <div
      className="row"
      style={{
        justifyContent: "space-between",
        alignItems: "center",
        padding: "0.55rem 0.75rem",
        borderTop: "1px solid var(--border)",
        gap: "0.75rem",
      }}
    >
      <div style={{ minWidth: 0, flex: 1 }}>
        <div className="row" style={{ gap: "0.5rem", alignItems: "baseline" }}>
          <strong style={{ wordBreak: "break-word" }}>{profile.name}</strong>
          <span
            className="mono dim"
            style={{
              fontSize: "0.8em",
              padding: "0.1rem 0.4rem",
              borderRadius: "var(--radius-sm, 6px)",
              background: "var(--bg-2, rgba(255,255,255,0.06))",
            }}
          >
            {profile.kind}
          </span>
          {alreadyImported && (
            <span className="dim" style={{ fontSize: "0.8em" }}>
              <FormattedMessage id="subscriptions.in_servers" />
            </span>
          )}
          {flashState === "saved" && (
            <span style={{ color: "var(--green)", fontSize: "0.8em" }}>
              <FormattedMessage id="subscriptions.flash_added" />
            </span>
          )}
          {flashState === "exists" && (
            <span className="dim" style={{ fontSize: "0.8em" }}>
              <FormattedMessage id="subscriptions.flash_exists" />
            </span>
          )}
          {flashState === "error" && (
            <span style={{ color: "var(--red)", fontSize: "0.8em" }}>
              <FormattedMessage id="subscriptions.flash_error" />
            </span>
          )}
        </div>
        <div className="mono dim" style={{ fontSize: "0.8em", marginTop: "0.15rem" }}>
          {profile.address}:{profile.port}
        </div>
      </div>
      <div className="row" style={{ gap: "0.4rem" }}>
        <button
          onClick={onImport}
          disabled={alreadyImported}
          title={intl.formatMessage({
            id: alreadyImported
              ? "subscriptions.import_title_already"
              : "subscriptions.import_title_add",
          })}
        >
          <FormattedMessage
            id={
              alreadyImported
                ? "subscriptions.imported_button"
                : "subscriptions.import_button"
            }
          />
        </button>
        <button
          className="primary"
          onClick={onUse}
          title={intl.formatMessage({ id: "subscriptions.use_title" })}
        >
          <FormattedMessage id="subscriptions.use_button" />
        </button>
      </div>
    </div>
  );
}

function formatRelative(intl: IntlShape, ms: number): string {
  const delta = Date.now() - ms;
  if (delta < 60_000)
    return intl.formatMessage({ id: "subscriptions.rel.just_now" });
  if (delta < 3_600_000)
    return intl.formatMessage(
      { id: "subscriptions.rel.minutes_ago" },
      { n: Math.floor(delta / 60_000) },
    );
  if (delta < 86_400_000)
    return intl.formatMessage(
      { id: "subscriptions.rel.hours_ago" },
      { n: Math.floor(delta / 3_600_000) },
    );
  // Beyond a day, use the platform's own absolute formatting (the
  // current locale is already part of intl, but `Date#toLocaleString`
  // is good enough and respects user OS prefs).
  return new Date(ms).toLocaleString(intl.locale);
}
