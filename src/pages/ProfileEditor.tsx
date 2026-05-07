import { useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { decodeShareLink } from "../lib/share-link";
import { useProfileStore } from "../stores/profile";
import type { Profile } from "../lib/profile";

export function ProfileEditor() {
  const intl = useIntl();
  const persisted = useProfileStore((s) => s.profile);
  const setProfile = useProfileStore((s) => s.set);

  const [pasted, setPasted] = useState("");
  const [previewProfile, setPreviewProfile] = useState<Profile | null>(persisted);
  const [parseError, setParseError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const handlePaste = (raw: string) => {
    setPasted(raw);
    setSaved(false);
    if (raw.trim().length === 0) {
      setPreviewProfile(persisted);
      setParseError(null);
      return;
    }
    const result = decodeShareLink(raw.trim());
    if (result.ok) {
      setPreviewProfile(result.profile);
      setParseError(null);
    } else {
      setPreviewProfile(null);
      setParseError(result.reason);
    }
  };

  const handleSave = async () => {
    if (!previewProfile) return;
    await setProfile(previewProfile);
    setSaved(true);
    setPasted("");
  };

  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>
        <FormattedMessage id="profile.editor_title" />
      </h2>

      <div className="field">
        <label className="label" htmlFor="paste">
          <FormattedMessage id="profile.paste_label" />
        </label>
        <textarea
          id="paste"
          value={pasted}
          onChange={(e) => handlePaste(e.target.value)}
          placeholder={intl.formatMessage({ id: "profile.paste_placeholder" })}
        />
        {parseError && (
          <p className="error">
            {intl.formatMessage(
              { id: "profile.parse_error" },
              { reason: parseError },
            )}
          </p>
        )}
      </div>

      {previewProfile && <ProfilePreview profile={previewProfile} />}

      <div className="row" style={{ marginTop: "1rem" }}>
        <button
          className="primary"
          type="button"
          disabled={!previewProfile || previewProfile === persisted}
          onClick={handleSave}
        >
          <FormattedMessage id="profile.save" />
        </button>
        {saved && (
          <span className="flash ok">
            <FormattedMessage id="profile.saved" />
          </span>
        )}
      </div>
    </div>
  );
}

function ProfilePreview({ profile }: { profile: Profile }) {
  return (
    <dl className="mono" style={{ display: "grid", gap: "0.4rem 1rem", gridTemplateColumns: "max-content 1fr", margin: 0 }}>
      <Field id="profile.kind" value={profile.kind} />
      <Field id="profile.address" value={profile.address} />
      <Field id="profile.port" value={String(profile.port)} />
      <Field id="profile.uuid" value={profile.uuid} />
      <Field id="profile.sni" value={profile.sni} />
      <Field id="profile.fingerprint" value={profile.fingerprint} />
      {profile.kind === "cdn-ws" && (
        <>
          <Field id="profile.host" value={profile.host} />
          <Field id="profile.path" value={profile.path} />
        </>
      )}
      {profile.kind === "reality" && (
        <>
          <Field id="profile.public_key" value={profile.publicKey} />
          <Field id="profile.short_id" value={profile.shortId} />
          <Field id="profile.flow" value={profile.flow} />
        </>
      )}
    </dl>
  );
}

function Field({ id, value }: { id: string; value: string }) {
  return (
    <>
      <dt className="muted" style={{ margin: 0 }}>
        <FormattedMessage id={id} />
      </dt>
      <dd className="mono" style={{ margin: 0, wordBreak: "break-all" }}>
        {value}
      </dd>
    </>
  );
}
