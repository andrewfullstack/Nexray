import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { FormattedMessage } from "react-intl";
import { decodeShadowrocketJson } from "../lib/import-json";
import { decodeShareLink } from "../lib/share-link";
import {
  CdnWsProfileSchema,
  FINGERPRINTS,
  ProfileSchema,
  RealityProfileSchema,
  TrojanProfileSchema,
  VMESS_SECURITIES,
  VmessProfileSchema,
  type Fingerprint,
  type Profile,
  type VmessSecurity,
} from "../lib/profile";
import { useProfileStore } from "../stores/profile";

type Kind = "cdn-ws" | "reality" | "trojan" | "vmess";

interface FormState {
  kind: Kind;
  address: string;
  port: string;
  uuid: string;       // VLESS / VMess user UUID
  password: string;   // Trojan credential
  remarks: string;
  // cdn-ws
  host: string;
  path: string;
  sni: string;
  alpnH2: boolean;
  alpnHttp11: boolean;
  // reality
  publicKey: string;
  shortId: string;
  spiderX: string;
  // vmess
  vmessSecurity: VmessSecurity;
  // shared
  fingerprint: Fingerprint;
}

const initial: FormState = {
  kind: "cdn-ws",
  address: "",
  port: "443",
  uuid: "",
  password: "",
  remarks: "",
  host: "",
  path: "/?ed=2560",
  sni: "",
  alpnH2: true,
  alpnHttp11: true,
  publicKey: "",
  shortId: "",
  spiderX: "",
  vmessSecurity: "auto",
  fingerprint: "chrome",
};

export function AddServer() {
  const navigate = useNavigate();
  const params = useParams<{ id?: string }>();
  const editId = params.id ?? null;
  const manualProfiles = useProfileStore((s) => s.manualProfiles);
  const saveProfile = useProfileStore((s) => s.save);

  // Edit mode: prefill from the matching manual profile. Add mode: blank form.
  const editTarget = useMemo(
    () => (editId ? manualProfiles.find((p) => p.id === editId) ?? null : null),
    [editId, manualProfiles],
  );

  const [form, setForm] = useState<FormState>(
    editTarget ? profileToForm(editTarget) : initial,
  );
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savedFlash, setSavedFlash] = useState(false);

  // Re-prefill if the edit target appears later (e.g. profiles hydrate
  // after first render) or the route id changes.
  useEffect(() => {
    if (editTarget) {
      setForm(profileToForm(editTarget));
    } else {
      setForm(initial);
    }
  }, [editTarget]);

  const profile = useMemo(() => buildProfile(form, editTarget?.id), [form, editTarget]);
  const valid = profile !== null;

  const handleSave = async () => {
    if (!profile) return;
    setError(null);
    try {
      await saveProfile(profile);
      setSavedFlash(true);
      window.setTimeout(() => setSavedFlash(false), 1500);
      navigate("/servers");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleImport = () => {
    setImportError(null);
    const r = decodeShareLink(importText.trim());
    if (!r.ok) {
      setImportError(r.reason);
      return;
    }
    setForm(profileToForm(r.profile));
    setImportText("");
  };

  const handleImportJson = () => {
    setJsonError(null);
    const r = decodeShadowrocketJson(jsonText);
    if (!r.ok) {
      setJsonError(r.reason);
      return;
    }
    setForm(profileToForm(r.profile));
    setJsonText("");
  };

  const update = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((s) => ({ ...s, [key]: value }));

  return (
    <>
      <div className="card">
        <Row label="Profile">
          <KindToggle value={form.kind} onChange={(v) => update("kind", v)} />
        </Row>
      </div>

      <div className="card" style={{ paddingTop: 0 }}>
        <FieldRow
          label="Address"
          hint="Required, domain or IP"
          value={form.address}
          onChange={(v) => update("address", v)}
        />
        <FieldRow
          label="Port"
          hint="Required, 1-65535"
          value={form.port}
          onChange={(v) => update("port", v)}
          inputMode="numeric"
        />
        {form.kind === "trojan" ? (
          <FieldRow
            label="Password"
            hint="Required"
            value={form.password}
            onChange={(v) => update("password", v)}
            mono
          />
        ) : form.kind === "vmess" ? (
          <>
            <FieldRow
              label="UUID"
              hint="Required"
              value={form.uuid}
              onChange={(v) => update("uuid", v)}
              mono
            />
            <Row label="alterId">
              <span className="dim mono">0 (AEAD)</span>
            </Row>
          </>
        ) : (
          <>
            <FieldRow
              label="UUID"
              hint="Required"
              value={form.uuid}
              onChange={(v) => update("uuid", v)}
              mono
            />
            <Row label="Encryption">
              <span className="dim mono">none</span>
            </Row>
          </>
        )}

        {form.kind === "cdn-ws" ? (
          <>
            <Row label="Transport">
              <span className="mono">ws</span>
            </Row>
            <Row label="TLS">
              <span className="mono">on</span>
            </Row>
            <FieldRow
              label="Host"
              hint="WS Host header"
              value={form.host}
              onChange={(v) => update("host", v)}
              mono
            />
            <FieldRow
              label="Path"
              hint="default /?ed=2560"
              value={form.path}
              onChange={(v) => update("path", v)}
              mono
            />
            <FieldRow
              label="SNI"
              hint="TLS server name"
              value={form.sni}
              onChange={(v) => update("sni", v)}
              mono
            />
            <Row label="ALPN">
              <div className="row" style={{ gap: "1rem" }}>
                <label>
                  <input
                    type="checkbox"
                    checked={form.alpnH2}
                    onChange={(e) => update("alpnH2", e.target.checked)}
                    style={{ width: "auto" }}
                  />{" "}
                  h2
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={form.alpnHttp11}
                    onChange={(e) => update("alpnHttp11", e.target.checked)}
                    style={{ width: "auto" }}
                  />{" "}
                  http/1.1
                </label>
              </div>
            </Row>
          </>
        ) : form.kind === "reality" ? (
          <>
            <Row label="Transport">
              <span className="mono">tcp</span>
            </Row>
            <Row label="Security">
              <span className="mono">reality</span>
            </Row>
            <Row label="Flow">
              <span className="mono">xtls-rprx-vision</span>
            </Row>
            <FieldRow
              label="SNI"
              hint="Borrowed dest, e.g. www.microsoft.com"
              value={form.sni}
              onChange={(v) => update("sni", v)}
              mono
            />
            <FieldRow
              label="Public Key"
              hint="43-char base64url"
              value={form.publicKey}
              onChange={(v) => update("publicKey", v)}
              mono
            />
            <FieldRow
              label="Short ID"
              hint="Hex, 0-16 chars, even length"
              value={form.shortId}
              onChange={(v) => update("shortId", v)}
              mono
            />
            <FieldRow
              label="SpiderX"
              hint="Optional"
              value={form.spiderX}
              onChange={(v) => update("spiderX", v)}
              mono
            />
          </>
        ) : form.kind === "vmess" ? (
          <>
            <Row label="Transport">
              <span className="mono">tcp</span>
            </Row>
            <Row label="TLS">
              <span className="mono">on</span>
            </Row>
            <Row label="Cipher">
              <select
                value={form.vmessSecurity}
                onChange={(e) =>
                  update("vmessSecurity", e.target.value as VmessSecurity)
                }
                style={{ width: "auto" }}
              >
                {VMESS_SECURITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </Row>
            <FieldRow
              label="SNI"
              hint="TLS server name"
              value={form.sni}
              onChange={(v) => update("sni", v)}
              mono
            />
            <Row label="ALPN">
              <div className="row" style={{ gap: "1rem" }}>
                <label>
                  <input
                    type="checkbox"
                    checked={form.alpnH2}
                    onChange={(e) => update("alpnH2", e.target.checked)}
                    style={{ width: "auto" }}
                  />{" "}
                  h2
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={form.alpnHttp11}
                    onChange={(e) => update("alpnHttp11", e.target.checked)}
                    style={{ width: "auto" }}
                  />{" "}
                  http/1.1
                </label>
              </div>
            </Row>
          </>
        ) : (
          <>
            <Row label="Transport">
              <span className="mono">tcp</span>
            </Row>
            <Row label="TLS">
              <span className="mono">on</span>
            </Row>
            <FieldRow
              label="SNI"
              hint="TLS server name"
              value={form.sni}
              onChange={(v) => update("sni", v)}
              mono
            />
            <Row label="ALPN">
              <div className="row" style={{ gap: "1rem" }}>
                <label>
                  <input
                    type="checkbox"
                    checked={form.alpnH2}
                    onChange={(e) => update("alpnH2", e.target.checked)}
                    style={{ width: "auto" }}
                  />{" "}
                  h2
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={form.alpnHttp11}
                    onChange={(e) => update("alpnHttp11", e.target.checked)}
                    style={{ width: "auto" }}
                  />{" "}
                  http/1.1
                </label>
              </div>
            </Row>
          </>
        )}

        <Row label="Fingerprint">
          <select
            value={form.fingerprint}
            onChange={(e) => update("fingerprint", e.target.value as Fingerprint)}
            style={{ width: "auto" }}
          >
            {FINGERPRINTS.map((fp) => (
              <option key={fp} value={fp}>
                {fp}
              </option>
            ))}
          </select>
        </Row>

        <FieldRow
          label="Remarks"
          hint="Optional label"
          value={form.remarks}
          onChange={(v) => update("remarks", v)}
        />
      </div>

      <div
        className="card row"
        style={{ justifyContent: "space-between", alignItems: "center" }}
      >
        <span className="dim">
          <small>
            <FormattedMessage
              id={valid ? "addserver.valid_hint" : "addserver.invalid_hint"}
            />
          </small>
        </span>
        <div className="row">
          {savedFlash && (
            <span className="flash ok">
              <FormattedMessage id="addserver.saved_flash" />
            </span>
          )}
          <button
            className="primary"
            onClick={() => void handleSave()}
            disabled={!valid}
          >
            <FormattedMessage id="addserver.save_button" />
          </button>
        </div>
      </div>

      {error && <div className="flash err">{error}</div>}

      <div className="card">
        <strong>
          <FormattedMessage id="addserver.heading.share_link" />
        </strong>
        <p className="dim" style={{ margin: "0.4rem 0 0.5rem" }}>
          <small>
            <FormattedMessage id="addserver.help.share_link" />
          </small>
        </p>
        <textarea
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          placeholder="vless:// · trojan://password@host:port · vmess://<base64(json)>"
          style={{ minHeight: "5rem" }}
        />
        {importError && (
          <div className="flash err">
            <FormattedMessage
              id="addserver.parse_failed"
              values={{ reason: importError }}
            />
          </div>
        )}
        <div className="row" style={{ justifyContent: "flex-end", marginTop: "0.5rem" }}>
          <button onClick={handleImport} disabled={!importText.trim()}>
            <FormattedMessage id="addserver.import_button" />
          </button>
        </div>
      </div>

      <div className="card">
        <strong>
          <FormattedMessage id="addserver.heading.json" />
        </strong>
        <p className="dim" style={{ margin: "0.4rem 0 0.5rem" }}>
          <small>
            <FormattedMessage id="addserver.help.json" />
          </small>
        </p>
        <textarea
          value={jsonText}
          onChange={(e) => setJsonText(e.target.value)}
          placeholder='{ "type": "VLESS", "host": "...", "port": "443", "password": "...", "obfs": "websocket", "tls": true, ... }'
          style={{ minHeight: "8rem" }}
          spellCheck={false}
        />
        {jsonError && (
          <div className="flash err">
            <FormattedMessage
              id="addserver.json_parse_failed"
              values={{ reason: jsonError }}
            />
          </div>
        )}
        <div className="row" style={{ justifyContent: "flex-end", marginTop: "0.5rem" }}>
          <button onClick={handleImportJson} disabled={!jsonText.trim()}>
            <FormattedMessage id="addserver.import_json_button" />
          </button>
        </div>
      </div>
    </>
  );
}

// ----------------------------------------------------------------------------
// Layout primitives
// ----------------------------------------------------------------------------

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div
      className="row"
      style={{
        justifyContent: "space-between",
        alignItems: "center",
        padding: "0.7rem 0",
        borderTop: "1px solid var(--border)",
        gap: "1rem",
        flexWrap: "wrap",
      }}
    >
      <strong style={{ minWidth: "8rem" }}>{label}</strong>
      <div style={{ flex: 1, textAlign: "right", minWidth: 0 }}>{children}</div>
    </div>
  );
}

interface FieldRowProps {
  label: string;
  hint: string;
  value: string;
  onChange: (value: string) => void;
  mono?: boolean;
  inputMode?: "text" | "numeric";
}

function FieldRow({ label, hint, value, onChange, mono, inputMode }: FieldRowProps) {
  return (
    <Row label={label}>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={hint}
        inputMode={inputMode}
        style={{
          textAlign: "right",
          fontFamily: mono ? "var(--mono)" : "inherit",
          background: "transparent",
          border: "none",
          padding: "0.2rem 0",
        }}
      />
    </Row>
  );
}

function KindToggle({ value, onChange }: { value: Kind; onChange: (v: Kind) => void }) {
  const kinds: Kind[] = ["cdn-ws", "reality", "trojan", "vmess"];
  return (
    <div className="row" style={{ gap: "1rem", flexWrap: "wrap" }}>
      {kinds.map((k) => (
        <label key={k}>
          <input
            type="radio"
            checked={value === k}
            onChange={() => onChange(k)}
            style={{ width: "auto", marginRight: "0.4rem" }}
          />
          {k}
        </label>
      ))}
    </div>
  );
}

// ----------------------------------------------------------------------------
// Form ↔ Profile bridge
// ----------------------------------------------------------------------------

function buildProfile(f: FormState, preserveId: string | undefined): Profile | null {
  const port = Number(f.port);
  if (!Number.isFinite(port)) return null;

  // For id derivation: VLESS kinds key by uuid, trojan keys by password. The
  // FNV hash needs *some* per-server distinguisher; the credential is the
  // natural one since address+port may collide across users.
  const credential = f.kind === "trojan" ? f.password : f.uuid;

  // In edit mode keep the original id even when fields change — otherwise
  // changing the address would create a new entry and orphan the old one.
  const id = preserveId ?? profileId(f.kind, f.address, port, credential);

  if (f.kind === "cdn-ws") {
    const alpn = [
      ...(f.alpnH2 ? (["h2"] as const) : []),
      ...(f.alpnHttp11 ? (["http/1.1"] as const) : []),
    ];
    if (alpn.length === 0) return null;
    const candidate = {
      kind: "cdn-ws" as const,
      id,
      name: f.remarks.trim() || `${f.address}:${port || ""}`,
      ...(f.remarks.trim() ? { remark: f.remarks.trim() } : {}),
      address: f.address.trim(),
      port,
      uuid: f.uuid.trim(),
      host: f.host.trim(),
      path: f.path.trim() || "/",
      sni: f.sni.trim() || f.host.trim(),
      alpn: alpn as ("h2" | "http/1.1")[],
      fingerprint: f.fingerprint,
    };
    return CdnWsProfileSchema.safeParse(candidate).data ?? null;
  }

  if (f.kind === "reality") {
    const candidate = {
      kind: "reality" as const,
      id,
      name: f.remarks.trim() || `${f.address}:${port || ""}`,
      ...(f.remarks.trim() ? { remark: f.remarks.trim() } : {}),
      address: f.address.trim(),
      port,
      uuid: f.uuid.trim(),
      sni: f.sni.trim(),
      publicKey: f.publicKey.trim(),
      shortId: f.shortId.trim().toLowerCase(),
      fingerprint: f.fingerprint,
      flow: "xtls-rprx-vision" as const,
      spiderX: f.spiderX,
    };
    return RealityProfileSchema.safeParse(candidate).data ?? null;
  }

  if (f.kind === "vmess") {
    const alpn = [
      ...(f.alpnH2 ? (["h2"] as const) : []),
      ...(f.alpnHttp11 ? (["http/1.1"] as const) : []),
    ];
    if (alpn.length === 0) return null;
    const candidate = {
      kind: "vmess" as const,
      id,
      name: f.remarks.trim() || `${f.address}:${port || ""}`,
      ...(f.remarks.trim() ? { remark: f.remarks.trim() } : {}),
      address: f.address.trim(),
      port,
      uuid: f.uuid.trim(),
      security: f.vmessSecurity,
      sni: f.sni.trim() || f.address.trim(),
      alpn: alpn as ("h2" | "http/1.1")[],
      fingerprint: f.fingerprint,
    };
    return VmessProfileSchema.safeParse(candidate).data ?? null;
  }

  // trojan
  const alpn = [
    ...(f.alpnH2 ? (["h2"] as const) : []),
    ...(f.alpnHttp11 ? (["http/1.1"] as const) : []),
  ];
  if (alpn.length === 0) return null;
  const candidate = {
    kind: "trojan" as const,
    id,
    name: f.remarks.trim() || `${f.address}:${port || ""}`,
    ...(f.remarks.trim() ? { remark: f.remarks.trim() } : {}),
    address: f.address.trim(),
    port,
    password: f.password,
    sni: f.sni.trim(),
    alpn: alpn as ("h2" | "http/1.1")[],
    fingerprint: f.fingerprint,
  };
  return TrojanProfileSchema.safeParse(candidate).data ?? null;
}

function profileToForm(p: Profile): FormState {
  const base: FormState = {
    ...initial,
    kind: p.kind,
    address: p.address,
    port: String(p.port),
    remarks: p.remark ?? "",
    sni: p.sni,
    fingerprint: p.fingerprint,
  };
  if (p.kind === "cdn-ws") {
    return {
      ...base,
      uuid: p.uuid,
      host: p.host,
      path: p.path,
      alpnH2: p.alpn.includes("h2"),
      alpnHttp11: p.alpn.includes("http/1.1"),
    };
  }
  if (p.kind === "reality") {
    return {
      ...base,
      uuid: p.uuid,
      publicKey: p.publicKey,
      shortId: p.shortId,
      spiderX: p.spiderX,
    };
  }
  if (p.kind === "vmess") {
    return {
      ...base,
      uuid: p.uuid,
      vmessSecurity: p.security,
      alpnH2: p.alpn.includes("h2"),
      alpnHttp11: p.alpn.includes("http/1.1"),
    };
  }
  // trojan
  return {
    ...base,
    password: p.password,
    alpnH2: p.alpn.includes("h2"),
    alpnHttp11: p.alpn.includes("http/1.1"),
  };
}

// FNV-1a 32-bit, mirrors `profileId` in src/lib/share-link.ts.
function profileId(kind: string, address: string, port: number, uuid: string): string {
  const s = `${kind}:${address}:${port}:${uuid}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

// keep ProfileSchema import alive — buildProfile uses CdnWs/Reality variants;
// the union schema is here for downstream consumers that import via `.parse`.
void ProfileSchema;
