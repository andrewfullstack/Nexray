/**
 * English (en) translation catalog. Add new IDs here AND in any locale files.
 * Per DEVELOPMENT.md §11 — UI strings must go through react-intl from day 1.
 */
export const en: Record<string, string> = {
  "app.title": "Nexray",
  "nav.home": "Connection",
  "nav.profile": "Profile",

  "status.disconnected": "Disconnected",
  "status.connecting": "Connecting…",
  "status.connected": "Connected",
  "status.crashed": "Crashed",

  "home.connect": "Connect",
  "home.disconnect": "Disconnect",
  "home.no_profile": "No profile saved yet — open the Profile tab to add one.",
  "home.uplink": "Up",
  "home.downlink": "Down",
  "home.profile_summary": "{kind} · {endpoint}",
  "home.last_error": "Last error: {error}",

  "profile.editor_title": "Profile",
  "profile.paste_label": "Paste a vless:// share link",
  "profile.paste_placeholder": "vless://uuid@host:port?type=…",
  "profile.parse_error": "Could not parse: {reason}",
  "profile.save": "Save profile",
  "profile.saved": "Saved.",
  "profile.kind": "Kind",
  "profile.address": "Address",
  "profile.port": "Port",
  "profile.sni": "SNI",
  "profile.fingerprint": "Fingerprint",
  "profile.host": "Host",
  "profile.path": "Path",
  "profile.public_key": "Public key",
  "profile.short_id": "Short ID",
  "profile.flow": "Flow",
  "profile.uuid": "UUID",
};
