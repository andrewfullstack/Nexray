import { create } from "zustand";
import type { Profile } from "../lib/profile";
import {
  clearActiveProfile,
  loadActiveProfile,
  loadManualProfiles,
  saveActiveProfile,
  saveManualProfiles,
} from "../lib/persistence";
import { useConnectionStore } from "./connection";

interface ProfileStore {
  /** All manually-saved profiles (Add Server / paste link). */
  manualProfiles: Profile[];
  /** Currently-selected profile. May come from `manualProfiles` OR a
   *  subscription pool entry (transient). Drives the Connect button. */
  active: Profile | null;
  /** Backwards-compat alias for `active`. Existing pages read `s.profile`
   *  to mean "what Connect uses"; keep that name working. */
  profile: Profile | null;
  loading: boolean;

  /** Load both active + manual list from disk. Idempotent. */
  hydrate: () => Promise<void>;

  /** Upsert a manual profile by id and select it as active. */
  save: (p: Profile) => Promise<void>;
  /** Delete a manual profile by id. If it was active, clear active too. */
  remove: (id: string) => Promise<void>;
  /** Set active to an arbitrary Profile (e.g. from the subscription pool).
   *  Does NOT add to the manual list. */
  setActive: (p: Profile) => Promise<void>;
  /** Set active by id from the manual list. No-op if id not found. */
  setActiveById: (id: string) => Promise<void>;
  /** Clear the active selection without touching the manual list. */
  clearActive: () => Promise<void>;

  // Backwards-compat — older call sites do `useProfileStore((s) => s.set)`.
  set: (p: Profile) => Promise<void>;
  clear: () => Promise<void>;
}

export const useProfileStore = create<ProfileStore>((set, get) => ({
  manualProfiles: [],
  active: null,
  profile: null,
  loading: true,

  hydrate: async () => {
    const [active, manualProfiles] = await Promise.all([
      loadActiveProfile(),
      loadManualProfiles(),
    ]);
    set({ manualProfiles, active, profile: active, loading: false });
  },

  save: async (profile) => {
    const list = get().manualProfiles;
    const existing = list.findIndex((p) => p.id === profile.id);
    const next =
      existing >= 0
        ? list.map((p, i) => (i === existing ? profile : p))
        : [...list, profile];
    await Promise.all([saveManualProfiles(next), saveActiveProfile(profile)]);
    set({ manualProfiles: next, active: profile, profile });
  },

  remove: async (id) => {
    const list = get().manualProfiles;
    const next = list.filter((p) => p.id !== id);
    const active = get().active;
    const wasActive = active?.id === id;
    await saveManualProfiles(next);
    if (wasActive) {
      await clearActiveProfile();
      set({ manualProfiles: next, active: null, profile: null });
    } else {
      set({ manualProfiles: next });
    }
  },

  setActive: async (profile) => {
    await saveActiveProfile(profile);
    set({ active: profile, profile });
    await reconnectIfLive(profile);
  },

  setActiveById: async (id) => {
    const found = get().manualProfiles.find((p) => p.id === id);
    if (!found) return;
    await saveActiveProfile(found);
    set({ active: found, profile: found });
    await reconnectIfLive(found);
  },

  clearActive: async () => {
    await clearActiveProfile();
    set({ active: null, profile: null });
  },

  // Backwards-compat: `set` historically meant "save and make active".
  set: async (profile) => {
    await get().save(profile);
  },
  clear: async () => {
    await get().clearActive();
  },
}));

/// If a connection is live, transparently reconnect with the newly-active
/// profile so the running xray's outbound actually points at the chosen
/// server. Without this, "switch active" only updates the UI label — the
/// backend keeps tunneling through the previously-connected server until
/// the user manually disconnects + reconnects.
async function reconnectIfLive(profile: Profile): Promise<void> {
  const conn = useConnectionStore.getState();
  if (
    conn.status.profileId === profile.id ||
    (conn.status.state !== "connected" && conn.status.state !== "connecting")
  ) {
    return;
  }
  await conn.disconnect();
  await conn.connect(profile);
}
