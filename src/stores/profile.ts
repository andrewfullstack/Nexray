import { create } from "zustand";
import type { Profile } from "../lib/profile";
import {
  clearActiveProfile,
  loadActiveProfile,
  loadGroupSettings,
  loadManualProfiles,
  loadProfileGroups,
  saveActiveProfile,
  saveGroupSettings,
  saveManualProfiles,
  saveProfileGroups,
  type GroupSettings,
} from "../lib/persistence";
import { useConnectionStore } from "./connection";

interface ProfileStore {
  /** All manually-saved profiles (Add Server / paste link / imported from
   *  a subscription pool). Single flat list — group membership lives in
   *  `groups` so a profile can be re-tagged without rewriting itself. */
  manualProfiles: Profile[];
  /** Currently-selected profile. May come from `manualProfiles` OR a
   *  subscription pool entry (transient). Drives the Connect button. */
  active: Profile | null;
  /** Backwards-compat alias for `active`. Existing pages read `s.profile`
   *  to mean "what Connect uses"; keep that name working. */
  profile: Profile | null;
  loading: boolean;

  /** profile id → subscription id. Profiles whose id is absent here are
   *  "ungrouped" (manual / share-link). When a subscription is deleted we
   *  drop its entries so its servers gracefully demote to manual. */
  groups: Record<string, string>;

  /** Per-subscription group settings. Keyed by subscription id; absent
   *  groups inherit `{ autoSwitch: false }` (manual mode is the default). */
  groupSettings: Record<string, GroupSettings>;

  /** Load both active + manual list from disk. Idempotent. */
  hydrate: () => Promise<void>;

  /** Upsert a manual profile by id and select it as active. */
  save: (p: Profile) => Promise<void>;
  /** Add a profile to the manual list without changing the active
   *  selection. Returns true if newly added, false if a profile with the
   *  same id was already present. When `subscriptionId` is supplied the
   *  profile is tagged as a member of that group (idempotent — re-importing
   *  an existing profile under the same group is a no-op; importing it
   *  under a different group updates the tag). Used by "import from
   *  subscription" so the user keeps servers without having to switch to
   *  them. */
  add: (
    p: Profile,
    options?: { subscriptionId?: string },
  ) => Promise<boolean>;
  /** Delete a manual profile by id. If it was active, clear active too.
   *  Group membership is cleaned up too — no orphaned tags. */
  remove: (id: string) => Promise<void>;
  /** Drop every membership entry pointing at `subscriptionId` and clear
   *  the group's auto-switch setting. The profiles themselves stay in
   *  `manualProfiles` — they demote to ungrouped/manual entries. Called
   *  when the user deletes a subscription URL but wants to keep the
   *  servers it imported. */
  untagGroup: (subscriptionId: string) => Promise<void>;
  /** Remove every profile tagged with `subscriptionId` and clear the
   *  group's auto-switch setting. Also clears `active` if the currently
   *  active profile belonged to the group. The subscription URL itself
   *  is NOT touched — the user can still see it on the Subscriptions
   *  page and re-import. Used by the "Delete group" button on the
   *  Servers page. */
  removeGroup: (subscriptionId: string) => Promise<void>;
  /** Persist a group's auto-switch toggle. Creates the entry on first
   *  call. */
  setGroupAutoSwitch: (
    subscriptionId: string,
    enabled: boolean,
  ) => Promise<void>;

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
  groups: {},
  groupSettings: {},

  hydrate: async () => {
    const [active, manualProfiles, groups, groupSettings] = await Promise.all([
      loadActiveProfile(),
      loadManualProfiles(),
      loadProfileGroups(),
      loadGroupSettings(),
    ]);
    set({
      manualProfiles,
      active,
      profile: active,
      groups,
      groupSettings,
      loading: false,
    });
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

  add: async (profile, options) => {
    const list = get().manualProfiles;
    const groups = get().groups;
    const subId = options?.subscriptionId;
    const exists = list.some((p) => p.id === profile.id);

    if (exists) {
      // Already in the list — just re-tag if the caller supplied a new
      // group. Lets a user re-import an existing profile under a new
      // subscription without manually deleting first.
      if (subId && groups[profile.id] !== subId) {
        const nextGroups = { ...groups, [profile.id]: subId };
        await saveProfileGroups(nextGroups);
        set({ groups: nextGroups });
      }
      return false;
    }

    const next = [...list, profile];
    const nextGroups = subId ? { ...groups, [profile.id]: subId } : groups;
    const writes: Promise<void>[] = [saveManualProfiles(next)];
    if (subId) writes.push(saveProfileGroups(nextGroups));
    await Promise.all(writes);
    set({ manualProfiles: next, groups: nextGroups });
    return true;
  },

  remove: async (id) => {
    const list = get().manualProfiles;
    const next = list.filter((p) => p.id !== id);
    const groups = get().groups;
    const hadGroup = id in groups;
    const { [id]: _omit, ...nextGroups } = groups;
    const active = get().active;
    const wasActive = active?.id === id;

    const writes: Promise<void>[] = [saveManualProfiles(next)];
    if (hadGroup) writes.push(saveProfileGroups(nextGroups));
    await Promise.all(writes);

    if (wasActive) {
      await clearActiveProfile();
      set({
        manualProfiles: next,
        active: null,
        profile: null,
        groups: nextGroups,
      });
    } else {
      set({ manualProfiles: next, groups: nextGroups });
    }
  },

  untagGroup: async (subscriptionId) => {
    const groups = get().groups;
    const settings = get().groupSettings;
    const nextGroups: Record<string, string> = {};
    for (const [pid, sid] of Object.entries(groups)) {
      if (sid !== subscriptionId) nextGroups[pid] = sid;
    }
    const { [subscriptionId]: _omit, ...nextSettings } = settings;
    await Promise.all([
      saveProfileGroups(nextGroups),
      saveGroupSettings(nextSettings),
    ]);
    set({ groups: nextGroups, groupSettings: nextSettings });
  },

  removeGroup: async (subscriptionId) => {
    const list = get().manualProfiles;
    const groups = get().groups;
    const settings = get().groupSettings;
    const active = get().active;

    const removedIds = new Set<string>();
    for (const [pid, sid] of Object.entries(groups)) {
      if (sid === subscriptionId) removedIds.add(pid);
    }
    if (removedIds.size === 0) return;

    const nextProfiles = list.filter((p) => !removedIds.has(p.id));
    const nextGroups: Record<string, string> = {};
    for (const [pid, sid] of Object.entries(groups)) {
      if (!removedIds.has(pid)) nextGroups[pid] = sid;
    }
    const { [subscriptionId]: _omit, ...nextSettings } = settings;
    const wasActive = active !== null && removedIds.has(active.id);

    await Promise.all([
      saveManualProfiles(nextProfiles),
      saveProfileGroups(nextGroups),
      saveGroupSettings(nextSettings),
    ]);

    if (wasActive) {
      // Mirror remove(): clear the active selection but don't try to
      // disconnect. The user can disconnect manually if a session is
      // still live; auto-disconnecting here would surprise them.
      await clearActiveProfile();
      set({
        manualProfiles: nextProfiles,
        groups: nextGroups,
        groupSettings: nextSettings,
        active: null,
        profile: null,
      });
    } else {
      set({
        manualProfiles: nextProfiles,
        groups: nextGroups,
        groupSettings: nextSettings,
      });
    }
  },

  setGroupAutoSwitch: async (subscriptionId, enabled) => {
    const settings = get().groupSettings;
    const nextSettings: Record<string, GroupSettings> = {
      ...settings,
      [subscriptionId]: { autoSwitch: enabled },
    };
    await saveGroupSettings(nextSettings);
    set({ groupSettings: nextSettings });
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
