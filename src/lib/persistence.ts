import { Store } from "@tauri-apps/plugin-store";
import { z } from "zod";
import { isLocale, type Locale } from "../messages/catalogs";
import type { Profile } from "./profile";
import { ProfileSchema } from "./profile";

const STORE_FILE = "nexray-state.json";
const ACTIVE_KEY = "active-profile";
const MANUAL_LIST_KEY = "manual-profiles";
const PROFILE_GROUPS_KEY = "profile-groups";
const GROUP_SETTINGS_KEY = "group-settings";
const LOCALE_KEY = "ui-locale";

/** Per-group UI behaviour. Owned by the React layer — Rust never reads it. */
export interface GroupSettings {
  /** When true, finishing a global Probe Latency sweep auto-switches the
   *  active profile to the lowest-latency server within this group, but
   *  only if the active profile already belongs to this group. The
   *  one-active-group invariant prevents two enabled groups from fighting
   *  over the active selection. */
  autoSwitch: boolean;
}

const ProfileGroupsRecordSchema = z.record(z.string());
const GroupSettingsSchema = z.object({ autoSwitch: z.boolean() }).strict();
const GroupSettingsRecordSchema = z.record(GroupSettingsSchema);

let cached: Promise<Store> | null = null;

function getStore(): Promise<Store> {
  if (!cached) cached = Store.load(STORE_FILE);
  return cached;
}

/**
 * Load the active profile (the one Connect will use). Returns `null` when
 * nothing is saved or the on-disk shape doesn't pass the Zod schema.
 *
 * Note: §12 rule 2 (Keychain/DPAPI/libsecret encryption-at-rest for
 * subscription credentials) is deferred to Phase 7; see docs/SECURITY.md.
 */
export async function loadActiveProfile(): Promise<Profile | null> {
  const store = await getStore();
  const raw = await store.get(ACTIVE_KEY);
  if (raw === undefined) return null;
  const parsed = ProfileSchema.safeParse(raw);
  if (!parsed.success) {
    console.warn("persisted active profile failed validation; discarding");
    await store.delete(ACTIVE_KEY);
    await store.save();
    return null;
  }
  return parsed.data;
}

export async function saveActiveProfile(profile: Profile): Promise<void> {
  const store = await getStore();
  await store.set(ACTIVE_KEY, profile);
  await store.save();
}

export async function clearActiveProfile(): Promise<void> {
  const store = await getStore();
  await store.delete(ACTIVE_KEY);
  await store.save();
}

/**
 * Load the list of manually-saved profiles. Filters out entries that fail
 * schema validation (so a single bad entry can't break the whole list).
 *
 * Auto-migration: if no list is saved yet but an active-profile is, the
 * existing single profile becomes the seed entry. Single-profile users
 * upgrading to multi-profile see their existing server show up in the
 * Servers list automatically.
 */
export async function loadManualProfiles(): Promise<Profile[]> {
  const store = await getStore();
  const raw = await store.get(MANUAL_LIST_KEY);
  if (raw === undefined) {
    const active = await loadActiveProfile();
    if (active !== null) {
      const seeded = [active];
      await saveManualProfiles(seeded);
      return seeded;
    }
    return [];
  }
  if (!Array.isArray(raw)) return [];
  const out: Profile[] = [];
  for (const item of raw) {
    const parsed = ProfileSchema.safeParse(item);
    if (parsed.success) out.push(parsed.data);
  }
  return out;
}

export async function saveManualProfiles(profiles: Profile[]): Promise<void> {
  const store = await getStore();
  await store.set(MANUAL_LIST_KEY, profiles);
  await store.save();
}

/**
 * Load the profile-id → subscription-id membership map. Profiles not in
 * this map are "ungrouped" (manually added or share-link imported).
 * Returns an empty map when nothing is saved or the on-disk shape is
 * invalid — better to demote to manual than lose the whole list.
 */
export async function loadProfileGroups(): Promise<Record<string, string>> {
  const store = await getStore();
  const raw = await store.get(PROFILE_GROUPS_KEY);
  if (raw === undefined) return {};
  const parsed = ProfileGroupsRecordSchema.safeParse(raw);
  return parsed.success ? parsed.data : {};
}

export async function saveProfileGroups(
  groups: Record<string, string>,
): Promise<void> {
  const store = await getStore();
  await store.set(PROFILE_GROUPS_KEY, groups);
  await store.save();
}

export async function loadGroupSettings(): Promise<Record<string, GroupSettings>> {
  const store = await getStore();
  const raw = await store.get(GROUP_SETTINGS_KEY);
  if (raw === undefined) return {};
  const parsed = GroupSettingsRecordSchema.safeParse(raw);
  return parsed.success ? parsed.data : {};
}

export async function saveGroupSettings(
  settings: Record<string, GroupSettings>,
): Promise<void> {
  const store = await getStore();
  await store.set(GROUP_SETTINGS_KEY, settings);
  await store.save();
}

/**
 * Load the persisted UI locale. Returns `null` when nothing is saved yet
 * (so the locale store can fall back to system-language detection on
 * first launch) or when the on-disk value isn't one of our bundled
 * locales.
 */
export async function loadLocale(): Promise<Locale | null> {
  const store = await getStore();
  const raw = await store.get(LOCALE_KEY);
  if (raw === undefined) return null;
  return isLocale(raw) ? raw : null;
}

export async function saveLocale(locale: Locale): Promise<void> {
  const store = await getStore();
  await store.set(LOCALE_KEY, locale);
  await store.save();
}

// Backwards-compat aliases used by older callers. Kept so a half-migrated
// import doesn't break the build during the multi-profile rollout.
export const loadProfile = loadActiveProfile;
export const saveProfile = saveActiveProfile;
export const clearProfile = clearActiveProfile;
