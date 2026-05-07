import { Store } from "@tauri-apps/plugin-store";
import type { Profile } from "./profile";
import { ProfileSchema } from "./profile";

const STORE_FILE = "nexray-state.json";
const ACTIVE_KEY = "active-profile";
const MANUAL_LIST_KEY = "manual-profiles";

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

// Backwards-compat aliases used by older callers. Kept so a half-migrated
// import doesn't break the build during the multi-profile rollout.
export const loadProfile = loadActiveProfile;
export const saveProfile = saveActiveProfile;
export const clearProfile = clearActiveProfile;
