import { Store } from "@tauri-apps/plugin-store";
import type { Profile } from "./profile";
import { ProfileSchema } from "./profile";

const STORE_FILE = "nexray-state.json";
const PROFILE_KEY = "active-profile";

let cached: Promise<Store> | null = null;

function getStore(): Promise<Store> {
  if (!cached) cached = Store.load(STORE_FILE);
  return cached;
}

/**
 * Load the persisted active profile, if any. Returns `null` when nothing is
 * saved or the on-disk shape doesn't pass the Zod schema (which means we'd
 * rather forget than silently use stale/invalid data).
 *
 * Note: §12 rule 2 (Keychain/DPAPI/libsecret encryption-at-rest for
 * subscription credentials) is deferred to Phase 7; see docs/SECURITY.md.
 */
export async function loadProfile(): Promise<Profile | null> {
  const store = await getStore();
  const raw = await store.get(PROFILE_KEY);
  if (raw === undefined) return null;
  const parsed = ProfileSchema.safeParse(raw);
  if (!parsed.success) {
    console.warn("persisted profile failed validation; discarding");
    await store.delete(PROFILE_KEY);
    await store.save();
    return null;
  }
  return parsed.data;
}

export async function saveProfile(profile: Profile): Promise<void> {
  const store = await getStore();
  await store.set(PROFILE_KEY, profile);
  await store.save();
}

export async function clearProfile(): Promise<void> {
  const store = await getStore();
  await store.delete(PROFILE_KEY);
  await store.save();
}
