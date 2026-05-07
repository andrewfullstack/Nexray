import { create } from "zustand";
import type { Profile } from "../lib/profile";
import {
  clearProfile as clearPersisted,
  loadProfile,
  saveProfile,
} from "../lib/persistence";

interface ProfileStore {
  profile: Profile | null;
  loading: boolean;
  /** Hydrate from disk. Call once at app boot. */
  hydrate: () => Promise<void>;
  /** Replace the active profile and persist. */
  set: (p: Profile) => Promise<void>;
  /** Clear the active profile from memory and disk. */
  clear: () => Promise<void>;
}

export const useProfileStore = create<ProfileStore>((set) => ({
  profile: null,
  loading: true,

  hydrate: async () => {
    const profile = await loadProfile();
    set({ profile, loading: false });
  },

  set: async (profile) => {
    await saveProfile(profile);
    set({ profile });
  },

  clear: async () => {
    await clearPersisted();
    set({ profile: null });
  },
}));
