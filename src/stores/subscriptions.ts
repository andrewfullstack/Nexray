import { create } from "zustand";
import type { AddSubscriptionRequest, Subscription } from "../lib/ipc";
import { tauri } from "../lib/tauri";
import { useProfileStore } from "./profile";

interface SubscriptionsStore {
  subs: Subscription[];
  loading: boolean;
  error: string | null;

  refresh: () => Promise<void>;
  add: (req: AddSubscriptionRequest) => Promise<void>;
  remove: (id: string) => Promise<void>;
  refreshOne: (id: string) => Promise<void>;
}

export const useSubscriptionsStore = create<SubscriptionsStore>((set) => ({
  subs: [],
  loading: true,
  error: null,

  refresh: async () => {
    try {
      const subs = await tauri.subscriptionsList();
      set({ subs, loading: false, error: null });
    } catch (e) {
      set({ loading: false, error: errMsg(e) });
    }
  },

  add: async (req) => {
    set({ error: null });
    try {
      await tauri.subscriptionAdd(req);
      const subs = await tauri.subscriptionsList();
      set({ subs });
    } catch (e) {
      set({ error: errMsg(e) });
      throw e;
    }
  },

  remove: async (id) => {
    await tauri.subscriptionDelete(id);
    // Demote any servers the user imported from this subscription back
    // into the ungrouped "manual" bucket so deleting an airport URL
    // doesn't silently take their saved servers with it. Group settings
    // (auto-switch toggle) for this group are dropped at the same time.
    await useProfileStore.getState().untagGroup(id);
    const subs = await tauri.subscriptionsList();
    set({ subs });
  },

  refreshOne: async (id) => {
    set({ error: null });
    try {
      await tauri.subscriptionRefresh(id);
      const subs = await tauri.subscriptionsList();
      set({ subs });
    } catch (e) {
      set({ error: errMsg(e) });
    }
  },
}));

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
