import { create } from "zustand";
import type { AddSubscriptionRequest, PoolEntry, Subscription } from "../lib/ipc";
import { tauri } from "../lib/tauri";

interface SubscriptionsStore {
  subs: Subscription[];
  pool: PoolEntry[];
  loading: boolean;
  error: string | null;

  refresh: () => Promise<void>;
  add: (req: AddSubscriptionRequest) => Promise<void>;
  remove: (id: string) => Promise<void>;
  refreshOne: (id: string) => Promise<void>;
  probeAll: () => Promise<void>;
}

export const useSubscriptionsStore = create<SubscriptionsStore>((set) => ({
  subs: [],
  pool: [],
  loading: true,
  error: null,

  refresh: async () => {
    try {
      const [subs, pool] = await Promise.all([tauri.subscriptionsList(), tauri.poolList()]);
      set({ subs, pool, loading: false, error: null });
    } catch (e) {
      set({ loading: false, error: errMsg(e) });
    }
  },

  add: async (req) => {
    set({ error: null });
    try {
      await tauri.subscriptionAdd(req);
      const [subs, pool] = await Promise.all([tauri.subscriptionsList(), tauri.poolList()]);
      set({ subs, pool });
    } catch (e) {
      set({ error: errMsg(e) });
      throw e;
    }
  },

  remove: async (id) => {
    await tauri.subscriptionDelete(id);
    const [subs, pool] = await Promise.all([tauri.subscriptionsList(), tauri.poolList()]);
    set({ subs, pool });
  },

  refreshOne: async (id) => {
    set({ error: null });
    try {
      await tauri.subscriptionRefresh(id);
      const [subs, pool] = await Promise.all([tauri.subscriptionsList(), tauri.poolList()]);
      set({ subs, pool });
    } catch (e) {
      set({ error: errMsg(e) });
    }
  },

  probeAll: async () => {
    const pool = await tauri.poolProbeAll();
    set({ pool });
  },
}));

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
