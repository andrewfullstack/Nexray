import { create } from "zustand";
import {
  DEFAULT_ROUTING_SETTINGS,
  type CustomRule,
  type DnsConfig,
  type RoutingPreset,
  type RoutingSettings,
} from "../lib/ipc";
import { tauri } from "../lib/tauri";

interface RoutingStore {
  settings: RoutingSettings;
  loading: boolean;
  error: string | null;
  dirty: boolean;

  hydrate: () => Promise<void>;
  setPreset: (preset: RoutingPreset) => void;
  setDns: (dns: DnsConfig) => void;
  addRule: (rule: CustomRule) => void;
  updateRule: (id: string, patch: Partial<CustomRule>) => void;
  deleteRule: (id: string) => void;
  reset: () => void;
  save: () => Promise<void>;
}

export const useRoutingStore = create<RoutingStore>((set, get) => ({
  settings: DEFAULT_ROUTING_SETTINGS,
  loading: true,
  error: null,
  dirty: false,

  hydrate: async () => {
    try {
      const settings = await tauri.routingGet();
      set({ settings, loading: false, error: null, dirty: false });
    } catch (e) {
      set({ loading: false, error: errMsg(e) });
    }
  },

  setPreset: (preset) =>
    set((s) => ({ settings: { ...s.settings, preset }, dirty: true })),

  setDns: (dns) => set((s) => ({ settings: { ...s.settings, dns }, dirty: true })),

  addRule: (rule) =>
    set((s) => ({
      settings: { ...s.settings, customRules: [...s.settings.customRules, rule] },
      dirty: true,
    })),

  updateRule: (id, patch) =>
    set((s) => ({
      settings: {
        ...s.settings,
        customRules: s.settings.customRules.map((r) =>
          r.id === id ? { ...r, ...patch } : r,
        ),
      },
      dirty: true,
    })),

  deleteRule: (id) =>
    set((s) => ({
      settings: {
        ...s.settings,
        customRules: s.settings.customRules.filter((r) => r.id !== id),
      },
      dirty: true,
    })),

  reset: () =>
    set({ settings: DEFAULT_ROUTING_SETTINGS, dirty: true, error: null }),

  save: async () => {
    try {
      const saved = await tauri.routingSet(get().settings);
      set({ settings: saved, dirty: false, error: null });
    } catch (e) {
      set({ error: errMsg(e) });
      throw e;
    }
  },
}));

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
