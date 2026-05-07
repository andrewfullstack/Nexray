import { create } from "zustand";
import type { TunCapabilities, TunStatus } from "../lib/ipc";
import { tauri } from "../lib/tauri";

const initialStatus: TunStatus = {
  state: "disabled",
  interfaceName: null,
  sinceMs: null,
  lastError: null,
};

interface TunStore {
  status: TunStatus;
  capabilities: TunCapabilities | null;
  busy: boolean;

  hydrate: () => Promise<void>;
  pollStatus: () => Promise<void>;
  enable: () => Promise<void>;
  disable: () => Promise<void>;
}

export const useTunStore = create<TunStore>((set) => ({
  status: initialStatus,
  capabilities: null,
  busy: false,

  hydrate: async () => {
    try {
      const [capabilities, status] = await Promise.all([
        tauri.tunCapabilities(),
        tauri.tunStatus(),
      ]);
      set({ capabilities, status });
    } catch {
      // Backend not ready (e.g. during boot) — leave defaults.
    }
  },

  pollStatus: async () => {
    try {
      const status = await tauri.tunStatus();
      set({ status });
    } catch {
      // ignore transient
    }
  },

  enable: async () => {
    set({ busy: true });
    try {
      const status = await tauri.tunEnable();
      set({ status });
    } finally {
      set({ busy: false });
    }
  },

  disable: async () => {
    set({ busy: true });
    try {
      const status = await tauri.tunDisable();
      set({ status });
    } finally {
      set({ busy: false });
    }
  },
}));
