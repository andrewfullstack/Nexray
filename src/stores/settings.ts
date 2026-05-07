import { create } from "zustand";
import { DEFAULT_APP_SETTINGS, type AppInfo, type AppSettings } from "../lib/ipc";
import { tauri } from "../lib/tauri";

interface SettingsStore {
  settings: AppSettings;
  info: AppInfo | null;
  loading: boolean;
  error: string | null;

  hydrate: () => Promise<void>;
  setAutoUpdate: (v: boolean) => Promise<void>;
}

export const useSettingsStore = create<SettingsStore>((set, get) => ({
  settings: DEFAULT_APP_SETTINGS,
  info: null,
  loading: true,
  error: null,

  hydrate: async () => {
    try {
      const [settings, info] = await Promise.all([tauri.settingsGet(), tauri.appInfo()]);
      set({ settings, info, loading: false, error: null });
    } catch (e) {
      set({ loading: false, error: errMsg(e) });
    }
  },

  setAutoUpdate: async (v) => {
    const settings = { ...get().settings, autoUpdateOptIn: v };
    try {
      const saved = await tauri.settingsSet(settings);
      set({ settings: saved });
    } catch (e) {
      set({ error: errMsg(e) });
    }
  },
}));

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
