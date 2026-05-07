import { create } from "zustand";
import {
  parseRulesConf,
  type ParseStats,
  type RuleDestination,
} from "../lib/rules-conf";
import { tauri } from "../lib/tauri";

interface RulesFileStore {
  contents: string;
  parsed: ParseStats;
  loading: boolean;
  error: string | null;

  hydrate: () => Promise<void>;
  saveRaw: (text: string) => Promise<void>;
  appendRule: (req: {
    matcherType: string;
    matcher: string;
    destination: string;
    noResolve: boolean;
  }) => Promise<void>;
  toggleEnabled: (index: number, enabled: boolean) => Promise<void>;
  setRuleDestination: (index: number, destination: RuleDestination) => Promise<void>;
  deleteRule: (index: number) => Promise<void>;
  resetToDefault: () => Promise<void>;
}

const empty: ParseStats = {
  rules: [],
  totalRules: 0,
  disabledCount: 0,
  unsupportedCount: 0,
};

export const useRulesFileStore = create<RulesFileStore>((set) => ({
  contents: "",
  parsed: empty,
  loading: true,
  error: null,

  hydrate: async () => {
    try {
      const text = await tauri.rulesFileGet();
      set({
        contents: text,
        parsed: parseRulesConf(text),
        loading: false,
        error: null,
      });
    } catch (e) {
      set({ loading: false, error: errMsg(e) });
    }
  },

  saveRaw: async (text) => {
    try {
      await tauri.rulesFileSet(text);
      const reloaded = await tauri.rulesFileGet();
      set({
        contents: reloaded,
        parsed: parseRulesConf(reloaded),
        error: null,
      });
    } catch (e) {
      set({ error: errMsg(e) });
      throw e;
    }
  },

  appendRule: async (req) => {
    await tauri.rulesFileAppend(req);
    const text = await tauri.rulesFileGet();
    set({ contents: text, parsed: parseRulesConf(text), error: null });
  },

  toggleEnabled: async (index, enabled) => {
    await tauri.rulesFileSetEnabled(index, enabled);
    const text = await tauri.rulesFileGet();
    set({ contents: text, parsed: parseRulesConf(text) });
  },

  setRuleDestination: async (index, destination) => {
    await tauri.rulesFileSetDestination(index, destination);
    const text = await tauri.rulesFileGet();
    set({ contents: text, parsed: parseRulesConf(text) });
  },

  deleteRule: async (index) => {
    await tauri.rulesFileDelete(index);
    const text = await tauri.rulesFileGet();
    set({ contents: text, parsed: parseRulesConf(text) });
  },

  resetToDefault: async () => {
    await tauri.rulesFileReset();
    const text = await tauri.rulesFileGet();
    set({ contents: text, parsed: parseRulesConf(text), error: null });
  },
}));

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
