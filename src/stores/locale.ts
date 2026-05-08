import { create } from "zustand";
import { detectLocale, type Locale } from "../messages/catalogs";
import { loadLocale, saveLocale } from "../lib/persistence";

interface LocaleStore {
  locale: Locale;
  /** True until `hydrate` finishes once. The provider renders English
   *  during this brief window — startup is fast enough that any flash
   *  of the wrong language is invisible in practice. */
  loading: boolean;
  hydrate: () => Promise<void>;
  setLocale: (locale: Locale) => Promise<void>;
}

/// Persisted UI-locale state. Locale is a pure UI concern (the Rust
/// shell never reads it), so it lives in its own zustand store rather
/// than sharing the AppSettings round-trip — keeps the JSON IPC schema
/// free of frontend-only fields and avoids dragging the gen-rust-types
/// pipeline into a one-line preference change.
export const useLocaleStore = create<LocaleStore>((set) => ({
  locale: "en",
  loading: true,

  hydrate: async () => {
    const saved = await loadLocale();
    if (saved !== null) {
      set({ locale: saved, loading: false });
      return;
    }
    // First launch — guess from the platform language. We persist the
    // detected value too so subsequent launches don't re-run detection
    // (and so an explicit Settings change starts from a known state).
    const detected = detectLocale(navigator.language);
    try {
      await saveLocale(detected);
    } catch {
      /* persistence is a best-effort optimisation here */
    }
    set({ locale: detected, loading: false });
  },

  setLocale: async (locale) => {
    await saveLocale(locale);
    set({ locale });
  },
}));
