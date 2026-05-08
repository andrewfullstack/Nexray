import { en } from "./en";
import { zhCN } from "./zh-CN";
import { zhTW } from "./zh-TW";
import { ru } from "./ru";

/** Locales bundled with the app. Adding a new one means: drop a
 *  `<tag>.ts` into this directory mirroring `en.ts`'s keys, then list
 *  the tag here + map it in `CATALOGS` and `LOCALE_LABELS`. */
export type Locale = "en" | "zh-CN" | "zh-TW" | "ru";

export const LOCALES: readonly Locale[] = ["en", "zh-CN", "zh-TW", "ru"];

/** Display label for the locale picker. Each label is rendered in the
 *  language it represents — users searching for their language read the
 *  endonym, not the English exonym. */
export const LOCALE_LABELS: Record<Locale, string> = {
  en: "English",
  "zh-CN": "简体中文",
  "zh-TW": "繁體中文",
  ru: "Русский",
};

const CATALOGS: Record<Locale, Record<string, string>> = {
  en,
  "zh-CN": zhCN,
  "zh-TW": zhTW,
  ru,
};

export function getCatalog(locale: Locale): Record<string, string> {
  return CATALOGS[locale];
}

/** Best-effort match of a BCP-47 tag (e.g. from `navigator.language`) to
 *  one of our bundled locales. Falls back to English. The Chinese
 *  branches use script-region heuristics so a user in HK/MO/TW lands on
 *  Traditional, while everyone else with `zh*` lands on Simplified. */
export function detectLocale(tag: string | undefined): Locale {
  if (!tag) return "en";
  const lower = tag.toLowerCase();
  if (lower.startsWith("zh")) {
    if (
      lower.startsWith("zh-tw") ||
      lower.startsWith("zh-hk") ||
      lower.startsWith("zh-mo") ||
      lower.includes("hant")
    ) {
      return "zh-TW";
    }
    return "zh-CN";
  }
  if (lower.startsWith("ru")) return "ru";
  return "en";
}

/** Type guard used when reading a persisted locale value off disk. */
export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}
