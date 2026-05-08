import { type ReactNode } from "react";
import { IntlProvider } from "react-intl";
import { getCatalog } from "../messages/catalogs";
import { useLocaleStore } from "../stores/locale";

/**
 * react-intl provider. The active locale is sourced from the Zustand
 * locale store, which hydrates from disk on app startup and falls back
 * to the platform language on first launch. Switching the locale in
 * Settings is just a `setLocale(...)` call away — every consumer of
 * `<FormattedMessage>` re-renders against the new catalog automatically.
 */
export function I18nProvider({ children }: { children: ReactNode }) {
  const locale = useLocaleStore((s) => s.locale);
  const messages = getCatalog(locale);
  return (
    <IntlProvider locale={locale} messages={messages} defaultLocale="en">
      {children}
    </IntlProvider>
  );
}
