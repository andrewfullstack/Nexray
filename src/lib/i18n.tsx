import { type ReactNode } from "react";
import { IntlProvider } from "react-intl";
import { en } from "../messages/en";

/**
 * react-intl provider. Phase 3 ships the `en` catalog only. Adding `zh-CN`
 * etc. is a one-line `import` + `<I18nProvider locale="zh-CN" messages={zh}>`.
 */
export function I18nProvider({ children }: { children: ReactNode }) {
  return (
    <IntlProvider locale="en" messages={en} defaultLocale="en">
      {children}
    </IntlProvider>
  );
}
