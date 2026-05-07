import { useEffect } from "react";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { I18nProvider } from "./lib/i18n";
import { Layout } from "./components/Layout";
import { AddServer } from "./pages/AddServer";
import { Home } from "./pages/Home";
import { Pool } from "./pages/Pool";
import { ProfileEditor } from "./pages/ProfileEditor";
import { Routing } from "./pages/Routing";
import { Settings } from "./pages/Settings";
import { Subscriptions } from "./pages/Subscriptions";
import { useProfileStore } from "./stores/profile";
import { useConnectionStore } from "./stores/connection";
import { tauri } from "./lib/tauri";

export function App() {
  const hydrate = useProfileStore((s) => s.hydrate);
  const startPolling = useConnectionStore((s) => s.startPolling);
  const stopPolling = useConnectionStore((s) => s.stopPolling);

  useEffect(() => {
    void hydrate();
  }, [hydrate]);

  useEffect(() => {
    startPolling();
    return () => stopPolling();
  }, [startPolling, stopPolling]);

  // Tray clicks emit "tray-click" with the menu id. Phase 3 surfaces only
  // navigation; the actual connect/disconnect logic lives on Home.
  useEffect(() => {
    let unsubscribe: (() => void) | null = null;
    void (async () => {
      unsubscribe = await tauri.on<string>("tray-click", (id) => {
        if (id === "connect" || id === "disconnect") {
          window.location.hash = "/";
        }
      });
    })();
    return () => {
      unsubscribe?.();
    };
  }, []);

  return (
    <I18nProvider>
      <HashRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Home />} />
            <Route path="profile" element={<ProfileEditor />} />
            <Route path="add-server" element={<AddServer />} />
            <Route path="subscriptions" element={<Subscriptions />} />
            <Route path="pool" element={<Pool />} />
            <Route path="routing" element={<Routing />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </HashRouter>
    </I18nProvider>
  );
}
