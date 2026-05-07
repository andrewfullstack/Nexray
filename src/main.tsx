import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// Suppress the native right-click context menu app-wide. Tauri's webview
// otherwise shows a generic browser-style menu (Inspect Element, etc.)
// which leaks dev-tools entry points and breaks the desktop-app feel.
// Native paste / cut / copy keyboard shortcuts (⌘V etc.) still work
// inside inputs and textareas.
window.addEventListener("contextmenu", (e) => {
  e.preventDefault();
});

const root = document.getElementById("root");
if (!root) {
  throw new Error("Root element #root not found in index.html");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
