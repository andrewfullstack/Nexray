//! System tray icon. Per DEVELOPMENT.md §13 lean (recorded in
//! docs/ARCHITECTURE.md): minimal Connect / Disconnect / Quit menu.
//!
//! Connect & Disconnect emit a `tray-click` event with the menu id; the React
//! UI listens for this and invokes the matching IPC command. Doing the
//! command-invoke directly here would couple the tray to AppState, which is
//! awkward (Tauri menu callbacks don't receive `State<T>` cleanly).

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter};

pub fn install(app: &mut tauri::App) -> tauri::Result<()> {
    let handle: AppHandle = app.handle().clone();

    let connect = MenuItem::with_id(&handle, "connect", "Connect", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(&handle, "disconnect", "Disconnect", true, None::<&str>)?;
    let quit = MenuItem::with_id(&handle, "quit", "Quit Nexray", true, None::<&str>)?;
    let menu = Menu::with_items(&handle, &[&connect, &disconnect, &quit])?;

    // tauri.conf.json bundles src-tauri/icons/icon.png; expect it present.
    let Some(icon) = handle.default_window_icon().cloned() else {
        tracing::error!("no default window icon — skipping tray install");
        return Ok(());
    };

    let _tray = TrayIconBuilder::new()
        .icon(icon)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "quit" => app.exit(0),
            other => {
                let _ = app.emit("tray-click", other.to_string());
            }
        })
        .build(&handle)?;

    Ok(())
}
