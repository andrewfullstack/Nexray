//! Auto-refresh scheduler for subscriptions.
//!
//! Tokio task that ticks every 60s, scans `AppState.subscriptions`, and
//! refreshes any subscription whose `last_fetched_ms` is older than the
//! configured interval (default 6h per DEVELOPMENT.md §5.4). Failed refreshes
//! preserve the existing `profiles` (cached pool keeps serving) and surface
//! `lastFetchError` so the UI can show a non-blocking warning banner.

use std::sync::Arc;
use std::time::Duration;

use nexray_core::Subscription;
use tauri::{AppHandle, Manager};
use tokio::time::interval;

use crate::state::AppState;
use crate::subscription::{self as sub_mod, fetch_and_classify, DEFAULT_REFRESH_INTERVAL};

const TICK: Duration = Duration::from_secs(60);

/// Spawn the auto-refresh task. The task lives until the Tauri app exits.
pub fn spawn(handle: AppHandle) {
    let handle = Arc::new(handle);
    tauri::async_runtime::spawn(async move {
        let mut tick = interval(TICK);
        // Skip the first immediate tick — let the UI hydrate first.
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = tick_once(&handle).await {
                tracing::warn!(target: "scheduler", "tick failed: {e}");
            }
        }
    });
}

async fn tick_once(handle: &AppHandle) -> Result<(), String> {
    let state = handle.state::<AppState>();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Snapshot the (id, url, name, added_ms, last_fetched_ms) tuples that
    // need refreshing. Drop the lock before awaiting any I/O.
    let due: Vec<(String, String, String, u64)> = {
        let guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        guard
            .values()
            .filter(|s| sub_mod::is_due(now_ms, s.last_fetched_ms, DEFAULT_REFRESH_INTERVAL))
            .map(|s| (s.id.clone(), s.url.clone(), s.name.clone(), s.added_ms))
            .collect()
    };

    if due.is_empty() {
        return Ok(());
    }

    for (id, url, name, added_ms) in due {
        let result = fetch_and_classify(&id, &url, &name, added_ms).await;
        let updated = match result {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(target: "scheduler", "refresh failed for {id}: {e}");
                let guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
                let existing = match guard.get(&id) {
                    Some(s) => s.clone(),
                    None => continue,
                };
                Subscription {
                    last_fetch_error: Some(e.to_string()),
                    ..existing
                }
            }
        };
        let mut guard = state.subscriptions.lock().map_err(|e| e.to_string())?;
        guard.insert(updated.id.clone(), updated);
    }

    // Persist after the batch.
    let _ = persist_after(handle, &state);
    Ok(())
}

fn persist_after(handle: &AppHandle, state: &tauri::State<'_, AppState>) -> Result<(), String> {
    use tauri_plugin_store::StoreExt;
    let store = handle
        .store("subscriptions.json")
        .map_err(|e| e.to_string())?;
    let snapshot: Vec<Subscription> = state
        .subscriptions
        .lock()
        .map_err(|e| e.to_string())?
        .values()
        .cloned()
        .collect();
    store.set(
        "subscriptions",
        serde_json::to_value(&snapshot).map_err(|e| e.to_string())?,
    );
    store.save().map_err(|e| e.to_string())?;
    Ok(())
}
