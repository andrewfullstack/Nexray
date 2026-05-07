// Phase 0/1/2 entrypoint. Delegates to `nexray::run` so the real shell logic
// lives in the lib crate and integration tests can exercise it.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() {
    nexray::run();
}
