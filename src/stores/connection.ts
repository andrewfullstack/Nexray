import { create } from "zustand";
import type { ConnectionStatus, TrafficStats } from "../lib/ipc";
import { tauri } from "../lib/tauri";
import type { Profile } from "../lib/profile";
import { useTunStore } from "./tun";
import {
  AUTO_SWITCH_FAIL_THRESHOLD,
  tryAutoSwitchOnFailure,
} from "../lib/auto-switch";

/// Poll cadence for status + traffic-stats. Three seconds is a calmer
/// rhythm than the original 1Hz: the Up/Down hero numbers still feel
/// live, and the per-second `xray api statsquery` subprocess churn
/// (visible in the xray log as a fresh `[api-in -> api]` accept every
/// tick) drops 3×. Combined with the visibility pause below, an idle
/// minimised window now does zero stats RPCs.
const POLL_MS = 3000;
/// Convenience for converting raw byte deltas (bytes since the previous
/// poll) into a per-second rate. The UI's `formatRate` always labels
/// the value with `/s`, so this normalisation must change in lockstep
/// with `POLL_MS`.
const POLL_SECONDS = POLL_MS / 1000;
const SPARK_LEN = 60; // 60 samples ≈ last 3 minutes of bytes/sec

interface ConnectionStore {
  status: ConnectionStatus;
  stats: TrafficStats;
  /** Ring buffer of (uplink, downlink) bytes-per-second deltas. */
  spark: { up: number[]; down: number[] };
  pollHandle: number | null;
  /** Whether a connect / disconnect call is in flight. */
  busy: boolean;
  /** Most recent error from a user-initiated connect / disconnect call.
   *  Distinct from `status.lastError`, which is the xray-core stderr line. */
  actionError: string | null;
  /** Counter for consecutive failed connects on `lastFailedProfileId`.
   *  Used by the failure-driven auto-switch — when this hits the
   *  threshold we probe the active profile's group and either swap to a
   *  healthier server or disconnect if everything's down. */
  consecutiveFailures: number;
  /** Profile id the failure counter is tracking. Reset on a successful
   *  connect, manual disconnect, or when a different profile fails. */
  lastFailedProfileId: string | null;

  startPolling: () => void;
  stopPolling: () => void;

  clearActionError: () => void;
  connect: (profile: Profile) => Promise<void>;
  disconnect: () => Promise<void>;
}

const initialStatus: ConnectionStatus = {
  state: "disconnected",
  profileId: null,
  socksPort: null,
  sinceMs: null,
  lastError: null,
};

const initialStats: TrafficStats = {
  available: false,
  uplinkBytes: 0,
  downlinkBytes: 0,
};

let lastUp = 0;
let lastDown = 0;
/// Reference to the `visibilitychange` listener we install in
/// `startPolling`, kept module-level so `stopPolling` can detach it.
let visibilityHandler: (() => void) | null = null;

export const useConnectionStore = create<ConnectionStore>((set, get) => {
  /// Increment the failure counter for `profileId`. Resets to 1 if the
  /// previous failure was on a different profile. When the count hits
  /// the threshold we reset it and fire the auto-switch coordinator —
  /// resetting first means a probe failure (fire-and-forget rejection)
  /// doesn't permanently arm the next failure to immediately re-fire.
  const recordFailure = (profileId: string) => {
    const cur = get();
    const failures =
      cur.lastFailedProfileId === profileId ? cur.consecutiveFailures + 1 : 1;
    set({
      consecutiveFailures: failures,
      lastFailedProfileId: profileId,
    });
    if (failures >= AUTO_SWITCH_FAIL_THRESHOLD) {
      set({ consecutiveFailures: 0, lastFailedProfileId: null });
      void tryAutoSwitchOnFailure(profileId);
    }
  };

  return {
    status: initialStatus,
    stats: initialStats,
    spark: { up: Array(SPARK_LEN).fill(0), down: Array(SPARK_LEN).fill(0) },
    pollHandle: null,
    busy: false,
    actionError: null,
    consecutiveFailures: 0,
    lastFailedProfileId: null,

    clearActionError: () => set({ actionError: null }),

    startPolling: () => {
      if (get().pollHandle !== null) return;
      const tick = async () => {
        // Skip when the window is hidden — minimised, behind another
        // app, on another macOS Space, or the user switched tabs in a
        // dev browser preview. The user can't see the numbers, so the
        // 3-second `tauri.status()`/`tauri.trafficStats()` RPCs would
        // be pure waste. The `visibilitychange` listener below fires
        // an immediate tick when the window comes back, so re-show
        // doesn't sit on stale data for up to POLL_MS.
        if (typeof document !== "undefined" && document.hidden) return;
        try {
          const status = await tauri.status();
          const stats = await tauri.trafficStats();
          // Bytes-per-second: divide the raw byte delta by the poll
          // interval in seconds. Raw delta would only equal "B/s" by
          // accident at POLL_MS = 1000.
          const dUp = stats.available
            ? Math.max(0, stats.uplinkBytes - lastUp) / POLL_SECONDS
            : 0;
          const dDown = stats.available
            ? Math.max(0, stats.downlinkBytes - lastDown) / POLL_SECONDS
            : 0;
          if (stats.available) {
            lastUp = stats.uplinkBytes;
            lastDown = stats.downlinkBytes;
          }
          // Detect xray-sidecar crashes: the second failure mode the
          // auto-switch coordinator reacts to. The connect IPC catches
          // synchronous failures; this catches "xray started, then died".
          // Edge-trigger on connected/connecting → crashed so each crash
          // event records exactly one failure.
          const prev = get().status;
          const justCrashed =
            status.state === "crashed" &&
            (prev.state === "connected" || prev.state === "connecting");
          set((s) => ({
            status,
            stats,
            spark: {
              up: [...s.spark.up.slice(1), dUp],
              down: [...s.spark.down.slice(1), dDown],
            },
          }));
          if (justCrashed && status.profileId) {
            recordFailure(status.profileId);
          }
        } catch (e) {
          console.error("[poll] failed", e);
        }
      };
      void tick();
      const handle = window.setInterval(tick, POLL_MS);

      // Wake the poller as soon as the window becomes visible again so
      // the user sees fresh numbers immediately rather than waiting up
      // to POLL_MS for the next interval fire.
      const onVisibility = () => {
        if (typeof document !== "undefined" && !document.hidden) {
          void tick();
        }
      };
      if (typeof document !== "undefined") {
        document.addEventListener("visibilitychange", onVisibility);
      }
      visibilityHandler = onVisibility;

      set({ pollHandle: handle });
    },

    stopPolling: () => {
      const h = get().pollHandle;
      if (h !== null) {
        window.clearInterval(h);
        if (visibilityHandler && typeof document !== "undefined") {
          document.removeEventListener("visibilitychange", visibilityHandler);
        }
        visibilityHandler = null;
        set({ pollHandle: null });
      }
    },

    connect: async (profile) => {
      set({ busy: true, actionError: null });
      try {
        const status = await tauri.connect({ profile });
        lastUp = 0;
        lastDown = 0;
        set({
          status,
          spark: { up: Array(SPARK_LEN).fill(0), down: Array(SPARK_LEN).fill(0) },
          consecutiveFailures: 0,
          lastFailedProfileId: null,
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error("connect failed", e);
        set({ actionError: msg });
        recordFailure(profile.id);
      } finally {
        set({ busy: false });
      }
    },

    disconnect: async () => {
      set({ busy: true, actionError: null });
      try {
        const status = await tauri.disconnect();
        set({
          status,
          stats: initialStats,
          consecutiveFailures: 0,
          lastFailedProfileId: null,
        });
        // Backend disconnect cascades TUN + system-proxy teardown.
        // Trigger an immediate refresh of the TUN store so the toggle
        // flips without waiting for its 2s poll. SystemProxyToggle
        // refreshes via its own 3s poll.
        void useTunStore.getState().pollStatus();
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error("disconnect failed", e);
        set({ actionError: msg });
      } finally {
        set({ busy: false });
      }
    },
  };
});
