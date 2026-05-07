import { create } from "zustand";
import type { ConnectionStatus, TrafficStats } from "../lib/ipc";
import { tauri } from "../lib/tauri";
import type { Profile } from "../lib/profile";

const POLL_MS = 1000;
const SPARK_LEN = 60; // 60 samples ≈ last minute of bytes/sec

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

export const useConnectionStore = create<ConnectionStore>((set, get) => ({
  status: initialStatus,
  stats: initialStats,
  spark: { up: Array(SPARK_LEN).fill(0), down: Array(SPARK_LEN).fill(0) },
  pollHandle: null,
  busy: false,
  actionError: null,

  clearActionError: () => set({ actionError: null }),

  startPolling: () => {
    if (get().pollHandle !== null) return;
    const tick = async () => {
      try {
        const status = await tauri.status();
        const stats = await tauri.trafficStats();
        const dUp = stats.available ? Math.max(0, stats.uplinkBytes - lastUp) : 0;
        const dDown = stats.available
          ? Math.max(0, stats.downlinkBytes - lastDown)
          : 0;
        if (stats.available) {
          lastUp = stats.uplinkBytes;
          lastDown = stats.downlinkBytes;
        }
        set((s) => ({
          status,
          stats,
          spark: {
            up: [...s.spark.up.slice(1), dUp],
            down: [...s.spark.down.slice(1), dDown],
          },
        }));
      } catch (e) {
        console.error("[poll] failed", e);
      }
    };
    void tick();
    const handle = window.setInterval(tick, POLL_MS);
    set({ pollHandle: handle });
  },

  stopPolling: () => {
    const h = get().pollHandle;
    if (h !== null) {
      window.clearInterval(h);
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
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("connect failed", e);
      set({ actionError: msg });
    } finally {
      set({ busy: false });
    }
  },

  disconnect: async () => {
    set({ busy: true, actionError: null });
    try {
      const status = await tauri.disconnect();
      set({ status, stats: initialStats });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("disconnect failed", e);
      set({ actionError: msg });
    } finally {
      set({ busy: false });
    }
  },
}));
