import { useProfileStore } from "../stores/profile";
import { useConnectionStore } from "../stores/connection";
import { tauri } from "./tauri";

/// Maximum consecutive failed connect attempts on a single profile before
/// auto-switch fires (when the profile's group has Auto mode enabled).
/// The user picked "1 original + 4 retries" — generous enough to ride out
/// transient network blips, tight enough to escalate before users start
/// suspecting Nexray itself is broken.
export const AUTO_SWITCH_FAIL_THRESHOLD = 5;

/// Try to recover from repeated connection failures by swapping the
/// active profile to a healthier server in the same subscription group,
/// or by disconnecting if no working alternative exists. Caller has
/// already validated the threshold was hit; this function decides
/// whether/where to switch.
///
/// Quiet bail-outs (no error, no toast) when:
///   - the failed profile is no longer active (user switched manually);
///   - the active profile isn't tagged with a subscription group;
///   - the group's Auto mode is off;
///   - the group is empty.
///
/// Probe failure (network down, IPC error) is also a quiet bail-out — we
/// don't want a single-shot probe error to escalate to a disconnect when
/// the user might still want to keep retrying manually.
export async function tryAutoSwitchOnFailure(
  failedProfileId: string,
): Promise<void> {
  const profileStore = useProfileStore.getState();
  const active = profileStore.active;
  if (!active || active.id !== failedProfileId) return;
  const subId = profileStore.groups[active.id];
  if (!subId) return;
  if (!profileStore.groupSettings[subId]?.autoSwitch) return;

  const groupProfiles = profileStore.manualProfiles.filter(
    (p) => profileStore.groups[p.id] === subId,
  );
  if (groupProfiles.length === 0) return;

  let probeResults;
  try {
    probeResults = await tauri.probeProfiles(groupProfiles);
  } catch (e) {
    console.error("[auto-switch] probe failed:", e);
    return;
  }
  const latencyById = new Map<string, number | null>();
  for (const r of probeResults) latencyById.set(r.profileId, r.latencyMs);

  // Candidates: numeric latency AND not the currently-failing profile.
  // We exclude the failing profile because we *know* its protocol layer
  // is broken (5 failures), even if its TCP-connect probe still
  // succeeds. Switching to it would just loop the failure.
  const candidates = groupProfiles.filter((p) => {
    if (p.id === failedProfileId) return false;
    return typeof latencyById.get(p.id) === "number";
  });

  if (candidates.length === 0) {
    // No working alternative — disconnect rather than thrash. Per the
    // spec: "if all servers in the list are all timeout, disconnect
    // automatically".
    console.warn(
      `[auto-switch] every other server in group ${subId} timed out; disconnecting`,
    );
    await useConnectionStore.getState().disconnect();
    return;
  }

  candidates.sort((a, b) => {
    const la = latencyById.get(a.id) as number;
    const lb = latencyById.get(b.id) as number;
    return la - lb;
  });

  // The non-empty check above proves candidates[0] exists, but TS's
  // noUncheckedIndexedAccess can't follow that across the sort, so a
  // narrowing assignment keeps the rest of the function strictly typed.
  const next = candidates[0];
  if (!next) return;
  console.info(
    `[auto-switch] ${failedProfileId} failed ${AUTO_SWITCH_FAIL_THRESHOLD}× → switching to ${next.id} (${latencyById.get(next.id)} ms)`,
  );
  await profileStore.setActive(next);
  // setActive reconnects only when the connection is currently live.
  // After the threshold fires the sidecar is in `disconnected` or
  // `crashed`, so reconnectIfLive is a no-op — kick the new connect
  // explicitly. The new profile id starts its own failure counter; if
  // it also fails 5×, we recurse through the group until we land on a
  // working one or run out of candidates.
  await useConnectionStore.getState().connect(next);
}
