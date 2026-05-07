import { invoke as rawInvoke } from "@tauri-apps/api/core";
import { listen as rawListen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  AppInfoSchema,
  AppSettingsSchema,
  ConnectionStatusSchema,
  EgressCheckSchema,
  ProbeResultSchema,
  RoutingSettingsSchema,
  SubscriptionSchema,
  SystemProxyStatusSchema,
  TrafficStatsSchema,
  TunCapabilitiesSchema,
  TunStatusSchema,
  type AddSubscriptionRequest,
  type AppInfo,
  type AppSettings,
  type ConnectionStatus,
  type ConnectRequest,
  type EgressCheck,
  type ProbeResult,
  type RoutingSettings,
  type Subscription,
  type SystemProxyStatus,
  type TrafficStats,
  type TunCapabilities,
  type TunStatus,
} from "./ipc";
import type { Profile } from "./profile";
import { z } from "zod";

/**
 * Typed Tauri-IPC client. Every command argument and response goes through a
 * Zod parse — the wire format is the JSON the Rust shell `serde`-encodes from
 * its mirror of the same schema. Mismatches surface here, loudly, with the
 * field name in the error message.
 */
export const tauri = {
  async ping(): Promise<string> {
    const r = await rawInvoke<string>("ping");
    if (typeof r !== "string") throw new Error("ping: expected string");
    return r;
  },

  async connect(req: ConnectRequest): Promise<ConnectionStatus> {
    const raw = await rawInvoke<unknown>("connect", { req });
    return ConnectionStatusSchema.parse(raw);
  },

  async disconnect(): Promise<ConnectionStatus> {
    const raw = await rawInvoke<unknown>("disconnect");
    return ConnectionStatusSchema.parse(raw);
  },

  async status(): Promise<ConnectionStatus> {
    const raw = await rawInvoke<unknown>("status");
    return ConnectionStatusSchema.parse(raw);
  },

  async trafficStats(): Promise<TrafficStats> {
    const raw = await rawInvoke<unknown>("traffic_stats");
    return TrafficStatsSchema.parse(raw);
  },

  async egressCheck(): Promise<EgressCheck> {
    const raw = await rawInvoke<unknown>("egress_check");
    return EgressCheckSchema.parse(raw);
  },

  // ---- Subscriptions / pool ------------------------------------------------

  async subscriptionsList(): Promise<Subscription[]> {
    const raw = await rawInvoke<unknown>("subscriptions_list");
    return z.array(SubscriptionSchema).parse(raw);
  },

  async subscriptionAdd(req: AddSubscriptionRequest): Promise<Subscription> {
    const raw = await rawInvoke<unknown>("subscription_add", { req });
    return SubscriptionSchema.parse(raw);
  },

  async subscriptionDelete(id: string): Promise<void> {
    await rawInvoke<unknown>("subscription_delete", { req: { id } });
  },

  async subscriptionRefresh(id: string): Promise<Subscription> {
    const raw = await rawInvoke<unknown>("subscription_refresh", { req: { id } });
    return SubscriptionSchema.parse(raw);
  },

  async probeProfiles(profiles: Profile[]): Promise<ProbeResult[]> {
    const raw = await rawInvoke<unknown>("probe_profiles", { profiles });
    return z.array(ProbeResultSchema).parse(raw);
  },

  // ---- Routing -------------------------------------------------------------

  async routingGet(): Promise<RoutingSettings> {
    const raw = await rawInvoke<unknown>("routing_get");
    return RoutingSettingsSchema.parse(raw);
  },

  async routingSet(settings: RoutingSettings): Promise<RoutingSettings> {
    const raw = await rawInvoke<unknown>("routing_set", { req: { settings } });
    return RoutingSettingsSchema.parse(raw);
  },

  // ---- TUN -----------------------------------------------------------------

  async tunCapabilities(): Promise<TunCapabilities> {
    const raw = await rawInvoke<unknown>("tun_capabilities");
    return TunCapabilitiesSchema.parse(raw);
  },

  async tunStatus(): Promise<TunStatus> {
    const raw = await rawInvoke<unknown>("tun_status");
    return TunStatusSchema.parse(raw);
  },

  async tunEnable(): Promise<TunStatus> {
    const raw = await rawInvoke<unknown>("tun_enable");
    return TunStatusSchema.parse(raw);
  },

  async tunDisable(): Promise<TunStatus> {
    const raw = await rawInvoke<unknown>("tun_disable");
    return TunStatusSchema.parse(raw);
  },

  // ---- System proxy --------------------------------------------------------

  async systemProxyStatus(): Promise<SystemProxyStatus> {
    const raw = await rawInvoke<unknown>("system_proxy_status");
    return SystemProxyStatusSchema.parse(raw);
  },

  async systemProxyEnable(): Promise<SystemProxyStatus> {
    const raw = await rawInvoke<unknown>("system_proxy_enable");
    return SystemProxyStatusSchema.parse(raw);
  },

  async systemProxyDisable(): Promise<SystemProxyStatus> {
    const raw = await rawInvoke<unknown>("system_proxy_disable");
    return SystemProxyStatusSchema.parse(raw);
  },

  // ---- Settings + About ----------------------------------------------------

  async settingsGet(): Promise<AppSettings> {
    const raw = await rawInvoke<unknown>("settings_get");
    return AppSettingsSchema.parse(raw);
  },

  async settingsSet(settings: AppSettings): Promise<AppSettings> {
    const raw = await rawInvoke<unknown>("settings_set", { req: { settings } });
    return AppSettingsSchema.parse(raw);
  },

  async appInfo(): Promise<AppInfo> {
    const raw = await rawInvoke<unknown>("app_info");
    return AppInfoSchema.parse(raw);
  },

  // ---- Rules file ----------------------------------------------------------

  async rulesFileGet(): Promise<string> {
    const raw = await rawInvoke<string>("rules_file_get");
    if (typeof raw !== "string") throw new Error("rules_file_get: not a string");
    return raw;
  },

  async rulesFileSet(contents: string): Promise<void> {
    await rawInvoke<unknown>("rules_file_set", { contents });
  },

  async rulesFileAppend(req: {
    matcherType: string;
    matcher: string;
    destination: string;
    noResolve: boolean;
  }): Promise<void> {
    await rawInvoke<unknown>("rules_file_append", {
      matcherType: req.matcherType,
      matcher: req.matcher,
      destination: req.destination,
      noResolve: req.noResolve,
    });
  },

  async rulesFileSetEnabled(ruleIndex: number, enabled: boolean): Promise<void> {
    await rawInvoke<unknown>("rules_file_set_enabled", { ruleIndex, enabled });
  },

  async rulesFileSetDestination(
    ruleIndex: number,
    destination: "direct" | "proxy" | "block",
  ): Promise<void> {
    await rawInvoke<unknown>("rules_file_set_destination", {
      ruleIndex,
      destination,
    });
  },

  async rulesFileDelete(ruleIndex: number): Promise<void> {
    await rawInvoke<unknown>("rules_file_delete", { ruleIndex });
  },

  async rulesFileReset(): Promise<void> {
    await rawInvoke<unknown>("rules_file_reset");
  },

  /** Subscribe to a Tauri event. Returns an unsubscribe function. */
  async on<T>(name: string, handler: (payload: T) => void): Promise<UnlistenFn> {
    return rawListen<T>(name, (event) => handler(event.payload));
  },
};
