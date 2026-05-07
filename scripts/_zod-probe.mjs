// Internal helper for gen-rust-types.mjs.
//
// Loaded via `node --import tsx/esm` so it can import the TS Zod schemas
// directly. Emits a single JSON document on stdout describing the shape of
// each schema. Imported only by gen-rust-types.mjs, not by the app.

import {
  CdnWsProfileSchema,
  RealityProfileSchema,
} from "../src/lib/profile.ts";
import {
  ConnectionStatusSchema,
  TrafficStatsSchema,
  ConnectRequestSchema,
  SubscriptionSchema,
  AddSubscriptionRequestSchema,
  SubscriptionIdRequestSchema,
  CustomRuleSchema,
  DnsConfigSchema,
  RoutingSettingsSchema,
  SetRoutingRequestSchema,
  TunStatusSchema,
  TunCapabilitiesSchema,
  SystemProxyStatusSchema,
  AppSettingsSchema,
  SetSettingsRequestSchema,
  AppInfoSchema,
} from "../src/lib/ipc.ts";

function describe(schema) {
  // Discriminated union members go through z.object. Pull `.shape`.
  const shape = schema._def?.shape ? schema._def.shape() : schema.shape;
  const keys = Object.keys(shape);
  return { keys };
}

const out = {
  CdnWsProfile: describe(CdnWsProfileSchema),
  RealityProfile: describe(RealityProfileSchema),
  ConnectionStatus: describe(ConnectionStatusSchema),
  TrafficStats: describe(TrafficStatsSchema),
  ConnectRequest: describe(ConnectRequestSchema),
  Subscription: describe(SubscriptionSchema),
  AddSubscriptionRequest: describe(AddSubscriptionRequestSchema),
  SubscriptionIdRequest: describe(SubscriptionIdRequestSchema),
  CustomRule: describe(CustomRuleSchema),
  DnsConfig: describe(DnsConfigSchema),
  RoutingSettings: describe(RoutingSettingsSchema),
  SetRoutingRequest: describe(SetRoutingRequestSchema),
  TunStatus: describe(TunStatusSchema),
  TunCapabilities: describe(TunCapabilitiesSchema),
  SystemProxyStatus: describe(SystemProxyStatusSchema),
  AppSettings: describe(AppSettingsSchema),
  SetSettingsRequest: describe(SetSettingsRequestSchema),
  AppInfo: describe(AppInfoSchema),
};

process.stdout.write(JSON.stringify(out));
