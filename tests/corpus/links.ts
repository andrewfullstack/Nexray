/**
 * Canonical fixtures for share-link and subscription tests. Each constant
 * is exercised by the spec files; do not delete one without removing its
 * usage. Keep UUIDs and public keys synthetic — never paste real ones.
 */

// Valid -- accepted by the parser ------------------------------------------

export const VALID_CDN_WS =
  "vless://550e8400-e29b-41d4-a716-446655440000@104.16.0.1:443" +
  "?type=ws&security=tls&host=cdn.example.com&path=%2F%3Fed%3D2560" +
  "&sni=cdn.example.com&fp=chrome&alpn=h2%2Chttp%2F1.1&encryption=none" +
  "#CDN-Edge";

export const VALID_REALITY =
  "vless://550e8400-e29b-41d4-a716-446655440001@198.51.100.7:443" +
  "?type=tcp&security=reality" +
  "&pbk=zR9LQ8Z3J0xWlb5fK0p9X1m3T7v6yE2u8N4o0aB1cD0" +
  "&sid=abcd1234&fp=chrome&sni=www.microsoft.com" +
  "&flow=xtls-rprx-vision&encryption=none&spx=%2F" +
  "#Reality-VPS";

export const VALID_TROJAN =
  "trojan://secret-pwd@198.51.100.42:443" +
  "?type=tcp&security=tls&sni=trojan.example.com&fp=chrome" +
  "&alpn=h2%2Chttp%2F1.1" +
  "#Trojan-VPS";

// VMess base64-JSON: { v=2, add=198.51.100.77, port=443,
// id=550e8400-...0042, aid=0, scy=auto, net=tcp, type=none, tls=tls,
// sni=vmess.example.com, alpn=h2,http/1.1, fp=chrome, ps=VMess-VPS }.
export const VALID_VMESS =
  "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MtVlBTIiwiYWRkIjoiMTk4LjUxLjEw" +
  "MC43NyIsInBvcnQiOjQ0MywiaWQiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00" +
  "NDY2NTU0NDAwNDIiLCJhaWQiOjAsInNjeSI6ImF1dG8iLCJuZXQiOiJ0Y3AiLCJ0" +
  "eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiIiwidGxzIjoidGxzIiwic25p" +
  "Ijoidm1lc3MuZXhhbXBsZS5jb20iLCJhbHBuIjoiaDIsaHR0cC8xLjEiLCJmcCI6" +
  "ImNocm9tZSJ9";

// Legacy -- rejected at the protocol prefix --------------------------------

export const SS_LINK = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#legacy";

export const SSR_LINK = "ssr://aG9zdDoxMjM0NTpvcmlnaW46YWVzLTI1Ni1jZmI=";

// trojan-go is a separate, incompatible fork; refused.
export const TROJAN_GO_LINK = "trojan-go://password@1.2.3.4:443#legacy";

// Plain trojan-WebSocket is rejected — Phase-7 scope is TCP+TLS only.
export const TROJAN_WS_LINK =
  "trojan://password@cdn.example.com:443" +
  "?type=ws&security=tls&host=cdn.example.com&path=%2Ftrojan&sni=cdn.example.com" +
  "#Trojan-WS";

// VMess+WebSocket is rejected — Phase-7 scope is TCP+TLS only.
export const VMESS_WS_LINK =
  "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MtV1MiLCJhZGQiOiJjZG4uZXhhbXBs" +
  "ZS5jb20iLCJwb3J0Ijo0NDMsImlkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYt" +
  "NDQ2NjU1NDQwMDQzIiwiYWlkIjowLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0" +
  "eXBlIjoibm9uZSIsImhvc3QiOiJjZG4uZXhhbXBsZS5jb20iLCJwYXRoIjoiL3Zt" +
  "ZXNzIiwidGxzIjoidGxzIiwic25pIjoiY2RuLmV4YW1wbGUuY29tIiwiYWxwbiI6" +
  "ImgyLGh0dHAvMS4xIiwiZnAiOiJjaHJvbWUifQ==";

export const HTTP_LINK = "http://proxy.example.com:8080#nope";

export const SOCKS_LINK = "socks://1.2.3.4:1080#nope";

// Invalid combinations -- VLESS variants we refuse -------------------------

export const REALITY_WS =
  "vless://550e8400-e29b-41d4-a716-446655440002@1.2.3.4:443" +
  "?type=ws&security=reality&pbk=zR9LQ8Z3J0xWlb5fK0p9X1m3T7v6yE2u8N4o0aB1cD0" +
  "&sid=abcd1234&fp=chrome&sni=www.microsoft.com&flow=xtls-rprx-vision" +
  "&encryption=none#Reality+WS";

export const REALITY_GRPC =
  "vless://550e8400-e29b-41d4-a716-446655440003@1.2.3.4:443" +
  "?type=grpc&security=reality&pbk=zR9LQ8Z3J0xWlb5fK0p9X1m3T7v6yE2u8N4o0aB1cD0" +
  "&sid=abcd1234&fp=chrome&sni=www.microsoft.com&flow=xtls-rprx-vision" +
  "&encryption=none#Reality+gRPC";

export const VLESS_TLS_DIRECT =
  "vless://550e8400-e29b-41d4-a716-446655440004@example.com:443" +
  "?type=tcp&security=tls&fp=chrome&sni=example.com&encryption=none" +
  "#VLESS-TLS-direct";

export const VLESS_KCP =
  "vless://550e8400-e29b-41d4-a716-446655440005@1.2.3.4:443" +
  "?type=kcp&security=tls&encryption=none#KCP";

// Malformed --------------------------------------------------------------

export const MALFORMED_NO_UUID = "vless://@1.2.3.4:443?type=ws&security=tls";
export const MALFORMED_BAD_FP =
  "vless://550e8400-e29b-41d4-a716-446655440006@cdn.example.com:443" +
  "?type=ws&security=tls&host=cdn.example.com&path=%2F&sni=cdn.example.com" +
  "&fp=hyperion&encryption=none#bad-fp";
export const REALITY_BAD_PBK =
  "vless://550e8400-e29b-41d4-a716-446655440007@1.2.3.4:443" +
  "?type=tcp&security=reality&pbk=tooshort&sid=abcd1234&fp=chrome" +
  "&sni=www.microsoft.com&flow=xtls-rprx-vision&encryption=none#bad-pbk";

// Mixed corpus used by subscription tests --------------------------------

export const MIXED_PLAIN_SUB = [
  VALID_CDN_WS,
  VALID_REALITY,
  VALID_TROJAN,
  VALID_VMESS,
  SS_LINK,
  TROJAN_GO_LINK,
  TROJAN_WS_LINK,
  VMESS_WS_LINK,
  REALITY_GRPC,
  REALITY_WS,
  VLESS_TLS_DIRECT,
  HTTP_LINK,
  VLESS_KCP,
].join("\n");
