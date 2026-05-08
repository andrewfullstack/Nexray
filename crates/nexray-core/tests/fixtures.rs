//! Mirrors `tests/corpus/links.ts`. Keep these constants in lockstep with the
//! TS fixtures — both test suites read from a logically identical corpus, so
//! any divergence between Rust parser and TS parser shows up as a test
//! failure on one side.

#![allow(dead_code)]

pub const VALID_CDN_WS: &str = "vless://550e8400-e29b-41d4-a716-446655440000@104.16.0.1:443\
?type=ws&security=tls&host=cdn.example.com&path=%2F%3Fed%3D2560\
&sni=cdn.example.com&fp=chrome&alpn=h2%2Chttp%2F1.1&encryption=none\
#CDN-Edge";

pub const VALID_REALITY: &str = "vless://550e8400-e29b-41d4-a716-446655440001@198.51.100.7:443\
?type=tcp&security=reality\
&pbk=zR9LQ8Z3J0xWlb5fK0p9X1m3T7v6yE2u8N4o0aB1cD0\
&sid=abcd1234&fp=chrome&sni=www.microsoft.com\
&flow=xtls-rprx-vision&encryption=none&spx=%2F\
#Reality-VPS";

pub const VALID_TROJAN: &str = "trojan://secret-pwd@198.51.100.42:443\
?type=tcp&security=tls&sni=trojan.example.com&fp=chrome\
&alpn=h2%2Chttp%2F1.1\
#Trojan-VPS";

pub const VMESS_LINK: &str = "vmess://eyJ2IjoiMiIsInBzIjoidm0iLCJhZGQiOiJleGFtcGxlLmNvbSJ9";
pub const SS_LINK: &str = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#legacy";
pub const SSR_LINK: &str = "ssr://aG9zdDoxMjM0NTpvcmlnaW46YWVzLTI1Ni1jZmI=";
// trojan-go is a separate, incompatible fork; refused.
pub const TROJAN_GO_LINK: &str = "trojan-go://password@1.2.3.4:443#legacy";
// Plain trojan-WebSocket is rejected — Phase-7 scope is TCP+TLS only.
pub const TROJAN_WS_LINK: &str = "trojan://password@cdn.example.com:443\
?type=ws&security=tls&host=cdn.example.com&path=%2Ftrojan&sni=cdn.example.com\
#Trojan-WS";
pub const HTTP_LINK: &str = "http://proxy.example.com:8080#nope";
pub const SOCKS_LINK: &str = "socks://1.2.3.4:1080#nope";

pub const REALITY_WS: &str = "vless://550e8400-e29b-41d4-a716-446655440002@1.2.3.4:443\
?type=ws&security=reality&pbk=zR9LQ8Z3J0xWlb5fK0p9X1m3T7v6yE2u8N4o0aB1cD0\
&sid=abcd1234&fp=chrome&sni=www.microsoft.com&flow=xtls-rprx-vision\
&encryption=none#Reality+WS";

pub const REALITY_GRPC: &str = "vless://550e8400-e29b-41d4-a716-446655440003@1.2.3.4:443\
?type=grpc&security=reality&pbk=zR9LQ8Z3J0xWlb5fK0p9X1m3T7v6yE2u8N4o0aB1cD0\
&sid=abcd1234&fp=chrome&sni=www.microsoft.com&flow=xtls-rprx-vision\
&encryption=none#Reality+gRPC";

pub const VLESS_TLS_DIRECT: &str = "vless://550e8400-e29b-41d4-a716-446655440004@example.com:443\
?type=tcp&security=tls&fp=chrome&sni=example.com&encryption=none\
#VLESS-TLS-direct";

pub const VLESS_KCP: &str =
    "vless://550e8400-e29b-41d4-a716-446655440005@1.2.3.4:443?type=kcp&security=tls&encryption=none#KCP";

pub const MALFORMED_NO_UUID: &str = "vless://@1.2.3.4:443?type=ws&security=tls";

pub const MALFORMED_BAD_FP: &str =
    "vless://550e8400-e29b-41d4-a716-446655440006@cdn.example.com:443\
?type=ws&security=tls&host=cdn.example.com&path=%2F&sni=cdn.example.com\
&fp=hyperion&encryption=none#bad-fp";

pub const REALITY_BAD_PBK: &str = "vless://550e8400-e29b-41d4-a716-446655440007@1.2.3.4:443\
?type=tcp&security=reality&pbk=tooshort&sid=abcd1234&fp=chrome\
&sni=www.microsoft.com&flow=xtls-rprx-vision&encryption=none#bad-pbk";

pub fn mixed_plain_sub() -> String {
    [
        VALID_CDN_WS,
        VMESS_LINK,
        VALID_REALITY,
        SS_LINK,
        VALID_TROJAN,
        TROJAN_GO_LINK,
        TROJAN_WS_LINK,
        REALITY_GRPC,
        REALITY_WS,
        VLESS_TLS_DIRECT,
        HTTP_LINK,
        VLESS_KCP,
    ]
    .join("\n")
}
