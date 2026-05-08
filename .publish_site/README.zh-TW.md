# Nexray

[English](README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [Русский](README.ru.md)

適用於 macOS、Linux、Windows 的現代輕量 VLESS + Trojan + VMess 代理客戶端。
系統列圖示般簡潔,核心級效能。

## 下載

- **全平台總入口** → <https://github.com/andrewfullstack/Nexray-App/releases/latest>
- **自動辨識系統的下載頁** → <https://andrewfullstack.github.io/Nexray-App/zh-TW/>

| 平台                     | 架構    | 安裝包                                  |
| ----------------------- | ------- | --------------------------------------- |
| macOS(Apple Silicon)  | aarch64 | `Nexray_<version>_aarch64.dmg`          |
| Linux                    | x86_64  | `nexray_<version>_amd64.deb`            |
| Windows                  | x86_64  | `Nexray_<version>_x64-setup.exe`        |

## 首次啟動 — 繞過未簽署警告

目前的安裝包未經程式碼簽署。macOS 首次會拒絕開啟 `.dmg`,Windows 也會以
SmartScreen 攔截 `.exe`。兩者都可以在數秒內繞過:

### macOS — 清除隔離標記

把 `Nexray.app` 拖到 `/Applications` 後,在終端機執行一次(會提示輸入密碼):

```bash
sudo xattr -dr com.apple.quarantine /Applications/Nexray.app
```

之後正常點兩下開啟即可。覆蓋更新後只要還在同一路徑,無須再次執行。

### Windows — 仍要執行

點兩下 `.exe`,SmartScreen 會顯示「Windows 已保護您的電腦」。按
**其他資訊** → **仍要執行**。每個版本只在首次執行時顯示這個警告。

## 核心特性

- **僅支援現代協定。** 支援 VLESS(CDN-WS 或 REALITY)、Trojan(TCP+TLS),
  以及 VMess(TCP+TLS,僅 AEAD)。拒絕 Shadowsocks、vmess/trojan 的
  WebSocket 變體,以及任何過時或預設不安全的協定組合 — 這是設計初衷。
- **訂閱匯入** + 每群組「自動」模式,持續把作用中設定固定在訂閱中延遲最低
  的伺服器。
- **智慧分流。** 內建 `geosite:cn` 規則,加上你自己的 `rules.conf`。國內
  站點直連、廣告攔截、其餘流量走代理。
- **TUN 全域接管。** 核心級封包擷取,涵蓋不支援 SOCKS 的應用程式;離開時
  自動還原路由,不留殘餘設定。
- **五種介面語言。** English、简体中文、繁體中文、Русский。系統語言自動
  辨識,亦可在設定中手動切換。
- **預設零打擾。** 不上傳資料、不主動連網檢查更新,除非你在設定裡主動開啟
  自動更新。

## 儲存庫結構

本儲存庫(`Nexray-App`)只承載公開發行物與下載頁 — **不包含原始碼**。

- `gh-pages` 分支 → 渲染 <https://andrewfullstack.github.io/Nexray-App/>
- Releases → 安裝包 (`.dmg` / `.deb` / `.exe`)

原始碼在另一個私有儲存庫維護;每次打 release 標籤都會觸發 CI 自動建置並把
安裝包(以及本 README、Pages 網站)推送到這裡。

## 授權

專屬授權 — 保留所有權利。未經版權方書面同意,不得複製、修改、再散布或建立
衍生作品。發行頁中的安裝包僅授權用於個人用途;其他用途請聯絡版權方。

隨附的第三方元件仍各自依其上游授權條款。完整的逐項說明 — 包括 `xray-core`
的 MPL-2.0、`tun2socks` 的 MIT、geoip/geosite 資料檔的 GPL-3.0 — 都包含在每
個安裝包的 `THIRD_PARTY_LICENSES.md`。
