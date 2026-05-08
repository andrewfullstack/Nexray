# Nexray

[English](README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [Русский](README.ru.md)

面向 macOS、Linux、Windows 的现代轻量 VLESS + Trojan + VMess 代理客户端。
系统托盘般简洁,内核级速度。

## 下载

- **全平台总入口** → <https://github.com/andrewfullstack/Nexray-App/releases/latest>
- **自动识别系统的下载页** → <https://andrewfullstack.github.io/Nexray-App/zh-CN/>

| 平台                     | 架构    | 安装包                                  |
| ----------------------- | ------- | --------------------------------------- |
| macOS(Apple Silicon)  | aarch64 | `Nexray_<version>_aarch64.dmg`          |
| Linux                    | x86_64  | `nexray_<version>_amd64.deb`            |
| Windows                  | x86_64  | `Nexray_<version>_x64_en-US.msi`        |

## 首次启动 — 绕过未签名警告

当前安装包未做代码签名,因此 macOS 首次会拒绝打开 `.dmg`,Windows 也会用
SmartScreen 拦截 `.msi`。两者都可以几秒内绕过:

### macOS — 移除隔离标记

把 `Nexray.app` 拖到 `/Applications` 后,在终端中执行一次(会要求输入密码):

```bash
sudo xattr -dr com.apple.quarantine /Applications/Nexray.app
```

然后正常双击即可。覆盖更新到同一目录后无需再次执行。

### Windows — 仍要运行

双击 `.msi`,SmartScreen 会提示「Windows 已保护你的电脑」。点击
**更多信息** → **仍要运行**。每个版本只在首次运行时弹这一次。

## 核心特性

- **仅现代协议。** 支持 VLESS(CDN-WS 或 REALITY)、Trojan(TCP+TLS),
  以及 VMess(TCP+TLS,仅 AEAD)。拒绝 Shadowsocks、vmess/trojan 的
  WebSocket 变体,以及其他任何过时或默认不安全的协议组合 — 这是设计初衷。
- **订阅导入** + 每分组「自动」模式,持续把活动配置固定在订阅中延迟最低的
  服务器。
- **智能分流。** 内置 `geosite:cn` 规则,叠加你自己的 `rules.conf`。国内
  站点直连,广告拦截,其余流量走代理。
- **TUN 全局接管。** 内核级抓包,覆盖那些不响应 SOCKS 的应用;退出时自动
  恢复路由,不留残留。
- **五种 UI 语言。** English、简体中文、繁體中文、Русский。系统语言自动
  识别,也可在设置中手动切换。
- **默认零打扰。** 不上报数据,不联网检查更新,除非你在设置里主动开启自动
  更新。

## 仓库构成

本仓库(`Nexray-App`)只承载公开发布物与下载页 — **不包含源代码**。

- `gh-pages` 分支 → 渲染 <https://andrewfullstack.github.io/Nexray-App/>
- Releases → 安装包 (`.dmg` / `.deb` / `.msi`)

源代码维护在独立的私有仓库;每次打 release 标签都会触发 CI 自动构建并把
安装包(以及本 README、Pages 站)推送到这里。

## 许可证

专有 — 保留所有权利。未经版权方书面同意,不得复制、修改、再分发或衍生
作品。仓库内的安装包仅授权用于个人使用;其他用途请联系版权方。

附带的第三方组件仍各自遵循其上游许可证。完整的逐项说明 — 包括 `xray-core`
的 MPL-2.0、`tun2socks` 的 MIT、geoip/geosite 数据的 GPL-3.0 — 都打包在每个
安装包中的 `THIRD_PARTY_LICENSES.md`。
