# sshkeygate TODO

## 待验证

- [ ] macOS 实机验证：Unix socket、`SSH_AUTH_SOCK`、Keychain 存取、`kern.procargs2` 取路径
- [ ] macOS 上 `LOCAL_PEERPID` 对系统完整性保护（SIP）进程的失败路径，确认降级为「无法识别来源」而不是放行
- [ ] macOS 实机验证 universal 包在 Intel 与 Apple Silicon 上都能启动（交叉编译已确认双架构，见下）
- [ ] Windows：系统自带 OpenSSH Authentication Agent 服务占用 `\\.\pipe\openssh-ssh-agent` 时的提示文案与引导（停用服务或改用其它管道名）

## 加固

- [ ] 解锁失败节流（原 Flutter 版有指数退避，Go 版尚未实现）
- [ ] 私钥内存清零的可验证性（Go GC 会复制切片，只能尽力而为）

## UX

- [ ] 密钥列表支持搜索与排序
- [ ] 导入后自动切换到密钥列表页

## 平台

- [ ] Linux：Unix socket + `SO_PEERCRED`、libsecret、systemd user 自启、logind 锁屏
- [ ] Linux：`XDG_RUNTIME_DIR` 下的 socket 路径
- [ ] macOS 签名与公证：需要 Apple Developer ID 证书，见「macOS 打包」
- [ ] macOS 图标资产：`Contents/Resources` 目前只有从 PNG 渲染的 `.icns`，若要更精细可提供 `Assets.car` 或 `.icon`

## 功能

- [ ] 支持一个文件内多把私钥
- [ ] 支持 SSH 证书（`*-cert-v01@openssh.com`）签名
- [ ] 密钥导出（导出为 PEM）
- [ ] 从 `flutter_secure_storage.dat` 的一次性迁移（当前明确不做）
- [ ] 自动更新（`mygo.Updater`）

## macOS 打包

已在 Windows 上验证 `go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/universal`：
产出 `sshkeygate.app`（26.6 MB），`Contents/MacOS/sshkeygate` 是 **fat binary**，
头部 `CA FE BA BE` + 2 个架构：`arm64`（0x0100000C）与 `x86_64`（0x01000007）。

### 配置（`mygo.json`，已提交）

```json
{
  "identifier": "com.sshkeygate.app",
  "icon": "app/assets/icon.png",
  "macos": { "minimumSystemVersion": "12.0" }
}
```

`darwin/universal` 由 MyGo 内建支持：它分别编译 `darwin/arm64` 与 `darwin/amd64`，
再用 `lipo` 合成一个可执行文件，不需要手动合并。

### 命令

```bash
# 双架构 .app + DMG（需要 macOS 才能产出 DMG 并签名）
go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/universal

# 只出 .app，跳过 DMG
go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/universal -skip-dmg

# 单独出一个架构（体积更小）
go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/arm64
go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/amd64
```

### 签名与公证（需在 macOS 上，且有 Apple Developer 账号）

未签名时 MyGo 用 `-`（ad hoc 签名），**只能在构建它的那台 Mac 上运行**，
拷到别的机器会被 Gatekeeper 拦下。要对外分发必须做两件事：

1. **Developer ID 签名**——`mygo.json` 里设 `macos.signingIdentity`：
   ```json
   "macos": {
     "signingIdentity": "Developer ID Application: Your Name (TEAMID)"
   }
   ```
   `security find-identity -v -p codesigning` 可列出本机可用的证书。

2. **公证（notarize）**——先存凭据，再在配置里开启：
   ```bash
   xcrun notarytool store-credentials sshkeygate-notary \
     --apple-id you@example.com --team-id TEAMID --password <app-specific-password>
   ```
   ```json
   "macos": {
     "notarize": { "keychainProfile": "sshkeygate-notary" }
   }
   ```
   `mygo build` 会依次公证 app 与 DMG 并 staple 票据。

### 交付物

| 平台参数 | 产物 |
|---|---|
| `darwin/universal` | `sshkeygate-0.3.0.dmg`（文件名不含架构） |
| `darwin/arm64` | `sshkeygate-0.3.0-arm64.dmg` |
| `darwin/amd64` | `sshkeygate-0.3.0-amd64.dmg` |

## 当前决定

- 保持 PBKDF2 10 万轮，与 Flutter 版一致的解锁延迟
- 不把签名放进独立进程做内存隔离
- 只有 device_key 进系统凭据库，其余加密落盘（绕过 2560 字节上限）
- Windows 管道自行实现而不依赖 go-winio，以便获取客户端进程句柄
- macOS 最低版本 12.0（Monterey），覆盖 Intel 与 Apple Silicon
