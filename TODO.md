# sshkeygate TODO

## 待验证

- [ ] macOS 实机验证：Unix socket、`SSH_AUTH_SOCK`、Keychain 存取、`kern.procargs2` 取路径
- [ ] macOS 上 `LOCAL_PEERPID` 对系统完整性保护（SIP）进程的失败路径，确认降级为「无法识别来源」而不是放行
- [ ] macOS 11 上从 Finder 双击启动（SSH 会话下 Keychain 拒绝交互，需桌面会话确认）
- [ ] macOS 11 上自动启动（13 以下走 launch agent）
- [ ] macOS 上点 Dock 图标恢复窗口（关窗后图标已消失，只能从菜单栏回来——确认这是期望行为）
- [x] macOS 11.7.10（Big Sur）实机验证：兼容层生效，应用可启动并解锁
- [x] macOS 关窗隐藏 Dock 图标（`ApplicationType` 实测转为 `UIElement`）
- [x] 菜单栏图标单色无文字、左键开窗、右键出菜单
- [x] Windows 托盘左键开窗、右键出菜单
- [x] Windows 管道冲突提示
- [x] 自动更新在 v0.3.3 发版后跑通（6 个产物齐全，清单签名正确）

## 加固

- [ ] **解锁失败节流**：`unlock()` 当前无限重试，`vault.Unlock` 每次仍做满 10 万轮 PBKDF2。
      原 Flutter 版有指数退避。建议：连续失败 N 次后按 2^n 秒延迟，成功或重启后清零。
      代价小，纯 `app` 层逻辑 + 单测。

## UX

- [ ] 密钥列表按「来源 / 是否启用」筛选（当前只能按名称与指纹）
- [ ] 设置页显示 Agent 端点的可复制文案（macOS 需 `export SSH_AUTH_SOCK=...`）

## 平台

- [ ] Linux：Unix socket + `SO_PEERCRED`、libsecret、systemd user 自启、logind 锁屏
- [ ] Linux：`XDG_RUNTIME_DIR` 下的 socket 路径
- [ ] macOS 签名与公证：需 Apple Developer ID 证书。当前 ad hoc 签名，用户首次打开要
      「右键 → 打开」或手动清 quarantine 属性
- [ ] macOS 图标资产：`Contents/Resources` 只有从 PNG 渲染的 `.icns`，可提供 `Assets.car`

## 功能

- [ ] **一个文件内多把私钥**：`ssh.ParseRawPrivateKey` 会返回 `*ssh.MultiPrivateKey`，
      `sshkey.Parse` 目前只保留了单把（`signer` 只存一个），需改成一个文件产出多把
- [ ] **SSH 证书签名**（`*-cert-v01@openssh.com`）
- [ ] **密钥导出**（导出为 PEM）：`vault.PrivateKey(id)` 已能取出明文，缺 UI 与写文件
- [ ] Bitwarden 组织/集合过滤（当前同步账号下所有 SSH key）
- [ ] 从 `flutter_secure_storage.dat` 的一次性迁移（**明确不做**，格式已不兼容）

## macOS 打包

已在 Windows 上验证 `go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/universal`：
产出 `sshkeygate.app`（26.6 MB），`Contents/MacOS/sshkeygate` 是 **fat binary**，
头部 `CA FE BA BE` + 2 个架构：`arm64`（0x0100000C）与 `x86_64`（0x01000007）。

### 配置（`mygo.json`，已提交）

```json
{
  "identifier": "com.sshkeygate.app",
  "icon": "app/assets/icon.png",
  "updates": { "publicKey": "...", "github": "howmp/sshkeygate" },
  "macos": { "minimumSystemVersion": "11.0" }
}
```

`darwin/universal` 由 MyGo 内建支持：它分别编译 `darwin/arm64` 与 `darwin/amd64`，
再用 `lipo` 合成一个可执行文件，不需要手动合并。

### 最低系统版本

两处都要设为 11.0，缺一不可：

1. `mygo.json` 的 `macos.minimumSystemVersion` → 写入 `Info.plist` 的 `LSMinimumSystemVersion`
2. 链接参数 `-macos 11.0` → 写入 Mach-O 的 `LC_BUILD_VERSION.minos`

**Go 1.27 的链接器默认 `macos = {13, 0, 0}`**（见 `cmd/link/internal/ld/macho.go`），
所以只改 plist 仍会在 macOS 11/12 上被 dyld 拒绝，报「需要更新版本的 macOS」。
通过 `MYGO_LDFLAGS` 把 `-macos` 传给 `mygo build`。
`tools/machoinfo` 可核对产物：`minos=11.0` 才算对。

运行时方面，MyGo 对所有 macOS 12+ 才有的 API 都用 `respondsToSelector:` 判断并降级
（如 `DataStoreForIdentifier`、`interactionState`、`CADisplayLink`），因此 11 可用。
macOS 13 以下的「开机启动」走 launch agent，而不是 `SMAppService`。

### 命令

```bash
# 双架构 .app + DMG（需要 macOS 才能产出 DMG 并签名）
# MYGO_LDFLAGS 里的 -macos 不能省，否则 minos 是 13.0
MYGO_LDFLAGS="-macos 11.0" \
  go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/universal

# 只出 .app，跳过 DMG
MYGO_LDFLAGS="-macos 11.0" \
  go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/universal -skip-dmg

# 单独出一个架构（体积更小）
MYGO_LDFLAGS="-macos 11.0" \
  go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/arm64
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
| `darwin/universal` | `sshkeygate-<version>.dmg`（文件名不含架构） |
| `darwin/arm64` | `sshkeygate-<version>-arm64.dmg` |
| `darwin/amd64` | `sshkeygate-<version>-amd64.dmg` |

## 当前决定

- 保持 PBKDF2 10 万轮，与 Flutter 版一致的解锁延迟
- 不把签名放进独立进程做内存隔离
- 只有 device_key 进系统凭据库，其余加密落盘（绕过 2560 字节上限）
- Windows 管道自行实现而不依赖 go-winio，以便获取客户端进程句柄
- **内存清零尽力而为**：`zero()` 有效但清不干净（Go 字符串不可变、AES 轮密钥与
  `ssh` 解析结果无法访问），`runtime/secret` 在 Windows / macOS 上是空操作。
  细节见 README「私钥不驻留内存」
- **Win32 命名管道不排他**：多个进程可用 `PIPE_UNLIMITED_INSTANCES` 各自创建同名
  实例，绑定不会失败；因此冲突只能靠「以客户端身份试连」发现，不能靠 `CreateNamedPipe` 报错
- **更新包自己签**：`mygo build` 的存档是加兼容层之前的包，用它更新会让 macOS 11
  启动不了；CI 用 `tools/updatesign` 从最终产物重新打包
- **Windows 用 `go build` 而非 `mygo build`**（保留提交的 `.syso` 图标），因此要手动
  补 `-X github.com/egoist/mygo.production=1` 与 `packageUpdateFeed` / `packageUpdateKey`，
  否则 `IsDev()` 为真、更新被判定为不可用
- **关窗只隐藏**，不再有「已最小化到托盘」的首次提示；`CloseAction` 只有 quit / hide 两种
- macOS 最低版本 11.0（Big Sur）：`Info.plist` 与 `-macos` 两处都要设，覆盖 Intel 与 Apple Silicon
