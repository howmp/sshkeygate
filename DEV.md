# sshkeygate 开发文档

面向改代码的人。用户文档见 [README.md](README.md)。

## 构建 & 运行

需要 Go **1.27.3+**（MyGo v0.10.0 的下限，`go.mod` 已声明；`GOTOOLCHAIN=auto` 会自动获取）。

```bash
# Windows：必须带 -H windowsgui，否则运行时弹出控制台黑框
go build -ldflags "-H windowsgui -s -w" -o dist/sshkeygate.exe .

# macOS
go build -o dist/sshkeygate .
```

验证：

```bash
gofmt -l .                                # 必须无输出
go vet ./...
go test ./...                             # 单元测试 + Windows 命名管道集成测试
GOOS=darwin GOARCH=arm64 go build ./...   # 交叉编译校验（MyGo 无 cgo）
```

## 目录结构

```
main.go                   # 单实例锁、服务装配、窗口、托盘、锁屏钩子
app/
  app.go                  # 服务聚合 + UI 状态 + 动作（解锁/导入/设置）
  views.go                # 侧边栏 + 5 页面 + 确认/改名/改密/导出弹窗
  window.go               # 窗口尺寸与解锁卡片测量
  theme.go                # 浅色/深色配色 + MyGo 主题
  i18n.go                 # 中英文案表
  icons.go                # 线性 SVG 图标
  confirm.go              # 签名确认队列（串行展示 + 倒计时）
  tray.go                 # 托盘菜单
  icon.go                 # 托盘图标 + 左键/右键分发
  update.go               # 检查更新 / 下载 / 安装
  export.go               # 私钥导出为 PEM
  wipe.go                 # 清空全部数据（忘记密码时的出路）
  wipe_view.go            # 清空的两步确认弹窗
  dock.go                 # macOS Dock 策略 + 点 Dock 恢复窗口
  endpoint.go             # Agent 地址与复制
  prefs.go                # 明文主题/语言，供解锁前渲染
internal/
  vault/                  # 加密存储（PBKDF2+AES-GCM、原子写、改密回滚）
  keystore/               # 元数据 + 按需解密签名
  memguard/               # 统一擦除、mlock/VirtualLock、进程加固
  sshkey/                 # 解析/指纹/RSA flags 签名 + 私钥对象擦除
  agent/                  # SSH Agent 协议 + 管道/socket 传输 + peer 识别
  policy/                 # 审批判定 + 信任校验（会话/定时模式未接入界面）
  auditlog/               # JSONL 日志
  bitwarden/              # KDF + EncString + 同步
tools/genicon/            # 图标生成器
tools/updatesign/         # 更新归档签名 + 清单生成
tools/machoinfo/          # 读 Mach-O 架构与 minos
tools/sectrustcompat/     # macOS 11 兼容层
tools/fakeagent/          # 手动验证管道冲突的假 agent
tools/preview/            # 重新生成 README 的截图
docs/screenshots/         # README 用的界面截图（由预览测试生成）
```

## 测试

| 包 | 覆盖 |
|---|---|
| `app/` | UI（`ui.NewTester` 无窗口渲染）、确认队列、主题、i18n、图标、窗口尺寸、解锁节流、导出、清空数据 |
| `internal/agent` | 协议响应、异常帧、并发、真实 Windows 管道与 peer 识别、管道冲突 |
| `internal/sshkey` | 夹具指纹、三种 RSA flags、加密私钥往返、`Wipe` 清零、拒绝不可擦类型 |
| `internal/memguard` | 切片/BigInt 清零、Lock/Unlock 容错、进程加固幂等 |
| `internal/vault` | 创建/解锁/改密/中断恢复/密文不含明文/改密后密钥仍可用 |
| `internal/policy` | 审批模式判定（含未接线的会话/定时授权）、mtime/SHA-256 失效、未识别进程 |
| `internal/keystore` | 导入去重/启停/改名/删除/签名 |
| `internal/auditlog` | 追加、重载、500 条上限、清除 |
| `internal/bitwarden` | EncString v2、MAC 篡改、HKDF 展开、换半重试 |
| `tools/updatesign` | 归档结构、签名覆盖、缺密钥拒绝 |

约定：

- 单元测试不依赖凭据库或系统 UI：`vault.SecretStore` 是接口，测试用内存实现
- `internal/agent/server_test.go` 用 `net.Pipe()` 跑协议，不监听端口
- `internal/agent/listen_windows_test.go` 是真实管道集成测试，覆写 `pipePath` 变量避免和系统 agent 抢管道
- `app/views_test.go` 用 `ui.NewTester` 无窗口渲染，断言页面文案与弹窗
- 测试夹具在 `internal/sshkey/testdata`（`id_ed25519`、`id_ed25519.pub`、`id_ed25519_bwagent`、`id_rsa`）
- 密码/口令在内部 API 一律用 `[]byte`，调用方 `defer memguard.Bytes`；UI 的 `string`
  只在调用点转换一次，不要把它再复制进新的长期字段
- **不要测剪贴板、`Theme.IsDark()`、`App.Locale()` 等需要事件循环的 MyGo API**，无窗口时会永久阻塞

## 图标

```bash
go run tools/genicon/main.go    # source.png → icon.png (256²)、tray.png (44²) 与 icon.ico (16–256 共 9 尺寸)
go run github.com/akavel/rsrc@latest -ico app/assets/icon.ico -o rsrc_windows_amd64.syso
```

- 源图 `tools/genicon/source.png` 是原版美术资源（1024²，绿色钥匙 + 环内深蓝终端提示符），**不要重画**
- `genicon` 只做盒式缩放，按预乘 alpha 平均，避免透明边缘渗色
- 窗口图标与非 macOS 托盘图标：`//go:embed assets/icon.png`（`app/icon.go`）；登录页与侧边栏用 `ui.Image` 绘制同一张
- macOS 菜单栏用单色模板图 `app/assets/tray.png`，由同一源图按「与原图背景色的距离」提取轮廓生成
- exe 图标：`rsrc_windows_amd64.syso` 编进二进制，**随仓库提交**（约 50KB，只有图标变化时才变）；改完 PNG/ICO 后 `go generate .` 重建 .syso

## 截图

README 里的 `docs/screenshots/*.png` 都由预览测试渲染，不是手工截图。用工具重新生成，
版本号由它传给测试：

```bash
go run tools/preview/main.go -version v0.4.0
```

工具先清空 `dist/preview`，跑 `TestPreview`，再把七张指定的渲染复制成 README 用的文件名，
并拒绝 `docs/screenshots` 里出现 README 不用的图片。省略 `-version` 时取最新的 git tag。

**发版前必须重新生成并提交**，否则用户看到的截图是旧版本的样子（侧边栏与「自动更新」行
都印着版本号）。渲染是确定的：日志时间戳固定在 `previewNow`，同一版本两次运行得到逐字节
相同的 PNG，所以 diff 里只会出现真正改过的界面。

直接跑测试（`SSHKEYGATE_PREVIEW=1 go test ./app/ -run TestPreview`）仍可用于样式自查，
产物在 `dist/preview`，不会改动 README 的图片。

| README 文件 | 来源 | 内容 |
|---|---|---|
| `unlock.png` | `light-unlock.png` | 解锁页（锁定的 app，388px 宽） |
| `keys.png` | `light-keys-zh.png` | 密钥列表，三把不同类型的密钥 |
| `prompt.png` | `light-confirm-zh.png` | 签名确认弹窗 |
| `trusted.png` | `light-trusted-zh.png` | 信任程序列表 |
| `log.png` | `light-log-zh.png` | 日志，几种结果混排 |
| `import.png` | `light-import-zh.png` | 导入页 |
| `settings.png` | `light-settings-zh-tall.png` | 配置页全图（1200px 高，免滚动） |

测试里为这几张图准备了固定数据：`%APPDATA%\sshkeygate` 数据目录、三条信任记录与八条
带时间差的日志，渲染结果与发布版一致。

## 打包

macOS 的 `.app` 由 `mygo build` 产出，配置在 `mygo.json`；发布的 DMG 不经过它（见下）：

```bash
# 双架构 .app（arm64 + amd64 由 lipo 合并），需在 macOS 上执行
MYGO_LDFLAGS="-X main.version=$TAG -macos 11.0" \
  go run github.com/egoist/mygo/cmd/mygo@latest build \
    -platform darwin/universal -skip-notarize -skip-dmg
```

`darwin/universal` 分别编译 arm64 与 amd64 再合成，一个包同时支持 Apple Silicon 与 Intel。
CI 之后再加 `tools/sectrustcompat` 兼容层、重新 `codesign`（ad hoc），并用 `hdiutil` 制作
DMG：`mygo build` 自己打的 DMG 会包含加兼容层之前的包，不能用于发布。

### 最低系统版本

两处都要设为 11.0，缺一不可：

1. `mygo.json` 的 `macos.minimumSystemVersion` → `Info.plist` 的 `LSMinimumSystemVersion`
2. 链接参数 `-macos 11.0` → Mach-O 的 `LC_BUILD_VERSION.minos`

**Go 1.27 的链接器默认 `macos = {13, 0, 0}`**（`cmd/link/internal/ld/macho.go`），
所以只改 plist 仍会在 11/12 上被 dyld 拒绝。用 `tools/machoinfo` 核对产物：

```bash
go run tools/machoinfo/main.go \
  dist/darwin-universal/sshkeygate.app/Contents/MacOS/sshkeygate.bin
# arm64   minos=11.0 sdk=26.2
# x86_64  minos=11.0 sdk=26.2
```

加兼容层后 `Contents/MacOS/sshkeygate` 是启动脚本，真正的 Mach-O 是 `sshkeygate.bin`。

Go 1.27 的 `crypto/x509` 还硬引用了 macOS 12 才有的 `SecTrustCopyCertificateChain`，
所以包里附带 `Contents/Frameworks/libsectrust_compat.dylib`（用旧 API 实现该符号）
与一个注入它的启动脚本。见 [tools/sectrustcompat](tools/sectrustcompat/README.md)。

### 部署时的坑

- **通过启动脚本或 `open <包>` 启动**：直接跑 `Contents/MacOS/sshkeygate.bin` 会
  `dyld: Symbol not found: _SecTrustCopyCertificateChain`，兼容层由启动脚本注入
- **重新部署前 `pkill -9`**：`SIGTERM` 后旧进程若残留，单实例锁会把新实例当成二次
  启动转发过去再退出，表现为「进程在跑但没有 socket」
- **清空 `~/.sshkeygate` 后要重启应用**，否则监听器不会重建端点
- **保存对话框不要传文件类型过滤器**：AppKit 会把它认为不合规的扩展名换掉
  （`id_rsa.pem` → `id_rsa.cer`），而「保存」并不需要过滤器限制用户

### 签名与公证

未签名时 MyGo 用 `-`（ad hoc 签名）：本机直接运行，拷到别的机器首次打开会被 Gatekeeper
拦下，需要手动放行（见 README「下载」）。对外分发需要 Apple Developer 账号：

1. **Developer ID 签名**——`mygo.json` 里设 `macos.signingIdentity`：
   ```json
   "macos": { "signingIdentity": "Developer ID Application: Your Name (TEAMID)" }
   ```
   `security find-identity -v -p codesigning` 可列出本机可用的证书。

2. **公证**——先存凭据，再在配置里开启：
   ```bash
   xcrun notarytool store-credentials sshkeygate-notary \
     --apple-id you@example.com --team-id TEAMID --password <app-specific-password>
   ```
   ```json
   "macos": { "notarize": { "keychainProfile": "sshkeygate-notary" } }
   ```
   `mygo build` 会依次公证 app 与 DMG 并 staple 票据。

## 自动更新

应用从 GitHub Releases 读取清单，下载存档，校验签名后原地替换：

| 平台 | 替换什么 | 清单 |
|---|---|---|
| Windows | 可执行文件所在目录里的 `sshkeygate.exe` | `update-windows-amd64.json` |
| macOS | 整个 `.app` 包 | `update-darwin-universal.json` |

Windows 的更新存档里只有一个 `sshkeygate.exe`，而 mygo 会保留正在运行的入口文件名：
安装时必须就叫 `sshkeygate.exe`，否则新版本会以另一个文件名落下，重启后仍运行旧文件。

清单与存档同发布在 release 里，`mygo.json` 的 `updates` 把地址与公钥编进程序：

```json
"updates": {
  "publicKey": "FUMaAl2P1NiNHM89QHiorz+btZIoC5AEW/QlwPABp8Y=",
  "github": "howmp/sshkeygate"
}
```

### 签名密钥

私钥只存在于 CI 的 `MYGO_UPDATER_PRIVATE_KEY` secret 里，仓库里没有。丢失私钥等于让所有
已安装的副本再也收不到更新，务必另行备份。重新生成会换掉公钥，旧版本将不再接受新包：

```bash
go run github.com/egoist/mygo/cmd/mygo@latest keygen -o dist/update-keys
# 公钥 → mygo.json 的 updates.publicKey
# 私钥 → GitHub secret MYGO_UPDATER_PRIVATE_KEY
```

### 为什么不用 `mygo build` 的存档

它签的是自己刚组装出来的包，而 macOS 包要在这之后再加兼容层（`libsectrust_compat.dylib`
与启动脚本）。用它的存档更新，装上的包没有兼容层，macOS 11 会启动不了。所以 CI 在加完
兼容层、重新签名之后再跑 `tools/updatesign`，从最终产物重新打包并签名：

```bash
MYGO_UPDATER_PRIVATE_KEY=... go run ./tools/updatesign \
  -version 0.4.0 -target darwin-universal \
  -app dist/darwin-universal/sshkeygate.app -tag v0.4.0 -out updates
```

**限制。** 应用必须能写自己所在的目录：Windows 是 exe 所在的目录，macOS 是 `.app` 所在的
目录（通常是 `/Applications`）。当前用户对该目录没有写权限时，配置页会说明无法自动更新。

## 发版

打一个 tag 就会构建并发布全部产物，无需改 `mygo.json`（CI 从 tag 同步版本号）：

```bash
git tag -a v0.4.0 -m "v0.4.0"
git push origin v0.4.0
```

一次发布产出 6 个文件：Windows exe、macOS DMG，以及两个平台各一份更新清单
（`update-<target>.json`）与存档（`.tar.gz`）。已安装的旧版本从
`releases/latest/download/` 读取清单，所以清单必须随 release 发布，不能漏传。

没有 `MYGO_UPDATER_PRIVATE_KEY` 时，CI 打一条警告并跳过签包：exe 与 DMG 照常发布，
但这次发布不会有自动更新文件。

## 关键设计决策

1. **MyGo 承担全部平台能力**：托盘 `mygo.NewTray`、开机启动 `App.SetOpenAtLogin`、锁屏
   `Power.OnLockScreen`、凭据库 `Secrets`、数据目录 `App.Path(PathUserData)`、单实例
   `RequestSingleInstanceLock`、更新 `Updater`。这些在 Flutter 版里都需要自己写 FFI/注册表代码
2. **`agent.ServeAgent` 负责协议**：分帧、长度上限、RSA flags 转发都由 `x/crypto/ssh/agent`
   处理。我们只需为每个连接实现 `ExtendedAgent`，把 peer 身份绑进去
3. **确认队列在 UI 侧**：agent 只投递 `*agent.Pending` 并阻塞等待，`app.Confirmer` 负责排队、
   一次展示一个、倒计时与记日志。签发/拒绝/信任的副作用（`policy.Grant`、`TrustProgram`、
   审计）都在 Confirmer 里，agent 只负责匹配密钥和签名
4. **只有 device_key 进凭据库**：MyGo `Secrets` 单条上限 2560 字节，vault 与私钥都加密
   落盘，凭据库里只放 32 字节设备密钥（派生方式见「安全实现」）
5. **私钥不常驻内存**：vault 元数据不含私钥；每把私钥单独加密为 `keys/<id>.bin`，
   签名时解密单条，用完擦除（细节见「安全实现」）
6. **Windows 管道自己实现**：go-winio 不导出管道句柄，而 `GetNamedPipeClientProcessId` 需要它。
   `internal/agent/listen_windows.go` 直接用 `x/sys/windows` 的
   `CreateNamedPipe`/`ConnectNamedPipe`，同时拿到句柄做 peer 识别
7. **macOS peer 识别**：`GetsockoptInt(fd, SOL_LOCAL, LOCAL_PEERPID)` 取 PID，再用
   `SysctlRaw("kern.procargs2", pid)` 取可执行文件路径
8. **不可识别来源永不放行**：`policy.NeedsConfirmation` 在 `path == ""` 时恒返回 true
9. **信任记录存全量**：路径 + 修改时间 + SHA-256 都保存，设置只控制校验哪些字段
10. **改密可回滚**：先写 `vault.migrate`（含旧盐值与旧密文），成功后才删；`Open` 时检测并恢复
11. **单实例**：`RequestSingleInstanceLock` 的命名取自 `App.SetName`，所以先设名字再取锁；
    后启动的实例被转发参数后直接退出，首个实例在 `OnSecondInstance` 里 `ShowWindow()`
    （无条件 `Restore` + `Show` + `Focus`，因为外部最小化时 `IsMinimized()` 不可靠）
12. **托盘左键开窗、右键出菜单**：Windows 原生就分开上报（`WM_LBUTTONUP` / `WM_RBUTTONUP`），
    后者还会自动弹出 `SetMenu` 给的菜单；AppKit 则只要 status item 带菜单，任何点击都先弹菜单。
    所以 `refreshTray` 在 macOS 上直接返回（不给 status item 菜单），右键时临时
    `SetMenu` + `PopUpMenu` + `SetMenu(nil)`，并用 `popping` 守卫防止 `PopUpMenu` 内部
    `performClick` 重入
13. **关窗不退出**：`CloseRequested` 只剩 `CloseQuit`（quitting 中）与 `CloseHide` 两种；
    macOS 隐藏时同时切到 `Accessory` 策略退出 Dock，`ShowWindow` 里先切回 `Regular`
14. **清空数据是唯一的出路**：密码只用于派生 `enc_key`，丢了就没有恢复途径，所以解锁页
    提供 `Vault.Destroy()`。它两步确认（第二步要输入本地化的「清空」二字），删 `vault.json`、
    `keys/*`、`prefs.json`，并清空 `agent.log`。`SecretStore` 没有删除接口，`device_key` 留着——
    没有旧的盐与密码它解不开任何东西，下次建库复用
15. **解锁失败退避**：连续 3 次错误后按 1/2/4/8… 秒递增，上限 60 秒，成功即清零。在
    PBKDF2 之前拦下，所以爆破成本从「每次 10 万轮」变成「每次还要等」
16. **更新包自己签**：`mygo build` 签的是加兼容层之前的包，用它更新会让 macOS 11 启动不了。
    CI 在 shim + codesign 之后跑 `tools/updatesign`，从最终产物重新打包签名
17. **Windows 用 `go build`**（保留提交的 `.syso` 图标），因此要手动补
    `-X github.com/egoist/mygo.production=1` 与 `packageUpdateFeed` / `packageUpdateKey`；
    缺 `production=1` 会让 `IsDev()` 为真、更新被判为不可用
18. **管道冲突靠试连发现**：Win32 命名管道在 `PIPE_UNLIMITED_INSTANCES` 下不排他，
    `CreateNamedPipe` 永不因被占用而失败；`Listen` 用 `dialPipeAt` 以客户端身份试连一次，
    连得上就记 `conflict`，托盘显示「被占用」
19. **内存擦除尽力而为**：统一走 `internal/memguard`，私钥用 `sshkey.Key.Wipe()`；密码与
    口令 API 一律收 `[]byte`，调用方负责擦自己的切片。覆盖范围、残留与边界见「安全实现」，
    不要把擦除当安全边界；`runtime/secret` 在 Go 1.27 仍需 `GOEXPERIMENT=runtimesecret`，
    默认构建不启用，因此不采用
20. **保持与 Flutter 版相同的 PBKDF2 轮数**（见「安全实现」），解锁延迟一致
21. **不把签名放进独立进程**做内存隔离
22. **macOS 最低版本 11.0**（Big Sur）：`Info.plist` 与 `-macos` 两处都要设，覆盖 Intel 与 Apple Silicon
23. **审批模式只有「每次确认」在运行**：`policy.Mode` 定义了 EveryRequest / Session /
    TimedMinutes / TrustedProcess 四个值，但设置页没有入口，`SetMode` 只在测试里调用；
    实际行为恒为 EveryRequest，信任程序列表在任何模式下都直接放行。会话/定时授权是
    未接线的代码，不要当成已有功能来写文档

## 安全实现

用户可见的安全承诺写在 [README](README.md#安全)，这里只记实现与边界。

### 密钥派生与存储

```
enc_key   = PBKDF2-SHA256(password ‖ device_key, salt, 100000)
vault     = AES-256-GCM(元数据 JSON, enc_key)
keys/<id> = AES-256-GCM(私钥 PEM, enc_key)
```

- `device_key`（32 字节）只在系统凭据库：Windows Credential Manager / macOS Keychain。
  其余全部加密落盘，因此不受 `Secrets` 单条 2560 字节上限约束
- 每把私钥单独一个文件，不进入 vault 元数据
- `vault.json` 与 `keys/<id>.bin` 的写入先写临时文件再 `rename`，避免半写状态；
  `prefs.json` 与 `agent.log` 不走这条路径
- 改密分两阶段：先写 `vault.migrate`（旧盐值 + 旧密文 + 旧私钥文件），成功后才删；
  `Open` 时检测并恢复
- `Vault.ChangePassword` 用所有权标志转移 `newKey`：成功时 vault 接管，失败时才清零。
  不能在 `v.encKey` 仍与局部变量别名时清零，否则保存出的 `vault.json` 无法再解密
  （回归测试 `TestChangePasswordKeepsWorkingKey`）

### 内存中的密钥材料

| 状态 | 内存中有什么 |
|---|---|
| 锁定 | `device_key`（32 字节，进程启动时从凭据库读出，锁定不清除）；`enc_key`、元数据与私钥都不在 |
| 解锁 | 元数据、公钥 blob、32 字节 `enc_key`（尽力 `mlock`/`VirtualLock`），以及常驻的 `device_key` |
| 签名 | 单条私钥的 PEM 与解析后的密钥对象，签名后 `Wipe` |

- 擦除统一走 `internal/memguard.Bytes`：`clear(b)` + `runtime.KeepAlive(b)`，
  既覆盖内容，也避免编译器把写入当作死存储删除
- `sshkey.Key` 保留解析出的 `raw crypto.PrivateKey` 并提供 `Wipe()`：擦 PEM，以及
  RSA 的 `D`/`Primes`/`Precomputed`、ECDSA 的 `D`、Ed25519 的 64 字节私钥
- `Parse` 拒绝无法擦除的类型（当前如 ML-DSA），宁可导入失败也不收下明文
- 覆盖全部路径：`keystore.Sign`/`Import`、`app.scanKeyFile`、文本与拖拽导入、
  Bitwarden 同步（`Forget`、`stretched`、展开的对称密钥、`Item.PrivateKey`）、
  导出、`vault` 的临时 `encKey` 副本、`bitwarden` 的 `master`/`stretched`/`plain`
- `vault.Create/Unlock/ChangePassword` 与 `sshkey.Parse`、`keystore.Import` 的口令参数
  都是 `[]byte`，所有权在调用方；`app` 在调用点转换一次并 `defer` 擦除
- `App.clearSensitiveState` 在锁库与清空数据时丢掉 UI 持有的密码、粘贴的私钥、扫描口令
- `memguard.HardenProcess` 在 Windows 关闭崩溃错误框，在 macOS 把 `RLIMIT_CORE` 设为 0

### 擦不掉的残留

这是已知限制，不要在任何地方承诺得比这更多：

- UI 输入是 Go `string`，不可变；置空只是丢引用，旧副本仍在内存里
- `pbkdf2`/`argon2` 内部状态、`hmac` 的 pad、`aes.NewCipher` 的轮密钥调度表、
  `ssh.ParseRawPrivateKey` 的解析缓冲都没有擦除接口
- 签名瞬间私钥必然完整出现在进程内存；栈、寄存器、编译器副本不可达也不可控
- 页文件、休眠文件、崩溃转储（含管理员配置的 WER LocalDumps）、同用户或管理员实时
  读取进程内存，都不在应用控制内
- `mlock`/`VirtualLock` 可能因配额或权限失败，静默降级，不影响功能

结论：擦除是缩短暴露窗口的纵深防御，不是安全边界；防不住本机实时读取进程内存。

## 数据存储

| 项 | 位置 |
|---|---|
| 数据目录 | `App.Path(PathUserData)`：`%APPDATA%\sshkeygate` / `~/Library/Application Support/sshkeygate` |
| `vault.json` | `{"version":1,"salt":"<b64 16B>","vault":"<b64 AES-GCM>"}` |
| `keys/<id>.bin` | base64(AES-GCM(私钥 PEM)) |
| `agent.log` | JSONL，≤500 行 |
| `prefs.json` | 明文主题与语言，供解锁前渲染 |
| device_key | Credential Manager / Keychain，account `device_key` |

**vault 明文结构**：`{keys[], trustedPaths[], trustedPrograms[], settings{}}`，**不含私钥**。
`trustedPaths` 是旧版遗留字段，当前代码不写入。
**settings 字段**：`confirmTimeoutSeconds`(30)、`lockOnScreenLock`(true)、
`trustVerification`(["path","mtime"])、`theme`("system")、`language`("system")。

## Agent 端点

- Windows：`\\.\pipe\openssh-ssh-agent`（`ssh.exe` 默认连接）
- macOS：`~/.sshkeygate/agent.sock`（0600），需 `export SSH_AUTH_SOCK=...`
