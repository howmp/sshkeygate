# sshkeygate

跨平台 SSH Agent（Windows / macOS），用纯 Go 编写，UI 基于 [MyGo](https://github.com/egoist/mygo) 原生 `ui` 包绘制。支持从 Bitwarden / Vaultwarden 导入密钥。

## 功能

- **SSH Agent** — Windows 使用 `\\.\pipe\openssh-ssh-agent` 命名管道，与 OpenSSH 原生兼容；macOS 使用 `~/.sshkeygate/agent.sock` Unix socket。支持 Ed25519 / RSA / ECDSA，含 `rsa-sha2-256` / `rsa-sha2-512` 签名算法
- **密钥导入** — 文本粘贴、拖拽文件、`~/.ssh` 目录扫描（识别加密密钥并可填口令）、Bitwarden / Vaultwarden 同步
- **密钥列表** — 按名称或指纹筛选，可按导入顺序 / 名称 / 算法排序
- **策略审批** — 每次确认 / 会话授权 / 定时授权 / 信任进程 四种模式
- **签名确认弹窗** — 可配置倒计时（10–120 秒，默认 30），超时自动拒绝；并发请求排队，一次只展示一个
- **进程识别** — Windows 走 `GetNamedPipeClientProcessId` + `QueryFullProcessImageNameW`；macOS 走 `LOCAL_PEERPID` + `kern.procargs2`。无法识别来源时永不自动放行
- **信任程序校验** — 以可执行文件路径为身份，可选校验最后修改时间与 SHA-256
- **操作日志** — JSONL 持久化，最多 500 条，锁定状态下也可记录
- **常驻托盘** — 关窗只隐藏窗口，Agent 继续服务；左键点图标唤回窗口，右键出菜单
- **自动更新** — 配置页检查新版本、下载并原地安装，安装后自动重启；更新包由 Ed25519 签名，只接受用本项目密钥签署的包
- **单实例** — 重复启动会退出新进程，并把已运行的窗口还原到前台
- **开机启动 / 锁屏自动锁定**
- **浅色 / 深色 / 跟随系统** — 配置页可切换，配色随主题整体变化
- **中英双语** — 跟随系统或手动切换，覆盖全部界面文案

主题与语言默认跟随系统：外观取系统深浅色，语言按首选语言在中文/英文中匹配。系统设置变化时界面即时跟随；在「配置 → 外观」里选定后则以所选为准。

## 下载

从 [Releases](https://github.com/howmp/sshkeygate/releases) 获取最新版本：

| 平台 | 文件 |
|------|------|
| Windows x64 | `sshkeygate-<version>-windows-amd64.exe` |
| macOS 11+（Intel + Apple Silicon） | `sshkeygate-<version>.dmg` |

macOS 包目前未签名（ad hoc 签名），首次打开需要「右键 → 打开」，或执行：

```bash
xattr -dr com.apple.quarantine /Applications/sshkeygate.app
```

macOS 包支持 **11.0（Big Sur）及以上**。Go 1.27 本身要求 macOS 13，
且其 `crypto/x509` 硬引用了 macOS 12 才有的 `SecTrustCopyCertificateChain`，
所以包里附带一个小型兼容层：`Contents/Frameworks/libsectrust_compat.dylib`
用 macOS 11 仍可用的旧 API 实现该函数，由启动脚本注入。详见
[tools/sectrustcompat](tools/sectrustcompat/README.md)。

## 客户端接入

- **Windows**：`ssh.exe` 默认连接 `\\.\pipe\openssh-ssh-agent`，无需额外配置
- **macOS**：把 socket 路径告诉客户端
  ```bash
  export SSH_AUTH_SOCK="$HOME/.sshkeygate/agent.sock"
  ```

## 构建

需要 Go **1.27.3+**（`go.mod` 已声明，`GOTOOLCHAIN=auto` 会自动获取）。

```bash
# Windows：-H windowsgui 让程序不带控制台窗口
go build -ldflags "-H windowsgui -s -w" -o dist/sshkeygate.exe .

# macOS
go build -o dist/sshkeygate .
```

验证：

```bash
go test ./...      # 单元测试 + Windows 命名管道集成测试
go vet ./...
gofmt -l .         # 应为空

GOOS=darwin GOARCH=arm64 go build ./...   # 交叉编译校验（MyGo 无 cgo）
```

### 打包

macOS 的 `.app` 与 DMG 由 `mygo build` 产出，配置在 `mygo.json`：

```bash
# 双架构 .app（arm64 + amd64 由 lipo 合并）与 DMG，需在 macOS 上执行
MYGO_LDFLAGS="-macos 11.0" \
  go run github.com/egoist/mygo/cmd/mygo@latest build -platform darwin/universal
```

`-macos 11.0` 不能省：Go 1.27 的链接器默认按 **macOS 13** 链接，dyld 会拒绝在
11/12 上加载，即使 `Info.plist` 写的是 11.0。可以用 `tools/machoinfo` 核对产物：

```bash
go run tools/machoinfo/main.go \
  dist/darwin-universal/sshkeygate.app/Contents/MacOS/sshkeygate
# arm64   minos=11.0 sdk=26.2
# x86_64  minos=11.0 sdk=26.2
```

`darwin/universal` 分别编译 arm64 与 amd64 再合成，一个包同时支持 Apple Silicon 与 Intel。
DMG 生成与代码签名需要 macOS；签名与公证的完整步骤见 [TODO.md](TODO.md)。

### 图标

图标由 `tools/genicon` 生成，不手工编辑：

```bash
go run tools/genicon/main.go       # tools/genicon/source.png → app/assets/icon.png + icon.ico

# 更新 exe 内嵌图标（Windows 资源），随后重新 go build
go run github.com/akavel/rsrc@latest -ico app/assets/icon.ico -o rsrc_windows_amd64.syso
```

- 源图 `tools/genicon/source.png` 为 1024² 透明底 PNG
- 缩放用盒式滤波并按预乘 alpha 平均，避免透明边缘渗色
- 窗口与托盘图标在运行时从 `app/assets/icon.png` 读取（`go:embed`）；登录页与侧边栏也直接绘制它
- 资源管理器 / 任务栏的 exe 图标来自 `rsrc_windows_amd64.syso`
- `.ico` 含 16–256 共 9 种尺寸

### 自动更新

应用从 GitHub Releases 读取清单，下载存档，校验签名后原地替换：

| 平台 | 替换什么 | 清单 |
|---|---|---|
| Windows | 可执行文件所在目录里的 `sshkeygate.exe` | `update-windows-amd64.json` |
| macOS | 整个 `.app` 包 | `update-darwin-universal.json` |

清单与存档同发布在 release 里，`mygo.json` 的 `updates` 把地址与公钥编进程序：

```json
"updates": {
  "publicKey": "FUMaAl2P1NiNHM89QHiorz+btZIoC5AEW/QlwPABp8Y=",
  "github": "howmp/sshkeygate"
}
```

**签名密钥。** 私钥只存在于 CI 的 `MYGO_UPDATER_PRIVATE_KEY` secret 里，
仓库里没有。丢失私钥等于让所有已安装的副本再也收不到更新，务必另行备份。
重新生成会换掉公钥，旧版本将不再接受新包：

```bash
go run github.com/egoist/mygo/cmd/mygo@latest keygen -o dist/update-keys
# 公钥 → mygo.json 的 updates.publicKey
# 私钥 → GitHub secret MYGO_UPDATER_PRIVATE_KEY
```

**为什么不用 `mygo build` 的存档。** 它签的是自己刚组装出来的包，而 macOS
包要在这之后再加兼容层（`libsectrust_compat.dylib` 与启动脚本）。用它的存档
更新，装上的包没有兼容层，macOS 11 会启动不了。所以 CI 在加完兼容层、重新
签名之后再跑 `tools/updatesign`，从最终产物重新打包并签名。

```bash
# 手动签名一个归档（CI 里就是这么调用的）
MYGO_UPDATER_PRIVATE_KEY=... go run ./tools/updatesign \
  -version 0.4.0 -target darwin-universal \
  -app dist/darwin-universal/sshkeygate.app -tag v0.4.0 -out updates
```

**限制。** 应用必须能写自己所在的目录：Windows 放在用户可写的文件夹里、
macOS 拖进 `/Applications` 且归当前用户所有。装在管理员所有的位置时，配置页
会说明无法自动更新，需手动下载。

### 发版

打一个 tag 就会构建并发布全部产物，无需改 `mygo.json`（CI 从 tag 同步版本号）：

```bash
git tag -a v0.4.0 -m "v0.4.0"
git push origin v0.4.0
```

一次发布产出 6 个文件：Windows exe、macOS DMG，以及两个平台各一份更新清单
（`update-<target>.json`）与存档（`.tar.gz`）。已安装的旧版本从
`releases/latest/download/` 读取清单，所以清单必须随 release 发布，不能漏传。

没有 `MYGO_UPDATER_PRIVATE_KEY` 时，CI 打一条警告并跳过签包：exe 与 DMG 照常
发布，但这次发布不会有自动更新文件。

## 目录结构

```
main.go                      # 单实例锁、服务装配、窗口/托盘、锁屏钩子
app/
  app.go                     # 服务聚合 + 状态 + 动作（解锁/导入/设置）
  views.go                   # 全部界面（侧边栏 + 5 个页面 + 弹窗）
  theme.go                   # 浅色/深色配色 + MyGo 主题
  i18n.go                    # 中英文案表
  icons.go                   # 线性 SVG 图标
  confirm.go                 # 签名确认队列（串行展示 + 倒计时）
  tray.go                    # 托盘菜单
  icon.go                    # 内嵌应用图标
  update.go                  # 检查更新 / 下载 / 安装
internal/
  vault/                     # 加密存储（PBKDF2 + AES-256-GCM，原子写，改密可回滚）
  keystore/                  # 密钥元数据 + 按需解密签名
  sshkey/                    # 密钥解析 / 指纹 / RSA flags 签名
  agent/                     # SSH Agent 协议 + 管道/socket 传输 + peer 识别
  policy/                    # 4 种策略 + 信任校验
  auditlog/                  # JSONL 审计日志
  bitwarden/                 # prelogin → token → sync → 解密
tools/genicon/               # 图标生成器
tools/updatesign/            # 更新归档签名 + 清单生成
```

## 安全设计

### 存储加密

```
enc_key   = PBKDF2-SHA256(用户密码 ‖ device_key, salt, 100000 轮)
vault     = AES-256-GCM(元数据 JSON, enc_key)
keys/<id> = AES-256-GCM(私钥 PEM, enc_key)
```

- `device_key`（32 字节）保存在系统凭据库：Windows Credential Manager / macOS Keychain。**只有它进凭据库**，其余全部加密落盘，因此不受凭据库单条 2560 字节上限约束
- 每把私钥单独加密成一个文件，不进入 vault 元数据
- 所有写入先写临时文件再 `rename`，避免半写状态
- 修改密码分两阶段：先写迁移记录，重加密成功后才删除；进程中断后启动时自动回滚

### 私钥不驻留内存

- **锁定态**：内存中无密钥材料，SSH 请求直接失败
- **解锁后**：内存仅保留元数据与公钥 blob
- **签名时**：解密单条私钥 → 签名 → 清零并丢弃

清零用 `zero()`（底层是一次 `runtime.memclrNoHeapPointers`，不会被编译器优化掉）。
但 Go 运行时让「彻底擦除」做不到，这是**已知限制**而非疏漏：

- 密码以 `string` 传入（Go 字符串不可变），调用方持有的副本无法清除；
  `deriveKey` 能清的只是它自己建的字节切片
- `aes.NewCipher` 会把密钥复制进轮密钥调度表，`ssh.ParseRawPrivateKey`
  返回的私钥结构也持有明文材料，两者都没有清除接口
- 标准库的 `runtime/secret`（Go 1.26+）**只在 linux/amd64 与 linux/arm64 上生效**，
  在 Windows / macOS 上 `secret.Do` 直接调用函数、不做任何擦除，因此用不上

结论：应用对敏感缓冲区尽力清零，但不承诺进程内存中绝无残留。

### 静态密钥保护

导入加密密钥时用口令解密，存储解密后的私钥，不保存口令。

### 进程可信

信任记录同时保存路径、修改时间与 SHA-256；设置项只决定**校验哪些字段**，不决定存哪些。任一字段不匹配即视为不可信。

## 数据位置

| 文件 | Windows | macOS |
|------|---------|-------|
| 数据目录 | `%APPDATA%\sshkeygate` | `~/Library/Application Support/sshkeygate` |
| `vault.json` | 盐值 + 加密元数据 | 同左 |
| `keys/<id>.bin` | 单独加密的私钥 | 同左 |
| `agent.log` | JSONL 审计日志 | 同左 |
| `prefs.json` | 主题与语言 | 同左 |
| device key | Credential Manager | Keychain |

## 测试

```
app/                 # UI（ui.NewTester 无窗口渲染）、确认队列、主题、i18n、图标、窗口尺寸
internal/agent       # 协议响应、异常帧、并发、真实 Windows 管道与 peer 识别
internal/sshkey      # 夹具指纹、三种 RSA flags、加密私钥往返
internal/vault       # 创建/解锁/改密/中断恢复/密文不含明文
internal/policy      # 4 种策略、mtime/SHA-256 失效、未识别进程
internal/keystore    # 导入去重/启停/改名/删除/签名
internal/auditlog    # 追加、重载、500 条上限、清除
internal/bitwarden   # EncString v2、MAC 篡改、HKDF 展开、换半重试
```

## 已知限制

- 仅 Windows 与 macOS（Linux 尚未实现）
- 不支持一个文件包含多把私钥，不支持 SSH 证书签名
- macOS 包未签名公证，需手动移除 quarantine 属性
