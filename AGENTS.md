# sshkeygate — Go 实现

跨平台 SSH Agent（Windows + macOS），纯 Go，无 cgo。UI 使用 MyGo 原生 `ui` 包。

## 构建 & 运行

```bash
# Windows：必须带 -H windowsgui，否则运行时会弹出控制台黑框
go build -ldflags "-H windowsgui -s -w" -o dist/sshkeygate.exe .

# macOS
go build -o dist/sshkeygate .

go test ./...                     # 全部测试
go vet ./... && gofmt -l .
GOOS=darwin GOARCH=arm64 go build ./...   # 交叉编译校验
go run github.com/egoist/mygo/cmd/mygo@latest build   # macOS .app 打包
```

Go 版本要求 **1.27.3+**（MyGo v0.10.0 的下限，`go.mod` 已声明）。

## 图标

```bash
go run tools/genicon/main.go    # tools/genicon/source.png → app/assets/icon.png (256²) + icon.ico (16–256 共 9 尺寸)
go run github.com/akavel/rsrc@latest -ico app/assets/icon.ico -o rsrc_windows_amd64.syso
```

- 源图 `tools/genicon/source.png` 是原版美术资源（1024²，绿色钥匙 + 环内深蓝终端提示符），**不要重画**
- `genicon` 只做盒式缩放，按预乘 alpha 平均，避免透明边缘渗色
- 窗口与托盘图标：`//go:embed assets/icon.png`（`app/icon.go`）；登录页与侧边栏用 `ui.Image` 绘制同一张
- exe 图标：`rsrc_windows_amd64.syso` 编进二进制，改图标后需重新生成并 `go build`


## 目录结构

```
main.go                   # 单实例锁、服务装配、窗口、托盘、锁屏钩子
app/
  app.go                  # 服务聚合 + UI 状态 + 动作
  views.go                # 侧边栏 + 5 页面 + 确认/改名/改密弹窗
  confirm.go              # 签名确认队列
  tray.go                 # 托盘菜单
  icon.go                 # 程序生成的托盘图标
internal/
  vault/                  # 加密存储（PBKDF2+AES-GCM、原子写、改密回滚）
  keystore/               # 元数据 + 按需解密签名
  sshkey/                 # 解析/指纹/RSA flags 签名
  agent/                  # SSH Agent 协议 + 传输 + peer 识别
  policy/                 # 4 种策略 + 信任校验
  auditlog/               # JSONL 日志
  bitwarden/              # KDF + EncString + 同步
```

## 关键设计决策

1. **MyGo 承担全部平台能力**：托盘 `mygo.NewTray`、开机启动 `App.SetOpenAtLogin`、锁屏 `Power.OnLockScreen`、凭据库 `Secrets`、数据目录 `App.Path(PathUserData)`、单实例 `RequestSingleInstanceLock`。这些在 Flutter 版里都需要自己写 FFI/注册表代码
2. **`agent.ServeAgent` 负责协议**：分帧、长度上限、RSA flags 转发都由 `x/crypto/ssh/agent` 处理。我们只需为每个连接实现 `ExtendedAgent`，把 peer 身份绑进去
3. **确认队列在 UI 侧**：agent 只投递 `*agent.Pending` 并阻塞等待，`app.Confirmer` 负责排队、一次展示一个、倒计时与记日志。签发/拒绝/信任的副作用（`policy.Grant`、`TrustProgram`、审计）都在 Confirmer 里，agent 只负责匹配密钥和签名
4. **只有 device_key 进凭据库**：MyGo `Secrets` 单条上限 2560 字节，vault 与私钥都加密落盘，key 派生为 `PBKDF2(password‖device_key, salt, 100k)`
5. **私钥不驻留内存**：vault 元数据不含私钥；每把私钥单独加密为 `keys/<id>.bin`，签名时解密单条后立即清零
6. **Windows 管道自己实现**：go-winio 不导出管道句柄，而 `GetNamedPipeClientProcessId` 需要它。`internal/agent/listen_windows.go` 直接用 `x/sys/windows` 的 `CreateNamedPipe`/`ConnectNamedPipe`，同时拿到句柄做 peer 识别
7. **macOS peer 识别**：`GetsockoptInt(fd, SOL_LOCAL, LOCAL_PEERPID)` 取 PID，再用 `SysctlRaw("kern.procargs2", pid)` 取可执行文件路径
8. **不可识别来源永不放行**：`policy.NeedsConfirmation` 在 `path == ""` 时恒返回 true
9. **信任记录存全量**：路径 + 修改时间 + SHA-256 都保存，设置只控制校验哪些字段
10. **改密可回滚**：先写 `vault.migrate`（含旧盐值与旧密文），成功后才删；`Open` 时检测并恢复

## 数据存储

| 项 | 位置 |
|---|---|
| 数据目录 | `App.Path(PathUserData)`：`%APPDATA%\sshkeygate` / `~/Library/Application Support/sshkeygate` |
| `vault.json` | `{"version":1,"salt":"<b64 16B>","vault":"<b64 AES-GCM>"}` |
| `keys/<id>.bin` | base64(AES-GCM(私钥 PEM)) |
| `agent.log` | JSONL，≤500 行 |
| device_key | Credential Manager / Keychain，account `device_key` |

**vault 明文结构**：`{keys[], trustedPaths[], trustedPrograms[], settings{}}`，**不含私钥**。
**settings 字段**：`confirmTimeoutSeconds`(30)、`lockOnScreenLock`(true)、`closeToTrayHintShown`(false)、`trustVerification`(["path","mtime"])。

## Agent 端点

- Windows：`\\.\pipe\openssh-ssh-agent`（`ssh.exe` 默认连接）
- macOS：`~/.sshkeygate/agent.sock`（0600），需 `export SSH_AUTH_SOCK=...`

## 测试约定

- 单元测试全部不依赖凭据库/系统 UI：`vault.SecretStore` 是接口，测试用内存实现
- `internal/agent/server_test.go` 用 `net.Pipe()` 跑协议，不需要监听端口
- `internal/agent/listen_windows_test.go` 是真实管道集成测试：覆盖 peer PID 与路径识别、`tryPeer=false` 的降级、`Close` 能唤醒 `ConnectNamedPipe`。测试覆写 `pipePath` 变量，避免和系统 agent 抢管道
- `app/views_test.go` 用 `ui.NewTester` 无窗口渲染，断言页面文案与弹窗
- 测试夹具在 `internal/sshkey/testdata`（`id_ed25519`、`id_ed25519.pub`、`id_ed25519_bwagent`、`id_rsa`）

## 已知问题

- 仅 Windows/macOS；Linux 未实现
- 不支持单文件多私钥、SSH 证书
- 中文文案硬编码
