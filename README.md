# sshkeygate

跨平台 SSH Agent（Windows / macOS），用纯 Go 编写，UI 基于 [MyGo](https://github.com/egoist/mygo) 原生 `ui` 包绘制。支持从 Bitwarden / Vaultwarden 导入密钥。

> 这是 Go 重写版。Flutter 原版保留在 `main` 分支；本分支没有数据迁移，需要重新设置密码并重新导入密钥（`~/.ssh` 扫描与 Bitwarden 同步都是一键完成）。

## 功能

- **SSH Agent** — Windows 使用 `\\.\pipe\openssh-ssh-agent` 命名管道，与 OpenSSH 原生兼容；macOS 使用 `~/.sshkeygate/agent.sock` Unix socket。支持 Ed25519 / RSA / ECDSA，含 `rsa-sha2-256` / `rsa-sha2-512` 签名算法
- **密钥导入** — 文本粘贴、拖拽文件、`~/.ssh` 目录扫描（识别加密密钥并可填口令）、Bitwarden / Vaultwarden 同步
- **策略审批** — 每次确认 / 会话授权 / 定时授权 / 信任进程 四种模式
- **签名确认弹窗** — 可配置倒计时（10–120 秒，默认 30），超时自动拒绝；并发请求排队，一次只展示一个
- **进程识别** — Windows 走 `GetNamedPipeClientProcessId` + `QueryFullProcessImageNameW`；macOS 走 `LOCAL_PEERPID` + `kern.procargs2`。无法识别来源时永不自动放行
- **信任程序校验** — 以可执行文件路径为身份，可选校验最后修改时间与 SHA-256
- **操作日志** — JSONL 持久化，最多 500 条，锁定状态下也可记录
- **系统托盘常驻** — 关窗最小化到托盘，Agent 持续可用
- **开机启动 / 锁屏自动锁定**

## 构建 & 运行

需要 Go **1.27.3+**（`go.mod` 已声明，`GOTOOLCHAIN=auto` 会自动获取）。

```bash
# Windows：-H windowsgui 让程序不带控制台窗口
go build -ldflags "-H windowsgui -s -w" -o dist/sshkeygate.exe .

# macOS
go build -o dist/sshkeygate .

go test ./...                     # 单元测试 + Windows 管道集成测试
go vet ./...
gofmt -l .                        # 应为空

# macOS 打包（生成 .app）
go run github.com/egoist/mygo/cmd/mygo@latest build
```

交叉编译校验（MyGo 无 cgo）：

```bash
GOOS=darwin GOARCH=arm64 go build ./...
```

### 图标

图标沿用原版美术资源（绿色钥匙 + 环内终端提示符），由 `tools/genicon` 转成各尺寸，不手工编辑：

```bash
go run tools/genicon/main.go       # 源图 tools/genicon/source.png → app/assets/icon.png + icon.ico

# 更新 exe 内嵌图标（Windows 资源），随后重新 go build
go run github.com/akavel/rsrc@latest -ico app/assets/icon.ico -o rsrc_windows_amd64.syso
```

- 源图 `tools/genicon/source.png` 为 1024² 透明底 PNG，即原 Flutter 版的 `assets/sshkeygate_icon.png`
- 缩放用盒式滤波并按预乘 alpha 平均，避免透明边缘渗色
- 窗口与托盘图标在运行时从 `app/assets/icon.png` 读取（`go:embed`）；登录页与侧边栏也直接绘制它
- 资源管理器 / 任务栏的 exe 图标来自 `rsrc_windows_amd64.syso`
- `.ico` 含 16–256 共 9 种尺寸

### 客户端接入

- **Windows**：`ssh.exe` 默认连接 `\\.\pipe\openssh-ssh-agent`，无需额外配置
- **macOS**：把 socket 路径告诉客户端
  ```bash
  export SSH_AUTH_SOCK="$HOME/.sshkeygate/agent.sock"
  ```

## 目录结构

```
main.go                      # 单实例锁、服务装配、窗口/托盘、锁屏钩子
app/
  app.go                     # 服务聚合 + 状态 + 动作（解锁/导入/设置）
  views.go                   # 全部界面（侧边栏 + 5 个页面 + 弹窗）
  confirm.go                 # 签名确认队列（串行展示 + 倒计时）
  tray.go                    # 托盘菜单
  icon.go                    # 程序生成的托盘图标
internal/
  vault/                     # 加密存储（PBKDF2 + AES-256-GCM，原子写，改密可回滚）
  keystore/                  # 密钥元数据 + 按需解密签名
  sshkey/                    # 密钥解析 / 指纹 / RSA flags 签名
  agent/                     # SSH Agent 协议 + 管道/socket 传输 + peer 识别
  policy/                    # 4 种策略 + 信任校验
  auditlog/                  # JSONL 审计日志
  bitwarden/                 # prelogin → token → sync → 解密
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
| device key | Credential Manager | Keychain |

## 测试

```
app/                 # UI（ui.NewTester 无窗口渲染）、确认队列
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
- 界面文案为中文硬编码
