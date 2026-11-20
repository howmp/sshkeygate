# sshkeygate

跨平台 SSH Agent（Windows / macOS），用纯 Go 编写，UI 基于 [MyGo](https://github.com/egoist/mygo) 原生 `ui` 包绘制。支持从 Bitwarden / Vaultwarden 导入密钥。

## 功能

- **SSH Agent** — Windows 使用 `\\.\pipe\openssh-ssh-agent` 命名管道，与 OpenSSH 原生兼容；macOS 使用 `~/.sshkeygate/agent.sock` Unix socket。支持 Ed25519 / RSA / ECDSA，含 `rsa-sha2-256` / `rsa-sha2-512` 签名算法
- **密钥导入** — 文本粘贴、拖拽文件、`~/.ssh` 目录扫描（识别加密密钥并可填口令）、Bitwarden / Vaultwarden 同步
- **密钥管理** — 按名称或指纹筛选，可按导入顺序 / 名称 / 算法排序；可导出为 PEM
- **策略审批** — 每次确认 / 会话授权 / 定时授权 / 信任进程 四种模式
- **签名确认弹窗** — 可配置倒计时（10–120 秒，默认 30），超时自动拒绝；并发请求排队，一次只展示一个
- **进程识别** — Windows 走 `GetNamedPipeClientProcessId` + `QueryFullProcessImageNameW`；macOS 走 `LOCAL_PEERPID` + `kern.procargs2`。无法识别来源时永不自动放行
- **信任程序校验** — 以可执行文件路径为身份，可选校验最后修改时间与 SHA-256
- **操作日志** — JSONL 持久化，最多 500 条，锁定状态下也可记录
- **常驻托盘** — 关窗只隐藏窗口，Agent 继续服务；左键点图标唤回窗口，右键出菜单
- **自动更新** — 配置页检查新版本、下载并原地安装，安装后自动重启；更新包由 Ed25519 签名，只接受用本项目密钥签署的包
- **单实例** — 重复启动会退出新进程，并把已运行的窗口还原到前台
- **忘记密码可重来** — 密码无法找回，解锁页提供「清空数据」：两次确认后删除密钥库、私钥与日志，回到初次运行
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

macOS 包目前未签名公证（ad hoc 签名），首次打开需要「右键 → 打开」，或执行：

```bash
xattr -dr com.apple.quarantine /Applications/sshkeygate.app
```

装在 `/Applications` 且归当前用户所有时，应用可以在配置页里自动更新；装在管理员所有的
位置则需手动下载新版本。

## 客户端接入

- **Windows**：`ssh.exe` 默认连接 `\\.\pipe\openssh-ssh-agent`，无需额外配置
- **macOS**：把 socket 路径告诉客户端（配置页底部有复制按钮）
  ```bash
  export SSH_AUTH_SOCK="$HOME/.sshkeygate/agent.sock"
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

### 解锁失败退避

连续 3 次输错后，每次尝试的等待时间按 1/2/4/8… 秒递增，上限 60 秒；输对或重启即清零。
每次尝试本身还要跑满 10 万轮 PBKDF2，因此本地爆破密码不可行。

### 静态密钥保护

导入加密密钥时用口令解密，存储解密后的私钥，不保存口令。

### 忘记密码

密码只用于派生 `enc_key`，没有找回途径：忘了就再也解不开密钥库。解锁页因此提供
「清空数据」——两次确认（第二次要输入「清空」二字）之后，删除 `vault.json`、全部
`keys/*.bin`、`agent.log` 与 `prefs.json`，应用回到初次运行的状态。

凭据库里的 `device_key` 会保留：它没有盐值和密码就解不开任何东西，而 `SecretStore`
接口也没有删除操作。下次创建密钥库时会复用它，只意味着「还是这台设备」。

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

## 已知限制

- 仅 Windows 与 macOS（Linux 尚未实现）
- 不支持一个文件包含多把私钥，不支持 SSH 证书签名
- macOS 包未签名公证，需手动移除 quarantine 属性
- 进程内存无法保证完全擦除（见上文「私钥不驻留内存」）

## 开发

构建、打包、发版、设计决策与测试约定见 [DEV.md](DEV.md)。
