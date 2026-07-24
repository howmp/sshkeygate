# sshkeygate - Flutter 实现

Windows SSH Agent，支持从 Bitwarden 导入密钥。纯 Dart 实现，使用 `dartssh2` 做密钥解析/签名。

## 构建 & 运行

```bash
flutter pub get
flutter build windows                    # 构建，产物在 build/windows/x64/runner/Release/
flutter test                             # 单元测试
flutter run -d windows                   # 开发运行
```

## 目录结构

```
lib/
├── main.dart                    # 入口、窗口管理、系统托盘、服务初始化
├── theme/app_colors.dart        # 颜色常量
├── services/
│   ├── secure_storage_service.dart  # 统一安全存储（PBKDF2+device_key→AES-256-GCM）
│   ├── log_service.dart         # 日志服务（持久化到 agent.log，JSONL 格式）
│   ├── crypto_service.dart      # Bitwarden 兼容加密（PBKDF2/Argon2id/AES-CBC/HKDF）
│   ├── bitwarden_service.dart   # Bitwarden 客户端（prelogin→登录→sync→解密）
│   ├── ssh_key_service.dart     # SSH 密钥解析与签名（dartssh2 驱动）
│   ├── blowfish_constants.dart  # Blowfish S-box 常量（Bitwarden 格式兼容）
│   ├── keystore_service.dart    # 密钥库（dartssh2 解析，私钥不驻留内存）
│   ├── policy_service.dart      # 策略引擎（4 种策略模式 + 路径信任）
│   ├── app_service.dart         # 服务聚合器
│   ├── ssh_agent_service.dart   # SSH Agent（Windows: dart_ipc 命名管道）
│   └── windows_service.dart     # Windows 平台服务（开机启动/进程路径FFI/锁屏检测）
├── pages/
│   ├── unlock_page.dart         # 解锁/设置密码页面
│   ├── keys_page.dart           # 密钥列表
│   ├── import_page.dart         # 导入密钥（文本拖拽/文件浏览/Bitwarden）
│   ├── trusted_page.dart        # 信任程序
│   ├── settings_page.dart       # 配置（开机启动/锁屏锁定/超时时间/修改密码）
│   └── log_page.dart            # 操作日志
└── widgets/
    ├── app_sidebar.dart          # 侧边栏（5页导航 + 锁定按钮）
    ├── app_toggle.dart           # 开关组件
    └── confirm_dialog.dart       # SSH 签名确认弹窗（带倒计时）
```

## 核心依赖

| 包 | 用途 |
|---|------|
| `dartssh2` | SSH 密钥解析（支持加密密钥）+ 签名（Ed25519/RSA/ECDSA） |
| `dart_ipc` | Windows 命名管道（`\\.\pipe\openssh-ssh-agent`） |
| `flutter_secure_storage` | 平台安全存储（Win: Credential Manager / macOS: Keychain / Linux: libsecret） |
| `cryptography` | PBKDF2、AES-256-GCM |
| `pointycastle` | RSA 签名（支持 rsa-sha2-256/512 算法选择） |
| `system_tray` | 系统托盘（最小化到托盘/右键菜单） |
| `file_picker` | 系统目录选择对话框 |
| `desktop_drop` | 文件拖拽导入 |
| `window_manager` | 窗口管理（尺寸锁定/前台激活/关闭拦截） |
| `ffi` | FFI 调用 kernel32/user32（GetNamedPipeClientProcessId, QueryFullProcessImageNameW, OpenInputDesktop） |

## 关键设计决策

1. **dartssh2 驱动**：密钥解析和签名使用 `dartssh2` 库，支持加密密钥（bcrypt-pbkdf + aes256-ctr）导入
2. **命名管道**：Windows 上通过 `dart_ipc` 创建 `\\.\pipe\openssh-ssh-agent`，与 OpenSSH 原生兼容
3. **密码保护的统一存储**：所有数据存储在 `flutter_secure_storage` 中（单文件），加密方案为 `AES-256-GCM(PBKDF2(用户密码 || device_key, salt, 100000轮))`
4. **私钥不驻留内存**：vault 元数据不含私钥；每条私钥单独加密存储为 `sshkeygate_pk_{id}`，签名时按需解密单条，用完即弃
5. **导入时解密存储**：加密密钥导入时使用 passphrase 解密，存储解密后的无密码 PEM。不存储 passphrase
6. **基于路径的进程信任**：信任列表以可执行文件路径（不区分大小写）为键，任何策略下已信任程序均自动放行
7. **签名确认倒计时**：确认弹窗带可配置倒计时（默认 30 秒），超时自动拒绝
8. **系统托盘常驻**：关窗最小化到托盘而非退出，SSH Agent 始终可用
9. **锁屏自动锁定**：FFI 调用 `OpenInputDesktop` 轮询检测桌面锁定状态
10. **操作日志**：所有签名请求/允许/拒绝/自动放行事件持久化记录

## 数据存储

所有数据存储在 `flutter_secure_storage` 管理的单文件中（`flutter_secure_storage.dat`），平台级 DPAPI 保护。

**文件位置：** `%APPDATA%\com.sshkeygate\sshkeygate\flutter_secure_storage.dat`

**存储条目：**
| Key | 内容 |
|-----|------|
| `sshkeygate_device_key` | 32 字节随机设备密钥（base64） |
| `sshkeygate_salt` | 16 字节随机盐（base64） |
| `sshkeygate_vault` | AES-256-GCM 加密的元数据 JSON（base64） |
| `sshkeygate_pk_{id}` | 每条私钥单独加密（AES-256-GCM，base64） |

**加密方案：**
```
enc_key = PBKDF2-SHA256(用户密码 || device_key, salt, 100000轮)
vault   = AES-GCM(JSON, enc_key)
pk_{id} = AES-GCM(PEM明文, enc_key)
```

**vault JSON 结构：**
```json
{
  "keys": [
    {
      "id": "uuid",
      "name": "my-key",
      "algorithm": "ssh-ed25519",
      "fingerprint": "SHA256:...",
      "publicKeyBlob": "<base64>",
      "source": "manual",
      "enabled": true
    }
  ],
  "trustedPaths": ["c:\\windows\\system32\\openssh\\ssh.exe"],
  "settings": {"confirmTimeoutSeconds": 30}
}
```

**日志文件：** `%APPDATA%\com.sshkeygate\sshkeygate\agent.log`（JSONL 格式，最多 500 条）

**内存模型：**
- 锁定态：内存中无任何密钥数据，SSH 请求直接拒绝
- 解锁后：内存保留元数据 + publicKeyBlob + trustedPaths + settings，**不含 privateKey**
- 签名时：从 `sshkeygate_pk_{id}` 解密单条 → `dartssh2` 签名 → 丢弃

## 已知问题

- **hot restart 后 SSH 卡住**：dart_ipc 管道在 hot restart 后重建，旧 SSH 连接失效。重新执行 ssh 命令即可，生产环境无此问题
- **`flutter test` 无法测试命名管道**：dart_ipc 依赖原生插件，仅在 `flutter run` 时可用。测试使用 `forceTcp: true` + 内存 FakeSecureStorage

## 测试

```
test/
├── keystore_service_test.dart      # 密钥导入/删除/切换 + SecureStorage 加解密
├── policy_service_test.dart        # 策略引擎（4 种策略 + 信任路径）
├── app_service_test.dart           # 集成测试（导入/删除/信任）
├── log_service_test.dart           # 日志服务（写入/读取/轮转/清理）
├── openssh_rsa_test.dart           # RSA 签名验证（pointycastle）
├── ssh_agent_protocol_test.dart    # SSH Agent 协议（TCP 模式）
├── crypto_service_test.dart        # Bitwarden 加密兼容性
├── bitwarden_sync_test.dart        # Bitwarden 服务器集成测试（skip）
└── widget_test.dart                # 颜色常量验证
# 总计: 69 passed, 1 skipped, 1 failed
```
