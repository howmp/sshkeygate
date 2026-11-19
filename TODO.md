# sshkeygate TODO

## 待验证

- [ ] macOS 实机验证：Unix socket、`SSH_AUTH_SOCK`、Keychain 存取、`kern.procargs2` 取路径
- [ ] macOS 上 `LOCAL_PEERPID` 对系统完整性保护（SIP）进程的失败路径，确认降级为「无法识别来源」而不是放行
- [ ] Windows：系统自带 OpenSSH Authentication Agent 服务占用 `\\.\pipe\openssh-ssh-agent` 时的提示文案与引导（停用服务或改用其它管道名）

## 加固

- [x] 并发签名请求排队，一次只展示一个（`app.Confirmer`）
- [x] 校验 Agent 帧长度，超长帧直接断开连接（`x/crypto/ssh/agent` 内建）
- [x] 信任程序绑定可选校验字段（路径恒需要，mtime 默认开启，SHA-256 可选）
- [x] 无法识别来源的进程禁用自动放行
- [x] 信任时同时记录 mtime 与 SHA-256
- [x] 改密中断可恢复（`vault.migrate` 两阶段）
- [x] 密码最少 12 位
- [x] 审计日志落盘上限 500 条，不只限制内存
- [x] 锁屏自动锁定设置持久化并生效
- [ ] 解锁失败节流（原 Flutter 版有指数退避，Go 版尚未实现）
- [ ] 私钥内存清零的可验证性（Go GC 会复制切片，只能尽力而为）

## UX

- [x] 侧边栏显示 Agent 状态与待处理请求数
- [x] 关窗到托盘时说明一次
- [x] 托盘菜单含状态、显示窗口、锁定、退出
- [x] 导入扫描区分「新文件 / 已导入 / 加密 / 异常」
- [ ] 界面多语言化（当前中文硬编码）
- [ ] 密钥列表支持搜索与排序
- [ ] 导入后自动切换到密钥列表页

## 平台

- [ ] Linux：Unix socket + `SO_PEERCRED`、libsecret、systemd user 自启、logind 锁屏
- [ ] Linux：`XDG_RUNTIME_DIR` 下的 socket 路径
- [ ] macOS 打包与签名（`mygo build` 产出 .app 后仍需 notarize）

## 功能

- [ ] 支持一个文件内多把私钥
- [ ] 支持 SSH 证书（`*-cert-v01@openssh.com`）签名
- [ ] 密钥导出（导出为 PEM）
- [ ] 从 `flutter_secure_storage.dat` 的一次性迁移（当前明确不做）
- [ ] 自动更新（`mygo.Updater`）

## 当前决定

- 保持 PBKDF2 10 万轮，与 Flutter 版一致的解锁延迟
- 不把签名放进独立进程做内存隔离
- 只有 device_key 进系统凭据库，其余加密落盘（绕过 2560 字节上限）
- Windows 管道自行实现而不依赖 go-winio，以便获取客户端进程句柄
