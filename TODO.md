# sshkeygate TODO

只是待办。构建、打包、发版与已定的设计决策见 [DEV.md](DEV.md)。

## 平台

- [ ] Linux：Unix socket + `SO_PEERCRED`、libsecret、systemd user 自启、logind 锁屏
- [ ] Linux：`XDG_RUNTIME_DIR` 下的 socket 路径
- [ ] macOS 签名与公证：需 Apple Developer ID 证书。当前 ad hoc 签名，用户首次打开要
      「右键 → 打开」或手动清 quarantine 属性。步骤见 [DEV.md](DEV.md)
- [ ] macOS 图标资产：`Contents/Resources` 只有从 PNG 渲染的 `.icns`，可提供 `Assets.car`

## 安全

- [ ] **识别 agent 转发**：`ForwardAgent` 开着时，远端的请求和本地请求在 agent 看来都是
      同一个本地 ssh 进程，所以把 ssh 加进信任程序会连带放行转发的请求。
      OpenSSH 8.9 起有 `session-bind@openssh.com` 扩展，带 `is_forwarding` 字段
      （客户端在 `sshconnect2.c` 里发 0，在 `clientloop.c` 里发 1），能真正区分两者。
      接入步骤：
      1. `internal/agent` 的 `connAgent` 实现 `Extension()`，解开
         `hostkey / session_id / signature / is_forwarding`，把标志放进 `agent.Peer`。
         现在恒返回 `ErrExtensionUnsupported`，x/crypto 会回 `SSH_AGENT_FAILURE`，
         OpenSSH 客户端只是 debug 一行后继续，所以现状功能正常但标志被丢弃。
      2. 要当安全依据就得校验 `signature` 对 `session_id` 成立（OpenSSH 在
         `ssh-agent.c` 的 `process_ext_session_bind` 里就是这么做的），否则客户端可以
         自行声称「我是本地认证」。
      3. `policy.NeedsConfirmation` 对 `forwarded == true` 永不自动放行，即使程序已在
         信任列表里。
      限制：只有 OpenSSH 8.9+ 客户端会发。**收不到绑定不等于本地** —— OpenSSH 自己把
      `nsession_ids == 0` 当作本地使用，我只能当作「不知道」。Git（libssh2）、PuTTY、
      各种 socat 式转发都不发。Windows 自带的 Win32-OpenSSH 长期基于上游 7.7p1，
      没有这个扩展，所以 Windows 侧要等它跟上
- [ ] **转发的兜底提示**：不依赖协议扩展的启发式 —— 从 peer PID 取命令行，出现
      `-A` / `ForwardAgent yes` 且处于非认证阶段时提示「可能在转发」。两个平台都能做，
      但只是猜测，不能当安全边界

## 功能

- [ ] **一个文件内多把私钥**：`ssh.ParseRawPrivateKey` 内部只用 `pem.Decode` 取第一个
      PEM 块，`sshkey.Parse` 也只产出一把；需要遍历所有块，并让 `Parse` 返回多把
- [ ] **审批模式接进界面**：`internal/policy` 已定义会话授权与 5 分钟定时授权，但设置页
      没有入口，`SetMode` 只在测试里调用；当前实际行为是每次确认（信任程序除外）
- [ ] **SSH 证书签名**（`*-cert-v01@openssh.com`）
- [ ] Bitwarden 组织/集合过滤（当前同步账号下所有 SSH key）
