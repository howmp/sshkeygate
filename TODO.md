# sshkeygate TODO

只是待办。构建、打包、发版与已定的设计决策见 [DEV.md](DEV.md)。

## 待验证

都需要图形界面会话，SSH 里做不了：

- [ ] macOS 实机：Unix socket、`SSH_AUTH_SOCK`、Keychain 存取、`kern.procargs2` 取路径
- [ ] macOS 上 `LOCAL_PEERPID` 对 SIP 进程的失败路径，确认降级为「无法识别来源」而不是放行
- [ ] macOS 11 上从 Finder 双击启动
- [ ] macOS 11 上开机启动（13 以下走 launch agent）
- [ ] 设置页的端点复制按钮在 macOS 上粘贴一次，确认带 `export SSH_AUTH_SOCK=` 前缀
- [ ] 密钥导出在 macOS 上完整走一遍（保存对话框 + 0600 权限）

## 平台

- [ ] Linux：Unix socket + `SO_PEERCRED`、libsecret、systemd user 自启、logind 锁屏
- [ ] Linux：`XDG_RUNTIME_DIR` 下的 socket 路径
- [ ] macOS 签名与公证：需 Apple Developer ID 证书。当前 ad hoc 签名，用户首次打开要
      「右键 → 打开」或手动清 quarantine 属性。步骤见 [DEV.md](DEV.md)
- [ ] macOS 图标资产：`Contents/Resources` 只有从 PNG 渲染的 `.icns`，可提供 `Assets.car`

## 功能

- [ ] **一个文件内多把私钥**：`ssh.ParseRawPrivateKey` 会返回 `*ssh.MultiPrivateKey`，
      `sshkey.Parse` 目前只保留了单把（`signer` 只存一个），需改成一个文件产出多把
- [ ] **SSH 证书签名**（`*-cert-v01@openssh.com`）
- [ ] Bitwarden 组织/集合过滤（当前同步账号下所有 SSH key）
- [ ] 从 `flutter_secure_storage.dat` 的一次性迁移（**明确不做**，格式已不兼容）