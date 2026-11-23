# sshkeygate TODO

只是待办。构建、打包、发版与已定的设计决策见 [DEV.md](DEV.md)。

## 平台

- [ ] Linux：Unix socket + `SO_PEERCRED`、libsecret、systemd user 自启、logind 锁屏
- [ ] Linux：`XDG_RUNTIME_DIR` 下的 socket 路径
- [ ] macOS 签名与公证：需 Apple Developer ID 证书。当前 ad hoc 签名，用户首次打开要
      「右键 → 打开」或手动清 quarantine 属性。步骤见 [DEV.md](DEV.md)
- [ ] macOS 图标资产：`Contents/Resources` 只有从 PNG 渲染的 `.icns`，可提供 `Assets.car`

## 功能

- [ ] **一个文件内多把私钥**：`ssh.ParseRawPrivateKey` 内部只用 `pem.Decode` 取第一个
      PEM 块，`sshkey.Parse` 也只产出一把；需要遍历所有块，并让 `Parse` 返回多把
- [ ] **审批模式接进界面**：`internal/policy` 已定义会话授权与 5 分钟定时授权，但设置页
      没有入口，`SetMode` 只在测试里调用；当前实际行为是每次确认（信任程序除外）
- [ ] **SSH 证书签名**（`*-cert-v01@openssh.com`）
- [ ] Bitwarden 组织/集合过滤（当前同步账号下所有 SSH key）
