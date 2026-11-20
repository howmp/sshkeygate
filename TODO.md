# sshkeygate TODO

只是待办。构建、打包、发版与已定的设计决策见 [DEV.md](DEV.md)。

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
