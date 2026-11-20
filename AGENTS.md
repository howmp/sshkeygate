# sshkeygate — 给 AI 的工作约定

跨平台 SSH Agent（Windows + macOS），纯 Go，无 cgo。UI 使用 MyGo 原生 `ui` 包。

构建、目录结构、测试、打包、发版、设计决策与数据格式**都在 [DEV.md](DEV.md)**，
本文件只放不能从代码里看出来的坑。

## 每次改完必须跑

```bash
gofmt -l .                                # 必须无输出
go vet ./...
go test ./...
GOOS=darwin GOARCH=arm64 go build ./...   # Windows 上也要跑，覆盖 macOS 编译
```

Windows 构建**必须带 `-H windowsgui`**，否则运行时弹出控制台黑框。

## MyGo 的坑

这些踩过多次，写代码前先看一眼：

- **`Padding` 是 CSS 顺序 `top, right, bottom, left`**，不是垂直/水平
- `ui.Column(...).Fill()` 在 `Row` 里会撑满，该用 `FillHeight()`
- `Clicked()` 必须在 `Children()` **之后**取
- **视图里不要直接调 `mygo.Theme.IsDark()` / `App.Locale()` / `Clipboard` / `Dialog`**：
  无窗口的 `ui.NewTester` 测试会永久阻塞在没有事件循环的 `onMain` 上。系统值缓存在
  `App.systemDark` / `systemLocale`
- **`mygo.App.SetLanguages("zh", "en")` 必须在 `main` 里调**，否则 `Locale()` 永远返回 `en`
- `App.appReady` 为 true 前不调用 `Theme.SetSource` 等需要事件循环的 API
- `NewTray` 必须在 `App.WhenReady` 里创建，早了会 panic
- **托盘**：`OnClick` 只在图标没有菜单时触发。macOS 的 status item 一旦有菜单，任何点击
  都先弹菜单——这就是 macOS 上 `refreshTray` 直接返回、右键才临时挂菜单的原因

## 平台差异

- **Windows 文件权限没有 Unix 位**：`0600` 会被映射成「不设只读」，读回来是 `0666`。
  断言权限要按 `runtime.GOOS` 分支
- **Win32 命名管道不排他**：`PIPE_UNLIMITED_INSTANCES` 下多进程可各自创建同名实例，
  `CreateNamedPipe` 永不因被占用而失败。检测冲突只能以客户端身份试连
- **Windows 用 `go build` 而非 `mygo build`**，所以更新相关的 `-X` 标志要手动补，
  漏了 `production=1` 会让 `IsDev()` 为真、更新功能静默失效
- **macOS 的 Go 1.27 默认链接 macOS 13**，`-macos 11.0` 不能省

## 文档

三个文件、三种读者，**内容不要互相复制**，需要时用链接：

| 文件 | 读者 | 写什么 |
|---|---|---|
| `README.md` | 用户 | 能做什么、怎么装/接入、有哪些限制 |
| `DEV.md` | 改代码的人 | 构建、测试、打包、发版、设计决策、数据格式、安全实现细节 |
| `AGENTS.md` | 接手的 AI | 从代码里看不出来的坑、易错约定 |

- **README 不写实现**：不要出现内部包名/函数名（`memguard.Bytes`、`sshkey.Key.Wipe`）、
  算法参数（PBKDF2 轮数、nonce 长度）、文件布局、调用链、测试约定。
  可以点名用到的加密算法（如 AES-256-GCM），但不展开派生流程与参数
- **DEV 不写用户教程**：安装步骤、客户端接入这类内容放 README
- **同一事实只写一处**：Go 版本以 `go.mod` 为准，构建/验证命令在 DEV，AGENTS 只放
  必须每次都跑的检查与坑
- **安全措辞要诚实**：只写能保证的。比如「私钥不常驻内存」成立，「私钥不进内存」不成立；
  同时列出无法清除的残留（Go string、KDF/密码库内部状态、页文件、崩溃转储）。
  任何加固改动要同步更新 README 的限制说明与 DEV 的设计决策，不能只改一处
- **改行为就改文档**：新增用户可见功能 → README 功能表；新增坑 → AGENTS；
  换实现方式 → DEV 设计决策。三者与代码同一次提交

## 提交前

- 不要在代码里加注释解释显而易见的事
- 跟现有风格走：错误用 `errors.New`，文案进 `app/i18n.go` 的中英双表
- 改视图后可以渲染预览自查：`SSHKEYGATE_PREVIEW=1 go test ./app/ -run TestPreview`，
  产物在 `dist/preview/`
