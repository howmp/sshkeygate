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

## 提交前

- 不要在代码里加注释解释显而易见的事
- 跟现有风格走：错误用 `errors.New`，文案进 `app/i18n.go` 的中英双表
- 改视图后可以渲染预览自查：`SSHKEYGATE_PREVIEW=1 go test ./app/ -run TestPreview`，
  产物在 `dist/preview/`
