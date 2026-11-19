# macOS 11（Big Sur）兼容方案

## 为什么需要

Go 1.27 起，官方要求 **macOS 13 Ventura 或更高**（[Go Wiki: Minimum Requirements](https://go.dev/wiki/MinimumRequirements)）。
即使把 `-macos 11.0` 传给链接器、把 `Info.plist` 的 `LSMinimumSystemVersion` 改成 11.0，
二进制仍会在 macOS 11 上启动失败：

```
dyld: Symbol not found: _SecTrustCopyCertificateChain
  Referenced from: /Applications/sshkeygate.app/Contents/MacOS/sshkeygate
  Expected in: /System/Library/Frameworks/Security.framework/Versions/A/Security
```

原因是 Go 1.27 的 `crypto/x509/internal/macos` 用 `//go:cgo_import_dynamic` 硬绑了
`SecTrustCopyCertificateChain`（macOS 12 才有的 API）。dyld 加载时需要该符号，
系统没有就直接退出 —— 这发生在 `main()` 之前，程序无法自行处理。

## 方案：注入兼容 dylib

用 [ink-splatters/darwin-sectrust-compat](https://github.com/ink-splatters/darwin-sectrust-compat)（MIT）
提供的 shim：用已被废弃的 `SecTrustGetCertificateCount` + `SecTrustGetCertificateAtIndex`
组合实现同名函数 `SecTrustCopyCertificateChain`，再通过 dyld 注入覆盖缺失的符号。

本仓库的 `tools/sectrustcompat/sectrust_compat.c` 是同一实现的副本，
并额外提供了把 object 打包成 `.syso` 的工具（见下文「为什么不用 .syso」）。

### 构建 shim（必须在 macOS 上）

```bash
cd tools/sectrustcompat
export MACOSX_DEPLOYMENT_TARGET=11.0

# 两个架构各编一份，再用 lipo 合成 universal
for arch in x86_64 arm64; do
  clang -arch $arch -c -O2 -DSECTRUST_COMPAT \
    -o sectrust_compat_$arch.o sectrust_compat.c
done
lipo -create sectrust_compat_x86_64.o sectrust_compat_arm64.o -output sectrust_compat.o
```

或者直接编译成 dylib：

```bash
clang -Wall -Wextra -O2 -DSECTRUST_COMPAT -dynamiclib \
  -Wl,-exported_symbol,_SecTrustCopyCertificateChain \
  -framework Security -framework CoreFoundation \
  -o libsectrust_compat.dylib sectrust_compat.c
```

### 验证 shim

```bash
nm -g libsectrust_compat.dylib | grep SecTrustCopyCertificateChain
# 0000000000003e70 T _SecTrustCopyCertificateChain

nm -u libsectrust_compat.dylib | grep -c SecTrustCopyCertificateChain
# 0   （导出，但不依赖）
```

### 运行

```bash
DYLD_INSERT_LIBRARIES=/path/to/libsectrust_compat.dylib \
DYLD_FORCE_FLAT_NAMESPACE=1 \
  /Applications/sshkeygate.app/Contents/MacOS/sshkeygate
```

真机实测（macOS 11.7.10 / x86_64）：dyld 检查通过，应用正常启动并进入解锁界面。

## 为什么不用 .syso

把 shim 编成 `sectrust_compat_darwin.syso` 放在包目录下，Go 会自动链接它。这看起来更优雅，
但**会让 Go 放弃内部链接**：

```
link.exe: running clang failed: exec: "clang": executable file not found in %PATH%
clang -arch x86_64 -m64 -Wl,-headerpad,1144 -o a.out go.o 000000.o \
  -lresolv -framework CoreFoundation -framework Security
```

链接器一旦看到外部 object，就必须调用平台链接器（macOS 上的 clang），
于是「在任何机器上交叉编译」这一特性就没有了。CI 也只能在 macOS 上构建。

因此本项目选择发布 dylib 与启动脚本，而不是 `.syso`。

## 打包到 .app

把 dylib 放进 `Contents/Frameworks/`，再让主可执行文件指向它。最省事的做法是
在 `Contents/MacOS/` 放一个启动脚本，把主程序改名：

```
sshkeygate.app/Contents/
  Frameworks/libsectrust_compat.dylib
  MacOS/
    sshkeygate          # 启动脚本
    sshkeygate.bin      # 真正的二进制（原 sshkeygate）
```

启动脚本：

```sh
#!/bin/sh
DIR="$(cd "$(dirname "$0")/.." && pwd)"
export DYLD_INSERT_LIBRARIES="$DIR/Frameworks/libsectrust_compat.dylib"
export DYLD_FORCE_FLAT_NAMESPACE=1
exec "$(dirname "$0")/sshkeygate.bin" "$@"
```

注意：改了 `CFBundleExecutable` 之外的布局后，macOS 的代码签名会失效，
需要重新 `codesign`。

## 其他限制

- **`DYLD_INSERT_LIBRARIES` 在受保护进程上会被忽略**：系统完整性保护（SIP）对
  平台二进制生效，但普通用户应用不受影响。
- **需要关闭 Gatekeeper 的严格校验**：dylib 未签名时，`codesign` 后仍需
  `xattr -dr com.apple.quarantine`。
- **Apple Silicon 上必须签名**：arm64 强制要求至少 ad-hoc 签名，
  `codesign -s - --deep sshkeygate.app` 即可。
- 该方案依赖未文档化的 dyld 行为，属于「能用但不受支持」，Apple 未来版本可能改变。

## 更好的选择

如果那台 Mac 能升级，**升级到 macOS 13+ 是唯一被官方支持的路径**。
macOS 11 已于 2023 年 9 月停止安全更新，继续使用本身有风险。
