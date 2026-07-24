import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

// =============================================================================
// 1. 开机启动管理
// =============================================================================
//
// 通过注册表项实现开机自启动：
//   HKCU\Software\Microsoft\Windows\CurrentVersion\Run\sshkeygate
//
// 使用 reg add / reg delete / reg query 命令行工具操作注册表。
// 安装 package:win32 后可改用 RegSetValueEx / RegDeleteValue 原生 API。
//

/// 注册表项路径（供开机启动使用）
const _runKey = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
const _runValueName = 'sshkeygate';

/// 检查当前是否已启用开机启动
///
/// 通过 `reg query` 命令查询注册表。
/// 返回 `true` 表示已设置开机启动。
Future<bool> isStartupEnabled() async {
  if (!Platform.isWindows) return false;

  try {
    final result = await Process.run('reg', [
      'query',
      _runKey,
      '/v',
      _runValueName,
    ]);

    if (result.exitCode == 0) {
      // 输出示例：
      //   HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
      //       sshkeygate    REG_SZ    "C:\path\to\sshkeygate.exe"
      final stdout = (result.stdout as String).trim();
      return stdout.contains(_runValueName);
    }

    // exitCode == 1 表示未找到值（没有开机启动），属于正常情况
    if (result.exitCode == 1) return false;

    // 其他错误码
    debugPrint(
      '[WindowsService] reg query 异常退出: ${result.exitCode}\n'
      'stderr: ${result.stderr}',
    );
    return false;
  } catch (e) {
    debugPrint('[WindowsService] isStartupEnabled 失败: $e');
    return false;
  }
}

/// 设置开机启动
///
/// [enabled] 为 `true` 时写入注册表，为 `false` 时删除注册表项。
///
/// 注册表值的数据为当前可执行文件的路径。
/// 如果无法获取可执行文件路径，则写入空字符串（仍能触发 exe 搜索）。
Future<void> setStartupEnabled(bool enabled) async {
  if (!Platform.isWindows) return;

  try {
    if (enabled) {
      // 获取当前可执行文件路径
      final exePath = _resolveExecutablePath();

      final result = await Process.run('reg', [
        'add',
        _runKey,
        '/v',
        _runValueName,
        '/t',
        'REG_SZ',
        '/d',
        exePath,
        '/f', // 强制覆盖，不提示
      ]);

      if (result.exitCode != 0) {
        throw Exception(
          'reg add 失败 (exitCode=${result.exitCode}): ${result.stderr}',
        );
      }

      debugPrint('[WindowsService] 开机启动已启用: $exePath');
    } else {
      final result = await Process.run('reg', [
        'delete',
        _runKey,
        '/v',
        _runValueName,
        '/f', // 强制删除，不提示
      ]);

      if (result.exitCode != 0) {
        // reg delete 在值不存在时也会返回 0，但如果键本身有问题会报错
        throw Exception(
          'reg delete 失败 (exitCode=${result.exitCode}): ${result.stderr}',
        );
      }

      debugPrint('[WindowsService] 开机启动已禁用');
    }
  } catch (e) {
    debugPrint('[WindowsService] setStartupEnabled 失败: $e');
    rethrow;
  }
}

/// 解析当前可执行文件路径
///
/// 优先使用 Platform.resolvedExecutable，回退到 Platform.script。
String _resolveExecutablePath() {
  try {
    // Platform.resolvedExecutable 返回实际解析后的可执行文件路径
    // 例如：C:\Program Files\sshkeygate\sshkeygate.exe
    final resolved = Platform.resolvedExecutable;
    if (resolved.isNotEmpty) return resolved;
  } catch (_) {
    // 某些沙箱环境中可能不可用
  }

  // 回退：script 路径（开发时为 dart 脚本，发布时通常为 exe）
  return Platform.script.toFilePath();
}

// =============================================================================
// 3. 锁屏检测
// =============================================================================
//
// 通过 WTSQuerySessionInformationW (wtsapi32.dll) 查询当前会话的锁屏状态。
// 使用 WTSSessionInfoEx (WTS_INFO_CLASS = 25) 返回 WTSINFOEX 结构体，
// 解析 WTSINFOEX_LEVEL1.SessionFlags 来判定锁屏。
// SessionFlags: 0 = 锁定 (WTS_SESSIONSTATE_LOCK), 1 = 解锁
// 首次轮询延迟 15 秒，避免启动阶段的误判。

typedef LockCallback = void Function();

// ---- wtsapi32.dll FFI 绑定 ----

typedef _WTSQuerySessionInformationWNative = Int32 Function(
    IntPtr hServer,
    Uint32 sessionId,
    Int32 wtsInfoClass,
    Pointer<Pointer<Void>> ppBuffer,
    Pointer<Uint32> pBytesReturned);
typedef _WTSQuerySessionInformationWDart = int Function(
    int hServer,
    int sessionId,
    int wtsInfoClass,
    Pointer<Pointer<Void>> ppBuffer,
    Pointer<Uint32> pBytesReturned);

typedef _WTSFreeMemoryNative = Void Function(Pointer<Void> pMemory);
typedef _WTSFreeMemoryDart = void Function(Pointer<Void> pMemory);

final _wtsapi32 = DynamicLibrary.open('wtsapi32.dll');

final _wtsQuerySessionInformationW = _wtsapi32.lookupFunction<
    _WTSQuerySessionInformationWNative,
    _WTSQuerySessionInformationWDart>('WTSQuerySessionInformationW');

final _wtsFreeMemory = _wtsapi32
    .lookupFunction<_WTSFreeMemoryNative, _WTSFreeMemoryDart>('WTSFreeMemory');

// ---- kernel32.dll FFI 绑定 ----

typedef _WTSGetActiveConsoleSessionIdNative = Uint32 Function();
typedef _WTSGetActiveConsoleSessionIdDart = int Function();

final _k32 = DynamicLibrary.open('kernel32.dll');

final _wtsGetActiveConsoleSessionId = _k32.lookupFunction<
    _WTSGetActiveConsoleSessionIdNative,
    _WTSGetActiveConsoleSessionIdDart>('WTSGetActiveConsoleSessionId');

// ---- 常量 ----

/// WTS_CURRENT_SERVER_HANDLE: 表示本地 RD 会话主机服务器
const _wtsCurrentServer = 0;

/// WTS_INFO_CLASS.WTSSessionInfoEx 枚举值
const _wtsSessionInfoEx = 25;

/// WTSINFOEX 结构体字段偏移（x64 布局）
///
/// typedef struct _WTSINFOEX {
///     DWORD Level;                  // offset 0
///     // 4 字节 padding (union 8 字节对齐)
///     WTSINFOEX_LEVEL Data;         // offset 8
/// } WTSINFOEX;
///
/// typedef struct _WTSINFOEX_LEVEL1 {
///     ULONG SessionId;              // offset 8（仅文档，未读取）
///     WTS_CONNECTSTATE_CLASS SessionState;  // offset 12（仅文档，未读取）
///     LONG SessionFlags;            // offset 16
/// } WTSINFOEX_LEVEL1;
const _offsetLevel = 0;
const _offsetSessionFlags = 16;

/// WTS_SESSIONSTATE_LOCK = 0
const _sessionStateLock = 0;

/// 锁屏检测器
///
/// 每 5 秒轮询一次锁屏状态（首次延迟 15 秒）。
/// 检测到锁屏时触发回调（仅从解锁→锁定状态转换时触发）。
class LockDetector {
  LockCallback? _onLock;
  bool _isRunning = false;
  bool _wasLocked = false;
  bool _firstPoll = true;

  bool get isRunning => _isRunning;

  void start(LockCallback onLock) {
    if (!Platform.isWindows) return;
    if (_isRunning) return;

    _onLock = onLock;
    _isRunning = true;
    _poll();
  }

  void _poll() {
    if (!_isRunning) return;
    final delay =
        _firstPoll ? const Duration(seconds: 15) : const Duration(seconds: 5);
    _firstPoll = false;

    Future.delayed(delay, () {
      if (!_isRunning) return;
      final locked = _isDesktopLocked();
      if (locked && !_wasLocked) {
        _onLock?.call();
      }
      _wasLocked = locked;
      _poll();
    });
  }

  /// 通过 WTSQuerySessionInformationW 查询当前会话的锁屏状态
  ///
  /// 解析返回的 WTSINFOEX 结构体，读取 WTSINFOEX_LEVEL1.SessionFlags：
  /// - 0 (WTS_SESSIONSTATE_LOCK) = 已锁定
  /// - 1 (WTS_SESSIONSTATE_UNLOCK) = 已解锁
  static bool _isDesktopLocked() {
    // 1. 获取活跃控制台会话 ID
    final sessionId = _wtsGetActiveConsoleSessionId();

    // 0xFFFFFFFF 表示没有活跃的控制台会话
    if (sessionId == 0xFFFFFFFF) {
      return false;
    }

    // 2. 查询会话信息
    final ppBuffer = calloc<Pointer<Void>>();
    final pBytesReturned = calloc<Uint32>();

    try {
      final result = _wtsQuerySessionInformationW(
        _wtsCurrentServer,
        sessionId,
        _wtsSessionInfoEx,
        ppBuffer,
        pBytesReturned,
      );

      if (result == 0 || ppBuffer.value.address == 0) {
        return false;
      }

      // 3. 解析 WTSINFOEX 结构体
      final rawBuf = ppBuffer.value.cast<Uint8>();

      final level = (rawBuf + _offsetLevel).cast<Uint32>().value;

      if (level != 1) {
        return false;
      }

      final sessionFlags = (rawBuf + _offsetSessionFlags).cast<Int32>().value;

      // SessionFlags == 0 → WTS_SESSIONSTATE_LOCK
      final locked = sessionFlags == _sessionStateLock;

      return locked;
    } finally {
      // 释放 WTS 分配的缓冲区
      if (ppBuffer.value.address != 0) {
        _wtsFreeMemory(ppBuffer.value);
      }
      calloc.free(ppBuffer);
      calloc.free(pBytesReturned);
    }
  }

  void stop() {
    _isRunning = false;
    _onLock = null;
  }

  void dispose() => stop();
}

// =============================================================================
// 4. 数据目录路径
// =============================================================================

/// 获取持久化数据目录（%LOCALAPPDATA%\sshkeygate\）
///
/// 优先使用 LOCALAPPDATA 环境变量，回退到 USERPROFILE\AppData\Local。
/// 如果目录不存在则自动创建。
///
/// 示例路径：`C:\Users\用户名\AppData\Local\sshkeygate\`
Future<String> getDataPath() async {
  final localAppData = Platform.environment['LOCALAPPDATA'] ??
      '${Platform.environment['USERPROFILE'] ?? r'C:\Users\Default'}\\AppData\\Local';

  final dir = Directory('$localAppData\\sshkeygate');

  try {
    if (!await dir.exists()) {
      await dir.create(recursive: true);
      debugPrint('[WindowsService] 数据目录已创建: ${dir.path}');
    }
  } catch (e) {
    debugPrint('[WindowsService] 创建数据目录失败: $e');
    // 不抛出异常，调用方在使用目录时自行处理错误
  }

  return dir.path;
}

// =============================================================================
// 5. 进程信息检测
// =============================================================================
//
// 通过 FFI 调用 OpenProcess + QueryFullProcessImageNameW 获取进程路径。
//

typedef _OpenProcessNative = IntPtr Function(
    Uint32 dwDesiredAccess, Int32 bInheritHandle, Uint32 dwProcessId);
typedef _OpenProcessDart = int Function(
    int dwDesiredAccess, int bInheritHandle, int dwProcessId);

typedef _QueryFullProcessImageNameWNative = Int32 Function(IntPtr hProcess,
    Uint32 dwFlags, Pointer<Utf16> lpExeName, Pointer<Uint32> lpdwSize);
typedef _QueryFullProcessImageNameWDart = int Function(int hProcess,
    int dwFlags, Pointer<Utf16> lpExeName, Pointer<Uint32> lpdwSize);

typedef _CloseHandleNative = Int32 Function(IntPtr hObject);
typedef _CloseHandleDart = int Function(int hObject);

final _kernel32 = DynamicLibrary.open('kernel32.dll');

final _openProcess = _kernel32
    .lookupFunction<_OpenProcessNative, _OpenProcessDart>('OpenProcess');

final _queryFullProcessImageNameW = _kernel32.lookupFunction<
    _QueryFullProcessImageNameWNative,
    _QueryFullProcessImageNameWDart>('QueryFullProcessImageNameW');

final _closeHandle = _kernel32
    .lookupFunction<_CloseHandleNative, _CloseHandleDart>('CloseHandle');

const _processQueryLimitedInformation = 0x1000;

/// 从 PID 获取进程可执行文件完整路径（FFI 调用 Win32 API）
Future<String?> getProcessPathFromPid(int pid) async {
  if (!Platform.isWindows) return null;

  final hProcess = _openProcess(_processQueryLimitedInformation, 0, pid);
  if (hProcess == 0) {
    debugPrint('[WindowsService] OpenProcess 失败: PID=$pid');
    return null;
  }

  try {
    final buffer = calloc<Uint16>(260);
    final size = calloc<Uint32>();
    size.value = 260;

    try {
      final result =
          _queryFullProcessImageNameW(hProcess, 0, buffer.cast(), size);
      if (result != 0 && size.value > 0) {
        return buffer.cast<Utf16>().toDartString(length: size.value);
      }
      debugPrint('[WindowsService] QueryFullProcessImageNameW 失败: PID=$pid');
      return null;
    } finally {
      calloc.free(buffer);
      calloc.free(size);
    }
  } finally {
    _closeHandle(hProcess);
  }
}

// =============================================================================
// WindowsService — 聚合服务
// =============================================================================

/// Windows 平台服务聚合器
///
/// 集中管理所有 Windows 特有功能，包括：
/// - 开机启动（注册表）
/// - 锁屏检测
/// - 数据目录
/// - 进程信息
///
/// 与 AppService 类似，提供统一的 ChangeNotifier 接口，
/// 方便 UI 层通过 Provider 等机制监听状态变化。
class WindowsService extends ChangeNotifier {
  final LockDetector _lockDetector = LockDetector();

  bool _startupEnabled = false;
  bool _startupChecked = false;

  bool get startupEnabled => _startupEnabled;
  bool get startupChecked => _startupChecked;

  LockDetector get lockDetector => _lockDetector;

  Future<void> initialize() async {
    if (!Platform.isWindows) return;
    await _refreshStartupStatus();
  }

  Future<void> _refreshStartupStatus() async {
    try {
      _startupEnabled = await isStartupEnabled();
      _startupChecked = true;
      notifyListeners();
    } catch (e) {
      debugPrint('[WindowsService] 刷新开机启动状态失败: $e');
    }
  }

  Future<void> setStartup(bool enabled) async {
    await setStartupEnabled(enabled);
    await _refreshStartupStatus();
  }

  Future<String?> getProcessPath(int pid) => getProcessPathFromPid(pid);

  @override
  void dispose() {
    _lockDetector.dispose();
    super.dispose();
  }
}
