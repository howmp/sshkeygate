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
// 通过 FFI 调用 OpenInputDesktop 检测锁屏状态。
// 当桌面被锁定时 OpenInputDesktop 返回 0（无法访问输入桌面）。
// 使用 5 秒定时器轮询。
//

typedef LockCallback = void Function();

typedef _OpenInputDesktopNative = IntPtr Function(
    Uint32 dwFlags, Int32 fInherit, Uint32 dwDesiredAccess);
typedef _OpenInputDesktopDart = int Function(
    int dwFlags, int fInherit, int dwDesiredAccess);

typedef _CloseDesktopNative = Int32 Function(IntPtr hDesktop);
typedef _CloseDesktopDart = int Function(int hDesktop);

final _user32 = DynamicLibrary.open('user32.dll');
final _openInputDesktop = _user32.lookupFunction<
    _OpenInputDesktopNative, _OpenInputDesktopDart>('OpenInputDesktop');
final _closeDesktop = _user32.lookupFunction<
    _CloseDesktopNative, _CloseDesktopDart>('CloseDesktop');

const _desktopReadObjects = 0x0001;

/// 锁屏检测器（FFI 轮询 OpenInputDesktop）
class LockDetector {
  LockCallback? _onLock;
  bool _isRunning = false;
  bool _wasLocked = false;

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
    Future.delayed(const Duration(seconds: 5), () {
      if (!_isRunning) return;
      final locked = _isDesktopLocked();
      if (locked && !_wasLocked) {
        _onLock?.call();
      }
      _wasLocked = locked;
      _poll();
    });
  }

  static bool _isDesktopLocked() {
    final hDesk = _openInputDesktop(0, 0, _desktopReadObjects);
    if (hDesk == 0) return true;
    _closeDesktop(hDesk);
    return false;
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

typedef _QueryFullProcessImageNameWNative = Int32 Function(
    IntPtr hProcess, Uint32 dwFlags, Pointer<Utf16> lpExeName, Pointer<Uint32> lpdwSize);
typedef _QueryFullProcessImageNameWDart = int Function(
    int hProcess, int dwFlags, Pointer<Utf16> lpExeName, Pointer<Uint32> lpdwSize);

typedef _CloseHandleNative = Int32 Function(IntPtr hObject);
typedef _CloseHandleDart = int Function(int hObject);

final _kernel32 = DynamicLibrary.open('kernel32.dll');

final _openProcess = _kernel32.lookupFunction<
    _OpenProcessNative, _OpenProcessDart>('OpenProcess');

final _queryFullProcessImageNameW = _kernel32.lookupFunction<
    _QueryFullProcessImageNameWNative,
    _QueryFullProcessImageNameWDart>('QueryFullProcessImageNameW');

final _closeHandle = _kernel32.lookupFunction<
    _CloseHandleNative, _CloseHandleDart>('CloseHandle');

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
      final result = _queryFullProcessImageNameW(hProcess, 0, buffer.cast(), size);
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
