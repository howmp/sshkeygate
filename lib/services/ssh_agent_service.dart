import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io' show Platform, ServerSocket, InternetAddress;

import 'package:flutter/foundation.dart';
import 'package:dart_ipc/dart_ipc.dart';
import 'package:ffi/ffi.dart';

import 'keystore_service.dart';
import 'log_service.dart';
import 'policy_service.dart';
import 'ssh_key_service.dart';
import 'windows_service.dart' show getProcessPathFromPid;

// Win32 GetNamedPipeClientProcessId
typedef _GetNamedPipeClientProcessIdNative = Int32 Function(
    IntPtr hNamedPipe, Pointer<Uint32> clientProcessId);
typedef _GetNamedPipeClientProcessIdDart = int Function(
    int hNamedPipe, Pointer<Uint32> clientProcessId);

final _kernel32 = DynamicLibrary.open('kernel32.dll');
final _getNamedPipeClientProcessId = _kernel32.lookupFunction<
    _GetNamedPipeClientProcessIdNative,
    _GetNamedPipeClientProcessIdDart>('GetNamedPipeClientProcessId');

const agentFailure = 5;
const agentSuccess = 6;
const agentcRequestIdentities = 11;
const agentIdentitiesAnswer = 12;
const agentcSignRequest = 13;
const agentSignResponse = 14;
const _maxAgentMessageLength = 1024 * 1024;

class SshAgentService extends ChangeNotifier {
  final KeyStoreService keystore;
  final PolicyService policy;
  final LogService? log;

  static const pipePath = r'\\.\pipe\openssh-ssh-agent';
  static const tcpPort = 43210;

  ServerSocket? _server;
  bool _running = false;
  final bool _forceTcp;
  Future<void> _confirmationTail = Future<void>.value();

  Future<int> Function(String keyName, String fingerprint, String? processPath,
      int clientPid)? onConfirm;

  SshAgentService(
      {required this.keystore,
      required this.policy,
      this.log,
      this.onConfirm,
      bool forceTcp = false})
      : _forceTcp = forceTcp;

  bool get isRunning => _running;

  Future<void> start() async {
    try {
      if (_running) return;
      // hot restart 后旧管道可能残留，先尝试关闭
      if (_server != null) {
        try {
          await _server!.close();
        } catch (_) {}
        _server = null;
      }
      _running = true;
      notifyListeners();
      if (Platform.isWindows && !_forceTcp) {
        debugPrint('[SshAgent] 创建管道（hot restart 后需重新执行 ssh 命令）...');
        _server = await bind(pipePath);
        debugPrint('[SshAgent] 管道已创建');
      } else if (_forceTcp) {
        debugPrint('[SshAgent] TCP 模式（仅限测试）端口 $tcpPort');
        _server =
            await ServerSocket.bind(InternetAddress.loopbackIPv4, tcpPort);
      } else {
        debugPrint('[SshAgent] 非 Windows 平台暂不支持');
        _running = false;
        notifyListeners();
        return;
      }
      _server!.listen(_handleClient);
    } catch (e) {
      debugPrint('[SshAgent] 启动失败: $e');
      _running = false;
      notifyListeners();
    }
  }

  Future<void> stop() async {
    _running = false;
    notifyListeners();
    try {
      await _server?.close();
    } catch (e) {
      debugPrint('[SshAgent] 关闭管道时异常（可忽略）: $e');
    }
    _server = null;
  }

  void _handleClient(dynamic sock) {
    final b = <int>[];
    // 获取客户端 PID（命名管道句柄存储在 sock.port 中）
    int clientPid = 0;
    if (Platform.isWindows && !_forceTcp) {
      try {
        final pipeHandle = sock.port as int;
        final pidPtr = calloc<Uint32>();
        try {
          final result = _getNamedPipeClientProcessId(pipeHandle, pidPtr);
          if (result != 0) {
            clientPid = pidPtr.value;
            debugPrint('[SshAgent] 客户端 PID: $clientPid');
          }
        } finally {
          calloc.free(pidPtr);
        }
      } catch (e) {
        debugPrint('[SshAgent] 获取客户端 PID 失败: $e');
      }
    }
    try {
      Future<void> processing = Future.value();
      sock.listen((List<int> d) {
        b.addAll(d);
        // 串行化：确保上一条消息处理完毕后再处理下一条
        processing = processing.then((_) async {
          while (b.length >= 4) {
            final len = _be32(b, 0);
            if (len < 1 || len > _maxAgentMessageLength) {
              b.clear();
              sock.destroy();
              return;
            }
            if (b.length < 4 + len) return;
            final msg = Uint8List.fromList(b.sublist(4, 4 + len));
            b.removeRange(0, 4 + len);
            sock.add(await _dispatch(msg[0], msg.sublist(1), clientPid));
            try {
              await sock.flush();
            } catch (e) {
              debugPrint('[SshAgent] flush 失败: $e');
            }
          }
        }).catchError((Object error, StackTrace stackTrace) {
          debugPrint('[SshAgent] 协议处理失败: $error');
          b.clear();
          sock.destroy();
        });
      }, onDone: () => sock.destroy());
    } catch (e) {
      debugPrint('[SshAgent] 客户端处理错误: $e');
      try {
        sock.destroy();
      } catch (e2) {
        debugPrint('[SshAgent] 销毁 socket 失败: $e2');
      }
    }
  }

  Future<Uint8List> _dispatch(
      int type, Uint8List payload, int clientPid) async {
    switch (type) {
      case agentcRequestIdentities:
        return _identities();
      case agentcSignRequest:
        debugPrint('[SshAgent] 收到签名请求');
        return await _sign(payload, clientPid);
      default:
        return _msg(agentFailure);
    }
  }

  Uint8List _identities() {
    if (keystore.isLocked) return _msg(agentFailure);
    final keys = keystore.keys.where((k) => k.enabled).toList();
    final w = _W();
    w.u32(keys.length);
    for (final k in keys) {
      w.bytes(k.publicKeyBlob);
      w.bytes(utf8.encode(k.name));
    }
    return _msg(agentIdentitiesAnswer, w.data);
  }

  Future<Uint8List> _sign(Uint8List payload, int clientPid) async {
    debugPrint('[SshAgent] _sign 被调用, locked=${keystore.isLocked}');
    if (keystore.isLocked) {
      log?.log(
          allowed: false,
          reason: '已锁定',
          keyName: '',
          processName: 'PID:$clientPid');
      return _msg(agentFailure);
    }
    late final Uint8List reqBlob;
    late final Uint8List data;
    late final int flags;
    try {
      final r = _R(payload);
      reqBlob = r.bytes();
      data = r.bytes();
      flags = r.u32();
      if (!r.isAtEnd) return _msg(agentFailure);
    } on FormatException {
      return _msg(agentFailure);
    }

    // 通过 publicKeyBlob 匹配密钥
    for (final key in keystore.keys.where((k) => k.enabled)) {
      if (!_bytesEq(key.publicKeyBlob, reqBlob)) continue;

      debugPrint('[SshAgent] 找到匹配密钥: ${key.name}');
      // 获取客户端进程路径用于信任判断
      String? clientPath;
      if (clientPid > 0) {
        clientPath = await getProcessPathFromPid(clientPid);
      }
      // 确认检查
      if (await policy.needsConfirmation(
          processPid: clientPid, processPath: clientPath)) {
        int retries = 0;
        while (onConfirm == null && retries < 10) {
          await Future.delayed(const Duration(milliseconds: 100));
          retries++;
        }
        if (onConfirm != null) {
          debugPrint('[SshAgent] 正在调用 onConfirm...');
          final result = await _requestConfirmation(
              key.name, key.fingerprint, clientPath, clientPid);
          debugPrint('[SshAgent] onConfirm 结果: $result');
          if (result == 0) return _msg(agentFailure);
          if (result == 1) {
            policy.grant(processPid: clientPid, processPath: clientPath);
          }
        } else {
          debugPrint('[SshAgent] onConfirm 超时未设置，默认拒绝');
          return _msg(agentFailure);
        }
      } else {
        log?.log(
            allowed: true,
            reason: '已信任程序',
            keyName: key.name,
            processName: clientPath ?? 'PID:$clientPid');
      }

      // 按需从磁盘读取私钥，签名后丢弃
      final privateKeyPem = await keystore.getPrivateKeyForSigning(key.id);
      debugPrint('[SshAgent] 私钥读取结果: ${privateKeyPem != null ? "成功" : "null"}');
      if (privateKeyPem == null) return _msg(agentFailure);

      try {
        final parsedKey = SshKeyService.parse(privateKeyPem);
        final sigBytes = parsedKey.sign(data, flags: flags);

        final w = _W();
        w.bytes(sigBytes);
        return _msg(agentSignResponse, w.data);
      } catch (e) {
        debugPrint('[SshAgent] 签名失败 ${key.name}: $e');
      }
    }
    return _msg(agentFailure);
  }

  Future<int> _requestConfirmation(String keyName, String fingerprint,
      String? processPath, int clientPid) async {
    final previous = _confirmationTail;
    final gate = Completer<void>();
    _confirmationTail = gate.future;
    await previous;
    try {
      final callback = onConfirm;
      if (callback == null) return 0;
      return await callback(keyName, fingerprint, processPath, clientPid);
    } finally {
      gate.complete();
    }
  }

  static Uint8List _msg(int type, [List<int>? body]) {
    final b = body ?? <int>[];
    final out = Uint8List(5 + b.length);
    _setBe32(out, 0, 1 + b.length);
    out[4] = type;
    if (b.isNotEmpty) out.setRange(5, 5 + b.length, b);
    return out;
  }

  static int _be32(List<int> d, int o) =>
      (d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
  static void _setBe32(Uint8List d, int o, int v) {
    d[o] = (v >> 24) & 0xFF;
    d[o + 1] = (v >> 16) & 0xFF;
    d[o + 2] = (v >> 8) & 0xFF;
    d[o + 3] = v & 0xFF;
  }

  static bool _bytesEq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }
}

class _W {
  final List<int> d = [];
  void u32(int n) =>
      d.addAll([(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]);
  void bytes(List<int> b) {
    u32(b.length);
    d.addAll(b);
  }

  List<int> get data => d;
}

class _R {
  final Uint8List d;
  int o = 0;
  _R(this.d);
  bool get isAtEnd => o == d.length;

  int u32() {
    _require(4);
    final v = (d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
    o += 4;
    return v;
  }

  Uint8List bytes() {
    final l = u32();
    _require(l);
    final r = d.sublist(o, o + l);
    o += l;
    return r;
  }

  void _require(int length) {
    if (length < 0 || o + length > d.length) {
      throw const FormatException('SSH Agent 消息长度无效');
    }
  }
}
