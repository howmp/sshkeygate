import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/foundation.dart';

import 'secure_storage_service.dart';

/// 签名确认提示
class SignPrompt {
  final String fingerprint;
  final int? processPid;
  final String? processPath;

  const SignPrompt({
    required this.fingerprint,
    this.processPid,
    this.processPath,
  });
}

/// 审批策略
enum ApprovalPolicy {
  everyRequest, // 每次确认
  session, // 会话授权
  timedMinutes, // 定时授权（N分钟）
  trustedProcess, // 信任进程
}

/// 策略引擎
class PolicyService extends ChangeNotifier {
  final SecureStorageService _storage;
  final Future<String?> Function(String path) _hashExecutable;
  final Future<int?> Function(String path) _modifiedTime;
  ApprovalPolicy _policy = ApprovalPolicy.everyRequest;
  bool _sessionGranted = false;
  DateTime? _grantedUntil;
  int? _grantedPid;

  PolicyService({
    required SecureStorageService storage,
    Future<String?> Function(String path)? hashExecutable,
    Future<int?> Function(String path)? modifiedTime,
  })  : _storage = storage,
        _hashExecutable = hashExecutable ?? _defaultHashExecutable,
        _modifiedTime = modifiedTime ?? _defaultModifiedTime;

  ApprovalPolicy get policy => _policy;
  Set<String> get trustedPaths => _storage.trustedPaths;
  Map<String, String> get trustedProgramHashes => _storage.trustedProgramHashes;
  Map<String, int> get trustedProgramModifiedTimes =>
      _storage.trustedProgramModifiedTimes;
  List<String> get trustVerification => _storage.trustVerification;

  Future<void> setTrustVerification(Iterable<String> values) async {
    final selected = values
        .where((v) => v == 'path' || v == 'mtime' || v == 'sha256')
        .toSet();
    // The path is always required to identify the trusted executable.
    selected.add('path');
    await _storage.updateSettings({
      ..._storage.getSettings(),
      'trustVerification': selected.toList(),
    });
    notifyListeners();
  }

  void setPolicy(ApprovalPolicy policy) {
    _policy = policy;
    _sessionGranted = false;
    _grantedUntil = null;
    _grantedPid = null;
    notifyListeners();
  }

  /// 检查是否需要用户确认
  Future<bool> needsConfirmation({int? processPid, String? processPath}) async {
    // 已信任的程序路径，任何策略下都自动放行
    if (processPath != null) {
      final normalized = processPath.toLowerCase();
      final selected = trustVerification.toSet();
      final trustedHash = _storage.trustedProgramHashes[normalized];
      final trustedMtime = _storage.trustedProgramModifiedTimes[normalized];
      var matches = selected.contains('path') &&
          (trustedHash != null || trustedMtime != null);
      if (matches && selected.contains('mtime')) {
        final currentMtime = await _modifiedTime(processPath);
        matches = currentMtime != null && currentMtime == trustedMtime;
      }
      if (matches && selected.contains('sha256')) {
        final currentHash = await _hashExecutable(processPath);
        matches = currentHash != null && currentHash == trustedHash;
      }
      if (matches) {
        return false;
      }
    }

    switch (_policy) {
      case ApprovalPolicy.everyRequest:
      case ApprovalPolicy.trustedProcess:
        return true;
      case ApprovalPolicy.session:
        if (!_sessionGranted) return true;
        return _grantedPid != processPid;
      case ApprovalPolicy.timedMinutes:
        final expired =
            _grantedUntil == null || DateTime.now().isAfter(_grantedUntil!);
        if (expired) return true;
        return _grantedPid != processPid;
    }
  }

  /// 记录授权
  void grant({int? processPid, String? processPath}) {
    _grantedPid = processPid;
    switch (_policy) {
      case ApprovalPolicy.session:
        _sessionGranted = true;
      case ApprovalPolicy.trustedProcess:
        break;
      case ApprovalPolicy.timedMinutes:
        _grantedUntil = DateTime.now().add(const Duration(minutes: 5));
      case ApprovalPolicy.everyRequest:
        break;
    }
    notifyListeners();
  }

  /// 添加信任程序
  Future<bool> addTrustedProcess(String path) async {
    // Always capture a complete snapshot. The setting controls which fields
    // are checked on each request, not which metadata is retained.
    final results = await Future.wait([
      _hashExecutable(path),
      _modifiedTime(path),
    ]);
    final hash = results[0] as String?;
    final modifiedTime = results[1] as int?;
    if (hash == null || modifiedTime == null) return false;
    await _storage.addTrustedProgram(path,
        sha256: hash, modifiedTimeMs: modifiedTime);
    notifyListeners();
    return true;
  }

  /// 移除信任程序
  Future<void> removeTrustedProcess(String path) async {
    await _storage.removeTrustedPath(path);
    notifyListeners();
  }

  /// 重置会话授权状态（不清除信任列表，信任列表跟随 vault）
  void resetSession() {
    _sessionGranted = false;
    _grantedUntil = null;
    _grantedPid = null;
    notifyListeners();
  }

  /// 重置所有（含信任列表）
  void reset() {
    _sessionGranted = false;
    _grantedUntil = null;
    _grantedPid = null;
    // 信任列表在 vault 里，锁定时自然清除
    notifyListeners();
  }

  static Future<String?> _defaultHashExecutable(String path) async {
    try {
      final file = File(path);
      if (!await file.exists()) return null;
      return (await crypto.sha256.bind(file.openRead()).first).toString();
    } catch (_) {
      return null;
    }
  }

  static Future<int?> _defaultModifiedTime(String path) async {
    try {
      final file = File(path);
      if (!await file.exists()) return null;
      return (await file.stat()).modified.millisecondsSinceEpoch;
    } catch (_) {
      return null;
    }
  }
}
