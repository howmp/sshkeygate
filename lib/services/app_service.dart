import 'package:flutter/foundation.dart';
import 'keystore_service.dart';
import 'policy_service.dart';
import 'secure_storage_service.dart';
import 'ssh_key_service.dart';
import 'bitwarden_service.dart';
import 'windows_service.dart';

/// 应用服务聚合器
class AppService extends ChangeNotifier {
  static const minimumPasswordLength = 12;

  final SecureStorageService storage;
  final KeyStoreService keystore;
  final PolicyService policy;
  final WindowsService windows;
  String _status = '就绪';
  int _failedUnlockAttempts = 0;
  DateTime? _nextUnlockAllowedAt;

  AppService({
    required this.storage,
    required this.keystore,
    required this.policy,
    required this.windows,
  });

  String get status => _status;
  bool get isLocked => keystore.isLocked;
  bool get isFirstRun => !storage.vaultExists;

  void setStatus(String msg) {
    _status = msg;
    notifyListeners();
  }

  /// 首次设置密码
  Future<bool> setupPassword(String password) async {
    if (!isFirstRun) {
      setStatus('密钥库已存在');
      return false;
    }
    if (password.length < minimumPasswordLength) {
      setStatus('密码至少 $minimumPasswordLength 个字符');
      return false;
    }
    try {
      await storage.createVault(password);
      keystore.loadFromStorage();
      setStatus('已创建并解锁');
      return true;
    } catch (e) {
      setStatus('创建失败：$e');
      return false;
    }
  }

  /// 解锁
  Future<bool> unlock(String password) async {
    final now = DateTime.now();
    if (_nextUnlockAllowedAt != null && now.isBefore(_nextUnlockAllowedAt!)) {
      final seconds = _nextUnlockAllowedAt!.difference(now).inSeconds + 1;
      setStatus('尝试过于频繁，请等待 $seconds 秒');
      return false;
    }
    final ok = await storage.unlock(password);
    if (ok) {
      _failedUnlockAttempts = 0;
      _nextUnlockAllowedAt = null;
      keystore.loadFromStorage();
      setStatus('已解锁');
      notifyListeners();
      return true;
    }
    _failedUnlockAttempts++;
    final exponent = _failedUnlockAttempts > 4 ? 3 : _failedUnlockAttempts - 1;
    final delaySeconds = 1 << exponent;
    _nextUnlockAllowedAt = DateTime.now().add(Duration(seconds: delaySeconds));
    setStatus('密码错误，请等待 $delaySeconds 秒后重试');
    return false;
  }

  /// 锁定
  void lock() {
    keystore.lock();
    storage.lock();
    policy.resetSession();
    setStatus('已锁定');
    notifyListeners();
  }

  /// 切换锁定状态（仅用于锁定方向，解锁需要密码）
  void toggleLock() {
    if (!keystore.isLocked) {
      lock();
    }
  }

  /// 修改密码
  Future<bool> changePassword(String oldPwd, String newPwd) async {
    if (newPwd.length < minimumPasswordLength) return false;
    try {
      return await storage.changePassword(oldPwd, newPwd);
    } catch (_) {
      return false;
    }
  }

  /// Bitwarden 同步
  Future<String> syncBitwarden({
    required String serverUrl,
    required String email,
    required String password,
  }) async {
    setStatus('Bitwarden 正在登录和同步…');
    try {
      final config = BitwardenConfig(
        serverUrl: serverUrl.trim(),
        email: email.trim(),
        password: password,
      );
      final client = BitwardenClient(config: config);
      final session = await client.login();
      final items = await client.sync(session);
      client.dispose();

      int imported = 0;
      int skipped = 0;
      final existingFingerprints =
          keystore.keys.map((k) => k.fingerprint).toSet();
      for (final item in items) {
        if (!item.enabled) continue;
        try {
          final parsedKey = SshKeyService.parse(
            item.privateKey,
            passphrase: item.passphrase,
          );
          if (existingFingerprints.contains(parsedKey.fingerprint)) {
            skipped++;
            continue;
          }
          await keystore.importKey(
            item.privateKey,
            item.name,
            item.passphrase,
            source: KeySource.bitwarden,
            algorithm: item.algorithm,
          );
          existingFingerprints.add(parsedKey.fingerprint);
          imported++;
        } catch (e) {
          skipped++;
        }
      }

      final msg = '同步完成：导入 $imported，跳过 $skipped';
      setStatus(msg);
      return msg;
    } catch (e) {
      final msg = '同步失败：$e';
      setStatus(msg);
      return msg;
    }
  }

  /// 手动文本导入
  Future<String> importFromText({
    required String keyText,
    String? name,
    String? passphrase,
  }) async {
    if (keyText.trim().isEmpty) {
      const msg = '导入失败：私钥文本为空';
      setStatus(msg);
      return msg;
    }
    if (!keyText.contains('PRIVATE KEY')) {
      const msg = '导入失败：私钥文本格式无效，缺少 PRIVATE KEY 标识';
      setStatus(msg);
      return msg;
    }
    try {
      await keystore.importKey(
        keyText,
        name?.trim().isNotEmpty == true ? name!.trim() : null,
        passphrase?.trim().isNotEmpty == true ? passphrase!.trim() : null,
      );
      setStatus('导入成功');
      return '导入成功';
    } catch (e) {
      setStatus('导入失败：$e');
      return '导入失败：$e';
    }
  }

  /// 删除密钥
  Future<void> deleteKey(String id) async {
    await keystore.deleteKey(id);
  }

  /// 切换密钥启用
  Future<void> toggleKey(String id) async {
    await keystore.toggleKey(id);
  }

  /// 添加信任程序
  Future<bool> addTrustedProcess(String path) {
    return policy.addTrustedProcess(path);
  }

  /// 移除信任程序
  Future<void> removeTrustedProcess(String path) {
    return policy.removeTrustedProcess(path);
  }

  // ── 设置操作 ──

  /// 获取确认超时时间（秒）
  int get confirmTimeoutSeconds => storage.confirmTimeoutSeconds;
  bool get lockOnScreenLock => storage.lockOnScreenLock;
  bool get closeToTrayHintShown => storage.closeToTrayHintShown;

  Future<void> markCloseToTrayHintShown() async {
    if (isLocked) return;
    final settings = getSettings();
    settings['closeToTrayHintShown'] = true;
    await updateSettings(settings);
  }

  /// 获取所有设置
  Map<String, dynamic> getSettings() => storage.getSettings();

  /// 更新设置
  Future<void> updateSettings(Map<String, dynamic> newSettings) async {
    await storage.updateSettings(newSettings);
    notifyListeners();
  }
}
