import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const _deviceKeyName = 'sshkeygate_device_key';
const _saltKeyName = 'sshkeygate_salt';
const _vaultKeyName = 'sshkeygate_vault';
const _pkPrefix = 'sshkeygate_pk_';
const _passwordMigrationKey = 'sshkeygate_password_migration';
const _pbkdf2Iterations = 100000;

/// 统一安全存储服务
///
/// 所有数据存储在 flutter_secure_storage 中（单文件 flutter_secure_storage.dat）。
/// 平台保护层：Windows Credential Manager(DPAPI) / macOS Keychain / Linux libsecret。
///
/// 存储结构：
/// - sshkeygate_device_key: 32字节随机设备密钥（base64）
/// - sshkeygate_salt: 16字节随机盐（base64）
/// - sshkeygate_vault: AES-256-GCM加密的元数据JSON（不含私钥）
/// - sshkeygate_pk_{id}: 每条私钥单独加密存储
///
/// 内存模型：
/// - 解锁后：_vaultData 仅含元数据 + trustedPaths，无私钥
/// - 签名时：按需读取并解密单条私钥，用完即弃
class SecureStorageService {
  final FlutterSecureStorage _secureStorage;
  Uint8List? _deviceKey;
  Uint8List? _salt;

  // 解密后的内存缓存（不含私钥）
  List<Map<String, dynamic>>? _keysMeta;
  Set<String>? _trustedPaths;
  Map<String, String>? _trustedProgramHashes;
  Map<String, int>? _trustedProgramModifiedTimes;
  Map<String, dynamic>? _settings;

  // vault 元数据（不含私钥），解锁期间持有
  Map<String, dynamic>? _vaultData;

  // 派生的加密密钥，解锁期间持有
  List<int>? _derivedKey;

  SecureStorageService({FlutterSecureStorage? secureStorage})
      : _secureStorage = secureStorage ?? const FlutterSecureStorage();

  bool get isInitialized => _deviceKey != null && _salt != null;
  List<Map<String, dynamic>> get keysMeta => _keysMeta ?? [];
  Set<String> get trustedPaths => _trustedPaths ?? {};
  Map<String, String> get trustedProgramHashes =>
      Map.unmodifiable(_trustedProgramHashes ?? const {});
  Map<String, int> get trustedProgramModifiedTimes =>
      Map.unmodifiable(_trustedProgramModifiedTimes ?? const {});
  Map<String, dynamic> get settings =>
      _settings ?? {'confirmTimeoutSeconds': 30, 'lockOnScreenLock': true};

  /// 初始化：确保 device_key 和 salt 存在
  Future<void> initialize() async {
    final existingKey = await _secureStorage.read(key: _deviceKeyName);
    if (existingKey != null) {
      _deviceKey = base64Decode(existingKey);
    } else {
      final algo = AesGcm.with256bits();
      final sk = await algo.newSecretKey();
      _deviceKey = Uint8List.fromList(await sk.extractBytes());
      await _secureStorage.write(
          key: _deviceKeyName, value: base64Encode(_deviceKey!));
    }

    final existingSalt = await _secureStorage.read(key: _saltKeyName);
    if (existingSalt != null) {
      _salt = base64Decode(existingSalt);
    } else {
      final algo = AesGcm.with256bits();
      final sk = await algo.newSecretKey();
      _salt = Uint8List.fromList((await sk.extractBytes()).sublist(0, 16));
      await _secureStorage.write(
          key: _saltKeyName, value: base64Encode(_salt!));
    }

    await _recoverInterruptedPasswordChange();
  }

  Future<bool> vaultExistsAsync() async {
    final v = await _secureStorage.read(key: _vaultKeyName);
    return v != null;
  }

  bool _vaultExistsCache = false;
  bool get vaultExists => _vaultExistsCache;

  Future<void> checkVaultExists() async {
    _vaultExistsCache = await vaultExistsAsync();
  }

  /// 创建新 vault（首次设置密码）
  Future<void> createVault(String password) async {
    _derivedKey = await _deriveKey(password);
    _vaultData = {
      'keys': [],
      'trustedPaths': [],
      'trustedPrograms': [],
      'settings': {
        'confirmTimeoutSeconds': 30,
        'lockOnScreenLock': true,
        'closeToTrayHintShown': false,
        'trustVerification': ['path', 'mtime']
      }
    };
    _keysMeta = [];
    _trustedPaths = {};
    _trustedProgramHashes = {};
    _trustedProgramModifiedTimes = {};
    _settings = {
      'confirmTimeoutSeconds': 30,
      'lockOnScreenLock': true,
      'closeToTrayHintShown': false,
      'trustVerification': ['path', 'mtime']
    };
    await _saveVault();
    _vaultExistsCache = true;
  }

  /// 解锁（验证密码并加载元数据到内存，私钥不进内存）
  Future<bool> unlock(String password) async {
    try {
      _derivedKey = await _deriveKey(password);
      final stored = await _secureStorage.read(key: _vaultKeyName);
      if (stored == null) return false;

      final encrypted = base64Decode(stored);
      final json = await _decrypt(encrypted, _derivedKey!);
      _vaultData = jsonDecode(json) as Map<String, dynamic>;

      final keys = (_vaultData!['keys'] as List?) ?? [];
      _keysMeta = keys.map((k) => Map<String, dynamic>.from(k as Map)).toList();

      final trustedPrograms = (_vaultData!['trustedPrograms'] as List?) ?? [];
      _trustedProgramHashes = {
        for (final item in trustedPrograms)
          if (item is Map && item['path'] is String && item['sha256'] is String)
            item['path'] as String: item['sha256'] as String,
      };
      _trustedProgramModifiedTimes = {
        for (final item in trustedPrograms)
          if (item is Map &&
              item['path'] is String &&
              item['modifiedTimeMs'] is num)
            item['path'] as String: (item['modifiedTimeMs'] as num).toInt(),
      };
      _trustedPaths = {
        ..._trustedProgramHashes!.keys,
        ..._trustedProgramModifiedTimes!.keys,
      };

      // Path-only trust records cannot prove which executable is being run.
      final legacyTrusted = (_vaultData!['trustedPaths'] as List?) ?? [];
      if (legacyTrusted.isNotEmpty || _vaultData!['trustedPrograms'] == null) {
        _vaultData!['trustedPaths'] = <String>[];
        _vaultData!['trustedPrograms'] = _serializeTrustedPrograms();
        await _saveVault();
      }

      final settingsData = _vaultData!['settings'] as Map<String, dynamic>?;
      _settings = settingsData != null
          ? Map<String, dynamic>.from(settingsData)
          : {'confirmTimeoutSeconds': 30, 'lockOnScreenLock': true};
      // 确保 vault 中有 settings 字段（兼容旧 vault）
      if (_vaultData!['settings'] == null) {
        _vaultData!['settings'] = _settings;
        await _saveVault();
      }

      return true;
    } catch (e) {
      debugPrint('[SecureStorage] 解锁失败: $e');
      _zeroize(_derivedKey);
      _derivedKey = null;
      _vaultData = null;
      _keysMeta = null;
      _trustedPaths = null;
      _trustedProgramHashes = null;
      _trustedProgramModifiedTimes = null;
      _settings = null;
      return false;
    }
  }

  /// 锁定（清除内存中所有敏感数据）
  void lock() {
    _zeroize(_derivedKey);
    _derivedKey = null;
    _vaultData = null;
    _keysMeta = null;
    _trustedPaths = null;
    _trustedProgramHashes = null;
    _trustedProgramModifiedTimes = null;
    _settings = null;
  }

  bool get isUnlocked => _derivedKey != null && _vaultData != null;

  /// 修改密码（需要重新加密所有私钥）
  Future<bool> changePassword(String oldPassword, String newPassword) async {
    if (!isUnlocked) return false;
    final activeKey = _derivedKey!;
    final oldKey = await _deriveKey(oldPassword);
    final storedVault = await _secureStorage.read(key: _vaultKeyName);
    if (storedVault == null) {
      _zeroize(oldKey);
      return false;
    }
    try {
      await _decrypt(base64Decode(storedVault), oldKey);
    } catch (_) {
      _zeroize(oldKey);
      return false;
    }

    final newKey = await _deriveKey(newPassword);
    final oldPrivateKeys = <String, String>{};
    final newPrivateKeys = <String, String>{};
    late final String migration;
    try {
      final keys = (_vaultData!['keys'] as List?) ?? [];
      for (final k in keys) {
        final id = k['id'] as String;
        final pkStored = await _secureStorage.read(key: '$_pkPrefix$id');
        if (pkStored != null) {
          final pkPlain = await _decrypt(base64Decode(pkStored), oldKey);
          oldPrivateKeys[id] = pkStored;
          newPrivateKeys[id] = base64Encode(await _encrypt(pkPlain, newKey));
        }
      }

      migration = jsonEncode({
        'vault': storedVault,
        'privateKeys': oldPrivateKeys,
      });
      await _secureStorage.write(key: _passwordMigrationKey, value: migration);
    } catch (_) {
      _zeroize(oldKey);
      _zeroize(newKey);
      return false;
    }

    try {
      for (final entry in newPrivateKeys.entries) {
        await _secureStorage.write(
            key: '$_pkPrefix${entry.key}', value: entry.value);
      }
      _derivedKey = newKey;
      await _saveVault();
      await _secureStorage.delete(key: _passwordMigrationKey);
      _zeroize(activeKey);
      _zeroize(oldKey);
      return true;
    } catch (_) {
      try {
        await _restorePasswordMigration(migration);
      } finally {
        _zeroize(newKey);
        _zeroize(oldKey);
        _derivedKey = activeKey;
      }
      return false;
    }
  }

  // ── 密钥操作 ──

  /// 添加密钥（私钥单独加密存储，不进入 vault 元数据）
  Future<void> addKey(Map<String, dynamic> keyData) async {
    _ensureUnlocked();
    final id = keyData['id'] as String;
    final privateKey = keyData['privateKey'] as String?;

    // 私钥单独加密存储（已是解密后的明文PEM）
    if (privateKey != null) {
      final encrypted = await _encrypt(privateKey, _derivedKey!);
      await _secureStorage.write(
          key: '$_pkPrefix$id', value: base64Encode(encrypted));
    }

    // vault 元数据中不含私钥
    final meta = Map<String, dynamic>.from(keyData);
    meta.remove('privateKey');

    (_vaultData!['keys'] as List).add(meta);
    _keysMeta!.add(Map<String, dynamic>.from(meta));
    await _saveVault();
  }

  /// 删除密钥
  Future<void> removeKey(String id) async {
    _ensureUnlocked();
    (_vaultData!['keys'] as List).removeWhere((k) => k['id'] == id);
    _keysMeta!.removeWhere((m) => m['id'] == id);
    // 删除私钥条目
    await _secureStorage.delete(key: '$_pkPrefix$id');
    await _saveVault();
  }

  /// 切换密钥启用状态
  Future<void> toggleKey(String id) async {
    _ensureUnlocked();
    for (final k in (_vaultData!['keys'] as List)) {
      if (k['id'] == id) {
        k['enabled'] = !(k['enabled'] as bool);
        break;
      }
    }
    for (final m in _keysMeta!) {
      if (m['id'] == id) {
        m['enabled'] = !(m['enabled'] as bool);
        break;
      }
    }
    await _saveVault();
  }

  /// 重命名密钥
  Future<void> renameKey(String id, String newName) async {
    _ensureUnlocked();
    for (final k in (_vaultData!['keys'] as List)) {
      if (k['id'] == id) {
        k['name'] = newName;
        break;
      }
    }
    for (final m in _keysMeta!) {
      if (m['id'] == id) {
        m['name'] = newName;
        break;
      }
    }
    await _saveVault();
  }

  /// 按需读取并解密单条私钥（签名时调用，用完由调用方丢弃）
  Future<String?> getPrivateKey(String id) async {
    _ensureUnlocked();
    final stored = await _secureStorage.read(key: '$_pkPrefix$id');
    if (stored == null) return null;
    try {
      return await _decrypt(base64Decode(stored), _derivedKey!);
    } catch (e) {
      debugPrint('[SecureStorage] 解密私钥失败: $e');
      return null;
    }
  }

  // ── 设置操作 ──

  /// 获取设置
  Map<String, dynamic> getSettings() {
    return Map<String, dynamic>.from(
        _settings ?? {'confirmTimeoutSeconds': 30, 'lockOnScreenLock': true});
  }

  /// 获取确认超时时间（秒）
  int get confirmTimeoutSeconds {
    final s = getSettings();
    return (s['confirmTimeoutSeconds'] as int?) ?? 30;
  }

  bool get lockOnScreenLock {
    final s = getSettings();
    return (s['lockOnScreenLock'] as bool?) ?? true;
  }

  bool get closeToTrayHintShown {
    return (getSettings()['closeToTrayHintShown'] as bool?) ?? false;
  }

  List<String> get trustVerification {
    final values = getSettings()['trustVerification'];
    if (values is! List) return const ['path', 'mtime'];
    final selected = values
        .whereType<String>()
        .where((v) => v == 'path' || v == 'mtime' || v == 'sha256')
        .toSet();
    return selected.isEmpty ? const ['path', 'mtime'] : selected.toList();
  }

  /// 更新设置
  Future<void> updateSettings(Map<String, dynamic> newSettings) async {
    _ensureUnlocked();
    _settings = Map<String, dynamic>.from(newSettings);
    _vaultData!['settings'] = _settings;
    await _saveVault();
  }

  // ── 信任路径操作 ──

  Future<void> addTrustedProgram(String path,
      {String? sha256, int? modifiedTimeMs}) async {
    _ensureUnlocked();
    _trustedPaths ??= <String>{};
    _trustedProgramHashes ??= <String, String>{};
    _trustedProgramModifiedTimes ??= <String, int>{};
    final normalized = path.toLowerCase();
    _trustedPaths!.add(normalized);
    if (sha256 != null) _trustedProgramHashes![normalized] = sha256;
    if (modifiedTimeMs != null) {
      _trustedProgramModifiedTimes![normalized] = modifiedTimeMs;
    }
    _vaultData!['trustedPrograms'] = _serializeTrustedPrograms();
    await _saveVault();
  }

  Future<void> removeTrustedPath(String path) async {
    _ensureUnlocked();
    final normalized = path.toLowerCase();
    _trustedPaths?.remove(normalized);
    _trustedProgramHashes?.remove(normalized);
    _trustedProgramModifiedTimes?.remove(normalized);
    _vaultData!['trustedPrograms'] = _serializeTrustedPrograms();
    await _saveVault();
  }

  List<Map<String, dynamic>> _serializeTrustedPrograms() => [
        for (final path in _trustedPaths ?? const <String>{})
          {
            'path': path,
            if (_trustedProgramModifiedTimes?[path] != null)
              'modifiedTimeMs': _trustedProgramModifiedTimes![path],
            if (_trustedProgramHashes?[path] case final hash?) 'sha256': hash,
          },
      ];

  // ── 内部方法 ──

  Future<void> _recoverInterruptedPasswordChange() async {
    final migration = await _secureStorage.read(key: _passwordMigrationKey);
    if (migration == null) return;
    await _restorePasswordMigration(migration);
  }

  Future<void> _restorePasswordMigration(String migration) async {
    final data = jsonDecode(migration) as Map<String, dynamic>;
    final vault = data['vault'] as String;
    final privateKeys = Map<String, dynamic>.from(
        data['privateKeys'] as Map? ?? const <String, dynamic>{});
    await _secureStorage.write(key: _vaultKeyName, value: vault);
    for (final entry in privateKeys.entries) {
      await _secureStorage.write(
          key: '$_pkPrefix${entry.key}', value: entry.value as String);
    }
    await _secureStorage.delete(key: _passwordMigrationKey);
  }

  void _ensureUnlocked() {
    if (!isUnlocked) throw StateError('Vault is locked');
  }

  void _zeroize(List<int>? bytes) {
    if (bytes == null) return;
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }

  Future<List<int>> _deriveKey(String password) async {
    final input = utf8.encode(password) + _deviceKey!;
    return await compute(_pbkdf2Derive, _Pbkdf2Params(input, _salt!));
  }

  Future<void> _saveVault() async {
    final json = jsonEncode(_vaultData);
    final encrypted = await _encrypt(json, _derivedKey!);
    await _secureStorage.write(
        key: _vaultKeyName, value: base64Encode(encrypted));
  }

  Future<Uint8List> _encrypt(String plaintext, List<int> key) async {
    final algorithm = AesGcm.with256bits();
    final secretKey = SecretKey(key);
    final secretBox = await algorithm.encrypt(
      utf8.encode(plaintext),
      secretKey: secretKey,
    );
    return Uint8List.fromList(secretBox.concatenation());
  }

  Future<String> _decrypt(Uint8List data, List<int> key) async {
    final algorithm = AesGcm.with256bits();
    final secretKey = SecretKey(key);
    final secretBox =
        SecretBox.fromConcatenation(data, nonceLength: 12, macLength: 16);
    final clearText = await algorithm.decrypt(secretBox, secretKey: secretKey);
    return utf8.decode(clearText);
  }
}

// ── 隔离线程 PBKDF2 ──

class _Pbkdf2Params {
  final List<int> input;
  final List<int> salt;
  const _Pbkdf2Params(this.input, this.salt);
}

Future<List<int>> _pbkdf2Derive(_Pbkdf2Params params) async {
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: _pbkdf2Iterations,
    bits: 256,
  );
  final secretKey = await pbkdf2.deriveKey(
    secretKey: SecretKey(params.input),
    nonce: params.salt,
  );
  return Uint8List.fromList(await secretKey.extractBytes());
}
