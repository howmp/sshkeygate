import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:uuid/uuid.dart';

import 'secure_storage_service.dart';
import 'ssh_key_service.dart';

/// 密钥来源
enum KeySource { bitwarden, manual }

extension KeySourceLabel on KeySource {
  String get label {
    switch (this) {
      case KeySource.bitwarden:
        return 'Bitwarden';
      case KeySource.manual:
        return '手动导入';
    }
  }
}

/// 密钥元数据（内存中只保留这些，不含私钥）
class KeyMeta {
  final String id;
  final String name;
  final String algorithm;
  final String fingerprint;
  final Uint8List publicKeyBlob;
  final KeySource source;
  bool enabled;

  KeyMeta({
    required this.id,
    required this.name,
    required this.algorithm,
    required this.fingerprint,
    required this.publicKeyBlob,
    required this.source,
    required this.enabled,
  });
}

/// 密钥库服务
///
/// 内存中只持有元数据和 publicKeyBlob。
/// 私钥仅在导入验证和签名时短暂出现在内存。
class KeyStoreService extends ChangeNotifier {
  final SecureStorageService _storage;
  final List<KeyMeta> _keys = [];
  bool _isLocked = true;

  KeyStoreService({required SecureStorageService storage}) : _storage = storage;

  List<KeyMeta> get keys => List.unmodifiable(_keys);
  bool get isLocked => _isLocked;

  /// 解锁后从 storage 加载元数据
  void loadFromStorage() {
    _keys.clear();
    for (final meta in _storage.keysMeta) {
      _keys.add(KeyMeta(
        id: meta['id'] as String,
        name: meta['name'] as String,
        algorithm: meta['algorithm'] as String,
        fingerprint: meta['fingerprint'] as String,
        publicKeyBlob:
            Uint8List.fromList(base64Decode(meta['publicKeyBlob'] as String)),
        source: KeySource.values.firstWhere((s) => s.name == meta['source'],
            orElse: () => KeySource.manual),
        enabled: meta['enabled'] as bool,
      ));
    }
    _isLocked = false;
    notifyListeners();
  }

  /// 锁定（清除内存）
  void lock() {
    _isLocked = true;
    _keys.clear();
    notifyListeners();
  }

  /// 导入密钥（支持加密密钥，验证后存储解密态 PEM）
  Future<KeyMeta> importKey(
      String privateKeyPem, String? name, String? passphrase,
      {KeySource source = KeySource.manual, String? algorithm}) async {
    final ParsedSshKey parsedKey;
    try {
      parsedKey = SshKeyService.parse(privateKeyPem, passphrase: passphrase);
    } catch (e) {
      throw FormatException('密钥解析失败：$e');
    }
    final publicKeyBlob = parsedKey.publicKeyBlob;
    final fingerprint = parsedKey.fingerprint;
    final decryptedPem = parsedKey.unencryptedPem;

    final id = const Uuid().v4();
    final keyData = {
      'id': id,
      'name': name ?? 'imported-key',
      'algorithm': algorithm ?? parsedKey.algorithm,
      'fingerprint': fingerprint,
      'publicKeyBlob': base64Encode(publicKeyBlob),
      'source': source.name,
      'enabled': true,
      'privateKey': decryptedPem,
    };

    await _storage.addKey(keyData);

    final meta = KeyMeta(
      id: id,
      name: name ?? 'imported-key',
      algorithm: algorithm ?? parsedKey.algorithm,
      fingerprint: fingerprint,
      publicKeyBlob: publicKeyBlob,
      source: source,
      enabled: true,
    );
    _keys.add(meta);
    notifyListeners();
    return meta;
  }

  /// 删除密钥
  Future<void> deleteKey(String id) async {
    await _storage.removeKey(id);
    _keys.removeWhere((k) => k.id == id);
    notifyListeners();
  }

  /// 切换启用状态
  Future<void> toggleKey(String id) async {
    await _storage.toggleKey(id);
    final key = _keys.firstWhere((k) => k.id == id);
    key.enabled = !key.enabled;
    notifyListeners();
  }

  /// 重命名密钥
  Future<void> renameKey(String id, String newName) async {
    await _storage.renameKey(id, newName);
    final idx = _keys.indexWhere((k) => k.id == id);
    if (idx >= 0) {
      final old = _keys[idx];
      _keys[idx] = KeyMeta(
        id: old.id,
        name: newName,
        algorithm: old.algorithm,
        fingerprint: old.fingerprint,
        publicKeyBlob: old.publicKeyBlob,
        source: old.source,
        enabled: old.enabled,
      );
      notifyListeners();
    }
  }

  /// 读取私钥用于签名（按需从加密存储解密，调用方用完必须丢弃引用）
  Future<String?> getPrivateKeyForSigning(String id) async {
    if (_isLocked) return null;
    return await _storage.getPrivateKey(id);
  }
}
