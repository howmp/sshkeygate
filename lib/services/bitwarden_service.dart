import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:uuid/uuid.dart';

import 'crypto_service.dart';

/// Bitwarden 配置
class BitwardenConfig {
  final String serverUrl;
  final String email;
  final String password;

  const BitwardenConfig({
    required this.serverUrl,
    required this.email,
    required this.password,
  });
}

/// 解密后的 SSH 密钥条目
class SshItem {
  final String name;
  final String privateKey;
  final String? passphrase;
  final String? algorithm;
  final bool enabled;

  const SshItem({
    required this.name,
    required this.privateKey,
    this.passphrase,
    this.algorithm,
    this.enabled = true,
  });
}

/// Bitwarden 登录会话
class BitwardenSession {
  final String accessToken;
  final String? refreshToken;
  final String? encryptedKey;
  final String? encryptedPrivateKey;
  final KdfConfig kdfConfig;

  const BitwardenSession({
    required this.accessToken,
    this.refreshToken,
    this.encryptedKey,
    this.encryptedPrivateKey,
    required this.kdfConfig,
  });
}

/// Bitwarden 客户端
///
/// 实现 prelogin → 登录 → 同步 → 解密 的完整流程。
/// 支持 PBKDF2-SHA256 和 Argon2id 两种 KDF 算法。
class BitwardenClient {
  final http.Client _http;
  final BitwardenConfig config;
  final String _deviceId;

  BitwardenClient({required this.config})
      : _http = http.Client(),
        _deviceId = const Uuid().v4();

  /// 登录并返回会话
  ///
  /// 1. POST {server}/identity/accounts/prelogin → 获取 KDF 参数
  /// 2. 派生密码哈希
  /// 3. POST {server}/identity/connect/token → 获取 access_token 和
  ///    encrypted key
  Future<BitwardenSession> login() async {
    // 1. Prelogin — 获取 KDF 参数
    final preloginUrl = '${config.serverUrl}/identity/accounts/prelogin';
    final preloginResp = await _http.post(
      Uri.parse(preloginUrl),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': config.email}),
    );
    if (preloginResp.statusCode != 200) {
      throw Exception(
        'Prelogin 失败: ${preloginResp.statusCode} ${preloginResp.body}',
      );
    }
    final prelogin = jsonDecode(preloginResp.body) as Map<String, dynamic>;
    final kdfConfig = KdfConfig.fromJson(prelogin);

    // 2. 派生密码哈希
    final passwordHash = await derivePasswordHash(
      config.password,
      config.email,
      kdfConfig.algorithm,
      kdfConfig.iterations,
      kdfConfig.isArgon2id ? kdfConfig.memory : null,
      kdfConfig.isArgon2id ? kdfConfig.parallelism : null,
    );

    // 3. 登录 — 获取 token
    final loginUrl = '${config.serverUrl}/identity/connect/token';
    final loginResp = await _http.post(
      Uri.parse(loginUrl),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: {
        'grant_type': 'password',
        'username': config.email.trim().toLowerCase(),
        'password': passwordHash,
        'scope': 'api offline_access',
        'client_id': 'web',
        'deviceType': '12',
        'deviceIdentifier': _deviceId,
        'deviceName': 'sshkeygate',
      },
    );
    if (loginResp.statusCode != 200) {
      throw Exception(
        '登录失败: ${loginResp.statusCode} ${loginResp.body}',
      );
    }
    final loginData = jsonDecode(loginResp.body) as Map<String, dynamic>;
    return BitwardenSession(
      accessToken: loginData['access_token'] as String,
      refreshToken: loginData['refresh_token'] as String?,
      encryptedKey: loginData['Key'] as String?,
      encryptedPrivateKey: loginData['PrivateKey'] as String?,
      kdfConfig: kdfConfig,
    );
  }

  /// 同步并解密 SSH 密钥
  ///
  /// 1. 派生 stretched key
  /// 2. 解包 SymmetricCryptoKey
  /// 3. GET {server}/api/sync → 获取 ciphers
  /// 4. 筛选 type=5 的 Cipher，解密提取 SSH 密钥
  Future<List<SshItem>> sync(BitwardenSession session) async {
    // 1. 派生 stretched key
    final stretchedKey = await deriveStretchedKey(
      config.password,
      config.email,
      session.kdfConfig.algorithm,
      session.kdfConfig.iterations,
      session.kdfConfig.isArgon2id ? session.kdfConfig.memory : null,
      session.kdfConfig.isArgon2id ? session.kdfConfig.parallelism : null,
    );

    // 2. 解包 SymmetricCryptoKey（64 字节：enc[0..32] + mac[32..64]）
    final encryptedKey = session.encryptedKey;
    if (encryptedKey == null || encryptedKey.isEmpty) {
      throw Exception('缺少加密密钥');
    }
    final cryptoKeyBytes = await unlockSymmetricCryptoKey(
      encryptedKey,
      stretchedKey,
    );

    // 3. 同步
    final syncUrl = '${config.serverUrl}/api/sync';
    final syncResp = await _http.get(
      Uri.parse(syncUrl),
      headers: {
        'Authorization': 'Bearer ${session.accessToken}',
        // Vaultwarden 需要此 header 才会返回 SSH key 字段
        'Bitwarden-Client-Version': '2025.1.0',
      },
    );
    if (syncResp.statusCode != 200) {
      throw Exception('同步失败: ${syncResp.statusCode}');
    }
    final syncData = jsonDecode(syncResp.body) as Map<String, dynamic>;
    final ciphers = (syncData['ciphers'] as List<dynamic>?) ?? [];
    final profile = syncData['profile'] as Map<String, dynamic>?;

    // 检查 profile.key（组织的加密密钥，优先使用）
    final profileKey = profile?['key'] as String?;
    List<int> finalKeyBytes = cryptoKeyBytes;
    if (profileKey != null && profileKey.isNotEmpty) {
      try {
        finalKeyBytes = await unlockSymmetricCryptoKey(
          profileKey,
          stretchedKey,
        );
      } catch (_) {
        // 回退到默认密钥
      }
    }

    // 4. 解密 SSH 条目（仅 type=5）
    final items = <SshItem>[];
    for (final cipher in ciphers) {
      final ct = cipher as Map<String, dynamic>;
      final cipherType = ct['type'] as int? ?? 0;
      if (cipherType != 5) continue;

      try {
        final item = await _decryptSshCipher(ct, finalKeyBytes);
        if (item != null) items.add(item);
      } catch (_) {
        // 跳过解密失败的条目
      }
    }
    return items;
  }

  /// 解密单个 SSH Cipher（type=5）
  ///
  /// 支持 cipher 自身带有独立 key（组织密钥场景），
  /// 以及 swapKeyHalves 重试（Bitwarden 密钥方向兼容）。
  Future<SshItem?> _decryptSshCipher(
    Map<String, dynamic> cipher,
    List<int> keyBytes,
  ) async {
    // 尝试使用 cipher 自身的 key（如果有）
    List<int> decryptKey = keyBytes;
    final cipherKey = cipher['key'] as String?;
    if (cipherKey != null && cipherKey.isNotEmpty) {
      try {
        decryptKey = await unlockSymmetricCryptoKey(cipherKey, keyBytes);
      } catch (_) {
        // 回退到默认密钥
      }
    }

    // 解密名称
    final nameEnc = cipher['name'] as String?;
    if (nameEnc == null || nameEnc.isEmpty) return null;
    String name;
    try {
      name = await decryptEncStringUtf8(nameEnc, decryptKey);
    } catch (_) {
      try {
        name = await decryptEncStringUtf8(nameEnc, swapKeyHalves(decryptKey));
      } catch (_) {
        return null;
      }
    }

    // 提取 sshKey.privateKey
    final sshKey = cipher['sshKey'] as Map<String, dynamic>?;
    if (sshKey == null) return null;
    final privateKeyEnc = sshKey['privateKey'] as String?;
    if (privateKeyEnc == null || privateKeyEnc.isEmpty) return null;

    String privateKey;
    try {
      privateKey = await decryptEncStringUtf8(privateKeyEnc, decryptKey);
    } catch (_) {
      try {
        privateKey = await decryptEncStringUtf8(
          privateKeyEnc,
          swapKeyHalves(decryptKey),
        );
      } catch (_) {
        return null;
      }
    }

    return SshItem(
      name: name,
      privateKey: privateKey,
      passphrase: null,
      algorithm: null,
      enabled: true,
    );
  }

  /// 释放 HTTP 客户端资源
  void dispose() {
    _http.close();
  }
}
