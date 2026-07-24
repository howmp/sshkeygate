import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:encrypt/encrypt.dart' as enc;

/// PBKDF2-SHA256 派生密钥
Future<SecretKey> derivePbkdf2(
    String password, String email, int iterations) async {
  final pbkdf2 =
      Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: iterations, bits: 256);
  return pbkdf2.deriveKeyFromPassword(
    password: password,
    nonce: utf8.encode(email.toLowerCase().trim()),
  );
}

/// Argon2id 派生密钥
Future<SecretKey> deriveArgon2id(String password, String email, int iterations,
    int memoryKib, int parallelism) async {
  final argon2 = Argon2id(
      parallelism: parallelism,
      memory: memoryKib,
      iterations: iterations,
      hashLength: 32);
  return argon2.deriveKey(
    secretKey: SecretKey(utf8.encode(password)),
    nonce: utf8.encode(email.toLowerCase().trim()),
  );
}

/// 派生密码哈希（用于登录验证）
Future<String> derivePasswordHash(String password, String email, int kdfType,
    int iterations, int? memory, int? parallelism) async {
  final SecretKey key;
  if (kdfType == 0) {
    key = await derivePbkdf2(password, email, iterations);
  } else {
    key = await deriveArgon2id(
        password, email, iterations, memory ?? 64, parallelism ?? 4);
  }
  final keyBytes = await key.extractBytes();
  // PBKDF2(master_key, password, 1) = HMAC(master_key, password || 0x00000001)
  final hmac = Hmac.sha256();
  final data = [...utf8.encode(password), 0x00, 0x00, 0x00, 0x01];
  final mac = await hmac.calculateMac(data, secretKey: SecretKey(keyBytes));
  return base64Encode(mac.bytes);
}

/// 派生拉伸密钥（64 字节）
Future<List<int>> deriveStretchedKey(String password, String email, int kdfType,
    int iterations, int? memory, int? parallelism) async {
  final SecretKey key;
  if (kdfType == 0) {
    key = await derivePbkdf2(password, email, iterations);
  } else {
    key = await deriveArgon2id(
        password, email, iterations, memory ?? 64, parallelism ?? 4);
  }
  final masterKeyBytes = await key.extractBytes();
  // HKDF-SHA256 expand（跳过 extract，master_key 直接作为 PRK）
  // T(1) = HMAC-SHA256(PRK, info || 0x01)
  final encMac = await Hmac.sha256().calculateMac(
    [...utf8.encode('enc'), 0x01],
    secretKey: SecretKey(masterKeyBytes),
  );
  final macMac = await Hmac.sha256().calculateMac(
    [...utf8.encode('mac'), 0x01],
    secretKey: SecretKey(masterKeyBytes),
  );
  return [...encMac.bytes, ...macMac.bytes];
}

/// 解密 EncString（Bitwarden 版本 2）
Future<List<int>> decryptEncString(String encString, List<int> keyBytes) async {
  if (keyBytes.length != 64) {
    throw Exception('需要 64 字节密钥，实际 ${keyBytes.length}');
  }
  if (!encString.startsWith('2.')) throw Exception('不支持的 EncString 版本');
  final parts = encString.substring(2).split('|');
  if (parts.length != 3) throw Exception('EncString 格式错误');

  final iv = base64Decode(parts[0]);
  final ct = base64Decode(parts[1]);
  final expectedMac = base64Decode(parts[2]);
  final encKey = keyBytes.sublist(0, 32);
  final macKey = keyBytes.sublist(32, 64);

  // HMAC-SHA256(mac_key, IV || ciphertext)
  final macCalc = await Hmac.sha256()
      .calculateMac([...iv, ...ct], secretKey: SecretKey(macKey));
  if (!_constantTimeEqual(macCalc.bytes, expectedMac)) {
    throw Exception('MAC 验证失败');
  }

  // AES-256-CBC 解密
  final key = enc.Key(Uint8List.fromList(encKey));
  final ivObj = enc.IV(Uint8List.fromList(iv));
  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.cbc));
  return encrypter.decryptBytes(enc.Encrypted(Uint8List.fromList(ct)),
      iv: ivObj);
}

bool _constantTimeEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  int diff = 0;
  for (int i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// 解密 EncString 并返回 UTF-8 字符串
Future<String> decryptEncStringUtf8(
    String encString, List<int> keyBytes) async {
  return utf8.decode(await decryptEncString(encString, keyBytes));
}

/// 从 EncString 解包 SymmetricCryptoKey，返回 64 字节
Future<List<int>> unlockSymmetricCryptoKey(
    String encryptedKey, List<int> stretchedKey) async {
  final raw = await decryptEncString(encryptedKey, stretchedKey);
  if (raw.length == 32) {
    final encMac = await Hmac.sha256()
        .calculateMac([...utf8.encode('enc'), 0x01], secretKey: SecretKey(raw));
    final macMac = await Hmac.sha256()
        .calculateMac([...utf8.encode('mac'), 0x01], secretKey: SecretKey(raw));
    return [...encMac.bytes, ...macMac.bytes];
  } else if (raw.length == 64) {
    return raw;
  }
  throw Exception('无效的 SymmetricCryptoKey 长度：${raw.length}');
}

/// 交换 64 字节密钥的 enc/mac 两半
List<int> swapKeyHalves(List<int> key64) {
  if (key64.length != 64) throw Exception('swapKeyHalves 期望 64 字节');
  return [...key64.sublist(32, 64), ...key64.sublist(0, 32)];
}

/// KDF 配置
class KdfConfig {
  final int algorithm;
  final int iterations;
  final int memory;
  final int parallelism;
  const KdfConfig(
      {required this.algorithm,
      required this.iterations,
      this.memory = 64,
      this.parallelism = 4});
  bool get isArgon2id => algorithm != 0;

  factory KdfConfig.fromJson(Map<String, dynamic> json) {
    final kdfVal = json['Kdf'] ?? json['kdf'] ?? 0;
    return KdfConfig(
      algorithm: (kdfVal is int) ? kdfVal : int.tryParse('$kdfVal') ?? 0,
      iterations: (json['KdfIterations'] ??
          json['kdfIterations'] ??
          json['kdf_iterations'] ??
          600000) as int,
      memory: (json['KdfMemory'] ??
          json['kdfMemory'] ??
          json['kdf_memory'] ??
          64) as int,
      parallelism: (json['KdfParallelism'] ??
          json['kdfParallelism'] ??
          json['kdf_parallelism'] ??
          4) as int,
    );
  }
}
