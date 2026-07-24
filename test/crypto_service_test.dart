import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:sshkeygate/services/crypto_service.dart';

void main() {
  group('CryptoService', () {
    const testPassword = 'test-password';
    const testEmail = 'test@example.com';

    test('derivePbkdf2 返回 32 字节密钥', () async {
      final key = await derivePbkdf2(testPassword, testEmail, 1000);
      final bytes = await key.extractBytes();
      expect(bytes.length, 32);
    });

    test('derivePbkdf2 同参数结果一致', () async {
      final key1 = await derivePbkdf2(testPassword, testEmail, 1000);
      final key2 = await derivePbkdf2(testPassword, testEmail, 1000);
      final bytes1 = await key1.extractBytes();
      final bytes2 = await key2.extractBytes();
      expect(bytes1, bytes2);
    });

    test('derivePbkdf2 不同密码结果不同', () async {
      final key1 = await derivePbkdf2(testPassword, testEmail, 1000);
      final key2 = await derivePbkdf2('other-password', testEmail, 1000);
      final bytes1 = await key1.extractBytes();
      final bytes2 = await key2.extractBytes();
      expect(bytes1, isNot(bytes2));
    });

    test('derivePasswordHash 返回 base64', () async {
      final hash = await derivePasswordHash(
          testPassword, testEmail, 0, 1000, null, null);
      expect(hash, isNotEmpty);
      // 应为有效 base64
      expect(() => base64Decode(hash), returnsNormally);
    });

    test('derivePasswordHash PBKDF2 结果可重现', () async {
      final hash1 = await derivePasswordHash(
          testPassword, testEmail, 0, 1000, null, null);
      final hash2 = await derivePasswordHash(
          testPassword, testEmail, 0, 1000, null, null);
      expect(hash1, hash2);
    });

    test('deriveStretchedKey 返回 64 字节', () async {
      final key = await deriveStretchedKey(
          testPassword, testEmail, 0, 1000, null, null);
      expect(key.length, 64);
    });

    test('deriveStretchedKey 前 32 和后 32 不同', () async {
      final key = await deriveStretchedKey(
          testPassword, testEmail, 0, 1000, null, null);
      final first32 = key.sublist(0, 32);
      final last32 = key.sublist(32, 64);
      expect(first32, isNot(last32));
    });

    test('swapKeyHalves 交换正确', () {
      final original = List.generate(64, (i) => i);
      final swapped = swapKeyHalves(original);
      expect(swapped.sublist(0, 32), original.sublist(32, 64));
      expect(swapped.sublist(32, 64), original.sublist(0, 32));
      // 两次交换恢复原样
      expect(swapKeyHalves(swapped), original);
    });

    test('swapKeyHalves 输入非 64 字节抛异常', () {
      expect(() => swapKeyHalves([1, 2, 3]), throwsException);
    });

    test('KdfConfig.fromJson PBKDF2', () {
      final json = {'Kdf': 0, 'KdfIterations': 600000};
      final config = KdfConfig.fromJson(json);
      expect(config.algorithm, 0);
      expect(config.iterations, 600000);
      expect(config.isArgon2id, isFalse);
    });

    test('KdfConfig.fromJson Argon2id', () {
      final json = {
        'Kdf': 1,
        'KdfIterations': 3,
        'KdfMemory': 65536,
        'KdfParallelism': 4,
      };
      final config = KdfConfig.fromJson(json);
      expect(config.algorithm, 1);
      expect(config.iterations, 3);
      expect(config.memory, 65536);
      expect(config.parallelism, 4);
      expect(config.isArgon2id, isTrue);
    });

    test('KdfConfig.fromJson 小驼峰字段', () {
      final json = {'kdf': 0, 'kdf_iterations': 5000};
      final config = KdfConfig.fromJson(json);
      expect(config.iterations, 5000);
    });

    test('KdfConfig.fromJson 默认值', () {
      final config = KdfConfig.fromJson({});
      expect(config.algorithm, 0);
      expect(config.iterations, 600000);
      expect(config.memory, 64);
      expect(config.parallelism, 4);
    });

    test('decryptEncString 拒绝小于 64 字节的密钥', () async {
      try {
        await decryptEncString('2.abc|def|ghi', List.filled(32, 0));
        fail('应抛出异常');
      } catch (e) {
        expect(e.toString(), contains('64'));
      }
    });

    test('decryptEncString 格式错误抛异常', () async {
      try {
        await decryptEncString('1.old_format', List.filled(64, 0));
        fail('应抛出异常');
      } catch (e) {
        expect(e.toString(), contains('版本'));
      }
    });

    test('Argon2id 派生返回 32 字节', () async {
      final key = await deriveArgon2id(testPassword, testEmail, 3, 65536, 4);
      final bytes = await key.extractBytes();
      expect(bytes.length, 32);
    }, skip: 'Argon2id 纯 Dart 实现较慢，仅在需要时运行');
  });
}
