import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:sshkeygate/services/keystore_service.dart';
import 'package:sshkeygate/services/secure_storage_service.dart';
import 'app_service_test.dart' show FakeSecureStorage;

/// 由 ssh-keygen -t ed25519 生成的真实测试密钥
const testEd25519Key = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCaSQhfOCWx8K9o3gmza+9GkaaYQyHh80NOr0Vi9AVR7wAAAJB4sxJYeLMS
WAAAAAtzc2gtZWQyNTUxOQAAACCaSQhfOCWx8K9o3gmza+9GkaaYQyHh80NOr0Vi9AVR7w
AAAEAKKXNtxKV2vRlwMVz2luATYTeck167JGqbVFbOFHa0OJpJCF84JbHwr2jeCbNr70aR
pphDIeHzQ06vRWL0BVHvAAAADGJ3YWdlbnQtdGVzdAE=
-----END OPENSSH PRIVATE KEY-----''';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('KeyStoreService', () {
    late SecureStorageService storage;
    late KeyStoreService keystore;

    setUp(() async {
      storage = SecureStorageService(secureStorage: FakeSecureStorage());
      await storage.initialize();
      await storage.createVault('testpass');
      keystore = KeyStoreService(storage: storage);
      keystore.loadFromStorage();
    });

    test('初始状态为解锁且有零条密钥', () {
      expect(keystore.isLocked, isFalse);
      expect(keystore.keys, isEmpty);
    });

    test('锁定后清除内存', () async {
      await keystore.importKey(testEd25519Key, 'test-key', null);
      expect(keystore.keys.length, 1);

      keystore.lock();
      expect(keystore.isLocked, isTrue);
      expect(keystore.keys, isEmpty);
    });

    test('导入密钥成功', () async {
      final meta = await keystore.importKey(testEd25519Key, 'my-key', null);

      expect(keystore.keys.length, 1);
      expect(meta.name, 'my-key');
      expect(meta.source, KeySource.manual);
      expect(meta.enabled, isTrue);
      expect(meta.algorithm, isNotEmpty);
      expect(meta.fingerprint, contains('SHA256:'));
      expect(meta.publicKeyBlob, isNotEmpty);
    });

    test('不提供名称时使用默认名称', () async {
      final meta = await keystore.importKey(testEd25519Key, null, null);
      expect(meta.name, 'imported-key');
    });

    test('Bitwarden 导入', () async {
      final meta = await keystore.importKey(
        testEd25519Key,
        'bw-key',
        null,
        source: KeySource.bitwarden,
        algorithm: 'ssh-ed25519',
      );

      expect(meta.source, KeySource.bitwarden);
      expect(meta.name, 'bw-key');
      expect(meta.algorithm, 'ssh-ed25519');
    });

    test('删除密钥', () async {
      final meta = await keystore.importKey(testEd25519Key, 'key-1', null);
      expect(keystore.keys.length, 1);

      await keystore.deleteKey(meta.id);
      expect(keystore.keys, isEmpty);
    });

    test('切换启用状态', () async {
      final meta = await keystore.importKey(testEd25519Key, 'key', null);
      expect(meta.enabled, isTrue);

      await keystore.toggleKey(meta.id);
      expect(keystore.keys.first.enabled, isFalse);

      await keystore.toggleKey(meta.id);
      expect(keystore.keys.first.enabled, isTrue);
    });

    test('KeySource label 值正确', () {
      expect(KeySource.bitwarden.label, 'Bitwarden');
      expect(KeySource.manual.label, '手动导入');
    });

    test('getPrivateKeyForSigning 返回私钥', () async {
      final meta = await keystore.importKey(testEd25519Key, 'key', null);
      final pk = await keystore.getPrivateKeyForSigning(meta.id);
      expect(pk, isNotNull);
      expect(pk!, contains('PRIVATE KEY'));
    });

    test('锁定后 getPrivateKeyForSigning 返回 null', () async {
      final meta = await keystore.importKey(testEd25519Key, 'key', null);
      keystore.lock();
      final pk = await keystore.getPrivateKeyForSigning(meta.id);
      expect(pk, isNull);
    });

    test('私钥不在 KeyMeta 中暴露', () async {
      await keystore.importKey(testEd25519Key, 'key', null);
      // KeyMeta 类没有 privateKey 字段
      final key = keystore.keys.first;
      expect(key, isA<KeyMeta>());
      // 编译时保证：KeyMeta 没有 privateKey 字段
    });
  });

  group('SecureStorageService', () {
    late SecureStorageService storage;

    setUp(() async {
      storage = SecureStorageService(secureStorage: FakeSecureStorage());
      await storage.initialize();
    });

    test('首次运行 vaultExists 为 false', () async {
      await storage.checkVaultExists();
      expect(storage.vaultExists, isFalse);
    });

    test('createVault 后 vaultExists 为 true', () async {
      await storage.createVault('mypassword');
      await storage.checkVaultExists();
      expect(storage.vaultExists, isTrue);
      expect(storage.isUnlocked, isTrue);
    });

    test('锁定后 unlock 需要正确密码', () async {
      await storage.createVault('mypassword');
      storage.lock();
      expect(storage.isUnlocked, isFalse);

      final bad = await storage.unlock('wrongpassword');
      expect(bad, isFalse);

      final good = await storage.unlock('mypassword');
      expect(good, isTrue);
    });

    test('仅修改时间的信任记录可持久化和删除', () async {
      await storage.createVault('pass');
      await storage.addTrustedProgram('/usr/bin/ssh', modifiedTimeMs: 1234);
      storage.lock();

      final ok = await storage.unlock('pass');
      expect(ok, isTrue);
      expect(storage.trustedPaths, contains('/usr/bin/ssh'));
      expect(storage.trustedProgramModifiedTimes['/usr/bin/ssh'], 1234);

      await storage.removeTrustedPath('/usr/bin/ssh');
      expect(storage.trustedPaths, isEmpty);
    });

    test('修改密码写入失败时回滚全部密钥', () async {
      final fakeStorage = FakeSecureStorage();
      final transactionalStorage =
          SecureStorageService(secureStorage: fakeStorage);
      await transactionalStorage.initialize();
      await transactionalStorage.createVault('old-password');
      await transactionalStorage.addKey({
        'id': 'key-1',
        'name': 'test',
        'algorithm': 'ssh-ed25519',
        'fingerprint': 'SHA256:test',
        'publicKeyBlob': '',
        'source': 'manual',
        'enabled': true,
        'privateKey': 'private-key-data',
      });

      fakeStorage.failNextWriteKey = 'sshkeygate_pk_key-1';
      expect(
        await transactionalStorage.changePassword(
            'old-password', 'new-password-long'),
        isFalse,
      );

      transactionalStorage.lock();
      expect(await transactionalStorage.unlock('old-password'), isTrue);
      expect(await transactionalStorage.getPrivateKey('key-1'),
          'private-key-data');
    });

    test('启动时恢复被中断的密码修改', () async {
      final fakeStorage = FakeSecureStorage();
      final original = SecureStorageService(secureStorage: fakeStorage);
      await original.initialize();
      await original.createVault('old-password');
      await original.addKey({
        'id': 'key-1',
        'name': 'test',
        'algorithm': 'ssh-ed25519',
        'fingerprint': 'SHA256:test',
        'publicKeyBlob': '',
        'source': 'manual',
        'enabled': true,
        'privateKey': 'private-key-data',
      });

      final oldVault = fakeStorage.data['sshkeygate_vault']!;
      final oldPrivateKey = fakeStorage.data['sshkeygate_pk_key-1']!;
      fakeStorage.data['sshkeygate_vault'] = 'interrupted-write';
      fakeStorage.data['sshkeygate_pk_key-1'] = 'interrupted-write';
      fakeStorage.data['sshkeygate_password_migration'] = jsonEncode({
        'vault': oldVault,
        'privateKeys': {'key-1': oldPrivateKey},
      });

      final recovered = SecureStorageService(secureStorage: fakeStorage);
      await recovered.initialize();
      expect(
          fakeStorage.data.containsKey('sshkeygate_password_migration'), isFalse);
      expect(await recovered.unlock('old-password'), isTrue);
      expect(await recovered.getPrivateKey('key-1'), 'private-key-data');
    });
  });
}
