import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart'
    show FlutterSecureStorage;
import 'package:sshkeygate/services/app_service.dart';
import 'package:sshkeygate/services/keystore_service.dart';
import 'package:sshkeygate/services/policy_service.dart';
import 'package:sshkeygate/services/windows_service.dart';
import 'package:sshkeygate/services/secure_storage_service.dart';

/// 由 ssh-keygen -t ed25519 生成的真实测试密钥
const testKey = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCaSQhfOCWx8K9o3gmza+9GkaaYQyHh80NOr0Vi9AVR7wAAAJB4sxJYeLMS
WAAAAAtzc2gtZWQyNTUxOQAAACCaSQhfOCWx8K9o3gmza+9GkaaYQyHh80NOr0Vi9AVR7w
AAAEAKKXNtxKV2vRlwMVz2luATYTeck167JGqbVFbOFHa0OJpJCF84JbHwr2jeCbNr70aR
pphDIeHzQ06vRWL0BVHvAAAADGJ3YWdlbnQtdGVzdAE=
-----END OPENSSH PRIVATE KEY-----''';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('AppService（集成测试）', () {
    late SecureStorageService storage;
    late KeyStoreService keystore;
    late PolicyService policy;
    late AppService app;

    setUp(() async {
      storage = SecureStorageService(secureStorage: FakeSecureStorage());
      await storage.initialize();
      await storage.createVault('testpass');
      keystore = KeyStoreService(storage: storage);
      policy = PolicyService(
        storage: storage,
        hashExecutable: (path) async => 'hash:${path.toLowerCase()}',
        modifiedTime: (path) async => 1,
      );
      keystore.loadFromStorage();
      app = AppService(
          storage: storage,
          keystore: keystore,
          policy: policy,
          windows: WindowsService());
    });

    test('初始状态为解锁（setUp 已解锁）', () {
      expect(app.isLocked, isFalse);
      expect(app.status, '就绪');
    });

    test('关闭到托盘提示状态可以持久化', () async {
      expect(app.closeToTrayHintShown, isFalse);
      await app.markCloseToTrayHintShown();
      expect(app.closeToTrayHintShown, isTrue);

      storage.lock();
      expect(await storage.unlock('testpass'), isTrue);
      expect(storage.closeToTrayHintShown, isTrue);
    });

    test('锁定后 keystore 不可访问', () {
      app.lock();
      expect(app.isLocked, isTrue);
      expect(keystore.keys, isEmpty);
    });

    test('连续解锁失败会触发等待窗口', () async {
      app.lock();
      expect(await app.unlock('wrong-password'), isFalse);
      expect(await app.unlock('testpass'), isFalse,
          reason: '等待窗口内即使密码正确也不应立即重试');
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      expect(await app.unlock('testpass'), isTrue);
    });

    test('importFromText 导入成功', () async {
      final result = await app.importFromText(
        keyText: testKey,
        name: 'test-import',
        passphrase: null,
      );
      expect(result, contains('成功'));
      expect(keystore.keys.length, 1);
      expect(keystore.keys.first.name, 'test-import');
    });

    test('importFromText 空文本报错', () async {
      final result = await app.importFromText(
          keyText: '   ', name: 'test', passphrase: null);
      expect(result, contains('为空'));
    });

    test('importFromText 无效文本报错', () async {
      final result = await app.importFromText(
          keyText: 'not a valid key', name: 'test', passphrase: null);
      expect(result, contains('失败'));
    });

    test('deleteKey 删除密钥', () async {
      await app.importFromText(keyText: testKey, name: 'k1', passphrase: null);
      expect(keystore.keys.length, 1);
      final id = keystore.keys.first.id;
      await app.deleteKey(id);
      expect(keystore.keys, isEmpty);
    });

    test('toggleKey 切换启用', () async {
      await app.importFromText(keyText: testKey, name: 'k1', passphrase: null);
      final id = keystore.keys.first.id;
      expect(keystore.keys.first.enabled, isTrue);
      await app.toggleKey(id);
      expect(keystore.keys.first.enabled, isFalse);
    });

    test('addTrustedProcess 和 removeTrustedProcess', () async {
      await app.addTrustedProcess('/usr/bin/ssh');
      expect(policy.trustedPaths, contains('/usr/bin/ssh'));
      await app.removeTrustedProcess('/usr/bin/ssh');
      expect(policy.trustedPaths, isEmpty);
    });

    test('lock 清除内存', () async {
      await app.importFromText(keyText: testKey, name: 'k1', passphrase: null);
      await app.addTrustedProcess('/usr/bin/ssh');
      app.lock();
      expect(keystore.keys, isEmpty);
      expect(app.isLocked, isTrue);
    });

    test('私钥不在 keysMeta 中', () async {
      await app.importFromText(keyText: testKey, name: 'k1', passphrase: null);
      // keysMeta 是 storage 层返回的元数据，不应含 privateKey
      for (final meta in storage.keysMeta) {
        expect(meta.containsKey('privateKey'), isFalse);
      }
    });

    test('getPrivateKeyForSigning 返回私钥', () async {
      await app.importFromText(keyText: testKey, name: 'k1', passphrase: null);
      final id = keystore.keys.first.id;
      final pk = await keystore.getPrivateKeyForSigning(id);
      expect(pk, isNotNull);
      expect(pk!, contains('PRIVATE KEY'));
    });
  });
}

/// 内存版 FlutterSecureStorage（测试用）
/// 只依赖 noSuchMethod + 手动转发 read/write
class FakeSecureStorage implements FlutterSecureStorage {
  final Map<String, String> _data = {};
  String? failNextWriteKey;

  Map<String, String> get data => _data;

  FakeSecureStorage();

  @override
  dynamic noSuchMethod(Invocation invocation) {
    final method = invocation.memberName;
    if (method == #read) {
      final key = invocation.namedArguments[#key] as String;
      return Future<String?>.value(_data[key]);
    }
    if (method == #write) {
      final key = invocation.namedArguments[#key] as String;
      final value = invocation.namedArguments[#value] as String?;
      if (key == failNextWriteKey) {
        failNextWriteKey = null;
        return Future<void>.error(StateError('simulated write failure'));
      }
      if (value == null) {
        _data.remove(key);
      } else {
        _data[key] = value;
      }
      return Future<void>.value();
    }
    if (method == #delete) {
      final key = invocation.namedArguments[#key] as String;
      _data.remove(key);
      return Future<void>.value();
    }
    if (method == #containsKey) {
      final key = invocation.namedArguments[#key] as String;
      return Future<bool>.value(_data.containsKey(key));
    }
    if (method == #readAll) {
      return Future<Map<String, String>>.value(Map.from(_data));
    }
    if (method == #deleteAll) {
      _data.clear();
      return Future<void>.value();
    }
    return null;
  }
}
