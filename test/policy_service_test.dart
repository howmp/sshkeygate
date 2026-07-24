import 'package:flutter_test/flutter_test.dart';
import 'package:sshkeygate/services/policy_service.dart';
import 'package:sshkeygate/services/secure_storage_service.dart';
import 'app_service_test.dart' show FakeSecureStorage;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('PolicyService', () {
    late SecureStorageService storage;
    late PolicyService policy;
    late Map<String, String> executableHashes;

    setUp(() async {
      storage = SecureStorageService(secureStorage: FakeSecureStorage());
      await storage.initialize();
      await storage.createVault('testpass');
      executableHashes = {
        '/usr/bin/ssh': 'hash-ssh-v1',
        '/usr/bin/git': 'hash-git-v1',
        r'c:\windows\ssh.exe': 'hash-win-v1',
      };
      policy = PolicyService(
        storage: storage,
        hashExecutable: (path) async => executableHashes[path.toLowerCase()],
        modifiedTime: (path) async =>
            executableHashes.containsKey(path.toLowerCase()) ? 1 : null,
      );
    });

    test('默认策略每次都需要确认', () async {
      expect(await policy.needsConfirmation(), isTrue);
      policy.grant(processPid: 123);
      expect(await policy.needsConfirmation(processPid: 123), isTrue);
    });

    test('显式信任且文件哈希未变化时自动放行', () async {
      expect(await policy.addTrustedProcess('/usr/bin/ssh'), isTrue);
      expect(
        await policy.needsConfirmation(processPath: '/usr/bin/ssh'),
        isFalse,
      );
    });

    test('同一路径的程序被替换后重新要求确认', () async {
      await policy.setTrustVerification(['path', 'sha256']);
      await policy.addTrustedProcess('/usr/bin/ssh');
      executableHashes['/usr/bin/ssh'] = 'hash-ssh-v2';
      expect(
        await policy.needsConfirmation(processPath: '/usr/bin/ssh'),
        isTrue,
      );
    });

    test('无法读取程序文件时不能添加信任', () async {
      expect(await policy.addTrustedProcess('/missing/program'), isFalse);
      expect(policy.trustedPaths, isEmpty);
    });

    test('路径匹配不区分大小写', () async {
      await policy.addTrustedProcess(r'C:\Windows\ssh.exe');
      expect(
        await policy.needsConfirmation(processPath: r'c:\windows\ssh.exe'),
        isFalse,
      );
    });

    test('关闭 SHA-256 校验时仅在建立信任时记录哈希', () async {
      var hashCalls = 0;
      policy = PolicyService(
        storage: storage,
        hashExecutable: (path) async {
          hashCalls++;
          return 'hash-ssh-v1';
        },
        modifiedTime: (path) async => 42,
      );
      expect(policy.trustVerification, containsAll(['path', 'mtime']));
      expect(policy.trustVerification, isNot(contains('sha256')));
      expect(await policy.addTrustedProcess('/usr/bin/ssh'), isTrue);
      expect(hashCalls, 1);
      expect(
          await policy.needsConfirmation(processPath: '/usr/bin/ssh'), isFalse);
      expect(hashCalls, 1);
    });

    test('移除信任后重新要求确认', () async {
      await policy.addTrustedProcess('/usr/bin/ssh');
      await policy.removeTrustedProcess('/usr/bin/ssh');
      expect(
        await policy.needsConfirmation(processPath: '/usr/bin/ssh'),
        isTrue,
      );
    });

    group('Session 策略', () {
      setUp(() => policy.setPolicy(ApprovalPolicy.session));

      test('只对已批准的同一 PID 放行', () async {
        expect(await policy.needsConfirmation(processPid: 100), isTrue);
        policy.grant(processPid: 100);
        expect(await policy.needsConfirmation(processPid: 100), isFalse);
        expect(await policy.needsConfirmation(processPid: 200), isTrue);
        expect(await policy.needsConfirmation(), isTrue);
      });
    });

    group('TimedMinutes 策略', () {
      setUp(() => policy.setPolicy(ApprovalPolicy.timedMinutes));

      test('只对时间窗口内的同一 PID 放行', () async {
        expect(await policy.needsConfirmation(processPid: 100), isTrue);
        policy.grant(processPid: 100);
        expect(await policy.needsConfirmation(processPid: 100), isFalse);
        expect(await policy.needsConfirmation(processPid: 200), isTrue);
      });
    });

    test('reset 清除会话状态', () async {
      policy.setPolicy(ApprovalPolicy.session);
      policy.grant(processPid: 100);
      policy.reset();
      expect(await policy.needsConfirmation(processPid: 100), isTrue);
    });
  });
}
