import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:sshkeygate/services/ssh_agent_service.dart';
import 'package:sshkeygate/services/keystore_service.dart';
import 'package:sshkeygate/services/policy_service.dart';
import 'package:sshkeygate/services/secure_storage_service.dart';
import 'app_service_test.dart' show FakeSecureStorage, testKey;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('SSH Agent 协议响应格式与 ssh-keygen 一致', () async {
    final storage = SecureStorageService(secureStorage: FakeSecureStorage());
    await storage.initialize();
    await storage.createVault('testpass');
    final keystore = KeyStoreService(storage: storage);
    final policy = PolicyService(storage: storage);
    keystore.loadFromStorage();

    await keystore.importKey(testKey, 'test-ed25519', null);

    final agent =
        SshAgentService(keystore: keystore, policy: policy, forceTcp: true);
    await agent.start();

    try {
      await Future.delayed(const Duration(milliseconds: 100));
      final socket = await Socket.connect('127.0.0.1', SshAgentService.tcpPort);

      final req = Uint8List(5);
      ByteData.view(req.buffer).setUint32(0, 1, Endian.big);
      req[4] = 11;
      socket.add(req);
      await socket.flush();

      final resp = await socket.first.timeout(const Duration(seconds: 2));

      expect(resp[4], 12, reason: 'SSH_AGENT_IDENTITIES_ANSWER');

      final numKeys = ByteData.sublistView(resp, 5, 9).getUint32(0, Endian.big);
      expect(numKeys, 1);

      final blobLen =
          ByteData.sublistView(resp, 9, 13).getUint32(0, Endian.big);
      final blob = resp.sublist(13, 13 + blobLen);
      final blobB64 = base64Encode(blob);

      final commentOff = 13 + blobLen;
      final commentLen = ByteData.sublistView(resp, commentOff, commentOff + 4)
          .getUint32(0, Endian.big);
      final comment = utf8
          .decode(resp.sublist(commentOff + 4, commentOff + 4 + commentLen));

      expect(blobB64,
          'AAAAC3NzaC1lZDI1NTE5AAAAIJpJCF84JbHwr2jeCbNr70aRpphDIeHzQ06vRWL0BVHv');
      expect(comment, 'test-ed25519');

      socket.destroy();
    } finally {
      await agent.stop();
    }
  });

  test('截断的签名请求返回 failure', () async {
    final fixture = await _startAgent();
    try {
      final socket = await Socket.connect('127.0.0.1', SshAgentService.tcpPort);
      socket.add(Uint8List.fromList([0, 0, 0, 1, agentcSignRequest]));
      await socket.flush();

      final response = await socket.first.timeout(const Duration(seconds: 2));
      expect(response, Uint8List.fromList([0, 0, 0, 1, agentFailure]));
      socket.destroy();
    } finally {
      await fixture.agent.stop();
    }
  });

  for (final invalidLength in [0, 1024 * 1024 + 1]) {
    test('非法帧长度 $invalidLength 会关闭当前连接', () async {
      final fixture = await _startAgent();
      try {
        final socket =
            await Socket.connect('127.0.0.1', SshAgentService.tcpPort);
        final header = ByteData(4)..setUint32(0, invalidLength, Endian.big);
        final closed = Completer<void>();
        socket.listen((_) {}, onDone: closed.complete);
        socket.add(header.buffer.asUint8List());
        await socket.flush();
        await closed.future.timeout(const Duration(seconds: 2));
      } finally {
        await fixture.agent.stop();
      }
    });
  }

  test('并发签名请求的确认回调保持串行', () async {
    final fixture = await _startAgent(importKey: true);
    var activeConfirmations = 0;
    var maxActiveConfirmations = 0;
    fixture.agent.onConfirm = (_, __, ___, ____) async {
      activeConfirmations++;
      if (activeConfirmations > maxActiveConfirmations) {
        maxActiveConfirmations = activeConfirmations;
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
      activeConfirmations--;
      return 1;
    };

    try {
      final socket1 =
          await Socket.connect('127.0.0.1', SshAgentService.tcpPort);
      final socket2 =
          await Socket.connect('127.0.0.1', SshAgentService.tcpPort);
      final frame = _signFrame(fixture.publicKeyBlob!);
      socket1.add(frame);
      socket2.add(frame);
      await Future.wait([socket1.flush(), socket2.flush()]);
      final responses = await Future.wait([
        socket1.first.timeout(const Duration(seconds: 2)),
        socket2.first.timeout(const Duration(seconds: 2)),
      ]);
      expect(responses.every((response) => response[4] == agentSignResponse),
          isTrue);
      expect(maxActiveConfirmations, 1);
      socket1.destroy();
      socket2.destroy();
    } finally {
      await fixture.agent.stop();
    }
  });
}

class _AgentFixture {
  final SshAgentService agent;
  final Uint8List? publicKeyBlob;

  const _AgentFixture(this.agent, this.publicKeyBlob);
}

Future<_AgentFixture> _startAgent({bool importKey = false}) async {
  final storage = SecureStorageService(secureStorage: FakeSecureStorage());
  await storage.initialize();
  await storage.createVault('testpass');
  final keystore = KeyStoreService(storage: storage)..loadFromStorage();
  Uint8List? publicKeyBlob;
  if (importKey) {
    publicKeyBlob =
        (await keystore.importKey(testKey, 'test-ed25519', null)).publicKeyBlob;
  }
  final policy = PolicyService(storage: storage);
  final agent =
      SshAgentService(keystore: keystore, policy: policy, forceTcp: true);
  await agent.start();
  await Future<void>.delayed(const Duration(milliseconds: 50));
  return _AgentFixture(agent, publicKeyBlob);
}

Uint8List _signFrame(Uint8List publicKeyBlob) {
  final body = BytesBuilder();
  body.addByte(agentcSignRequest);
  _writeString(body, publicKeyBlob);
  _writeString(body, utf8.encode('data-to-sign'));
  body.add(Uint8List(4));
  final payload = body.takeBytes();
  final frame = BytesBuilder();
  final length = ByteData(4)..setUint32(0, payload.length, Endian.big);
  frame.add(length.buffer.asUint8List());
  frame.add(payload);
  return frame.takeBytes();
}

void _writeString(BytesBuilder writer, List<int> value) {
  final length = ByteData(4)..setUint32(0, value.length, Endian.big);
  writer.add(length.buffer.asUint8List());
  writer.add(value);
}
