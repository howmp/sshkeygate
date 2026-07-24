// ignore_for_file: avoid_print

import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:sshkeygate/services/bitwarden_service.dart';

void main() {
  test('Bitwarden 同步集成测试', () async {
    // 读取 .env 凭证
    final envFile = File('.env');
    if (!await envFile.exists()) {
      print('⚠ 未找到 .env 文件，跳过测试');
      return;
    }

    final lines = await envFile.readAsLines();
    String? email, password, serverUrl;
    for (final line in lines) {
      if (line.startsWith('BWEMAIL=')) email = line.substring(8).trim();
      if (line.startsWith('BWPWD=')) password = line.substring(6).trim();
      if (line.startsWith('BWURL=')) serverUrl = line.substring(6).trim();
    }

    if (email == null || password == null || serverUrl == null) {
      print('⚠ .env 文件格式不正确，跳过测试');
      return;
    }

    print('═══════════════════════════════════════');
    print('  sshkeygate Bitwarden 同步集成测试');
    print('═══════════════════════════════════════');
    print('服务器: $serverUrl');
    print('邮箱:   $email');
    print('');

    // 1. 创建客户端
    final config = BitwardenConfig(
      serverUrl: serverUrl,
      email: email,
      password: password,
    );
    final client = BitwardenClient(config: config);

    try {
      // 2. 登录
      print('[1/3] 正在登录...');
      final session = await client.login();
      print('  ✅ 登录成功');
      print(
          '  KDF 类型:    ${session.kdfConfig.isArgon2id ? "Argon2id" : "PBKDF2-SHA256"}');
      print('  KDF 迭代:   ${session.kdfConfig.iterations}');
      if (session.kdfConfig.isArgon2id) {
        print('  内存 (KiB): ${session.kdfConfig.memory}');
        print('  并行度:     ${session.kdfConfig.parallelism}');
      }
      print('  Access Token: ${session.accessToken.substring(0, 20)}...');
      print(
          '  Encrypted Key: ${session.encryptedKey != null ? "✅ 已获取" : "❌ 缺失"}');

      // 3. 同步
      print('\n[2/3] 正在同步密码库...');
      final items = await client.sync(session);
      print('  ✅ 同步完成');

      // 4. 分析结果
      print('\n[3/3] 分析 SSH 密钥条目:');
      if (items.isEmpty) {
        print('  ⚠ 未找到 type=5 的 SSH 密钥条目');
        print('  提示: 请确认 Bitwarden 中存在 SSH Key 类型的条目');
      } else {
        print('  共找到 ${items.length} 个 SSH 密钥条目:\n');
        int validCount = 0;
        for (var i = 0; i < items.length; i++) {
          final item = items[i];
          print('  ─── 条目 ${i + 1} ───');
          print('  名称:     ${item.name}');
          print('  算法:     ${item.algorithm ?? "未知"}');
          print('  启用:     ${item.enabled ? "✅" : "❌"}');

          // 检查私钥格式
          final pk = item.privateKey;
          if (pk.contains('PRIVATE KEY')) {
            final lines = pk.trim().split('\n');
            final beginLine = lines.firstWhere(
              (l) => l.startsWith('-----BEGIN '),
              orElse: () => '',
            );
            print(
                '  格式:     ${beginLine.replaceAll('-----BEGIN ', '').replaceAll(' PRIVATE KEY-----', '')}');
            print('  长度:     ${pk.length} 字符');
            validCount++;
          } else {
            print('  私钥格式: ⚠ 非 OpenSSH 格式');
          }
          print(
              '  私钥预览: ${pk.substring(0, pk.indexOf('\n') > 0 ? pk.indexOf('\n') : pk.length.clamp(0, 50))}...');
          if (item.passphrase != null) {
            print('  密码:     *** (已加密)');
          }
        }

        print('\n  统计: 有效 $validCount/${items.length}');
        expect(validCount, greaterThan(0), reason: '至少应该有一个有效的 SSH 密钥');
      }
    } catch (e, stack) {
      print('\n  ❌ 测试失败: $e');
      print('  $stack');
      rethrow;
    } finally {
      client.dispose();
    }

    print('\n═══════════════════════════════════════');
    print('  测试完成');
    print('═══════════════════════════════════════');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
