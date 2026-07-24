import 'dart:convert';
import 'dart:io';

import 'package:sshkeygate/services/log_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('磁盘日志始终限制为最近 500 条', () async {
    final directory = await Directory.systemTemp.createTemp('sshkeygate-log-');
    final file = File('${directory.path}${Platform.pathSeparator}agent.log');
    addTearDown(() => directory.delete(recursive: true));

    final lines = List.generate(
      510,
      (index) => jsonEncode({
        'time': DateTime(2026, 1, 1)
            .add(Duration(seconds: index))
            .toIso8601String(),
        'allowed': true,
        'reason': 'test',
        'keyName': 'key-$index',
        'processName': 'process',
      }),
    );
    await file.writeAsString('${lines.join('\n')}\n');

    final service = LogService(logFile: file);
    await service.initialize();
    expect(service.entries, hasLength(500));
    expect(await file.readAsLines(), hasLength(500));

    service.log(allowed: false, reason: 'latest', keyName: 'latest');
    expect(service.entries, hasLength(500));
    expect(await file.readAsLines(), hasLength(500));
    expect(service.entries.first.keyName, 'latest');
  });
}
