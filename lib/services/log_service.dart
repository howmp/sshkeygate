import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

/// 日志条目
class LogEntry {
  final DateTime time;
  final bool allowed;
  final String reason;
  final String keyName;
  final String processName;

  const LogEntry({
    required this.time,
    required this.allowed,
    required this.reason,
    required this.keyName,
    required this.processName,
  });

  Map<String, dynamic> toJson() => {
        'time': time.toIso8601String(),
        'allowed': allowed,
        'reason': reason,
        'keyName': keyName,
        'processName': processName,
      };

  factory LogEntry.fromJson(Map<String, dynamic> json) => LogEntry(
        time: DateTime.parse(json['time'] as String),
        allowed: json['allowed'] as bool? ?? false,
        reason: json['reason'] as String? ?? '',
        keyName: json['keyName'] as String? ?? '',
        processName: json['processName'] as String? ?? '',
      );
}

/// 日志服务（持久化到数据目录，无论锁定解锁都可记录）
class LogService extends ChangeNotifier {
  final List<LogEntry> _entries = [];
  File? _logFile;
  int _diskEntryCount = 0;
  static const _maxEntries = 500;

  LogService({File? logFile}) : _logFile = logFile;

  List<LogEntry> get entries => List.unmodifiable(_entries);

  Future<void> initialize() async {
    if (_logFile == null) {
      final dir = await getApplicationSupportDirectory();
      _logFile = File('${dir.path}${Platform.pathSeparator}agent.log');
    }
    await _loadFromDisk();
  }

  void log({
    required bool allowed,
    required String reason,
    String keyName = '',
    String processName = '',
  }) {
    final entry = LogEntry(
      time: DateTime.now(),
      allowed: allowed,
      reason: reason,
      keyName: keyName,
      processName: processName,
    );
    _entries.insert(0, entry);
    if (_entries.length > _maxEntries) {
      _entries.removeRange(_maxEntries, _entries.length);
    }
    notifyListeners();
    if (_diskEntryCount >= _maxEntries) {
      _rewriteDisk();
    } else {
      _appendToDisk(entry);
      _diskEntryCount++;
    }
  }

  Future<void> _loadFromDisk() async {
    if (_logFile == null || !await _logFile!.exists()) return;
    try {
      final lines = await _logFile!.readAsLines();
      _diskEntryCount = lines.where((line) => line.trim().isNotEmpty).length;
      for (final line in lines) {
        if (line.trim().isEmpty) continue;
        try {
          _entries.add(LogEntry.fromJson(jsonDecode(line)));
        } catch (_) {}
      }
      _entries.sort((a, b) => b.time.compareTo(a.time));
      if (_entries.length > _maxEntries) {
        _entries.removeRange(_maxEntries, _entries.length);
      }
      if (_diskEntryCount > _maxEntries) {
        _rewriteDisk();
      }
      notifyListeners();
    } catch (e) {
      debugPrint('[LogService] 加载日志失败: $e');
    }
  }

  void _appendToDisk(LogEntry entry) {
    if (_logFile == null) return;
    try {
      _logFile!.writeAsStringSync('${jsonEncode(entry.toJson())}\n',
          mode: FileMode.append);
    } catch (e) {
      debugPrint('[LogService] 写入日志失败: $e');
    }
  }

  void _rewriteDisk() {
    if (_logFile == null) return;
    try {
      final content =
          _entries.map((entry) => jsonEncode(entry.toJson())).join('\n');
      _logFile!.writeAsStringSync(content.isEmpty ? '' : '$content\n');
      _diskEntryCount = _entries.length;
    } catch (e) {
      debugPrint('[LogService] 截断日志失败: $e');
    }
  }

  Future<void> clear() async {
    _entries.clear();
    if (_logFile != null && await _logFile!.exists()) {
      await _logFile!.writeAsString('');
    }
    _diskEntryCount = 0;
    notifyListeners();
  }
}
