import 'package:flutter/material.dart';
import '../theme/app_colors.dart';
import '../services/log_service.dart';

/// 日志页面
class LogPage extends StatelessWidget {
  final LogService logService;
  const LogPage({super.key, required this.logService});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text('签名请求日志',
                style: TextStyle(fontSize: 12, color: AppColors.textLight)),
            GestureDetector(
              onTap: () => logService.clear(),
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                    border: Border.all(color: AppColors.border),
                    borderRadius: BorderRadius.circular(6)),
                child: const Text('清除',
                    style: TextStyle(fontSize: 11, color: AppColors.textLight)),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Expanded(
          child: Container(
            decoration: BoxDecoration(
                color: AppColors.white,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.border)),
            child: ListenableBuilder(
              listenable: logService,
              builder: (context, _) {
                final entries = logService.entries;
                if (entries.isEmpty) {
                  return const Center(
                    child: Text('暂无日志',
                        style: TextStyle(
                            color: AppColors.textLight, fontSize: 14)),
                  );
                }
                return Column(
                  children: [
                    // 表头
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 14, vertical: 10),
                      decoration: const BoxDecoration(
                        border:
                            Border(bottom: BorderSide(color: AppColors.border)),
                      ),
                      child: const Row(
                        children: [
                          SizedBox(
                              width: 100,
                              child: Text('时间',
                                  style: TextStyle(
                                      fontSize: 11,
                                      fontWeight: FontWeight.w600,
                                      color: AppColors.textSecondary))),
                          SizedBox(
                              width: 40,
                              child: Text('动作',
                                  style: TextStyle(
                                      fontSize: 11,
                                      fontWeight: FontWeight.w600,
                                      color: AppColors.textSecondary))),
                          Expanded(
                              flex: 2,
                              child: Text('原因',
                                  style: TextStyle(
                                      fontSize: 11,
                                      fontWeight: FontWeight.w600,
                                      color: AppColors.textSecondary))),
                          Expanded(
                              flex: 2,
                              child: Text('密钥',
                                  style: TextStyle(
                                      fontSize: 11,
                                      fontWeight: FontWeight.w600,
                                      color: AppColors.textSecondary))),
                          Expanded(
                              flex: 3,
                              child: Text('程序',
                                  style: TextStyle(
                                      fontSize: 11,
                                      fontWeight: FontWeight.w600,
                                      color: AppColors.textSecondary))),
                        ],
                      ),
                    ),
                    // 列表
                    Expanded(
                      child: ListView.separated(
                        itemCount: entries.length,
                        separatorBuilder: (_, __) => const Divider(
                            height: 1, color: AppColors.borderLight),
                        itemBuilder: (context, index) {
                          final e = entries[index];
                          return Padding(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 14, vertical: 8),
                            child: Row(
                              children: [
                                SizedBox(
                                  width: 100,
                                  child: Text(
                                    _formatTime(e.time),
                                    style: const TextStyle(
                                        fontSize: 11,
                                        color: AppColors.textLight,
                                        fontFamily: 'monospace'),
                                  ),
                                ),
                                SizedBox(
                                  width: 40,
                                  child: Icon(
                                    e.allowed
                                        ? Icons.check_circle
                                        : Icons.cancel,
                                    size: 16,
                                    color: e.allowed
                                        ? AppColors.green
                                        : AppColors.red,
                                  ),
                                ),
                                Expanded(
                                  flex: 2,
                                  child: Text(e.reason,
                                      style: const TextStyle(
                                          fontSize: 11,
                                          color: AppColors.textBody),
                                      overflow: TextOverflow.ellipsis),
                                ),
                                Expanded(
                                  flex: 2,
                                  child: Text(e.keyName,
                                      style: const TextStyle(
                                          fontSize: 11,
                                          color: AppColors.textBody),
                                      overflow: TextOverflow.ellipsis),
                                ),
                                Expanded(
                                  flex: 3,
                                  child: Tooltip(
                                    message: e.processName,
                                    child: Text(
                                      e.processName
                                          .split(RegExp(r'[/\\]'))
                                          .last,
                                      style: const TextStyle(
                                          fontSize: 11,
                                          color: AppColors.textLight),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          );
                        },
                      ),
                    ),
                  ],
                );
              },
            ),
          ),
        ),
      ],
    );
  }

  String _formatTime(DateTime t) {
    return '${t.month.toString().padLeft(2, '0')}-${t.day.toString().padLeft(2, '0')} '
        '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:'
        '${t.second.toString().padLeft(2, '0')}';
  }
}
