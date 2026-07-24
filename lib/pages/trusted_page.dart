import 'package:flutter/material.dart';
import '../theme/app_colors.dart';
import '../services/app_service.dart';

/// 信任程序页面
class TrustedPage extends StatelessWidget {
  final AppService appService;
  const TrustedPage({super.key, required this.appService});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('以下程序发起的签名请求将自动批准，无需弹窗确认。',
                style: TextStyle(fontSize: 12, color: AppColors.textLight)),
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
              listenable: appService.policy,
              builder: (context, _) {
                final paths = appService.policy.trustedPaths;
                if (paths.isEmpty) {
                  return const Center(
                    child: Column(mainAxisSize: MainAxisSize.min, children: [
                      Text('暂无信任程序',
                          style: TextStyle(
                              color: AppColors.textLight, fontSize: 14)),
                      SizedBox(height: 4),
                      Text('通过签名弹窗中"信任此程序"自动添加',
                          style: TextStyle(
                              fontSize: 12, color: AppColors.textLight)),
                    ]),
                  );
                }
                final pathList = paths.toList();
                return ListView.separated(
                  itemCount: pathList.length,
                  separatorBuilder: (_, __) =>
                      const Divider(height: 1, color: AppColors.borderLight),
                  itemBuilder: (context, index) {
                    final path = pathList[index];
                    return _TrustRow(
                        path: path,
                        sha256: appService.policy.trustedProgramHashes[path],
                        modifiedTimeMs:
                            appService.policy.trustedProgramModifiedTimes[path],
                        onRemove: () => appService.removeTrustedProcess(path));
                  },
                );
              },
            ),
          ),
        ),
      ],
    );
  }
}

class _TrustRow extends StatelessWidget {
  final String path;
  final String? sha256;
  final int? modifiedTimeMs;
  final Future<void> Function() onRemove;

  const _TrustRow(
      {required this.path,
      required this.sha256,
      required this.modifiedTimeMs,
      required this.onRemove});

  @override
  Widget build(BuildContext context) {
    final displayName = path.split(RegExp(r'[/\\]')).last;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
      child: Row(children: [
        Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
                color: AppColors.primaryLight,
                borderRadius: BorderRadius.circular(8)),
            child:
                const Icon(Icons.computer, size: 16, color: AppColors.primary)),
        const SizedBox(width: 14),
        Expanded(
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(displayName,
                style: const TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textBody)),
            const SizedBox(height: 2),
            Text(path,
                style:
                    const TextStyle(fontSize: 11, color: AppColors.textLight)),
            const SizedBox(height: 2),
            Text(
                modifiedTimeMs == null
                    ? '文件修改时间：未记录'
                    : '文件修改时间：${DateTime.fromMillisecondsSinceEpoch(modifiedTimeMs!)}',
                style:
                    const TextStyle(fontSize: 10, color: AppColors.textLight)),
            Tooltip(
              message: sha256 == null
                  ? '文件哈希（SHA-256）：未记录，请重新信任该程序'
                  : '文件哈希（SHA-256）：$sha256',
              child: Text(
                  sha256 == null
                      ? '文件哈希（SHA-256）：未记录'
                      : '文件哈希（SHA-256）：${sha256!.length > 12 ? sha256!.substring(0, 12) : sha256}...',
                  style: const TextStyle(
                      fontSize: 10, color: AppColors.textLight)),
            ),
          ]),
        ),
        GestureDetector(
          onTap: () {
            showDialog(
              context: context,
              builder: (ctx) => AlertDialog(
                title: const Text('确认移除'),
                content: Text('确定要移除信任程序「$displayName」吗？'),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(ctx),
                    child: const Text('取消'),
                  ),
                  TextButton(
                    onPressed: () async {
                      Navigator.pop(ctx);
                      try {
                        await onRemove();
                      } catch (_) {
                        if (!context.mounted) return;
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('移除失败，请稍后重试')),
                        );
                      }
                    },
                    style: TextButton.styleFrom(foregroundColor: AppColors.red),
                    child: const Text('移除'),
                  ),
                ],
              ),
            );
          },
          child: Container(
              width: 28,
              height: 28,
              decoration: BoxDecoration(borderRadius: BorderRadius.circular(6)),
              child: const Icon(Icons.delete_outline,
                  size: 15, color: AppColors.red)),
        ),
      ]),
    );
  }
}
