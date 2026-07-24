import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../theme/app_colors.dart';
import '../services/app_service.dart';
import '../services/keystore_service.dart';

/// 密钥列表页面
class KeysPage extends StatelessWidget {
  final AppService appService;
  final VoidCallback? onNavigateToImport;

  const KeysPage({
    super.key,
    required this.appService,
    this.onNavigateToImport,
  });

  void _deleteKey(BuildContext context, String id, String name) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('确认删除'),
        content: Text('确定要删除密钥「$name」吗？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('取消'),
          ),
          TextButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await appService.deleteKey(id);
            },
            style: TextButton.styleFrom(foregroundColor: AppColors.red),
            child: const Text('删除'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // 添加密钥按钮
        Align(
          alignment: Alignment.centerRight,
          child: GestureDetector(
            onTap: onNavigateToImport,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
              decoration: BoxDecoration(
                color: AppColors.green,
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.add, size: 13, color: AppColors.white),
                  SizedBox(width: 5),
                  Text('添加密钥',
                      style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                          color: AppColors.white)),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 16),
        // 密钥卡片
        Expanded(
          child: Container(
            decoration: BoxDecoration(
              color: AppColors.white,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: AppColors.border),
            ),
            child: ListenableBuilder(
              listenable: appService.keystore,
              builder: (context, _) {
                final keys = appService.keystore.keys;
                if (keys.isEmpty) {
                  return const Center(
                    child: Text('暂无密钥',
                        style: TextStyle(
                            color: AppColors.textLight, fontSize: 14)),
                  );
                }
                return ListView.separated(
                  itemCount: keys.length,
                  separatorBuilder: (_, __) =>
                      const Divider(height: 1, color: AppColors.borderLight),
                  itemBuilder: (context, index) =>
                      _buildKeyRow(context, keys[index]),
                );
              },
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildKeyRow(BuildContext context, KeyMeta key) {
    return Container(
      constraints: const BoxConstraints(minHeight: 58),
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
      child: Row(
        children: [
          // 复选框
          GestureDetector(
            onTap: () => appService.toggleKey(key.id),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              width: 18,
              height: 18,
              decoration: BoxDecoration(
                color: key.enabled ? AppColors.primary : null,
                borderRadius: BorderRadius.circular(5),
                border: Border.all(
                  color: key.enabled ? AppColors.primary : AppColors.disabledBg,
                  width: 2,
                ),
              ),
              child: key.enabled
                  ? const Icon(Icons.check, size: 11, color: AppColors.white)
                  : null,
            ),
          ),
          const SizedBox(width: 14),
          // 密钥信息
          Expanded(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(key.name,
                    style: const TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                        color: AppColors.textBody)),
                const SizedBox(height: 2),
                Text(key.fingerprint,
                    overflow: TextOverflow.ellipsis,
                    maxLines: 1,
                    style: const TextStyle(
                        fontSize: 11, color: AppColors.textLight)),
              ],
            ),
          ),
          const SizedBox(width: 8),
          // 类型标签
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
            decoration: BoxDecoration(
                color: AppColors.tagBg,
                borderRadius: BorderRadius.circular(5)),
            child: Text(key.algorithm,
                style: const TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: AppColors.textMuted)),
          ),
          const SizedBox(width: 8),
          // 来源
          SizedBox(
            width: 60,
            child: Text(key.source.label,
                style:
                    const TextStyle(fontSize: 11, color: AppColors.textLight),
                textAlign: TextAlign.right),
          ),
          const SizedBox(width: 4),
          // 复制公钥
          _iconButton(Icons.copy, AppColors.textLight, '复制公钥', () {
            final pubKeyStr = _formatPublicKey(key);
            Clipboard.setData(ClipboardData(text: pubKeyStr));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('公钥已复制'), duration: Duration(seconds: 2)),
            );
          }),
          // 编辑名称
          _iconButton(Icons.edit_outlined, AppColors.textLight, '编辑名称', () {
            _renameKey(context, key);
          }),
          // 删除
          _iconButton(Icons.delete_outline, AppColors.red, '删除', () {
            _deleteKey(context, key.id, key.name);
          }),
        ],
      ),
    );
  }

  Widget _iconButton(IconData icon, Color color, String tooltip, VoidCallback onTap) {
    return Tooltip(
      message: tooltip,
      child: GestureDetector(
        onTap: onTap,
        child: Container(
          width: 28,
          height: 28,
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(6)),
          child: Icon(icon, size: 15, color: color),
        ),
      ),
    );
  }

  void _renameKey(BuildContext context, KeyMeta key) {
    final ctrl = TextEditingController(text: key.name);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('编辑密钥名称'),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          decoration: const InputDecoration(hintText: '输入新名称'),
          onSubmitted: (_) {
            final newName = ctrl.text.trim();
            if (newName.isNotEmpty) {
              appService.keystore.renameKey(key.id, newName);
            }
            Navigator.pop(ctx);
          },
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('取消')),
          TextButton(
            onPressed: () {
              final newName = ctrl.text.trim();
              if (newName.isNotEmpty) {
                appService.keystore.renameKey(key.id, newName);
              }
              Navigator.pop(ctx);
            },
            child: const Text('确定'),
          ),
        ],
      ),
    );
  }

  String _formatPublicKey(KeyMeta key) {
    final b64 = base64Encode(key.publicKeyBlob);
    // 公钥类型从 blob 的前几字节解析（SSH wire format: uint32 len + type string）
    String keyType = key.algorithm;
    if (key.publicKeyBlob.length > 4) {
      final typeLen = (key.publicKeyBlob[0] << 24) | (key.publicKeyBlob[1] << 16) |
          (key.publicKeyBlob[2] << 8) | key.publicKeyBlob[3];
      if (typeLen > 0 && typeLen + 4 <= key.publicKeyBlob.length) {
        keyType = String.fromCharCodes(key.publicKeyBlob, 4, 4 + typeLen);
      }
    }
    return '$keyType $b64 ${key.name}';
  }
}
