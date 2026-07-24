import 'dart:async';
import 'package:flutter/material.dart';
import '../theme/app_colors.dart';

/// 确认弹窗（SSH 签名请求）- 带倒计时自动拒绝
class ConfirmDialog extends StatefulWidget {
  final String keyName;
  final String keyFingerprint;
  final String? sourcePath;
  final int sourcePid;
  final int pendingCount;
  final bool trustBusy;
  final String? trustError;
  final int timeoutSeconds;
  final VoidCallback onDeny;
  final VoidCallback onAllowOnce;
  final VoidCallback? onTrust;
  final VoidCallback? onTimeout;

  const ConfirmDialog({
    super.key,
    required this.keyName,
    required this.keyFingerprint,
    required this.sourcePath,
    required this.sourcePid,
    this.pendingCount = 1,
    this.trustBusy = false,
    this.trustError,
    this.timeoutSeconds = 30,
    required this.onDeny,
    required this.onAllowOnce,
    required this.onTrust,
    this.onTimeout,
  });

  @override
  State<ConfirmDialog> createState() => _ConfirmDialogState();
}

class _ConfirmDialogState extends State<ConfirmDialog> {
  late int _remainingSeconds;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _remainingSeconds = widget.timeoutSeconds;
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      if (widget.trustBusy) return;
      setState(() {
        _remainingSeconds--;
      });
      if (_remainingSeconds <= 0) {
        _timer?.cancel();
        _timer = null;
        if (widget.onTimeout != null) {
          widget.onTimeout!();
        } else {
          widget.onDeny();
        }
      }
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: true,
      onPopInvokedWithResult: (didPop, result) => widget.onDeny(),
      child: GestureDetector(
        onTap: widget.onDeny,
        child: Container(
          color: Colors.black54,
          alignment: Alignment.center,
          child: GestureDetector(
            onTap: () {}, // 阻止冒泡
            child: Container(
              width: 440,
              margin: const EdgeInsets.symmetric(horizontal: 40),
              padding: const EdgeInsets.all(28),
              decoration: BoxDecoration(
                color: AppColors.white,
                borderRadius: BorderRadius.circular(16),
                boxShadow: const [
                  BoxShadow(
                    color: Colors.black26,
                    blurRadius: 40,
                    offset: Offset(0, 8),
                  ),
                ],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 警告图标 + 标题 + 倒计时
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Row(
                        children: [
                          Container(
                            width: 42,
                            height: 42,
                            decoration: BoxDecoration(
                              color: AppColors.warningBg,
                              borderRadius: BorderRadius.circular(12),
                            ),
                            child: const Icon(
                              Icons.warning_amber_rounded,
                              color: AppColors.warningStroke,
                              size: 22,
                            ),
                          ),
                          const SizedBox(width: 12),
                          const Text(
                            '是否允许本次签名请求？',
                            style: TextStyle(
                              fontSize: 17,
                              fontWeight: FontWeight.w700,
                              color: AppColors.textPrimary,
                            ),
                          ),
                        ],
                      ),
                      // 倒计时显示
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: _remainingSeconds <= 10
                              ? const Color(0xFFFEE2E2)
                              : const Color(0xFFF1F5F9),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.timer_outlined,
                              size: 14,
                              color: _remainingSeconds <= 10
                                  ? AppColors.red
                                  : AppColors.textSecondary,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              '${_remainingSeconds}s',
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                                color: _remainingSeconds <= 10
                                    ? AppColors.red
                                    : AppColors.textSecondary,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  if (widget.pendingCount > 1) ...[
                    Text(
                      '待处理请求：${widget.pendingCount}',
                      style: const TextStyle(
                          fontSize: 12, color: AppColors.warningStroke),
                    ),
                    const SizedBox(height: 8),
                  ],
                  Text(
                    '密钥：${widget.keyName}',
                    style: const TextStyle(
                      fontSize: 11,
                      color: AppColors.textMuted,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    widget.sourcePath == null
                        ? '来源：无法识别 (PID ${widget.sourcePid})'
                        : '来源：${widget.sourcePath} (PID ${widget.sourcePid})',
                    style: const TextStyle(
                      fontSize: 11,
                      color: AppColors.textMuted,
                    ),
                  ),
                  if (widget.trustError != null) ...[
                    const SizedBox(height: 10),
                    Text(widget.trustError!,
                        style: const TextStyle(
                            fontSize: 12, color: AppColors.red)),
                  ],
                  const SizedBox(height: 20),
                  // 操作按钮
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      _DialogButton(
                        label: '拒绝',
                        onTap: widget.trustBusy ? null : widget.onDeny,
                        isOutline: true,
                      ),
                      const SizedBox(width: 8),
                      _DialogButton(
                        label: '允许本次',
                        onTap: widget.trustBusy ? null : widget.onAllowOnce,
                        isPrimary: true,
                      ),
                      const SizedBox(width: 8),
                      if (widget.onTrust != null)
                        _DialogButton(
                          label: widget.trustBusy ? '验证中...' : '信任此程序',
                          onTap: widget.trustBusy ? null : widget.onTrust,
                          isGreen: true,
                        ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _DialogButton extends StatelessWidget {
  final String label;
  final VoidCallback? onTap;
  final bool isOutline;
  final bool isPrimary;
  final bool isGreen;

  const _DialogButton({
    required this.label,
    required this.onTap,
    this.isOutline = false,
    this.isPrimary = false,
    this.isGreen = false,
  });

  @override
  Widget build(BuildContext context) {
    Color bgColor;
    Color textColor;

    if (isGreen) {
      bgColor = AppColors.green;
      textColor = AppColors.white;
    } else if (isPrimary) {
      bgColor = AppColors.primary;
      textColor = AppColors.white;
    } else {
      bgColor = AppColors.white;
      textColor = AppColors.textSecondary;
    }

    return Opacity(
      opacity: onTap == null ? 0.5 : 1,
      child: Material(
        color: bgColor,
        borderRadius: BorderRadius.circular(8),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(8),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(8),
              border: isOutline ? Border.all(color: AppColors.border) : null,
            ),
            child: Text(
              label,
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: textColor,
              ),
            ),
          ),
        ),
      ),
    );
  }
}
