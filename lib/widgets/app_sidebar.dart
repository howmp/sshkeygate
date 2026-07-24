import 'package:flutter/material.dart';
import '../theme/app_colors.dart';

/// 应用侧边栏
class AppSidebar extends StatefulWidget {
  final int selectedIndex;
  final ValueChanged<int> onPageChanged;
  final bool isLocked;
  final bool agentRunning;
  final int pendingRequestCount;
  final VoidCallback onToggleLock;

  const AppSidebar({
    super.key,
    required this.selectedIndex,
    required this.onPageChanged,
    required this.isLocked,
    required this.agentRunning,
    required this.pendingRequestCount,
    required this.onToggleLock,
  });

  @override
  State<AppSidebar> createState() => _AppSidebarState();
}

class _AppSidebarState extends State<AppSidebar> {
  static const _navItems = [
    _NavItemData(Icons.vpn_key_outlined, '密钥列表'),
    _NavItemData(Icons.download_outlined, '导入密钥'),
    _NavItemData(Icons.verified_user_outlined, '信任程序'),
    _NavItemData(Icons.settings_outlined, '配置'),
    _NavItemData(Icons.article_outlined, '日志'),
  ];

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 200,
      color: AppColors.white,
      child: Column(
        children: [
          // 品牌区
          _buildBrand(),
          // 导航
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              children: [
                for (int i = 0; i < _navItems.length; i++) _buildNavItem(i),
              ],
            ),
          ),
          // 底部状态
          _buildFooter(),
        ],
      ),
    );
  }

  Widget _buildBrand() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 20, 18, 16),
      child: Row(
        children: [
          // 品牌图标
          Container(
            width: 34,
            height: 34,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(10),
              gradient: const LinearGradient(
                colors: [Color(0xFF3B82F6), Color(0xFF2563EB)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
            ),
            child: const Icon(Icons.vpn_key, color: Colors.white, size: 18),
          ),
          const SizedBox(width: 10),
          const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'sshkeygate',
                style: TextStyle(
                  fontSize: 17,
                  fontWeight: FontWeight.w800,
                  color: AppColors.textPrimary,
                ),
              ),
              Text(
                'v0.2.0',
                style: TextStyle(fontSize: 10, color: AppColors.textLight),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildNavItem(int index) {
    final isActive = widget.selectedIndex == index;
    return GestureDetector(
      onTap: () => widget.onPageChanged(index),
      child: Container(
        margin: const EdgeInsets.only(bottom: 2),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: isActive ? AppColors.primaryLight : null,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          children: [
            Icon(
              _navItems[index].icon,
              size: 18,
              color: isActive ? AppColors.primary : AppColors.textMuted,
            ),
            const SizedBox(width: 10),
            Text(
              _navItems[index].label,
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: isActive ? AppColors.primary : AppColors.textMuted,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFooter() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: const BoxDecoration(
        border: Border(top: BorderSide(color: AppColors.borderLight)),
      ),
      child: Row(
        children: [
          _StatusBadge(
            isLocked: widget.isLocked,
            agentRunning: widget.agentRunning,
            pendingRequestCount: widget.pendingRequestCount,
          ),
          const Spacer(),
          _LockButton(
            isLocked: widget.isLocked,
            onTap: widget.onToggleLock,
          ),
        ],
      ),
    );
  }
}

/// 状态徽章（运行中 / 已锁定）
class _StatusBadge extends StatelessWidget {
  final bool isLocked;
  final bool agentRunning;
  final int pendingRequestCount;

  const _StatusBadge({
    required this.isLocked,
    required this.agentRunning,
    required this.pendingRequestCount,
  });

  @override
  Widget build(BuildContext context) {
    final isRunning = agentRunning && !isLocked;
    final label = !agentRunning
        ? 'Agent 已停止'
        : isLocked
            ? 'Agent 已锁定'
            : pendingRequestCount > 0
                ? '待处理 $pendingRequestCount'
                : 'Agent 运行中';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 3),
      decoration: BoxDecoration(
        color: isRunning ? AppColors.greenBg : AppColors.redBg,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: isRunning ? AppColors.greenText : AppColors.redText,
            ),
          ),
          const SizedBox(width: 5),
          Text(
            label,
            style: TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.w700,
              color: isRunning ? AppColors.greenText : AppColors.redText,
            ),
          ),
        ],
      ),
    );
  }
}

/// 锁定/解锁按钮（侧边栏底部）
class _LockButton extends StatelessWidget {
  final bool isLocked;
  final VoidCallback onTap;

  const _LockButton({required this.isLocked, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 32,
        height: 32,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppColors.border),
        ),
        child: Icon(
          isLocked ? Icons.lock : Icons.lock_open,
          size: 16,
          color: isLocked ? AppColors.red : AppColors.textMuted,
        ),
      ),
    );
  }
}

class _NavItemData {
  final IconData icon;
  final String label;

  const _NavItemData(this.icon, this.label);
}
