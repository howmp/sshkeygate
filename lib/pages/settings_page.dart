import 'dart:io';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import '../theme/app_colors.dart';
import '../services/app_service.dart';
import '../widgets/app_toggle.dart';

/// 配置页面
class SettingsPage extends StatefulWidget {
  final AppService appService;
  const SettingsPage({super.key, required this.appService});
  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  bool _autoStart = false;
  bool _lockOnScreenLock = true;
  String? _dataDir;
  double _confirmTimeout = 30;
  Set<String> _trustVerification = {'path', 'mtime'};

  @override
  void initState() {
    super.initState();
    _loadDataDir();
    _autoStart = widget.appService.windows.startupEnabled;
    _lockOnScreenLock = widget.appService.lockOnScreenLock;
    _confirmTimeout = widget.appService.confirmTimeoutSeconds.toDouble();
    _trustVerification = widget.appService.policy.trustVerification.toSet();
  }

  Future<void> _loadDataDir() async {
    final dir = await getApplicationSupportDirectory();
    if (mounted) setState(() => _dataDir = dir.path);
  }

  Future<void> _openDataDir() async {
    if (_dataDir == null) return;
    await Process.run('explorer.exe', [_dataDir!]);
  }

  Future<void> _showChangePassword() async {
    final oldCtrl = TextEditingController();
    final newCtrl = TextEditingController();
    final confirmCtrl = TextEditingController();
    String? error;
    bool changing = false;

    await showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('修改锁定密码'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: oldCtrl,
                obscureText: true,
                decoration: const InputDecoration(labelText: '当前密码'),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: newCtrl,
                obscureText: true,
                decoration: const InputDecoration(labelText: '新密码'),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: confirmCtrl,
                obscureText: true,
                decoration: const InputDecoration(labelText: '确认新密码'),
              ),
              if (error != null) ...[
                const SizedBox(height: 10),
                Text(error!,
                    style: const TextStyle(color: AppColors.red, fontSize: 13)),
              ],
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('取消'),
            ),
            TextButton(
              onPressed: () async {
                if (changing) return;
                if (newCtrl.text.length < AppService.minimumPasswordLength) {
                  setDialogState(() =>
                      error = '新密码至少 ${AppService.minimumPasswordLength} 个字符');
                  return;
                }
                if (newCtrl.text != confirmCtrl.text) {
                  setDialogState(() => error = '两次输入的密码不一致');
                  return;
                }
                setDialogState(() {
                  changing = true;
                  error = null;
                });
                final ok = await widget.appService
                    .changePassword(oldCtrl.text, newCtrl.text);
                if (!ctx.mounted || !mounted) return;
                if (ok) {
                  Navigator.pop(ctx);
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('密码已修改')),
                  );
                } else {
                  setDialogState(() {
                    changing = false;
                    error = '当前密码错误或安全存储写入失败';
                  });
                }
              },
              child: Text(changing ? '修改中...' : '确认'),
            ),
          ],
        ),
      ),
    );
    oldCtrl.dispose();
    newCtrl.dispose();
    confirmCtrl.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Expanded(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            decoration: BoxDecoration(
                color: AppColors.white,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.border)),
            child: ListenableBuilder(
              listenable: widget.appService,
              builder: (context, _) => SingleChildScrollView(
                child: Column(children: [
                  _SettingRow(
                      label: '开机自动启动',
                      description: '登录 Windows 时自动运行 sshkeygate',
                      value: _autoStart,
                      onChanged: (v) async {
                        setState(() => _autoStart = v);
                        await widget.appService.windows.setStartup(v);
                      }),
                  const Divider(height: 1, color: AppColors.borderLight),
                  _SettingRow(
                      label: '锁屏自动锁定',
                      description: 'Windows 锁屏时清空内存中的密钥',
                      value: _lockOnScreenLock,
                      onChanged: (v) async {
                        setState(() => _lockOnScreenLock = v);
                        final settings = widget.appService.getSettings();
                        settings['lockOnScreenLock'] = v;
                        await widget.appService.updateSettings(settings);
                      }),
                  const Divider(height: 1, color: AppColors.borderLight),
                  // 确认超时时间设置
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text('签名确认超时',
                                    style: TextStyle(
                                        fontSize: 14,
                                        fontWeight: FontWeight.w600,
                                        color: AppColors.textBody)),
                                SizedBox(height: 2),
                                Text('超时后自动拒绝签名请求',
                                    style: TextStyle(
                                        fontSize: 12,
                                        color: AppColors.textLight)),
                              ],
                            ),
                            Text('${_confirmTimeout.round()} 秒',
                                style: const TextStyle(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w600,
                                    color: AppColors.primary)),
                          ],
                        ),
                        const SizedBox(height: 8),
                        SliderTheme(
                          data: SliderThemeData(
                            activeTrackColor: AppColors.primary,
                            inactiveTrackColor: AppColors.border,
                            thumbColor: AppColors.primary,
                            overlayColor: AppColors.primary.withOpacity(0.1),
                            trackHeight: 3,
                            thumbShape: const RoundSliderThumbShape(
                                enabledThumbRadius: 7),
                          ),
                          child: Slider(
                            value: _confirmTimeout,
                            min: 10,
                            max: 120,
                            divisions: 22,
                            onChanged: (v) =>
                                setState(() => _confirmTimeout = v),
                            onChangeEnd: (v) async {
                              final settings = widget.appService.getSettings();
                              settings['confirmTimeoutSeconds'] = v.round();
                              await widget.appService.updateSettings(settings);
                            },
                          ),
                        ),
                        const Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text('10秒',
                                style: TextStyle(
                                    fontSize: 10, color: AppColors.textLight)),
                            Text('120秒',
                                style: TextStyle(
                                    fontSize: 10, color: AppColors.textLight)),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const Divider(height: 1, color: AppColors.borderLight),
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('信任程序校验',
                            style: TextStyle(
                                fontSize: 14,
                                fontWeight: FontWeight.w600,
                                color: AppColors.textBody)),
                        const SizedBox(height: 2),
                        const Text(
                            '默认使用路径和最后修改时间；SHA-256 会读取整个文件。路径始终作为程序身份标识。',
                            style: TextStyle(
                                fontSize: 12, color: AppColors.textLight)),
                        const SizedBox(height: 6),
                        Row(
                          children: [
                            ('path', '程序路径'),
                            ('mtime', '最后修改时间'),
                            ('sha256', 'SHA-256'),
                          ]
                              .map((item) => Expanded(
                                    child: CheckboxListTile(
                                      dense: true,
                                      visualDensity: VisualDensity.compact,
                                      controlAffinity:
                                          ListTileControlAffinity.leading,
                                      contentPadding: EdgeInsets.zero,
                                      title: Text(item.$2,
                                          style: const TextStyle(fontSize: 12)),
                                      value:
                                          _trustVerification.contains(item.$1),
                                      onChanged: item.$1 == 'path'
                                          ? null
                                          : (value) async {
                                              final next = {
                                                ..._trustVerification
                                              };
                                              if (value == true) {
                                                next.add(item.$1);
                                              } else {
                                                next.remove(item.$1);
                                              }
                                              setState(() =>
                                                  _trustVerification = next);
                                              await widget.appService.policy
                                                  .setTrustVerification(next);
                                            },
                                    ),
                                  ))
                              .toList(),
                        ),
                      ],
                    ),
                  ),
                  const Divider(height: 1, color: AppColors.borderLight),
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('修改锁定密码',
                                style: TextStyle(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w600,
                                    color: AppColors.textBody)),
                            SizedBox(height: 2),
                            Text('更改用于保护密钥库的密码',
                                style: TextStyle(
                                    fontSize: 12, color: AppColors.textLight)),
                          ],
                        ),
                        GestureDetector(
                          onTap: _showChangePassword,
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 12, vertical: 6),
                            decoration: BoxDecoration(
                              border: Border.all(color: AppColors.border),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: const Text('修改',
                                style: TextStyle(
                                    fontSize: 12, color: AppColors.textBody)),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const Divider(height: 1, color: AppColors.borderLight),
                ]),
              ),
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.all(8),
          child: GestureDetector(
            onTap: _openDataDir,
            child: Column(
              children: [
                Text(_dataDir != null ? '数据目录：$_dataDir' : '数据目录：加载中...',
                    style: const TextStyle(
                        fontSize: 11,
                        color: AppColors.primary,
                        decoration: TextDecoration.underline),
                    textAlign: TextAlign.center),
                const SizedBox(height: 2),
                const Text('密钥数据受密码 + 设备密钥双重保护，离开此设备后文件无法解密',
                    style: TextStyle(fontSize: 10, color: AppColors.textLight),
                    textAlign: TextAlign.center),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _SettingRow extends StatelessWidget {
  final String label;
  final String description;
  final bool value;
  final ValueChanged<bool> onChanged;
  const _SettingRow(
      {required this.label,
      required this.description,
      required this.value,
      required this.onChanged});
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 16),
      child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
        Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label,
              style: const TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                  color: AppColors.textBody)),
          const SizedBox(height: 2),
          Text(description,
              style: const TextStyle(fontSize: 12, color: AppColors.textLight)),
        ]),
        AppToggle(value: value, onChanged: onChanged),
      ]),
    );
  }
}
