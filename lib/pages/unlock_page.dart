import 'package:flutter/material.dart';
import '../theme/app_colors.dart';
import '../services/app_service.dart';

/// 解锁/设置密码页面
class UnlockPage extends StatefulWidget {
  final AppService appService;
  final VoidCallback onUnlocked;

  const UnlockPage({
    super.key,
    required this.appService,
    required this.onUnlocked,
  });

  @override
  State<UnlockPage> createState() => _UnlockPageState();
}

class _UnlockPageState extends State<UnlockPage> {
  final _passwordController = TextEditingController();
  final _confirmController = TextEditingController();
  String? _error;
  bool _loading = false;

  bool get _isFirstRun => widget.appService.isFirstRun;

  @override
  void dispose() {
    _passwordController.dispose();
    _confirmController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final password = _passwordController.text;
    if (password.isEmpty) {
      setState(() => _error = '请输入密码');
      return;
    }

    if (_isFirstRun) {
      if (password.length < AppService.minimumPasswordLength) {
        setState(() => _error = '密码至少 ${AppService.minimumPasswordLength} 个字符');
        return;
      }
      if (_confirmController.text != password) {
        setState(() => _error = '两次输入的密码不一致');
        return;
      }
      setState(() {
        _loading = true;
        _error = null;
      });
      final ok = await widget.appService.setupPassword(password);
      if (!mounted) return;
      setState(() => _loading = false);
      if (ok) {
        widget.onUnlocked();
      } else {
        setState(() => _error = '创建失败');
      }
    } else {
      setState(() {
        _loading = true;
        _error = null;
      });
      final ok = await widget.appService.unlock(password);
      if (!mounted) return;
      setState(() => _loading = false);
      if (ok) {
        widget.onUnlocked();
      } else {
        setState(() => _error = widget.appService.status);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bg,
      body: Center(
        child: Container(
          width: 380,
          padding: const EdgeInsets.all(36),
          decoration: BoxDecoration(
            color: AppColors.white,
            borderRadius: BorderRadius.circular(16),
            boxShadow: const [
              BoxShadow(
                  color: Colors.black12, blurRadius: 24, offset: Offset(0, 4))
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                _isFirstRun ? Icons.lock_outline : Icons.lock,
                size: 48,
                color: AppColors.primary,
              ),
              const SizedBox(height: 16),
              Text(
                _isFirstRun ? '设置锁定密码' : '解锁 sshkeygate',
                style: const TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.w700,
                  color: AppColors.textBody,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                _isFirstRun ? '此密码用于保护你的 SSH 私钥' : '输入密码以访问密钥库',
                style:
                    const TextStyle(fontSize: 13, color: AppColors.textLight),
              ),
              const SizedBox(height: 24),
              TextField(
                controller: _passwordController,
                obscureText: true,
                autofocus: true,
                onSubmitted: (_) => _submit(),
                decoration: InputDecoration(
                  labelText: '密码',
                  border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8)),
                  contentPadding:
                      const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                ),
              ),
              if (_isFirstRun) ...[
                const SizedBox(height: 14),
                TextField(
                  controller: _confirmController,
                  obscureText: true,
                  onSubmitted: (_) => _submit(),
                  decoration: InputDecoration(
                    labelText: '确认密码',
                    border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8)),
                    contentPadding: const EdgeInsets.symmetric(
                        horizontal: 14, vertical: 12),
                  ),
                ),
              ],
              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(_error!,
                    style: const TextStyle(color: AppColors.red, fontSize: 13)),
              ],
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                height: 40,
                child: ElevatedButton(
                  onPressed: _loading ? null : _submit,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: AppColors.white,
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8)),
                  ),
                  child: _loading
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(
                              strokeWidth: 2, color: AppColors.white))
                      : Text(_isFirstRun ? '创建' : '解锁'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
