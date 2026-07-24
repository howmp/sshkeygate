import 'dart:async';
import 'dart:collection';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:window_manager/window_manager.dart';
import 'package:system_tray/system_tray.dart';
import 'theme/app_colors.dart';
import 'services/app_service.dart';
import 'services/keystore_service.dart';
import 'services/log_service.dart';
import 'services/policy_service.dart';
import 'services/secure_storage_service.dart';
import 'services/ssh_agent_service.dart';
import 'services/windows_service.dart';
import 'widgets/app_sidebar.dart';
import 'widgets/confirm_dialog.dart';
import 'pages/keys_page.dart';
import 'pages/import_page.dart';
import 'pages/trusted_page.dart';
import 'pages/settings_page.dart';
import 'pages/log_page.dart';
import 'pages/unlock_page.dart';

late final SystemTray _systemTray;
final ValueNotifier<int> _pendingSignRequests = ValueNotifier<int>(0);

Future<void> _refreshSystemTrayMenu(
    AppService appService, SshAgentService sshAgent) async {
  await _systemTray.setContextMenu([
    MenuItem(
        label: 'Agent：${sshAgent.isRunning ? '运行中' : '已停止'}', enabled: false),
    MenuItem(
        label: appService.isLocked ? '密钥库：已锁定' : '密钥库：已解锁', enabled: false),
    MenuItem(label: '待处理签名：${_pendingSignRequests.value}', enabled: false),
    MenuSeparator(),
    MenuItem(
        label: '显示主窗口',
        onClicked: () async {
          await windowManager.show();
          await windowManager.focus();
        }),
    MenuItem(
        label: '锁定密钥库',
        enabled: !appService.isLocked,
        onClicked: appService.lock),
    MenuSeparator(),
    MenuItem(
        label: '退出',
        onClicked: () async {
          await windowManager.destroy();
          exit(0);
        }),
  ]);
}

Future<void> _initSystemTray(
    AppService appService, SshAgentService sshAgent) async {
  _systemTray = SystemTray();
  try {
    await _systemTray.initSystemTray(
      iconPath: 'assets/tray_icon.ico',
      title: 'sshkeygate',
      toolTip: 'sshkeygate SSH Agent',
    );

    await _refreshSystemTrayMenu(appService, sshAgent);
    Future<void> refreshTraySafely() async {
      try {
        await _refreshSystemTrayMenu(appService, sshAgent);
      } catch (e) {
        debugPrint('[SystemTray] 更新菜单失败: $e');
      }
    }

    void refreshTray() => unawaited(refreshTraySafely());
    appService.addListener(refreshTray);
    sshAgent.addListener(refreshTray);
    _pendingSignRequests.addListener(refreshTray);

    _systemTray.registerSystemTrayEventHandler((eventName) async {
      if (eventName == 'leftMouseUp' || eventName == 'leftMouseDblClk') {
        await windowManager.show();
        await windowManager.focus();
      } else if (eventName == 'rightMouseUp') {
        await _systemTray.popUpContextMenu();
      }
    });
  } catch (e) {
    debugPrint('[SystemTray] 初始化失败（可忽略）: $e');
  }
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();
  await windowManager.setSize(const Size(920, 620));
  await windowManager.setMinimumSize(const Size(820, 560));
  await windowManager.setPreventClose(true);
  await windowManager.center();
  await windowManager.show();

  final logService = LogService();
  await logService.initialize();

  final storage = SecureStorageService();
  await storage.initialize();
  await storage.checkVaultExists();
  final keystore = KeyStoreService(storage: storage);
  final policy = PolicyService(storage: storage);
  final winService = WindowsService();
  await winService.initialize();
  final appService = AppService(
      storage: storage,
      keystore: keystore,
      policy: policy,
      windows: winService);
  final sshAgent =
      SshAgentService(keystore: keystore, policy: policy, log: logService);
  await _initSystemTray(appService, sshAgent);
  winService.lockDetector.start(() {
    if (!appService.lockOnScreenLock) return;
    appService.lock();
    logService.log(
        allowed: false, reason: '锁屏检测', keyName: '', processName: '');
  });

  SystemChrome.setApplicationSwitcherDescription(
    ApplicationSwitcherDescription(
        label: 'sshkeygate', primaryColor: AppColors.primary.value),
  );

  runApp(SshKeyGateApp(
      appService: appService,
      winService: winService,
      sshAgent: sshAgent,
      logService: logService));
}

class SshKeyGateApp extends StatelessWidget {
  final AppService appService;
  final WindowsService winService;
  final SshAgentService sshAgent;
  final LogService logService;
  const SshKeyGateApp(
      {super.key,
      required this.appService,
      required this.winService,
      required this.sshAgent,
      required this.logService});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'sshkeygate',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(seedColor: AppColors.primary),
          fontFamily: 'Microsoft YaHei',
          scaffoldBackgroundColor: AppColors.bg),
      home: AppShell(
          appService: appService, sshAgent: sshAgent, logService: logService),
    );
  }
}

/// 外壳：锁定时显示解锁页，解锁后显示主界面
class AppShell extends StatefulWidget {
  final AppService appService;
  final SshAgentService sshAgent;
  final LogService logService;
  const AppShell(
      {super.key,
      required this.appService,
      required this.sshAgent,
      required this.logService});

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> with WindowListener {
  bool _handlingClose = false;
  @override
  void initState() {
    super.initState();
    windowManager.addListener(this);
    widget.sshAgent.start();
  }

  @override
  void dispose() {
    windowManager.removeListener(this);
    widget.sshAgent.stop();
    super.dispose();
  }

  @override
  void onWindowClose() async {
    if (_handlingClose) return;
    _handlingClose = true;
    try {
      if (!widget.appService.closeToTrayHintShown && mounted) {
        await showDialog<void>(
          context: context,
          barrierDismissible: false,
          builder: (context) => AlertDialog(
            title: const Text('已最小化到系统托盘'),
            content: const Text('关闭主窗口不会退出 SSH Agent。你可以从系统托盘重新打开或退出程序。'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('知道了'),
              ),
            ],
          ),
        );
        try {
          await widget.appService.markCloseToTrayHintShown();
        } catch (e) {
          debugPrint('[Window] 保存关闭提示状态失败: $e');
        }
      }
      await windowManager.hide();
    } finally {
      _handlingClose = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.appService,
      builder: (context, _) {
        if (widget.appService.isLocked) {
          return UnlockPage(
            appService: widget.appService,
            onUnlocked: () => setState(() {}),
          );
        }
        return AppWindow(
          appService: widget.appService,
          sshAgent: widget.sshAgent,
          logService: widget.logService,
          pendingRequests: _pendingSignRequests,
          onLocked: () => setState(() {}),
        );
      },
    );
  }
}

class AppWindow extends StatefulWidget {
  final AppService appService;
  final SshAgentService sshAgent;
  final LogService logService;
  final ValueNotifier<int> pendingRequests;
  final VoidCallback onLocked;
  const AppWindow(
      {super.key,
      required this.appService,
      required this.sshAgent,
      required this.logService,
      required this.pendingRequests,
      required this.onLocked});

  @override
  State<AppWindow> createState() => _AppWindowState();
}

class _PendingSignRequest {
  final String keyName;
  final String fingerprint;
  final String? processPath;
  final int clientPid;
  final Completer<int> completer = Completer<int>();

  _PendingSignRequest({
    required this.keyName,
    required this.fingerprint,
    required this.processPath,
    required this.clientPid,
  });
}

class _AppWindowState extends State<AppWindow> {
  int _selectedIndex = 0;
  bool _showConfirm = false;
  bool _trusting = false;
  String? _trustError;
  final Queue<_PendingSignRequest> _pendingRequests = Queue();
  _PendingSignRequest? _activeRequest;

  AppService get _app => widget.appService;

  @override
  void initState() {
    super.initState();
    widget.sshAgent.onConfirm = _onSignRequest;
    widget.sshAgent.addListener(_handleStatusChanged);
  }

  void _handleStatusChanged() {
    if (mounted) setState(() {});
  }

  Future<int> _onSignRequest(
      String keyName, String fp, String? processPath, int clientPid) {
    final request = _PendingSignRequest(
      keyName: keyName,
      fingerprint: fp,
      processPath: processPath,
      clientPid: clientPid,
    );
    _pendingRequests.add(request);
    _updatePendingCount();
    if (_activeRequest == null) _showNextRequest();
    return request.completer.future;
  }

  void _showNextRequest() {
    if (!mounted || _activeRequest != null || _pendingRequests.isEmpty) return;
    setState(() {
      _activeRequest = _pendingRequests.removeFirst();
      _showConfirm = true;
      _trusting = false;
      _trustError = null;
    });
    _updatePendingCount();
    unawaited(_focusWindow());
  }

  Future<void> _focusWindow() async {
    await windowManager.setAlwaysOnTop(true);
    await windowManager.show();
    await windowManager.focus();
    await windowManager.setAlwaysOnTop(false);
  }

  void _deny() {
    _resolveCurrent(0, allowed: false, reason: '用户拒绝');
  }

  void _allowOnce() {
    _resolveCurrent(1, allowed: true, reason: '用户允许');
  }

  Future<void> _trust() async {
    final request = _activeRequest;
    final path = request?.processPath;
    if (request == null || path == null || _trusting) return;
    setState(() {
      _trusting = true;
      _trustError = null;
    });
    final trusted = await _app.addTrustedProcess(path);
    if (!mounted || _activeRequest != request) {
      if (trusted) await _app.removeTrustedProcess(path);
      return;
    }
    if (!trusted) {
      setState(() {
        _trusting = false;
        _trustError = '无法验证程序文件，未添加信任';
      });
      return;
    }
    _resolveCurrent(2, allowed: true, reason: '信任程序');
  }

  void _timeout() {
    _resolveCurrent(0, allowed: false, reason: '超时未响应');
  }

  void _resolveCurrent(int result,
      {required bool allowed, required String reason}) {
    final request = _activeRequest;
    if (request == null || request.completer.isCompleted) return;
    request.completer.complete(result);
    widget.logService.log(
      allowed: allowed,
      reason: reason,
      keyName: request.keyName,
      processName: request.processPath ?? '未知程序 (PID ${request.clientPid})',
    );
    setState(() {
      _showConfirm = false;
      _activeRequest = null;
      _trusting = false;
      _trustError = null;
    });
    _updatePendingCount();
    scheduleMicrotask(_showNextRequest);
  }

  void _rejectAllPending() {
    final requests = [
      if (_activeRequest != null) _activeRequest!,
      ..._pendingRequests,
    ];
    for (final request in requests) {
      if (!request.completer.isCompleted) request.completer.complete(0);
    }
    _pendingRequests.clear();
    _activeRequest = null;
    _showConfirm = false;
    _updatePendingCount();
  }

  void _updatePendingCount() {
    widget.pendingRequests.value =
        _pendingRequests.length + (_activeRequest == null ? 0 : 1);
  }

  void _onPageChanged(int i) => setState(() => _selectedIndex = i);

  @override
  void dispose() {
    // 拒绝未决的签名请求，防止 _sign() 协程永久挂起
    _rejectAllPending();
    widget.sshAgent.onConfirm = null;
    widget.sshAgent.removeListener(_handleStatusChanged);
    widget.pendingRequests.value = 0;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bg,
      body: Stack(children: [
        Container(
          decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(12),
              boxShadow: const [
                BoxShadow(
                    color: Colors.black12, blurRadius: 24, offset: Offset(0, 4))
              ]),
          clipBehavior: Clip.antiAlias,
          child: Row(children: [
            AppSidebar(
                selectedIndex: _selectedIndex,
                onPageChanged: _onPageChanged,
                isLocked: _app.isLocked,
                agentRunning: widget.sshAgent.isRunning,
                pendingRequestCount: widget.pendingRequests.value,
                onToggleLock: () {
                  _rejectAllPending();
                  _app.lock();
                  widget.onLocked();
                }),
            const VerticalDivider(width: 1, color: AppColors.border),
            Expanded(
                child: Container(
                    color: AppColors.white,
                    child: Padding(
                        padding: const EdgeInsets.all(20),
                        child: IndexedStack(index: _selectedIndex, children: [
                          KeysPage(
                              appService: _app,
                              onNavigateToImport: () => _onPageChanged(1)),
                          ImportPage(appService: _app),
                          TrustedPage(appService: _app),
                          SettingsPage(appService: _app),
                          LogPage(logService: widget.logService),
                        ])))),
          ]),
        ),
        if (_showConfirm && _activeRequest != null)
          ConfirmDialog(
              key: ValueKey(_activeRequest),
              keyName: _activeRequest!.keyName,
              keyFingerprint: _activeRequest!.fingerprint,
              sourcePath: _activeRequest!.processPath,
              sourcePid: _activeRequest!.clientPid,
              pendingCount: _pendingRequests.length + 1,
              trustBusy: _trusting,
              trustError: _trustError,
              timeoutSeconds: _app.confirmTimeoutSeconds,
              onDeny: _deny,
              onAllowOnce: _allowOnce,
              onTrust: _activeRequest!.processPath == null ? null : _trust,
              onTimeout: _timeout),
      ]),
    );
  }
}
