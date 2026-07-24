import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:desktop_drop/desktop_drop.dart';
import '../theme/app_colors.dart';
import '../services/app_service.dart';
import '../services/ssh_key_service.dart';
/// 导入密钥页面
class ImportPage extends StatefulWidget {
  final AppService appService;
  const ImportPage({super.key, required this.appService});
  @override
  State<ImportPage> createState() => _ImportPageState();
}

class _ImportPageState extends State<ImportPage> {
  int _activeTab = 0;
  bool _busy = false;
  bool _scanning = false;
  bool _isDragging = false;

  // ── 文本导入 ──
  final _nameCtrl = TextEditingController();
  final _keyCtrl = TextEditingController();
  final _passphraseCtrl = TextEditingController();

  // ── 文件导入 ──
  final _dirCtrl = TextEditingController();
  List<_SshFile> _files = [];
  bool _selectAll = true;
  String? _scanSummary;
  final Map<String, TextEditingController> _filePassCtrls = {};

  // ── Bitwarden ──
  final _bwServerCtrl = TextEditingController();
  final _bwEmailCtrl = TextEditingController();
  final _bwPasswordCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _dirCtrl.text = '${Platform.environment['USERPROFILE']}\\.ssh';
    _scanDirectory(silent: true);
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _keyCtrl.dispose();
    _passphraseCtrl.dispose();
    _dirCtrl.dispose();
    for (final c in _filePassCtrls.values) {
      c.dispose();
    }
    _bwServerCtrl.dispose();
    _bwEmailCtrl.dispose();
    _bwPasswordCtrl.dispose();
    super.dispose();
  }

  // ──────────────────────────────────────────────────────
  // 文本导入
  // ──────────────────────────────────────────────────────

  Future<void> _doTextImport() async {
    final text = _keyCtrl.text;
    if (text.trim().isEmpty) {
      _showResult('请粘贴私钥文本');
      return;
    }
    setState(() => _busy = true);
    final result = await widget.appService.importFromText(
      keyText: text,
      name: _nameCtrl.text,
      passphrase: _passphraseCtrl.text,
    );
    setState(() => _busy = false);
    _showResult(result);
    if (result == '导入成功') {
      _keyCtrl.clear();
      _nameCtrl.clear();
      _passphraseCtrl.clear();
    }
  }

  // ──────────────────────────────────────────────────────
  // 文件导入
  // ──────────────────────────────────────────────────────

  /// 浏览选择目录
  Future<void> _browseDirectory() async {
    final result = await FilePicker.getDirectoryPath(
      dialogTitle: '选择 SSH 密钥目录',
      initialDirectory: _dirCtrl.text.trim(),
    );
    if (result != null) {
      setState(() => _dirCtrl.text = result);
      _scanDirectory();
    }
  }

  /// 处理拖拽文件（文本导入标签页）
  Future<void> _handleDroppedFiles(DropDoneDetails details) async {
    setState(() => _isDragging = false);
    for (final file in details.files) {
      final path = file.path;
      // 仅接受 .pem 文件或无扩展名文件
      final fileName = path.split(Platform.pathSeparator).last;
      final hasExtension = fileName.contains('.');
      final isPem = fileName.endsWith('.pem');
      if (!isPem && hasExtension) continue;

      try {
        final content = await File(path).readAsString();
        if (content.contains('PRIVATE KEY')) {
          setState(() {
            _keyCtrl.text = content;
            if (_nameCtrl.text.isEmpty) {
              _nameCtrl.text = fileName;
            }
          });
          break; // 只取第一个有效文件
        }
      } catch (_) {}
    }
  }

  /// 扫描 SSH 目录，列出所有私钥文件
  Future<void> _scanDirectory({bool silent = false}) async {
    final dirPath = _dirCtrl.text.trim();
    if (dirPath.isEmpty) return;

    // 清理旧的 passphrase 控制器
    for (final c in _filePassCtrls.values) {
      c.dispose();
    }

    setState(() {
      _scanning = true;
      _files = [];
      _filePassCtrls.clear();
      _selectAll = true;
      _scanSummary = null;
    });

    try {
      final dir = Directory(dirPath);
      if (!await dir.exists()) {
        if (!mounted) return;
        setState(() => _scanning = false);
        if (!silent) _showResult('目录不存在：$dirPath');
        return;
      }

      // 收集已导入记录的指纹集合
      final importedFingerprints =
          widget.appService.keystore.keys.map((r) => r.fingerprint).toSet();

      final entities = await dir.list().toList();
      final List<_SshFile> found = [];
      var skipped = 0;

      for (final entity in entities) {
        if (entity is! File) continue;

        final fileName = entity.path.split(Platform.pathSeparator).last;

        // 跳过 .pub 公钥文件
        if (fileName.endsWith('.pub')) continue;
        // 跳过常见非密钥文件
        if (fileName == 'known_hosts' ||
            fileName == 'authorized_keys' ||
            fileName == 'config') continue;
        // 跳过隐藏文件（. 开头，排除 id_ 系列）
        if (fileName.startsWith('.') && !fileName.startsWith('id_')) continue;

        try {
          final content = await entity.readAsString();
          // 通过内容检测是否为 PEM 格式的私钥
          if (!content.contains('PRIVATE KEY-----')) {
            skipped++;
            continue;
          }

          String keyType = 'unknown';
          bool needsPassphrase = false;
          bool alreadyImported = false;

          try {
            if (SshKeyService.isEncrypted(content)) {
              keyType = '加密密钥';
              needsPassphrase = true;
            } else {
              final parsedKey = SshKeyService.parse(content);
              keyType = parsedKey.algorithm;
              alreadyImported = importedFingerprints.contains(parsedKey.fingerprint);
            }
          } catch (e) {
            found.add(_SshFile(name: fileName, path: entity.path,
                keyType: '无法解析', error: e.toString(), isSelected: false));
            continue;
          }

          found.add(_SshFile(
            name: fileName,
            path: entity.path,
            keyType: keyType,
            alreadyImported: alreadyImported,
            needsPassphrase: needsPassphrase,
            isSelected: !alreadyImported && !needsPassphrase,
          ));
          if (needsPassphrase) {
            _filePassCtrls[entity.path] = TextEditingController();
          }
        } catch (e) {
          found.add(_SshFile(name: fileName, path: entity.path,
              keyType: '读取失败', error: e.toString(), isSelected: false));
        }
      }

      found.sort((a, b) => a.name.compareTo(b.name));

      if (!mounted) return;
      setState(() {
        _files = found;
        _scanning = false;
        final encrypted = found.where((f) => f.needsPassphrase).length;
        final invalid = found.where((f) => f.error != null).length;
        _scanSummary =
            '扫描完成：可识别 ${found.length - invalid}，加密 $encrypted，异常 $invalid，忽略 $skipped';
      });
      if (found.isEmpty && !silent) {
        _showResult('未找到 SSH 私钥文件');
      }
    } catch (e) {
      if (!mounted) return;
      setState(() => _scanning = false);
      _showResult('扫描失败：$e');
    }
  }

  /// 批量导入选中的文件
  Future<void> _doFileImport() async {
    final selected =
        _files.where((f) => f.isSelected && !f.alreadyImported).toList();
    if (selected.isEmpty) {
      _showResult('没有可导入的选中文件');
      return;
    }

    setState(() => _busy = true);
    int success = 0;
    int failed = 0;

    for (final file in selected) {
      try {
        final content = await File(file.path).readAsString();
        final passCtrl = _filePassCtrls[file.path];
        final passphrase = passCtrl != null && passCtrl.text.trim().isNotEmpty
            ? passCtrl.text.trim()
            : null;

        final result = await widget.appService.importFromText(
          keyText: content,
          name: file.name,
          passphrase: passphrase,
        );
        if (result == '导入成功') {
          success++;
        } else {
          failed++;
        }
      } catch (e) {
        failed++;
      }
    }

    if (!mounted) return;
    setState(() => _busy = false);
    _showResult('导入完成：成功 $success，失败 $failed');
    // 重新扫描以刷新已导入状态
    _scanDirectory();
  }

  /// 切换全选 / 取消全选
  void _toggleSelectAll() {
    setState(() {
      _selectAll = !_selectAll;
      for (final f in _files) {
        // 已导入的文件不改变选中状态
        if (!f.alreadyImported) {
          f.isSelected = _selectAll;
        }
      }
    });
  }

  // ──────────────────────────────────────────────────────
  // Bitwarden 同步
  // ──────────────────────────────────────────────────────

  Future<void> _doBwSync() async {
    final server = _bwServerCtrl.text.trim();
    final email = _bwEmailCtrl.text.trim();
    final password = _bwPasswordCtrl.text;
    if (server.isEmpty || email.isEmpty || password.isEmpty) {
      _showResult('请填写服务器地址、邮箱和密码');
      return;
    }
    setState(() => _busy = true);
    final result = await widget.appService.syncBitwarden(
      serverUrl: server,
      email: email,
      password: password,
    );
    setState(() => _busy = false);
    if (!mounted) return;
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('同步结果'),
        content: Text(result),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('确定'),
          ),
        ],
      ),
    );
  }

  // ──────────────────────────────────────────────────────
  // 通用方法
  // ──────────────────────────────────────────────────────

  void _showResult(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(msg), duration: const Duration(seconds: 3)));
  }

  // ──────────────────────────────────────────────────────
  // 构建
  // ──────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        _buildTabs(),
        Expanded(
          child: Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
                color: AppColors.white,
                borderRadius: const BorderRadius.only(
                    bottomLeft: Radius.circular(12),
                    bottomRight: Radius.circular(12)),
                border: Border.all(color: AppColors.border)),
            child: IndexedStack(index: _activeTab, children: [
              _buildTextImport(),
              _buildFileImport(),
              _buildBitwardenImport(),
            ]),
          ),
        ),
      ],
    );
  }

  Widget _buildTabs() {
    const tabs = [
      (_TabData(Icons.article_outlined, '从文本导入')),
      (_TabData(Icons.folder_open_outlined, '从文件导入')),
      (_TabData(Icons.cloud_outlined, '从 Bitwarden 导入'))
    ];
    return Container(
      decoration: const BoxDecoration(
          color: AppColors.white,
          borderRadius: BorderRadius.vertical(top: Radius.circular(12)),
          border: Border(
              left: BorderSide(color: AppColors.border),
              right: BorderSide(color: AppColors.border),
              top: BorderSide(color: AppColors.border))),
      child: Row(
        children: [
          for (int i = 0; i < tabs.length; i++)
            GestureDetector(
              onTap: () => setState(() => _activeTab = i),
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 18, vertical: 10),
                decoration: BoxDecoration(
                    border: Border(
                        bottom: BorderSide(
                            color: _activeTab == i
                                ? AppColors.primary
                                : Colors.transparent,
                            width: 2))),
                child: Row(children: [
                  Icon(tabs[i].icon,
                      size: 15,
                      color: _activeTab == i
                          ? AppColors.primary
                          : AppColors.textLight),
                  const SizedBox(width: 6),
                  Text(tabs[i].label,
                      style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          color: _activeTab == i
                              ? AppColors.primary
                              : AppColors.textLight)),
                ]),
              ),
            ),
        ],
      ),
    );
  }

  // ──────────────────────────────────────────────────────
  // 文本导入 UI
  // ──────────────────────────────────────────────────────

  Widget _buildTextImport() {
    return SingleChildScrollView(
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        _FormRow(
            label: '名称',
            child: SizedBox(
                width: 340,
                height: 32,
                child: _buildInput(_nameCtrl, '给密钥起个名字，如 github-ed25519'))),
        const SizedBox(height: 6),
        const _FormRow(label: '私钥', child: SizedBox.shrink()),
        const SizedBox(height: 4),
        // 拖拽区域包裹私钥输入框
        DropTarget(
          onDragEntered: (_) => setState(() => _isDragging = true),
          onDragExited: (_) => setState(() => _isDragging = false),
          onDragDone: _handleDroppedFiles,
          child: Stack(
            children: [
              SizedBox(
                  width: 500,
                  height: 160,
                  child: TextField(
                      controller: _keyCtrl,
                      maxLines: null,
                      expands: true,
                      textAlignVertical: TextAlignVertical.top,
                      style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
                      decoration: InputDecoration(
                          hintText:
                              '-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n\n拖拽 .pem 文件到此处也可导入',
                          hintStyle: const TextStyle(
                              color: AppColors.textLight,
                              fontSize: 12,
                              fontFamily: 'monospace'),
                          contentPadding: const EdgeInsets.all(10),
                          border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: BorderSide(
                                  color: _isDragging ? AppColors.primary : AppColors.border)),
                          enabledBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: BorderSide(
                                  color: _isDragging ? AppColors.primary : AppColors.border)),
                          focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide:
                                  const BorderSide(color: AppColors.focusBorder))))),
              // 拖拽提示覆盖层
              if (_isDragging)
                Positioned.fill(
                  child: Container(
                    decoration: BoxDecoration(
                      color: AppColors.primary.withOpacity(0.08),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: AppColors.primary, width: 2),
                    ),
                    child: const Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.file_download_outlined,
                              size: 32, color: AppColors.primary),
                          SizedBox(height: 8),
                          Text('释放以导入私钥文件',
                              style: TextStyle(
                                  fontSize: 14,
                                  fontWeight: FontWeight.w600,
                                  color: AppColors.primary)),
                        ],
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        _FormRow(
            label: '密钥口令',
            child: SizedBox(
                width: 200,
                height: 32,
                child: _buildInput(_passphraseCtrl, '如有加密请填写', obscure: true))),
        const SizedBox(height: 14),
        _buildButton('导入', onTap: _busy ? null : _doTextImport),
      ]),
    );
  }

  // ──────────────────────────────────────────────────────
  // 文件导入 UI
  // ──────────────────────────────────────────────────────

  Widget _buildFileImport() {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      // 目录路径行：标签 + 输入框 + 浏览按钮 + 扫描按钮
      Row(children: [
        const SizedBox(
            width: 80,
            child: Text('目录',
                style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textSecondary))),
        const SizedBox(width: 12),
        SizedBox(
          width: 300,
          height: 32,
          child: _buildInput(_dirCtrl, r'C:\Users\you\.ssh',
              onSubmit: (_) => _scanDirectory()),
        ),
        const SizedBox(width: 8),
        GestureDetector(
          onTap: _browseDirectory,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border)),
            child: const Row(mainAxisSize: MainAxisSize.min, children: [
              Icon(Icons.folder_open, size: 14, color: AppColors.textSecondary),
              SizedBox(width: 4),
              Text('浏览',
                  style: TextStyle(fontSize: 12, color: AppColors.textSecondary)),
            ]),
          ),
        ),
        const SizedBox(width: 8),
        GestureDetector(
          onTap: _scanning ? null : _scanDirectory,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border)),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              _scanning
                  ? const SizedBox(
                      width: 12,
                      height: 12,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: AppColors.primary))
                  : const Icon(Icons.refresh,
                      size: 14, color: AppColors.textSecondary),
              const SizedBox(width: 4),
              Text(_scanning ? '扫描中…' : '扫描',
                  style: const TextStyle(
                      fontSize: 12, color: AppColors.textSecondary)),
            ]),
          ),
        ),
      ]),
      if (_scanSummary != null) ...[
        const SizedBox(height: 8),
        Text(_scanSummary!, style: const TextStyle(fontSize: 11, color: AppColors.textLight)),
      ],
      const SizedBox(height: 12),

      // 文件列表
      _buildFileTable(),
    ]);
  }

  /// 构建文件表格（表头 + 文件行 + 底部按钮）
  Widget _buildFileTable() {
    if (_files.isEmpty && !_scanning) {
      return const Padding(
        padding: EdgeInsets.only(top: 20),
        child: Center(
            child: Text('未找到私钥文件',
                style: TextStyle(color: AppColors.textLight, fontSize: 13))),
      );
    }

    final hasSelectable = _files.any((f) => !f.alreadyImported && f.error == null);

    return Expanded(
      child: Column(
        children: [
          // 表头
          _buildFileHeader(hasSelectable),
          const Divider(height: 1, color: AppColors.border),

          // 文件列表（可滚动）
          Expanded(
            child: _scanning
                ? const Center(child: CircularProgressIndicator(strokeWidth: 2))
                : ListView.builder(
                    itemCount: _files.length,
                    itemBuilder: (ctx, i) => _buildFileRow(_files[i]),
                  ),
          ),

          // 底部操作栏
          if (!_scanning && hasSelectable) ...[
            const Divider(height: 1, color: AppColors.border),
            Padding(
              padding: const EdgeInsets.only(top: 10),
              child: Row(children: [
                _buildButton(
                  '批量导入 (${_files.where((f) => f.isSelected && !f.alreadyImported).length})',
                  onTap: _busy ? null : _doFileImport,
                ),
              ]),
            ),
          ],
        ],
      ),
    );
  }

  /// 表头行
  Widget _buildFileHeader(bool hasSelectable) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(children: [
        // 全选复选框
        SizedBox(
          width: 34,
          child: Checkbox(
            value: _selectAll && hasSelectable,
            onChanged: hasSelectable ? (_) => _toggleSelectAll() : null,
            visualDensity: VisualDensity.compact,
            materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
          ),
        ),
        const SizedBox(width: 4),
        // 文件名
        const SizedBox(
            width: 150,
            child: Text('文件名',
                style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textSecondary))),
        // 类型
        const SizedBox(
            width: 80,
            child: Text('类型',
                style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textSecondary))),
        // 状态
        const SizedBox(
            width: 60,
            child: Text('状态',
                style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textSecondary))),
        // 密钥口令
        const Text('密钥口令',
            style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: AppColors.textSecondary)),
      ]),
    );
  }

  /// 单行文件条目
  Widget _buildFileRow(_SshFile file) {
    final passCtrl = _filePassCtrls[file.path];
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(children: [
        // 复选框
        SizedBox(
          width: 34,
          child: Checkbox(
            value: file.isSelected,
            onChanged: file.alreadyImported || file.error != null
                ? null
                : (v) => setState(() => file.isSelected = v ?? false),
            visualDensity: VisualDensity.compact,
            materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
          ),
        ),
        const SizedBox(width: 4),
        // 文件名
        SizedBox(
          width: 150,
          child: Tooltip(
            message: file.path,
            child: Text(file.name,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                    fontSize: 12,
                    color: file.alreadyImported || file.error != null
                        ? AppColors.textLight
                        : AppColors.textBody)),
          ),
        ),
        // 类型标签
        SizedBox(
          width: 80,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
                color: AppColors.tagBg, borderRadius: BorderRadius.circular(4)),
            child: Text(file.keyType,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                    fontSize: 11, color: AppColors.textSecondary)),
          ),
        ),
        // 状态标签
        SizedBox(
          width: 60,
          child: Text(
            file.error != null ? '异常' : file.alreadyImported ? '已导入' : '新文件',
            style: TextStyle(
                fontSize: 12,
                color: file.error != null ? AppColors.red : file.alreadyImported
                    ? AppColors.greenText
                    : AppColors.primary),
          ),
        ),
        // 密钥口令输入框
        if (file.error != null)
          Expanded(child: Tooltip(message: file.error!, child: Text(file.error!,
              maxLines: 1, overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 11, color: AppColors.red))))
        else if (passCtrl != null)
          SizedBox(
            width: 160,
            height: 28,
            child: TextField(
              controller: passCtrl,
              obscureText: true,
              style: const TextStyle(fontSize: 12),
              decoration: InputDecoration(
                hintText: '如有加密请填写',
                hintStyle:
                    const TextStyle(fontSize: 11, color: AppColors.textLight),
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(6),
                    borderSide: const BorderSide(color: AppColors.border)),
                enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(6),
                    borderSide: const BorderSide(color: AppColors.border)),
                focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(6),
                    borderSide: const BorderSide(color: AppColors.focusBorder)),
              ),
            ),
          ),
      ]),
    );
  }

  // ──────────────────────────────────────────────────────
  // Bitwarden 导入 UI
  // ──────────────────────────────────────────────────────

  Widget _buildBitwardenImport() {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      _FormRow(
          label: '服务器',
          child: SizedBox(
              width: 340,
              height: 32,
              child: _buildInput(_bwServerCtrl, 'https://vault.example.com'))),
      const SizedBox(height: 6),
      _FormRow(
          label: '邮箱',
          child: SizedBox(
              width: 340,
              height: 32,
              child: _buildInput(_bwEmailCtrl, 'user@example.com'))),
      const SizedBox(height: 6),
      _FormRow(
          label: '密码',
          child: SizedBox(
              width: 340,
              height: 32,
              child: _buildInput(_bwPasswordCtrl, '主密码', obscure: true))),
      const SizedBox(height: 14),
      _buildButton('登录并同步', onTap: _busy ? null : _doBwSync),
    ]);
  }

  // ──────────────────────────────────────────────────────
  // 通用组件
  // ──────────────────────────────────────────────────────

  Widget _buildInput(TextEditingController ctrl, String hint,
      {bool obscure = false, ValueChanged<String>? onSubmit}) {
    return TextField(
        controller: ctrl,
        obscureText: obscure,
        style: const TextStyle(fontSize: 13),
        onSubmitted: onSubmit,
        decoration: InputDecoration(
            hintText: hint,
            hintStyle:
                const TextStyle(fontSize: 13, color: AppColors.textLight),
            contentPadding: const EdgeInsets.symmetric(horizontal: 10),
            border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.border)),
            enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.border)),
            focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.focusBorder))));
  }

  Widget _buildButton(String label, {VoidCallback? onTap}) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        decoration: BoxDecoration(
            color: AppColors.primary, borderRadius: BorderRadius.circular(8)),
        child: _busy
            ? const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(
                    strokeWidth: 2, color: AppColors.white))
            : Text(label,
                style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: AppColors.white)),
      ),
    );
  }
}

// ──────────────────────────────────────────────────────────
// 私有辅助类
// ──────────────────────────────────────────────────────────

/// 文件导入标签页中的 SSH 文件条目
class _SshFile {
  final String name;
  final String path;
  final String keyType;
  final bool alreadyImported;
  final String? error;
  final bool needsPassphrase;
  bool isSelected;

  _SshFile({
    required this.name,
    required this.path,
    required this.keyType,
    this.alreadyImported = false,
    this.error,
    this.needsPassphrase = false,
    this.isSelected = true,
  });
}

class _FormRow extends StatelessWidget {
  final String label;
  final Widget child;
  const _FormRow({required this.label, required this.child});
  @override
  Widget build(BuildContext context) {
    return Row(children: [
      SizedBox(
          width: 80,
          child: Text(label,
              style: const TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: AppColors.textSecondary))),
      const SizedBox(width: 12),
      child
    ]);
  }
}

class _TabData {
  final IconData icon;
  final String label;
  const _TabData(this.icon, this.label);
}

