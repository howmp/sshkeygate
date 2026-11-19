package app

import (
	"fmt"
	"strings"

	"github.com/sshkeygate/sshkeygate/internal/vault"
)

// Language choices.
const (
	LangSystem  = "system"
	LangChinese = "zh"
	LangEnglish = "en"
)

// message is one string in the languages the app speaks.
type message struct {
	zh string
	en string
}

// messages holds every visible string. Keys are grouped by area.
var messages = map[string]message{
	// Navigation and shell.
	"app.name":       {"sshkeygate", "sshkeygate"},
	"nav.keys":       {"密钥列表", "Keys"},
	"nav.import":     {"导入密钥", "Import"},
	"nav.trusted":    {"信任程序", "Trusted apps"},
	"nav.settings":   {"配置", "Settings"},
	"nav.log":        {"日志", "Log"},
	"shell.lock":     {"锁定", "Lock"},
	"shell.agentUp":  {"Agent 运行中", "Agent running"},
	"shell.agentOff": {"Agent 已停止", "Agent stopped"},
	"shell.pending":  {"待处理 %d", "%d pending"},

	// Tray menu.
	"tray.agent":    {"Agent：%s", "Agent: %s"},
	"tray.vault":    {"密钥库：%s", "Vault: %s"},
	"tray.pending":  {"待处理签名：%d", "Pending signatures: %d"},
	"tray.show":     {"显示主窗口", "Show window"},
	"tray.lock":     {"锁定密钥库", "Lock vault"},
	"tray.quit":     {"退出", "Quit"},
	"tray.running":  {"运行中", "running"},
	"tray.stopped":  {"已停止", "stopped"},
	"tray.unlocked": {"已解锁", "unlocked"},
	"tray.locked":   {"已锁定", "locked"},

	// Unlock.
	"unlock.title":       {"解锁 sshkeygate", "Unlock sshkeygate"},
	"unlock.subtitle":    {"输入密码以访问密钥库", "Enter your password to open the vault"},
	"setup.title":        {"设置锁定密码", "Set a vault password"},
	"setup.subtitle":     {"此密码用于保护你的 SSH 私钥", "This password protects your SSH keys"},
	"unlock.password":    {"密码", "Password"},
	"unlock.confirm":     {"确认密码", "Confirm password"},
	"unlock.placeholder": {"至少 12 个字符", "At least 12 characters"},
	"unlock.repeat":      {"再次输入", "Enter it again"},
	"unlock.unlock":      {"解锁", "Unlock"},
	"unlock.create":      {"创建", "Create"},

	// Keys page.
	"keys.add":              {"添加", "Add"},
	"keys.addTip":           {"添加密钥", "Add a key"},
	"keys.empty":            {"暂无密钥", "No keys yet"},
	"keys.emptyHint":        {"到「导入密钥」页面添加", "Add one on the Import page"},
	"keys.copy":             {"复制", "Copy"},
	"keys.rename":           {"改名", "Rename"},
	"keys.delete":           {"删除", "Delete"},
	"keys.copyTip":          {"复制公钥", "Copy public key"},
	"keys.source.manual":    {"手动导入", "Imported"},
	"keys.source.bitwarden": {"Bitwarden", "Bitwarden"},

	// Import page.
	"import.tab.text":        {"从文本导入", "From text"},
	"import.tab.file":        {"从文件导入", "From files"},
	"import.tab.bitwarden":   {"从 Bitwarden 导入", "From Bitwarden"},
	"import.name":            {"名称", "Name"},
	"import.nameHint":        {"给密钥起个名字", "A name for this key"},
	"import.key":             {"私钥", "Private key"},
	"import.passphrase":      {"密钥口令", "Passphrase"},
	"import.passphraseHint":  {"如有加密请填写", "Fill in if encrypted"},
	"import.do":              {"导入", "Import"},
	"import.dropHint":        {"松开以导入私钥文件", "Release to import the key file"},
	"import.dir":             {"目录", "Folder"},
	"import.browse":          {"浏览", "Browse"},
	"import.scan":            {"扫描", "Scan"},
	"import.noFiles":         {"未找到私钥文件", "No private keys found"},
	"import.statusNew":       {"新文件", "New"},
	"import.statusImported":  {"已导入", "Imported"},
	"import.statusError":     {"异常", "Unreadable"},
	"import.statusEncrypted": {"加密密钥", "Encrypted"},
	"import.statusUnparsed":  {"无法解析", "Unrecognised"},
	"import.pickDir":         {"选择 SSH 密钥目录", "Choose the SSH key folder"},
	"import.phrase":          {"口令", "Passphrase"},
	"import.importSelected":  {"导入选中", "Import selected"},
	"import.selectHint":      {"勾选要导入的文件", "Tick the files to import"},
	"import.server":          {"服务器", "Server"},
	"import.email":           {"邮箱", "Email"},
	"import.masterPassword":  {"密码", "Password"},
	"import.masterHint":      {"主密码", "Master password"},
	"import.sync":            {"登录并同步", "Sign in and sync"},
	"import.syncHint": {"仅导入类型为 SSH Key 的条目，已存在的密钥会自动跳过",
		"Only SSH key items are imported; keys you already have are skipped"},

	// Trusted page.
	"trusted.intro": {"以下程序发起的签名请求将自动批准，无需弹窗确认。",
		"Requests from these programs are approved without asking."},
	"trusted.empty":     {"暂无信任程序", "No trusted programs"},
	"trusted.emptyHint": {"通过签名弹窗中「信任此程序」添加", "Add one from the signing prompt"},
	"trusted.mtime":     {"文件修改时间：%s", "Modified: %s"},
	"trusted.hash":      {"文件哈希：%s", "SHA-256: %s"},
	"trusted.missing":   {"未记录", "not recorded"},
	"trusted.remove":    {"移除", "Remove"},

	// Settings page.
	"settings.autostart":      {"开机自动启动", "Start at login"},
	"settings.autostartHint":  {"登录系统时自动运行 sshkeygate", "Run sshkeygate when you sign in"},
	"settings.lockOnLock":     {"锁屏自动锁定", "Lock when the screen locks"},
	"settings.lockOnLockHint": {"锁屏时清空内存中的密钥", "Clear keys from memory when the screen locks"},
	"settings.timeout":        {"签名确认超时", "Signing prompt timeout"},
	"settings.timeoutHint":    {"超时后自动拒绝签名请求", "Deny the request when it runs out"},
	"settings.seconds":        {"%d 秒", "%d s"},
	"settings.verify":         {"信任程序校验", "Trusted program checks"},
	"settings.verifyHint": {"路径始终作为程序身份标识；SHA-256 会读取整个文件。",
		"The path always identifies the program; SHA-256 reads the whole file."},
	"settings.verifyPath":         {"程序路径（必需）", "Path (required)"},
	"settings.verifyMtime":        {"最后修改时间", "Modification time"},
	"settings.verifySha":          {"SHA-256", "SHA-256"},
	"settings.changePassword":     {"修改锁定密码", "Change vault password"},
	"settings.changePasswordHint": {"更改用于保护密钥库的密码", "Change the password that protects the vault"},
	"settings.change":             {"修改", "Change"},
	"settings.openData":           {"打开数据目录", "Open data folder"},
	"settings.dataHint": {"密钥数据受密码 + 设备密钥双重保护，离开此设备后文件无法解密",
		"Keys are protected by your password and this device's key; the files cannot be decrypted elsewhere"},
	"settings.endpoint":     {"Agent 地址：%s", "Agent endpoint: %s"},
	"settings.appearance":   {"外观", "Appearance"},
	"settings.theme":        {"主题", "Theme"},
	"settings.themeHint":    {"选择整个应用的配色", "The colours of the whole app"},
	"settings.themeSystem":  {"跟随系统", "System"},
	"settings.themeLight":   {"浅色", "Light"},
	"settings.themeDark":    {"深色", "Dark"},
	"settings.language":     {"语言", "Language"},
	"settings.languageHint": {"界面文字的语言", "The language of the interface"},
	"settings.langSystem":   {"跟随系统", "System"},
	"settings.langZh":       {"中文", "中文"},
	"settings.langEn":       {"English", "English"},

	// Log page.
	"log.title":   {"签名请求日志", "Signing log"},
	"log.clear":   {"清除", "Clear"},
	"log.empty":   {"暂无日志", "No entries yet"},
	"log.time":    {"时间", "Time"},
	"log.action":  {"动作", "Action"},
	"log.reason":  {"原因", "Reason"},
	"log.key":     {"密钥", "Key"},
	"log.process": {"程序", "Program"},
	"log.allowed": {"允许", "Allowed"},
	"log.denied":  {"拒绝", "Denied"},

	// Signing prompt.
	"confirm.title":     {"是否允许本次签名请求？", "Allow this signature?"},
	"confirm.pending":   {"待处理请求：%d", "Waiting: %d"},
	"confirm.key":       {"密钥：%s", "Key: %s"},
	"confirm.source":    {"来源：%s (PID %d)", "From: %s (PID %d)"},
	"confirm.unknown":   {"无法识别", "unidentified"},
	"confirm.deny":      {"拒绝", "Deny"},
	"confirm.allowOnce": {"允许本次", "Allow once"},
	"confirm.trust":     {"信任此程序", "Trust this program"},

	// Dialogs.
	"rename.title":     {"编辑密钥名称", "Rename key"},
	"dialog.cancel":    {"取消", "Cancel"},
	"dialog.ok":        {"确定", "OK"},
	"password.current": {"当前密码", "Current password"},
	"password.new":     {"新密码", "New password"},
	"password.confirm": {"确认新密码", "Confirm new password"},
	"password.ok":      {"确认", "Confirm"},
	"trayHint.title":   {"已最小化到系统托盘", "Still running in the tray"},
	"trayHint.body": {"关闭主窗口不会退出 SSH Agent。你可以从系统托盘重新打开或退出程序。",
		"Closing the window does not stop the SSH agent. Open it again or quit from the tray."},
	"trayHint.ok": {"知道了", "Got it"},

	// Statuses and errors.
	"status.created":     {"已创建并解锁", "Vault created"},
	"status.unlocked":    {"已解锁", "Unlocked"},
	"status.locked":      {"已锁定", "Locked"},
	"status.creating":    {"正在创建密钥库…", "Creating the vault…"},
	"status.unlocking":   {"正在解锁…", "Unlocking…"},
	"status.deleted":     {"已删除密钥", "Key deleted"},
	"status.renamed":     {"已重命名", "Renamed"},
	"status.copied":      {"公钥已复制", "Public key copied"},
	"status.imported":    {"导入成功", "Key imported"},
	"status.duplicate":   {"该密钥已存在", "That key is already here"},
	"status.scanning":    {"正在扫描…", "Scanning…"},
	"status.scanDone":    {"扫描完成：共 %d 个，加密 %d，异常 %d", "Scanned %d files: %d encrypted, %d unreadable"},
	"status.importing":   {"正在导入…", "Importing…"},
	"status.importDone":  {"导入完成：成功 %d，失败 %d", "Imported %d, failed %d"},
	"status.noSelection": {"没有可导入的选中文件", "No files selected"},
	"status.signingIn":   {"正在登录 Bitwarden…", "Signing in to Bitwarden…"},
	"status.syncDone":    {"同步完成：导入 %d，跳过 %d", "Synced: imported %d, skipped %d"},
	"status.changingPwd": {"正在修改密码…", "Changing the password…"},
	"status.pwdChanged":  {"密码已修改", "Password changed"},
	"status.untrusted":   {"已移除信任程序", "Trusted program removed"},

	"err.minPassword":   {"密码至少 %d 个字符", "Use at least %d characters"},
	"err.mismatch":      {"两次输入的密码不一致", "The passwords do not match"},
	"err.createFailed":  {"创建失败：%s", "Could not create the vault: %s"},
	"err.wrongPassword": {"密码错误", "Wrong password"},
	"err.deleteFailed":  {"删除失败：%s", "Could not delete: %s"},
	"err.opFailed":      {"操作失败：%s", "Failed: %s"},
	"err.renameFailed":  {"重命名失败：%s", "Could not rename: %s"},
	"err.pasteKey":      {"请粘贴私钥文本", "Paste a private key first"},
	"err.badKeyText":    {"导入失败：私钥文本格式无效", "Import failed: that is not a private key"},
	"err.importFailed":  {"导入失败：%s", "Import failed: %s"},
	"err.noDir":         {"请填写目录", "Choose a folder first"},
	"err.scanFailed":    {"扫描失败：%s", "Could not scan: %s"},
	"err.fillServer":    {"请填写服务器地址、邮箱和密码", "Fill in the server, email and password"},
	"err.syncFailed":    {"同步失败：%s", "Sync failed: %s"},
	"err.saveSettings":  {"保存设置失败：%s", "Could not save: %s"},
	"err.autoStart":     {"设置开机启动失败：%s", "Could not change start at login: %s"},
	"err.pwdWrong":      {"修改失败：当前密码错误", "Could not change it: the current password is wrong"},
	"err.pwdFailed":     {"修改失败：%s", "Could not change it: %s"},
	"err.untrustFailed": {"移除失败：%s", "Could not remove it: %s"},
	"err.clearLog":      {"清除日志失败：%s", "Could not clear the log: %s"},
	"err.openData":      {"无法打开数据目录：%s", "Could not open the data folder: %s"},
	"err.agentFailed":   {"Agent 启动失败：%s", "The agent failed to start: %s"},
	"err.trustFailed":   {"信任失败：%s", "Could not trust it: %s"},
}

// resolveLanguage picks the language to show, following the system when the
// user has not chosen one.
func (a *App) resolveLanguage() string {
	switch a.language {
	case LangChinese:
		return LangChinese
	case LangEnglish:
		return LangEnglish
	}
	if strings.HasPrefix(strings.ToLower(a.systemLocale), "zh") {
		return LangChinese
	}
	return LangEnglish
}

// t returns the string for key in the shown language.
func (a *App) t(key string) string {
	m, ok := messages[key]
	if !ok {
		return key
	}
	if a.resolveLanguage() == LangChinese {
		return m.zh
	}
	return m.en
}

// tf returns the string for key with its arguments filled in.
func (a *App) tf(key string, args ...any) string {
	format := a.t(key)
	// Both languages use the same verbs, so either format works.
	return fmt.Sprintf(format, args...)
}

// setLanguage stores the choice and repaints.
func (a *App) setLanguage(lang string) {
	a.language = lang
	a.persistPrefs()
	if a.Vault.IsUnlocked() {
		a.UpdateSettings(func(s *vault.Settings) { s.Language = lang })
	}
	a.refreshTray()
	a.notify()
}
