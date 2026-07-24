# sshkeygate TODO

## Current hardening

- [x] Queue concurrent signing confirmations so requests cannot overwrite each other.
- [x] Validate SSH Agent frame and field lengths and cap request size.
- [x] Bind trusted programs to configurable executable attributes (path is
      mandatory; modification time is enabled by default, SHA-256 is optional).
- [x] Disable permanent trust when the requesting process cannot be identified.
- [x] Capture executable modification time and SHA-256 when trusting a program.
- [x] Make password changes recoverable if secure-storage writes are interrupted.
- [x] Require stronger vault passwords and throttle failed unlock attempts.
- [x] Bound the on-disk audit log, not only the in-memory list.
- [x] Persist and honor the lock-on-screen-lock setting.
- [x] Handle widget disposal during asynchronous password operations.
- [x] Add regression tests for signing queues, malformed protocol messages,
      trusted executable replacement, and interrupted password changes.

## UX follow-up

- [x] Show the Agent running/locked state and pending request count in the main UI.
- [x] Explain once that closing the window keeps the Agent running in the tray.
- [x] Add a Lock action to the tray menu.
- [x] Add live Agent status/actions to the tray menu.
- [x] Improve import scan results for encrypted and unparseable key files.
- [x] Allow the desktop window to be resized.
- [x] Make fixed-width tables responsive at the minimum window size.
- [x] Normalize the remaining visible SSH terminology.
- [ ] Add localization support.

## Cross-platform (deferred)

- [ ] Replace the Windows named pipe with a Unix-domain socket transport on
      macOS/Linux and publish its path through `SSH_AUTH_SOCK`.
- [ ] Obtain peer PID/UID/path through `SO_PEERCRED` on Linux and peer
      credentials plus `proc_pidpath`/code-signing identity on macOS.
- [ ] Move Windows DLL loading behind conditional imports before enabling a
      non-Windows build.
- [ ] Implement lock-state providers for macOS workspace notifications and
      Linux systemd-logind/DBus.
- [ ] Add macOS LaunchAgent and Linux systemd-user/autostart integrations.
- [ ] Verify Keychain/libsecret availability and fail closed when secure
      storage is unavailable.
- [ ] Add `.icns`/PNG tray resources and verify menu-bar/AppIndicator behavior.
- [ ] Centralize platform data, log, socket, and startup paths.
- [ ] Add Windows, macOS, and Linux CI builds and integration tests.

## Current decisions

- Keep the vault PBKDF2 iteration count at 100,000 to avoid increasing unlock
  and decryption latency.
- Do not move signing into an isolate/native boundary for deterministic memory
  erasure.
- Keep the current Flutter and `dartssh2` versions; no dependency upgrade is
  planned.
