# SPIKE-003 — Chrome MV3 notification lifecycle

Status: core lifecycle behavior validated on Windows Chrome

## Safety boundary

This spike creates extension-local test notifications only. A `request-remote-dismiss` decision is recorded for inspection but is not sent to any server or Android device.

## Implemented

- Pure close-decision policy with unit tests
- Remote dismiss only when `byUser === true` and no programmatic marker exists
- Conservative ignore for ambiguous non-user closes
- Persistent programmatic-close marker written before `chrome.notifications.clear`
- Marker consumption and five-minute stale-marker cleanup
- Persistent close audit for popup inspection
- Worker start counter to observe MV3 suspension/restart
- Local test notification and programmatic-clear controls

## Manual verification

1. Build and load `dist/` as an unpacked extension.
2. Open the popup and create a lifecycle test notification.
3. Manually close it in the operating-system notification center.
4. Confirm the popup reports `request-remote-dismiss`, `byUser: true`, and no marker.
5. Create another test notification and click **Clear programmatically**.
6. Confirm the popup reports `ignore-programmatic` and a consumed marker.
7. Reload the extension between tests and confirm the worker start count increases without losing the audit.
8. Let Chrome suspend the worker, then repeat creation/clear and verify the same policy.
9. Close Chrome or let the OS remove a notification and confirm uncertain events never request remote deletion.

## Validation result

- Type check, unit tests and production build: passed
- GitHub Actions: passed
- Developer-mode load on Windows Chrome: passed
- Manual close: `byUser = true`, decision `request-remote-dismiss`
- Programmatic clear: marker consumed, decision `ignore-programmatic`
- Observed behavior matched all expected results

## Follow-up evidence

- Long-duration automatic Worker suspension test
- Browser exit/OS notification-center cleanup behavior
- Decision on WebSocket keepalive versus alarm/pull fallback
