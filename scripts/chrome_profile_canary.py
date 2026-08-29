#!/usr/bin/env python3
"""Scan an isolated real Chromium extension profile for sensitive-data canaries.

This is a release-review tool, not a unit test. It launches the production dist/
in headless Cent Browser, attaches to the MV3 Worker through CDP, exercises real
browser IndexedDB/WebCrypto/chrome.storage/chrome.notifications APIs, restarts the
browser, and scans the closed profile export. The generated secrets and business
canaries are never written to the JSON report.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from typing import Any

try:
    import websocket
except ImportError as error:  # pragma: no cover - local tool prerequisite
    raise SystemExit("websocket-client is required: python -m pip install websocket-client") from error


EXTENSION_ID = "onkfgdniiifdflginmjggfaccomeneho"
EXPECTED_INDEXEDDB_FRAGMENT = (
    f"IndexedDB/chrome-extension_{EXTENSION_ID}_0.indexeddb.leveldb"
)


@dataclass
class BrowserRun:
    process: subprocess.Popen[bytes]
    worker: "CdpConnection"
    stdout_file: Any
    stderr_file: Any
    port: int


class CdpConnection:
    def __init__(self, url: str) -> None:
        self.socket = websocket.create_connection(
            url,
            timeout=15,
            suppress_origin=True,
        )
        self.next_id = 1
        self.console_events = 0
        self.exception_events = 0
        self.log_events = 0
        self.diagnostic_texts: list[str] = []

    def command(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        command_id = self.next_id
        self.next_id += 1
        self.socket.send(json.dumps({
            "id": command_id,
            "method": method,
            **({} if params is None else {"params": params}),
        }))
        while True:
            message = json.loads(self.socket.recv())
            self._observe_event(message)
            if message.get("id") == command_id:
                if "error" in message:
                    raise RuntimeError(f"CDP {method} failed: {message['error']}")
                return message

    def _observe_event(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        if method == "Runtime.consoleAPICalled":
            self.console_events += 1
            for argument in message.get("params", {}).get("args", []):
                value = argument.get("value", argument.get("description"))
                if value is not None:
                    self.diagnostic_texts.append(str(value))
        elif method == "Runtime.exceptionThrown":
            self.exception_events += 1
            details = message.get("params", {}).get("exceptionDetails", {})
            self.diagnostic_texts.append(str(details.get("text", "")))
            description = details.get("exception", {}).get("description")
            if description is not None:
                self.diagnostic_texts.append(str(description))
        elif method == "Log.entryAdded":
            self.log_events += 1
            entry = message.get("params", {}).get("entry", {})
            self.diagnostic_texts.extend([
                str(entry.get("text", "")),
                str(entry.get("url", "")),
            ])

    def drain_events(self, duration_seconds: float = 0.5) -> None:
        deadline = time.monotonic() + duration_seconds
        self.socket.settimeout(min(0.1, duration_seconds))
        try:
            while time.monotonic() < deadline:
                try:
                    self._observe_event(json.loads(self.socket.recv()))
                except websocket.WebSocketTimeoutException:
                    continue
        finally:
            self.socket.settimeout(15)

    def evaluate(self, expression: str) -> Any:
        response = self.command("Runtime.evaluate", {
            "expression": expression,
            "awaitPromise": True,
            "returnByValue": True,
        })
        result = response.get("result", {})
        if "exceptionDetails" in result:
            description = result.get("result", {}).get("description", "JavaScript evaluation failed")
            raise RuntimeError(description)
        return result.get("result", {}).get("value")

    def close(self) -> None:
        self.socket.close()


def parse_args() -> argparse.Namespace:
    script = pathlib.Path(__file__).resolve()
    repository = script.parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--browser",
        type=pathlib.Path,
        default=pathlib.Path(r"C:\Neko7ina\Cent Browser\chrome.exe"),
    )
    parser.add_argument(
        "--extension-dir",
        type=pathlib.Path,
        default=repository / "dist",
    )
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--keep-profile", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser.parse_args()


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def fetch_json(url: str, timeout: float = 1.0) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.load(response)


def start_browser(
    browser: pathlib.Path,
    extension_dir: pathlib.Path,
    profile: pathlib.Path,
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    timeout_seconds: int,
) -> BrowserRun:
    port = free_local_port()
    stdout_file = stdout_path.open("ab")
    stderr_file = stderr_path.open("ab")
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        [
            str(browser),
            "--headless=new",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            f"--disable-extensions-except={extension_dir}",
            f"--load-extension={extension_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
        ],
        stdout=stdout_file,
        stderr=stderr_file,
        creationflags=creation_flags,
    )
    deadline = time.monotonic() + timeout_seconds
    target: dict[str, Any] | None = None
    while time.monotonic() < deadline and process.poll() is None:
        try:
            targets = fetch_json(f"http://127.0.0.1:{port}/json")
            target = next(
                (item for item in targets if item.get("type") == "service_worker"
                 and item.get("url", "").endswith("/background/service-worker.js")),
                None,
            )
            if target is not None:
                break
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    if target is None:
        stop_process_tree(process)
        stdout_file.close()
        stderr_file.close()
        raise RuntimeError("Production MV3 Worker did not appear before the timeout")
    worker = CdpConnection(target["webSocketDebuggerUrl"])
    worker.command("Runtime.enable")
    try:
        worker.command("Log.enable")
    except RuntimeError:
        # Runtime console/exception events remain available if this target omits Log.
        pass
    return BrowserRun(process, worker, stdout_file, stderr_file, port)


def stop_browser(run: BrowserRun) -> None:
    run.worker.close()
    try:
        version = fetch_json(f"http://127.0.0.1:{run.port}/json/version")
        browser = CdpConnection(version["webSocketDebuggerUrl"])
        try:
            browser.command("Browser.close")
        except (RuntimeError, websocket.WebSocketException):
            pass
        finally:
            try:
                browser.close()
            except websocket.WebSocketException:
                pass
    except (OSError, ValueError, KeyError, websocket.WebSocketException):
        pass
    try:
        run.process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        stop_process_tree(run.process)
    run.stdout_file.close()
    run.stderr_file.close()


def stop_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def seed_expression() -> str:
    return r"""
(async () => {
  const openDatabase = (name, version, upgrade) => new Promise((resolve, reject) => {
    const request = indexedDB.open(name, version);
    request.onupgradeneeded = () => upgrade(request.result, request.transaction);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error(`open failed: ${name}`));
  });
  const transactionDone = (transaction) => new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error('transaction aborted'));
    transaction.onerror = () => reject(transaction.error ?? new Error('transaction failed'));
  });
  const put = async (database, storeName, value, key) => {
    const transaction = database.transaction(storeName, 'readwrite');
    const done = transactionDone(transaction);
    if (key === undefined) transaction.objectStore(storeName).put(value);
    else transaction.objectStore(storeName).put(value, key);
    await done;
  };
  const randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));
  const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const suffix = hex(randomBytes(12));
  const currentToken = randomBytes(32);
  const pendingToken = randomBytes(32);
  while (currentToken.every((byte, index) => byte === pendingToken[index])) {
    crypto.getRandomValues(pendingToken);
  }
  const title = `CHROME_PROFILE_TITLE_${suffix}`;
  const body = `CHROME_PROFILE_BODY_${suffix}`;
  const reply = `CHROME_PROFILE_REPLY_${suffix}`;
  const notificationId = `profile.canary/${suffix}`;
  const chromeNotificationId = `sn1:profile-canary:${suffix}`;
  const sourceDeviceId = randomBytes(16);
  const actionId = randomBytes(16);
  const identity = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', identity.publicKey));
  const identityKeyId = await sha256(publicKey);

  const identityDb = await openDatabase('syncnotifications-crypto-v1', 1, (database) => {
    if (!database.objectStoreNames.contains('identities')) database.createObjectStore('identities');
  });
  await put(identityDb, 'identities', identity, 'primary-hpke-auth-v1');
  identityDb.close();

  const credentialDb = await openDatabase('syncnotifications-transport-v1', 1, (database) => {
    if (!database.objectStoreNames.contains('credentials')) {
      database.createObjectStore('credentials', { keyPath: 'id' });
    }
  });
  await put(credentialDb, 'credentials', {
    id: 'primary-transport-v1',
    serverOrigin: 'http://127.0.0.1:9',
    workspaceId: randomBytes(16),
    deviceId: randomBytes(16),
    authToken: currentToken,
    identityKeyId,
    pendingAuthToken: pendingToken,
    rotationPhase: 'attempted',
  });
  credentialDb.close();

  const notificationDb = await openDatabase('syncnotifications-notification-state-v1', 2, (database) => {
    if (!database.objectStoreNames.contains('notification-state')) {
      database.createObjectStore('notification-state', { keyPath: 'tuple' });
    }
    if (!database.objectStoreNames.contains('notification-snapshot')) {
      database.createObjectStore('notification-snapshot', { keyPath: 'sourceKey' });
    }
  });
  await put(notificationDb, 'notification-state', {
    tuple: `${hex(sourceDeviceId)}:${notificationId}`,
    sourceDeviceId,
    notificationId,
    chromeNotificationId,
    revision: '1',
    phase: 'visible',
    payloadSha256: await sha256(new TextEncoder().encode(`${title}\u0000${body}`)),
    sourceApplicationId: 'sevenmirror.profile.canary',
    sourceApplicationName: 'SevenMirror profile canary',
    title,
    body,
    actions: [{
      actionId,
      title: 'Reply',
      requiresTextInput: true,
      allowsFreeFormInput: true,
    }],
  });
  notificationDb.close();

  const pendingDb = await openDatabase('syncnotifications-pending-actions-default', 1, (database) => {
    if (!database.objectStoreNames.contains('pending-action')) {
      const store = database.createObjectStore('pending-action', { keyPath: 'idempotencyKey' });
      store.createIndex('by-expiry', 'expiresAtUnixMs', { unique: false });
    }
  });
  const now = Date.now();
  await put(pendingDb, 'pending-action', {
    idempotencyKey: hex(randomBytes(16)),
    senderDeviceId: hex(sourceDeviceId),
    operationDigest: hex(await sha256(new TextEncoder().encode(reply))),
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 30 * 24 * 60 * 60 * 1000,
    state: 'pending',
    canonicalInvokePayload: new TextEncoder().encode(reply),
    recipientKeyId: randomBytes(32),
    nextAttemptAtUnixMs: now,
    invokeAttemptCount: 0,
    invokeDeliveryMode: 'once',
  });
  pendingDb.close();

  const notificationCreated = await new Promise((resolve, reject) => {
    chrome.notifications.create(chromeNotificationId, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/notification.png'),
      title,
      message: body,
      priority: 0,
    }, (createdId) => {
      const error = chrome.runtime.lastError;
      if (error) reject(new Error(error.message));
      else resolve(createdId);
    });
  });
  const nativeNotifications = await new Promise((resolve) => chrome.notifications.getAll(resolve));
  const storage = await chrome.storage.local.get(null);
  const interactionUrl = `${chrome.runtime.getURL('interaction/index.html')}?notification=${encodeURIComponent(chromeNotificationId)}`;
  let privateExportRejected = false;
  try {
    await crypto.subtle.exportKey('pkcs8', identity.privateKey);
  } catch {
    privateExportRejected = true;
  }
  return {
    currentToken: Array.from(currentToken),
    pendingToken: Array.from(pendingToken),
    currentTokenDigest: hex(await sha256(currentToken)),
    pendingTokenDigest: hex(await sha256(pendingToken)),
    publicKeyDigest: hex(await sha256(publicKey)),
    title,
    body,
    reply,
    chromeNotificationId,
    notificationCreated,
    nativeNotificationPresent: Object.hasOwn(nativeNotifications, chromeNotificationId),
    privateKeyExtractable: identity.privateKey.extractable,
    privateExportRejected,
    storage,
    interactionUrl,
  };
})()
"""


def inspect_expression() -> str:
    return r"""
(async () => {
  const open = (name) => new Promise((resolve, reject) => {
    const request = indexedDB.open(name);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error(`open failed: ${name}`));
  });
  const get = async (databaseName, storeName, key) => {
    const database = await open(databaseName);
    try {
      const transaction = database.transaction(storeName, 'readonly');
      const request = transaction.objectStore(storeName).get(key);
      return await new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error('get failed'));
      });
    } finally {
      database.close();
    }
  };
  const first = async (databaseName, storeName) => {
    const database = await open(databaseName);
    try {
      const transaction = database.transaction(storeName, 'readonly');
      const request = transaction.objectStore(storeName).getAll();
      const values = await new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error('getAll failed'));
      });
      return values[0];
    } finally {
      database.close();
    }
  };
  const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  const sha256Hex = async (bytes) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
  const identity = await get(
    'syncnotifications-crypto-v1', 'identities', 'primary-hpke-auth-v1');
  const credential = await get(
    'syncnotifications-transport-v1', 'credentials', 'primary-transport-v1');
  const notification = await first(
    'syncnotifications-notification-state-v1', 'notification-state');
  const action = await first(
    'syncnotifications-pending-actions-default', 'pending-action');
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', identity.publicKey));
  let privateExportRejected = false;
  try {
    await crypto.subtle.exportKey('pkcs8', identity.privateKey);
  } catch {
    privateExportRejected = true;
  }
  const nativeNotificationId = notification.chromeNotificationId;
  await new Promise((resolve, reject) => {
    chrome.notifications.create(nativeNotificationId, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/notification.png'),
      title: notification.title,
      message: notification.body,
      priority: 0,
    }, () => {
      const error = chrome.runtime.lastError;
      if (error) reject(new Error(error.message));
      else resolve();
    });
  });
  const nativeNotifications = await new Promise((resolve) => chrome.notifications.getAll(resolve));
  const storage = await chrome.storage.local.get(null);
  return {
    currentTokenDigest: await sha256Hex(credential.authToken),
    pendingTokenDigest: await sha256Hex(credential.pendingAuthToken),
    publicKeyDigest: await sha256Hex(publicKey),
    privateKeyExtractable: identity.privateKey.extractable,
    privateExportRejected,
    title: notification.title,
    body: notification.body,
    reply: new TextDecoder().decode(action.canonicalInvokePayload),
    notificationPhase: notification.phase,
    invokeDeliveryMode: action.invokeDeliveryMode,
    storage,
    nativeNotificationPresent: Object.hasOwn(nativeNotifications, nativeNotificationId),
    interactionUrl: `${chrome.runtime.getURL('interaction/index.html')}?notification=${encodeURIComponent(nativeNotificationId)}`,
  };
})()
"""


def encoded_variants(value: bytes) -> dict[str, bytes]:
    return {
        "standard_base64": base64.b64encode(value),
        "unpadded_base64url": base64.urlsafe_b64encode(value).rstrip(b"="),
    }


def scan_files(root: pathlib.Path, needles: dict[str, bytes]) -> tuple[dict[str, list[str]], int]:
    matches = {name: [] for name in needles}
    scanned_bytes = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        scanned_bytes += len(data)
        relative = path.relative_to(root).as_posix()
        for name, needle in needles.items():
            if needle and needle in data:
                matches[name].append(relative)
    return matches, scanned_bytes


def contains_value(value: Any, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, list):
        return any(contains_value(item, needle) for item in value)
    if isinstance(value, dict):
        return any(contains_value(item, needle) for item in value.values())
    return False


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def diagnostic_forbidden_matches(connection: CdpConnection, seeded: dict[str, Any]) -> int:
    current_token = bytes(seeded["currentToken"])
    pending_token = bytes(seeded["pendingToken"])
    forbidden = [
        current_token.hex(),
        pending_token.hex(),
        base64.b64encode(current_token).decode(),
        base64.urlsafe_b64encode(current_token).rstrip(b"=").decode(),
        base64.b64encode(pending_token).decode(),
        base64.urlsafe_b64encode(pending_token).rstrip(b"=").decode(),
        seeded["title"],
        seeded["body"],
        seeded["reply"],
    ]
    return sum(
        1
        for diagnostic in connection.diagnostic_texts
        for needle in forbidden
        if needle and needle in diagnostic
    )


def redacted_runtime_summary(run: BrowserRun) -> dict[str, int]:
    return {
        "console_events": run.worker.console_events,
        "exception_events": run.worker.exception_events,
        "log_events": run.worker.log_events,
    }


def main() -> int:
    args = parse_args()
    browser = args.browser.resolve()
    extension_dir = args.extension_dir.resolve()
    require(browser.is_file(), f"Browser not found: {browser}")
    require((extension_dir / "manifest.json").is_file(), "Production dist/ is missing")
    manifest = json.loads((extension_dir / "manifest.json").read_text(encoding="utf-8"))
    require(manifest.get("manifest_version") == 3, "The scanned build is not Manifest V3")

    workspace = pathlib.Path(tempfile.mkdtemp(prefix="sevenmirror-chrome-profile-canary-"))
    profile = workspace / "profile"
    stdout_path = workspace / "browser.stdout.log"
    stderr_path = workspace / "browser.stderr.log"
    report: dict[str, Any] = {
        "schema_version": 1,
        "browser": str(browser),
        "extension_version": manifest.get("version"),
        "extension_id": EXTENSION_ID,
        "headless": True,
        "result": "failed",
    }
    run: BrowserRun | None = None
    secret_values: list[str] = []
    try:
        run = start_browser(
            browser, extension_dir, profile, stdout_path, stderr_path, args.timeout_seconds)
        seeded = run.worker.evaluate(seed_expression())
        require(isinstance(seeded, dict), "Canary seeding returned no structured result")
        run.worker.drain_events()
        first_runtime = redacted_runtime_summary(run)
        require(diagnostic_forbidden_matches(run.worker, seeded) == 0,
                "A credential or business canary entered Worker diagnostics")
        require(seeded["notificationCreated"] == seeded["chromeNotificationId"],
                "chrome.notifications returned a different notification ID")
        require(seeded["nativeNotificationPresent"], "Native notification was not active")
        require(not seeded["privateKeyExtractable"], "Generated HPKE private key is extractable")
        require(seeded["privateExportRejected"], "Generated HPKE private key export succeeded")
        for canary in (seeded["title"], seeded["body"], seeded["reply"]):
            require(not contains_value(seeded["storage"], canary),
                    "Business canary entered chrome.storage")
            require(canary not in seeded["interactionUrl"],
                    "Business canary entered the interaction URL")
        stop_browser(run)
        run = None

        run = start_browser(
            browser, extension_dir, profile, stdout_path, stderr_path, args.timeout_seconds)
        restored = run.worker.evaluate(inspect_expression())
        require(isinstance(restored, dict), "Restart inspection returned no structured result")
        run.worker.drain_events()
        second_runtime = redacted_runtime_summary(run)
        require(diagnostic_forbidden_matches(run.worker, seeded) == 0,
                "A credential or business canary entered restart diagnostics")
        require(restored["currentTokenDigest"] == seeded["currentTokenDigest"],
                "Current transport token changed across browser restart")
        require(restored["pendingTokenDigest"] == seeded["pendingTokenDigest"],
                "Pending transport token changed across browser restart")
        require(restored["publicKeyDigest"] == seeded["publicKeyDigest"],
                "HPKE identity changed across browser restart")
        require(not restored["privateKeyExtractable"],
                "Restored HPKE private key became extractable")
        require(restored["privateExportRejected"],
                "Restored HPKE private key export succeeded")
        require(restored["title"] == seeded["title"], "Notification title did not persist")
        require(restored["body"] == seeded["body"], "Notification body did not persist")
        require(restored["reply"] == seeded["reply"], "Reply payload did not persist")
        require(restored["notificationPhase"] == "visible", "Notification state was not visible")
        require(restored["invokeDeliveryMode"] == "once", "Reply state lost one-shot mode")
        require(restored["nativeNotificationPresent"],
                "Native notification API did not accept restored presentation state")
        for canary in (seeded["title"], seeded["body"], seeded["reply"]):
            require(not contains_value(restored["storage"], canary),
                    "Business canary entered chrome.storage after restart")
            require(canary not in restored["interactionUrl"],
                    "Business canary entered the interaction URL after restart")
        stop_browser(run)
        run = None

        current_token = bytes(seeded["currentToken"])
        pending_token = bytes(seeded["pendingToken"])
        secret_values = [
            current_token.hex(),
            pending_token.hex(),
            seeded["title"],
            seeded["body"],
            seeded["reply"],
        ]
        needles: dict[str, bytes] = {
            "current_token_raw": current_token,
            "pending_token_raw": pending_token,
            "title_plaintext": seeded["title"].encode(),
            "body_plaintext": seeded["body"].encode(),
            "reply_plaintext": seeded["reply"].encode(),
        }
        for prefix, token in (("current_token", current_token), ("pending_token", pending_token)):
            for variant, encoded in encoded_variants(token).items():
                needles[f"{prefix}_{variant}"] = encoded
        matches, scanned_bytes = scan_files(workspace, needles)
        for name in ("current_token_raw", "pending_token_raw"):
            require(matches[name], f"Expected durable {name} was absent from the profile export")
            require(all(EXPECTED_INDEXEDDB_FRAGMENT in path for path in matches[name]),
                    f"{name} appeared outside the extension IndexedDB profile area")
        for name in (
            "current_token_standard_base64",
            "current_token_unpadded_base64url",
            "pending_token_standard_base64",
            "pending_token_unpadded_base64url",
        ):
            require(not matches[name], f"Encoded credential leaked into the profile export: {name}")
        for name in ("title_plaintext", "body_plaintext", "reply_plaintext"):
            require(matches[name], f"Expected endpoint-local plaintext was absent: {name}")
            require(all(EXPECTED_INDEXEDDB_FRAGMENT in path for path in matches[name]),
                    f"Endpoint-local plaintext appeared outside extension IndexedDB: {name}")

        require(first_runtime["console_events"] == 0, "Console output occurred during canary seeding")
        require(first_runtime["exception_events"] == 0,
                "Uncaught Worker exception occurred during canary seeding")
        require(second_runtime["console_events"] == 0,
                "Console output occurred during restart inspection")
        require(second_runtime["exception_events"] == 0,
                "Uncaught Worker exception occurred during restart inspection")

        report.update({
            "result": "passed",
            "runtime": {
                "first_run": first_runtime,
                "restart": second_runtime,
                "native_notification_present": True,
                "hpke_private_key_non_extractable_after_restart": True,
                "chrome_storage_forbidden_matches": 0,
                "interaction_url_forbidden_matches": 0,
                "diagnostic_forbidden_matches": 0,
            },
            "profile_export": {
                "scanned_bytes": scanned_bytes,
                "scanned_root_removed_after_test": not args.keep_profile,
                "credential_raw_match_files": {
                    "current": len(matches["current_token_raw"]),
                    "pending": len(matches["pending_token_raw"]),
                },
                "credential_encoded_match_files": 0,
                "expected_business_plaintext_match_files": {
                    "title": len(matches["title_plaintext"]),
                    "body": len(matches["body_plaintext"]),
                    "reply": len(matches["reply_plaintext"]),
                },
                "all_sensitive_matches_confined_to_extension_indexeddb": True,
            },
            "limitations": [
                "Cent Browser headless mode blocks extension HTML pages with ERR_BLOCKED_BY_CLIENT; interaction DOM rendering remains open.",
                "The scan does not inspect process memory, crash dumps, OS notification history, browser sync, backup, IME history, screenshots, or screen recording.",
                "Canary records are seeded with the production schema through browser APIs; registration and authenticated notification delivery are covered by separate end-to-end evidence.",
            ],
        })
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0
    except Exception as error:
        message = str(error)
        for secret in secret_values:
            message = message.replace(secret, "[REDACTED]")
        report["error"] = message
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Chrome profile canary failed: {message}", file=sys.stderr)
        return 1
    finally:
        if run is not None:
            try:
                stop_browser(run)
            except Exception:
                stop_process_tree(run.process)
                run.stdout_file.close()
                run.stderr_file.close()
        if args.keep_profile:
            print(f"Sensitive canary profile retained by explicit request: {workspace}", file=sys.stderr)
        else:
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
