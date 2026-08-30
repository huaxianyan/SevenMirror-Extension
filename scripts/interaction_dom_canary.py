#!/usr/bin/env python3
"""Exercise the production interaction page in an isolated non-headless browser."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
from typing import Any

from chrome_profile_canary import CdpConnection, fetch_json, free_local_port, stop_process_tree


def parse_args() -> argparse.Namespace:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", type=Path)
    parser.add_argument("--extension-dir", type=Path, default=repository / "dist")
    parser.add_argument(
        "--membership-vector",
        type=Path,
        default=repository / "protocol" / "test-vectors" / "workspace-membership-v1.json",
    )
    parser.add_argument(
        "--worker-fixture",
        type=Path,
        default=repository / "scripts" / "interaction-worker-fixture.json",
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep-profile", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser.parse_args()


def default_browser() -> Path:
    if os.name == "nt":
        return Path(r"C:\Neko7ina\Cent Browser\chrome.exe")
    for candidate in ("google-chrome", "chromium", "chromium-browser"):
        resolved = shutil.which(candidate)
        if resolved is not None:
            return Path(resolved)
    raise RuntimeError("A Chromium browser is required")


def browser_command(browser: Path, arguments: list[str]) -> list[str]:
    if os.name != "nt" and not os.environ.get("DISPLAY"):
        xvfb = shutil.which("xvfb-run")
        if xvfb is None:
            raise RuntimeError("xvfb-run is required for a non-headless Linux check")
        return [xvfb, "--auto-servernum", "--server-args=-screen 0 1280x800x24", str(browser), *arguments]
    return [str(browser), *arguments]


def wait_for_page(port: int, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            targets = fetch_json(f"http://127.0.0.1:{port}/json")
            page = next((target for target in targets if target.get("type") == "page"), None)
            if page is not None:
                return page
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError("Browser page did not appear before timeout")


def discover_extension_id(
    page: CdpConnection,
    extension_dir: Path,
    timeout_seconds: int,
) -> str:
    page.command("Page.navigate", {"url": "chrome://extensions-internals"})
    encoded = evaluate_until(page, """
(() => {
  const text = document.body?.innerText?.trim();
  return text?.startsWith('[') ? text : false;
})()
""", timeout_seconds)
    extensions = json.loads(encoded)
    expected_path = os.path.normcase(str(extension_dir.resolve()))
    matches = [entry for entry in extensions
        if entry.get("location") == "COMMAND_LINE"
        and entry.get("manifest_version") == 3
        and os.path.normcase(str(Path(entry.get("path", "")).resolve())) == expected_path]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
        raise RuntimeError("Built command-line extension was not uniquely discoverable")
    return matches[0]["id"]


def evaluate_until(connection: CdpConnection, expression: str, timeout_seconds: int) -> Any:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        value = connection.evaluate(expression)
        if value is not None and value is not False:
            return value
        time.sleep(0.1)
    raise RuntimeError("Interaction page condition did not become true")


def seeding_script(data: dict[str, Any]) -> str:
    encoded = json.dumps(data, separators=(",", ":"))
    return f"""
(async () => {{
  const data = {encoded};
  const h = (value) => Uint8Array.from(value.match(/../g).map((byte) => parseInt(byte, 16)));
  const b64 = (value) => btoa(String.fromCharCode(...value))
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  const publicKey = h(data.localPublicKeyHex);
  const privateKey = await crypto.subtle.importKey('jwk', {{
    kty: 'EC', crv: 'P-256', x: b64(publicKey.slice(1, 33)),
    y: b64(publicKey.slice(33)), d: b64(h(data.localPrivateScalarHex)), ext: true,
  }}, {{ name: 'ECDH', namedCurve: 'P-256' }}, false, ['deriveBits']);
  const importedPublicKey = await crypto.subtle.importKey(
    'raw', publicKey, {{ name: 'ECDH', namedCurve: 'P-256' }}, true, []);

  const write = (name, version, stores, storeName, value, key) => new Promise((resolve, reject) => {{
    const open = indexedDB.open(name, version);
    open.onupgradeneeded = () => stores.forEach(([entry, options]) => {{
      if (!open.result.objectStoreNames.contains(entry)) open.result.createObjectStore(entry, options);
    }});
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {{
      const database = open.result;
      const transaction = database.transaction(storeName, 'readwrite');
      transaction.oncomplete = () => {{ database.close(); resolve(true); }};
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
      const store = transaction.objectStore(storeName);
      key === undefined ? store.put(value) : store.put(value, key);
    }};
  }});

  await write('syncnotifications-crypto-v1', 1, [['identities', undefined]], 'identities',
    {{ privateKey, publicKey: importedPublicKey }}, 'primary-hpke-auth-v1');
  await write('syncnotifications-transport-v1', 1, [['credentials', {{ keyPath: 'id' }}]], 'credentials', {{
    id: 'primary-transport-v1', serverOrigin: 'http://127.0.0.1:9',
    workspaceId: h(data.workspaceIdHex), deviceId: h(data.localDeviceIdHex),
    authToken: h(data.authTokenHex), identityKeyId: h(data.localKeyIdHex),
  }});
  await write('syncnotifications-workspace-membership-v1', 1,
    [['workspace-membership', {{ keyPath: 'tuple' }}]], 'workspace-membership', {{
      tuple: `${{data.workspaceIdHex}}:${{data.localDeviceIdHex}}`,
      workspaceId: h(data.workspaceIdHex), deviceId: h(data.localDeviceIdHex),
      authorityPublicKey: h(data.authorityPublicKeyHex), authorityEpoch: '1',
      authorityTransitionDigest: new Uint8Array(32), signedCertificate: h(data.localCertificateHex),
      rosterEpoch: '1', rosterDigest: h(data.rosterDigestHex), signedRoster: h(data.signedRosterHex),
      localDeviceActive: true,
    }});
  await write('syncnotifications-notification-state-v1', 2,
    [['notification-state', {{ keyPath: 'tuple' }}], ['notification-snapshot', {{ keyPath: 'sourceKey' }}]],
    'notification-state', {{
      tuple: `${{data.androidDeviceIdHex}}:${{data.notificationId}}`,
      sourceDeviceId: h(data.androidDeviceIdHex), notificationId: data.notificationId,
      chromeNotificationId: data.chromeNotificationId, revision: data.revision, phase: 'visible',
      payloadSha256: h(data.notificationDigestHex), sourceApplicationId: 'canary.application',
      sourceApplicationName: data.sourceApplicationName, title: data.title, body: data.body,
      actions: [{{ actionId: h(data.actionIdHex), title: 'Reply',
        requiresTextInput: true, allowsFreeFormInput: true }}],
    }});
  return true;
}})()
"""


def parse_protobuf(encoded: bytes) -> list[tuple[int, int, Any]]:
    fields: list[tuple[int, int, Any]] = []
    offset = 0
    while offset < len(encoded):
        key, offset = parse_varint(encoded, offset)
        field_number, wire_type = key >> 3, key & 7
        if field_number < 1 or wire_type not in (0, 2):
            raise RuntimeError("Canonical action payload contains an unsupported protobuf field")
        if wire_type == 0:
            value, offset = parse_varint(encoded, offset)
        else:
            size, offset = parse_varint(encoded, offset)
            end = offset + size
            if end > len(encoded):
                raise RuntimeError("Canonical action payload is truncated")
            value, offset = encoded[offset:end], end
        fields.append((field_number, wire_type, value))
    return fields


def parse_varint(encoded: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(encoded):
            raise RuntimeError("Canonical action payload has a truncated varint")
        byte = encoded[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, offset
    raise RuntimeError("Canonical action payload has an oversized varint")


def require_fields(
    fields: list[tuple[int, int, Any]],
    expected: list[tuple[int, int]],
    label: str,
) -> list[Any]:
    shape = [(field, wire) for field, wire, _ in fields]
    if shape != expected:
        raise RuntimeError(f"{label} does not have the exact canonical field shape")
    return [value for _, _, value in fields]


def main() -> None:
    args = parse_args()
    browser = (args.browser or default_browser()).resolve()
    extension_dir = args.extension_dir.resolve()
    if not browser.is_file() or not (extension_dir / "interaction" / "index.html").is_file():
        raise RuntimeError("built extension and browser are required")

    suffix = secrets.token_hex(12)
    title = f"INTERACTION_TITLE_{suffix}"
    body = f"INTERACTION_BODY_{suffix}"
    reply = f"INTERACTION_REPLY_{suffix}"
    distractor = f"INTERACTION_DISTRACTOR_{suffix}"
    chrome_notification_id = f"sn1:interaction-canary:{suffix}"
    action_id = secrets.token_hex(16)
    membership_vector = json.loads(args.membership_vector.resolve().read_text(encoding="utf-8"))
    worker_fixture = json.loads(args.worker_fixture.resolve().read_text(encoding="utf-8"))
    notification_id = f"interaction-worker-canary-{suffix}"
    seed = {
        "workspaceIdHex": membership_vector["workspaceIdHex"],
        "localDeviceIdHex": membership_vector["deviceIdHex"],
        "localKeyIdHex": membership_vector["identityKeyIdHex"],
        "localPublicKeyHex": membership_vector["identityPublicKeyHex"],
        "localPrivateScalarHex": membership_vector["identityPrivateScalarHex"],
        "localCertificateHex": worker_fixture["localSignedCertificateHex"],
        "authorityPublicKeyHex": membership_vector["authorityPublicKeyHex"],
        "androidDeviceIdHex": worker_fixture["androidDeviceIdHex"],
        "androidKeyIdHex": worker_fixture["androidIdentityKeyIdHex"],
        "rosterDigestHex": worker_fixture["rosterDigestHex"],
        "signedRosterHex": worker_fixture["signedRosterHex"],
        "authTokenHex": secrets.token_hex(32),
        "notificationId": notification_id,
        "chromeNotificationId": chrome_notification_id,
        "revision": "7",
        "notificationDigestHex": secrets.token_hex(32),
        "sourceApplicationName": "Canary application",
        "title": title,
        "body": body,
        "actionIdHex": action_id,
    }

    report_path = args.report.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sevenmirror-interaction-dom-") as temporary:
        root = Path(temporary)
        profile = root / "profile"
        stdout_path = root / "browser.stdout.log"
        stderr_path = root / "browser.stderr.log"
        port = free_local_port()
        arguments = [
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            f"--disable-extensions-except={extension_dir}",
            f"--load-extension={extension_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--window-position=-32000,-32000",
            "--window-size=800,600",
            "about:blank",
        ]
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            process = subprocess.Popen(
                browser_command(browser, arguments),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                creationflags=creation_flags,
            )
            page: CdpConnection | None = None
            try:
                page_target = wait_for_page(port, args.timeout_seconds)
                page = CdpConnection(page_target["webSocketDebuggerUrl"])
                page.command("Runtime.enable")
                page.command("Page.enable")
                extension_id = discover_extension_id(page, extension_dir, args.timeout_seconds)
                interaction_url = (
                    f"chrome-extension://{extension_id}/interaction/index.html"
                    f"?notification={chrome_notification_id.replace(':', '%3A')}"
                )
                if any(value in interaction_url for value in (title, body, reply, distractor)):
                    raise RuntimeError("Business canary entered the interaction URL")

                try:
                    page.command("Log.enable")
                except RuntimeError:
                    pass
                page.command("Page.navigate", {
                    "url": f"chrome-extension://{extension_id}/interaction/index.html",
                })
                evaluate_until(page, "document.readyState === 'complete'", args.timeout_seconds)
                if page.evaluate(seeding_script(seed)) is not True:
                    raise RuntimeError("Failed to seed isolated production stores")
                page.command("Page.navigate", {"url": interaction_url})
                rendered = evaluate_until(page, """
(() => {
  const input = document.querySelector('textarea');
  const notification = document.getElementById('notification');
  if (!input || !notification || notification.hidden) return false;
  return {
    title: document.getElementById('notification-title')?.textContent,
    body: document.getElementById('notification-body')?.textContent,
    source: document.getElementById('source')?.textContent,
    sourceApplication: document.getElementById('source-application')?.textContent,
    text: document.body.innerText,
    href: location.href,
  };
})()
""", args.timeout_seconds)
                if rendered["title"] != title or rendered["body"] != body:
                    raise RuntimeError("Interaction page did not render the target notification")
                if "Canary Android" not in rendered["source"] or \
                        rendered["sourceApplication"] != "Canary application":
                    raise RuntimeError("Interaction page did not render the certified source labels")
                if distractor in rendered["text"] or reply in rendered["text"]:
                    raise RuntimeError("Interaction page rendered unrelated or pre-submit reply content")

                submitted = page.evaluate(f"""
(async () => {{
  const input = document.querySelector('textarea');
  const form = document.querySelector('form.input-action');
  input.value = {json.dumps(reply)};
  form.requestSubmit();
  return {{ inputValue: input.value, href: location.href, bodyText: document.body.innerText }};
}})()
""")
                record = evaluate_until(page, """
(async () => {
  const databases = await indexedDB.databases();
  if (!databases.some((database) => database.name === 'syncnotifications-pending-actions-default')) {
    return false;
  }
  const record = await new Promise((resolve, reject) => {
    const open = indexedDB.open('syncnotifications-pending-actions-default', 1);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const database = open.result;
      const transaction = database.transaction('pending-action', 'readonly');
      const request = transaction.objectStore('pending-action').getAll();
      request.onerror = () => reject(request.error);
      request.onsuccess = () => { database.close(); resolve(request.result[0]); };
    };
  });
  if (!record) return false;
  return {
    idempotencyKey: record.idempotencyKey,
    senderDeviceId: record.senderDeviceId,
    operationDigest: record.operationDigest,
    state: record.state,
    canonicalInvokePayloadHex: Array.from(record.canonicalInvokePayload ?? [],
      (byte) => byte.toString(16).padStart(2, '0')).join(''),
    recipientKeyIdHex: Array.from(record.recipientKeyId ?? [],
      (byte) => byte.toString(16).padStart(2, '0')).join(''),
    invokeAttemptCount: record.invokeAttemptCount,
    invokeDeliveryMode: record.invokeDeliveryMode,
  };
})()
""", args.timeout_seconds)
                canonical = bytes.fromhex(record["canonicalInvokePayloadHex"])
                outer = require_fields(parse_protobuf(canonical), [(1, 0), (10, 2)], "EncryptedPayload")
                action = require_fields(
                    parse_protobuf(outer[1]),
                    [(1, 2), (2, 0), (3, 2), (4, 2), (5, 2)],
                    "ActionInvoke",
                )
                if outer[0] != 2 or action[0].decode("utf-8") != notification_id or \
                        action[1] != 7 or action[2].hex() != action_id or \
                        action[3].hex() != record["idempotencyKey"] or \
                        action[4].decode("utf-8") != reply:
                    raise RuntimeError("Canonical reply payload is not bound to the rendered action and revision")
                if record["senderDeviceId"] != worker_fixture["androidDeviceIdHex"] or \
                        record["recipientKeyIdHex"] != worker_fixture["androidIdentityKeyIdHex"] or \
                        record["operationDigest"] != hashlib.sha256(canonical).hexdigest() or \
                        record["state"] != "pending" or record["invokeAttemptCount"] != 0 or \
                        record["invokeDeliveryMode"] != "once":
                    raise RuntimeError("Canonical one-shot pending-action metadata is incorrect")
                evaluate_until(page, """
(() => {
  const input = document.querySelector('textarea');
  return input && input.disabled === false;
})()
""", args.timeout_seconds)
                if submitted["inputValue"] != "":
                    raise RuntimeError("Reply input remained in the DOM after submission")
                if any(value in submitted["href"] for value in (title, body, reply, distractor)):
                    raise RuntimeError("Business canary entered the interaction URL after submission")
                if reply in submitted["bodyText"] or distractor in submitted["bodyText"]:
                    raise RuntimeError("Submitted or unrelated reply content remained visible in the DOM")
                page.drain_events()
                diagnostics = "\n".join(page.diagnostic_texts)
                if any(value in diagnostics for value in (title, body, reply, distractor)):
                    raise RuntimeError("Interaction business content entered browser diagnostics")

                report = {
                    "result": "passed",
                    "browser_mode": "isolated-non-headless",
                    "target_notification_rendered": True,
                    "unrelated_notification_matches": 0,
                    "reply_input_cleared_after_submit": True,
                    "reply_request_bound_to_action_and_revision": True,
                    "production_worker_boundary_crossed": True,
                    "authority_certified_recipient_resolved": True,
                    "canonical_one_shot_pending_action_persisted": True,
                    "business_canary_url_matches": 0,
                    "business_canary_diagnostic_matches": 0,
                    "limitations": [
                        "The relay is deliberately offline; the canary proves production Worker authorization and canonical one-shot persistence before transport acceptance, not relay delivery or Android execution.",
                        "Process memory, IME, OS notification history, crash dumps, screenshots, screen recording, sync, backup, and filesystem recovery remain open.",
                    ],
                }
                report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            finally:
                if page is not None:
                    try:
                        page.close()
                    except Exception:
                        pass
                stop_process_tree(process)

        logs = stdout_path.read_bytes() + stderr_path.read_bytes()
        if any(value.encode() in logs for value in (title, body, reply, distractor)):
            raise RuntimeError("Interaction business content entered browser stdout/stderr")
        if args.keep_profile:
            kept = report_path.parent / f"interaction-profile-{suffix}"
            shutil.copytree(profile, kept)
            print(f"WARNING: sensitive interaction profile retained at {kept}")

    print("Chrome interaction DOM canary passed.")


if __name__ == "__main__":
    main()
