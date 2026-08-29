#!/usr/bin/env python3
"""Exercise the production interaction page in an isolated non-headless browser."""

from __future__ import annotations

import argparse
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


def wait_for_targets(port: int, timeout_seconds: int) -> tuple[dict[str, Any], dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            targets = fetch_json(f"http://127.0.0.1:{port}/json")
            worker = next((target for target in targets
                if target.get("type") == "service_worker"
                and target.get("url", "").endswith("/background/service-worker.js")), None)
            page = next((target for target in targets if target.get("type") == "page"), None)
            if worker is not None and page is not None:
                return worker, page
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError("Extension Worker and browser page did not appear before timeout")


def evaluate_until(connection: CdpConnection, expression: str, timeout_seconds: int) -> Any:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        value = connection.evaluate(expression)
        if value is not None and value is not False:
            return value
        time.sleep(0.1)
    raise RuntimeError("Interaction page condition did not become true")


def injection_script(fixture: dict[str, Any]) -> str:
    encoded = json.dumps(fixture, separators=(",", ":"))
    return f"""
(() => {{
  const fixture = {encoded};
  globalThis.__interactionMessages = [];
  const sendMessage = async (message) => {{
    globalThis.__interactionMessages.push(structuredClone(message));
    if (message?.type === 'get-notification-interaction') {{
      return {{ notification: fixture.notification }};
    }}
    if (message?.type === 'invoke-notification-interaction') {{
      return {{ outcome: 'unavailable' }};
    }}
    if (message?.type === 'get-notification-interaction-operation') {{
      return {{ state: 'unavailable' }};
    }}
    throw new Error('Unexpected interaction-page message');
  }};
  Object.defineProperty(chrome.runtime, 'sendMessage', {{ value: sendMessage }});
}})();
"""


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
    fixture = {
        "notification": {
            "chromeNotificationId": chrome_notification_id,
            "revision": "7",
            "sourceName": "Canary Android",
            "sourceApplicationName": "Canary application",
            "title": title,
            "body": body,
            "actions": [{
                "actionId": action_id,
                "title": "Reply",
                "requiresTextInput": True,
                "allowsFreeFormInput": True,
            }],
        },
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
                worker_target, page_target = wait_for_targets(port, args.timeout_seconds)
                extension_id = worker_target["url"].split("/", 3)[2]
                interaction_url = (
                    f"chrome-extension://{extension_id}/interaction/index.html"
                    f"?notification={chrome_notification_id.replace(':', '%3A')}"
                )
                if any(value in interaction_url for value in (title, body, reply, distractor)):
                    raise RuntimeError("Business canary entered the interaction URL")

                page = CdpConnection(page_target["webSocketDebuggerUrl"])
                page.command("Runtime.enable")
                page.command("Page.enable")
                try:
                    page.command("Log.enable")
                except RuntimeError:
                    pass
                page.command("Page.addScriptToEvaluateOnNewDocument", {
                    "source": injection_script(fixture),
                })
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
  const deadline = Date.now() + 5000;
  while (globalThis.__interactionMessages.length < 2 && Date.now() < deadline) {{
    await new Promise((resolve) => setTimeout(resolve, 25));
  }}
  return {{
    inputValue: input.value,
    messages: globalThis.__interactionMessages,
    href: location.href,
    bodyText: document.body.innerText,
  }};
}})()
""")
                messages = submitted["messages"]
                invoke = next((message for message in messages
                    if message.get("type") == "invoke-notification-interaction"), None)
                if invoke is None or invoke.get("operation") != "reply" or \
                        invoke.get("replyText") != reply or invoke.get("actionId") != action_id or \
                        invoke.get("revision") != "7" or \
                        invoke.get("chromeNotificationId") != chrome_notification_id:
                    raise RuntimeError("Reply submission was not bound to the rendered action and revision")
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
                    "business_canary_url_matches": 0,
                    "business_canary_diagnostic_matches": 0,
                    "limitations": [
                        "The runtime message boundary is intercepted before the Worker; authenticated recipient resolution, canonical pending-action persistence, encryption, and Android execution remain covered by separate tests.",
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
