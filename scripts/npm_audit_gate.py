#!/usr/bin/env python3
"""Run npm audit once and emit lock-bound query-time evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

REGISTRY = "https://registry.npmjs.org"
SEVERITIES = ("info", "low", "moderate", "high", "critical")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    return parser.parse_args()


def executable(name: str) -> str:
    candidates = (f"{name}.cmd", name) if os.name == "nt" else (name,)
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError(f"required executable {name} was not found")


def canonical_revision(revision: str) -> None:
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("npm audit revision must be a canonical commit")


def run_gate(
    output: Path,
    revision: str,
    observed_at: datetime,
    npm_command: str,
    node_command: str,
    repository: Path,
) -> dict[str, object]:
    canonical_revision(revision)
    if output.exists() or output.is_symlink():
        raise RuntimeError("npm audit evidence output must not already exist")
    lockfile = repository / "package-lock.json"
    if not lockfile.is_file() or lockfile.is_symlink():
        raise RuntimeError("npm audit requires a regular package-lock.json")
    try:
        lock = json.loads(lockfile.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("package-lock.json is invalid") from error
    if lock.get("lockfileVersion") != 2 or not isinstance(lock.get("packages"), dict):
        raise RuntimeError("npm audit requires the canonical lockfile v2 inventory")
    completed = subprocess.run(
        [
            npm_command, "audit", "--json", "--audit-level=high",
            f"--registry={REGISTRY}",
        ],
        cwd=repository,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        timeout=180,
        env=os.environ.copy(),
    )
    try:
        report = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("npm audit did not return valid JSON") from error
    vulnerabilities = report.get("vulnerabilities")
    metadata = report.get("metadata")
    if report.get("auditReportVersion") != 2 or not isinstance(vulnerabilities, dict) or \
            not isinstance(metadata, dict) or not isinstance(metadata.get("vulnerabilities"), dict) or \
            not isinstance(metadata.get("dependencies"), dict):
        raise RuntimeError("npm audit report shape is unsupported")
    counts = metadata["vulnerabilities"]
    if any(not isinstance(counts.get(severity), int) or counts[severity] < 0 for severity in SEVERITIES) or \
            counts.get("total") != sum(counts[severity] for severity in SEVERITIES):
        raise RuntimeError("npm audit severity counts are invalid")
    finding_packages: list[dict[str, str]] = []
    for name, finding in vulnerabilities.items():
        if not isinstance(name, str) or not name or not isinstance(finding, dict) or \
                finding.get("name") != name or finding.get("severity") not in SEVERITIES:
            raise RuntimeError("npm audit finding inventory is invalid")
        finding_packages.append({"name": name, "severity": finding["severity"]})
    finding_packages.sort(key=lambda finding: finding["name"])
    npm_version = subprocess.check_output(
        [npm_command, "--version"], cwd=repository, text=True, encoding="utf-8",
    ).strip()
    node_version = subprocess.check_output(
        [node_command, "--version"], cwd=repository, text=True, encoding="utf-8",
    ).strip()
    evidence = {
        "schema": "sevenmirror-vulnerability-scan-evidence-v1",
        "repository": "SevenMirror-Extension",
        "source_revision": revision,
        "scanner": "npm-audit",
        "scanner_version": npm_version,
        "runtime_version": node_version,
        "registry": REGISTRY,
        "database_last_modified": None,
        "timestamp_semantics": "registry-query-completed-at",
        "observed_at": observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "lockfile_sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest(),
        "lockfile_version": 2,
        "locked_package_records": len(lock["packages"]),
        "severity_counts": {severity: counts[severity] for severity in SEVERITIES},
        "total_finding_count": counts["total"],
        "finding_packages": finding_packages,
        "dependency_counts": metadata["dependencies"],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if completed.returncode != 0 and counts["high"] == 0 and counts["critical"] == 0:
        raise RuntimeError(f"npm audit failed without a blocking finding: status {completed.returncode}")
    if counts["high"] or counts["critical"]:
        blocking = [
            finding["name"] for finding in finding_packages
            if finding["severity"] in {"high", "critical"}
        ]
        raise RuntimeError(f"npm audit reported blocking packages: {blocking}")
    if completed.returncode != 0:
        raise RuntimeError(f"npm audit exited unexpectedly with status {completed.returncode}")
    return evidence


def main() -> None:
    args = parse_args()
    repository = Path(__file__).resolve().parents[1]
    evidence = run_gate(
        args.output.resolve(), args.revision, datetime.now(timezone.utc),
        executable("npm"), executable("node"), repository,
    )
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
