from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from npm_audit_gate import run_gate

REVISION = "6" * 40
OBSERVED = datetime(2026, 8, 31, 7, 0, tzinfo=timezone.utc)


def report(severity: str = "moderate") -> subprocess.CompletedProcess[str]:
    counts = {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0}
    counts[severity] = 1
    vulnerabilities = {
        "fixture-package": {"name": "fixture-package", "severity": severity},
    }
    return subprocess.CompletedProcess(
        args=[], returncode=1 if severity in {"high", "critical"} else 0,
        stdout=json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": vulnerabilities,
            "metadata": {
                "vulnerabilities": {**counts, "total": 1},
                "dependencies": {
                    "prod": 1, "dev": 1, "optional": 0,
                    "peer": 0, "peerOptional": 0, "total": 2,
                },
            },
        }),
        stderr="",
    )


class NpmAuditGateTest(unittest.TestCase):
    @patch("npm_audit_gate.subprocess.check_output", side_effect=["10.9.0\n", "v20.19.0\n"])
    @patch("npm_audit_gate.subprocess.run")
    def test_nonblocking_findings_remain_visible_and_high_findings_fail(
        self, run: Mock, versions: Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package-lock.json").write_text(json.dumps({
                "name": "fixture",
                "lockfileVersion": 2,
                "packages": {"": {"name": "fixture"}, "node_modules/example": {}},
            }), encoding="utf-8")
            output = repository / "evidence.json"
            run.return_value = report("moderate")
            evidence = run_gate(
                output, REVISION, OBSERVED, "npm", "node", repository,
            )
            self.assertEqual(evidence["severity_counts"]["moderate"], 1)
            self.assertEqual(evidence["finding_packages"], [
                {"name": "fixture-package", "severity": "moderate"},
            ])

            versions.side_effect = ["10.9.0\n", "v20.19.0\n"]
            run.return_value = report("high")
            with self.assertRaisesRegex(RuntimeError, "blocking packages"):
                run_gate(
                    repository / "blocking.json", REVISION, OBSERVED,
                    "npm", "node", repository,
                )


if __name__ == "__main__":
    unittest.main()
