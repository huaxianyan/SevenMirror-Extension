from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from build_release_package import build, verify


class ChromeReleasePackageTest(unittest.TestCase):
    def test_package_is_reproducible_and_rejects_archive_tampering(self) -> None:
        revision = "2" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            (dist / "background").mkdir(parents=True)
            (dist / "manifest.json").write_text(
                '{"manifest_version":3,"name":"fixture","version":"1.2.3"}\n',
                encoding="utf-8",
            )
            (dist / "background" / "service-worker.js").write_text(
                "console.log('fixture');\n", encoding="utf-8",
            )
            first = root / "first"
            second = root / "second"
            build(dist, first, revision, "1.2.3-dev")
            build(dist, second, revision, "1.2.3-dev")

            self.assertEqual(
                (first / "sevenmirror-extension-1.2.3.zip").read_bytes(),
                (second / "sevenmirror-extension-1.2.3.zip").read_bytes(),
            )
            verify(first, revision)
            archive = first / "sevenmirror-extension-1.2.3.zip"
            archive.write_bytes(archive.read_bytes() + b"tampered")
            with self.assertRaisesRegex(RuntimeError, "does not match its manifest"):
                verify(first, revision)


if __name__ == "__main__":
    unittest.main()
