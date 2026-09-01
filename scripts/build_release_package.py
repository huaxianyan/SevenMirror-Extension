#!/usr/bin/env python3
"""Build and verify the deterministic SevenMirror Chrome submission ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*)){0,3}$")
REPOSITORY = "https://github.com/huaxianyan/SevenMirror-Extension"
SCHEMA = "sevenmirror-extension-release-v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--package-version")
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_revision(revision: str) -> None:
    if not REVISION.fullmatch(revision):
        raise RuntimeError("release revision must be a canonical 40-character commit")


def validate_version(version: object) -> str:
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise RuntimeError("extension version is not canonical")
    if any(int(part) > 65535 for part in version.split(".")):
        raise RuntimeError("extension version component exceeds Chrome's limit")
    return version


def collect_dist(dist: Path) -> tuple[str, list[tuple[str, bytes]]]:
    if not dist.is_dir() or dist.is_symlink():
        raise RuntimeError("dist must be a non-symlink directory")
    files: list[tuple[str, bytes]] = []
    for path in sorted(dist.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("dist must not contain symlinks")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError("dist contains a non-regular entry")
        name = path.relative_to(dist).as_posix()
        if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
            raise RuntimeError("dist contains an unsafe path")
        files.append((name, path.read_bytes()))
    names = {name for name, _ in files}
    if len(names) != len(files) or "manifest.json" not in names:
        raise RuntimeError("dist inventory is invalid")
    manifest_content = next(content for name, content in files if name == "manifest.json")
    try:
        chrome_manifest = json.loads(manifest_content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Chrome manifest is invalid") from error
    if chrome_manifest.get("manifest_version") != 3:
        raise RuntimeError("release package must use Manifest V3")
    return validate_version(chrome_manifest.get("version")), files


def build(dist: Path, output: Path, revision: str, package_version: str) -> None:
    validate_revision(revision)
    if output.exists() or output.is_symlink():
        raise RuntimeError("release output must not already exist")
    if not package_version or any(character.isspace() for character in package_version):
        raise RuntimeError("npm package version is invalid")
    extension_version, files = collect_dist(dist)
    output.mkdir(mode=0o700)
    zip_name = f"sevenmirror-extension-{extension_version}.zip"
    zip_path = output / zip_name
    with zipfile.ZipFile(
        zip_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9,
    ) as archive:
        for name, content in files:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.flag_bits |= 0x800
            archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    file_records = [
        {"name": name, "sha256": sha256_bytes(content), "size": len(content)}
        for name, content in files
    ]
    release_manifest = {
        "schema": SCHEMA,
        "source_repository": REPOSITORY,
        "source_revision": revision,
        "package_version": package_version,
        "extension_version": extension_version,
        "manifest_version": 3,
        "archive": {
            "name": zip_name,
            "sha256": sha256_file(zip_path),
            "size": zip_path.stat().st_size,
        },
        "files": file_records,
    }
    (output / "release-manifest.json").write_text(
        json.dumps(release_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "SHA256SUMS").write_text(
        f"{release_manifest['archive']['sha256']}  {zip_name}\n", encoding="ascii",
    )


def verify_zip(zip_path: Path, records: list[dict[str, object]]) -> None:
    expected_names = [record.get("name") for record in records]
    if any(not isinstance(name, str) for name in expected_names) or \
            expected_names != sorted(expected_names) or \
            len(expected_names) != len(set(expected_names)):
        raise RuntimeError("release file inventory is not canonical")
    with zipfile.ZipFile(zip_path, "r") as archive:
        infos = archive.infolist()
        if [info.filename for info in infos] != expected_names:
            raise RuntimeError("ZIP entries do not match the release manifest")
        for info, record in zip(infos, records, strict=True):
            path = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if path.is_absolute() or ".." in path.parts or info.is_dir() or \
                    info.flag_bits & 0x1 or info.date_time != (1980, 1, 1, 0, 0, 0) or \
                    not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o644:
                raise RuntimeError("ZIP contains an unsafe or noncanonical entry")
            content = archive.read(info)
            digest = record.get("sha256")
            size = record.get("size")
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or \
                    not isinstance(size, int) or size < 1 or \
                    len(content) != size or sha256_bytes(content) != digest:
                raise RuntimeError(f"ZIP entry {info.filename} does not match its manifest")


def verify(output: Path, revision: str) -> None:
    validate_revision(revision)
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("release output must be a non-symlink directory")
    manifest_path = output / "release-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("release manifest is invalid") from error
    archive = manifest.get("archive")
    if manifest.get("schema") != SCHEMA or manifest.get("source_repository") != REPOSITORY or \
            manifest.get("source_revision") != revision or manifest.get("manifest_version") != 3 or \
            not isinstance(archive, dict):
        raise RuntimeError("release manifest source binding is invalid")
    extension_version = validate_version(manifest.get("extension_version"))
    zip_name = f"sevenmirror-extension-{extension_version}.zip"
    expected_entries = {zip_name, "release-manifest.json", "SHA256SUMS"}
    entries = list(output.iterdir())
    if {entry.name for entry in entries} != expected_entries or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise RuntimeError("release output has missing, extra, or unsafe entries")
    zip_path = output / zip_name
    digest = archive.get("sha256")
    size = archive.get("size")
    if archive.get("name") != zip_name or not isinstance(digest, str) or \
            not DIGEST.fullmatch(digest) or not isinstance(size, int) or size < 1 or \
            zip_path.stat().st_size != size or sha256_file(zip_path) != digest:
        raise RuntimeError("release ZIP does not match its manifest")
    records = manifest.get("files")
    if not isinstance(records, list) or not records:
        raise RuntimeError("release file inventory is invalid")
    verify_zip(zip_path, records)
    with zipfile.ZipFile(zip_path, "r") as archive_file:
        chrome_manifest = json.loads(archive_file.read("manifest.json"))
    if chrome_manifest.get("manifest_version") != 3 or \
            chrome_manifest.get("version") != extension_version:
        raise RuntimeError("packaged Chrome manifest binding is invalid")
    if (output / "SHA256SUMS").read_text(encoding="ascii") != f"{digest}  {zip_name}\n":
        raise RuntimeError("release checksum does not match the manifest")


def main() -> None:
    args = parse_args()
    output = args.output.resolve()
    if not args.verify_only:
        if args.dist is None or args.package_version is None:
            raise RuntimeError("--dist and --package-version are required for building")
        build(args.dist.resolve(), output, args.revision, args.package_version)
    verify(output, args.revision)
    print("SevenMirror Chrome release package verified.")


if __name__ == "__main__":
    main()
