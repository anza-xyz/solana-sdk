#!/usr/bin/env python3

import argparse
import io
import os
import pathlib
import subprocess
import shutil
import tarfile
import tempfile
import urllib.request

VERSION = "v0.1.2"
ARCHIVE_URL = (
    f"https://github.com/ethereum/bls12-381-tests/releases/download/{VERSION}/"
    "bls_tests_json.tar.gz"
)
REQUIRED_DIRS = (
    "aggregate",
    "aggregate_verify",
    "batch_verify",
    "deserialization_G1",
    "deserialization_G2",
    "fast_aggregate_verify",
    "sign",
    "verify",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    return parser.parse_args()


def output_is_ready(output_dir: pathlib.Path) -> bool:
    return all((output_dir / name).is_dir() for name in REQUIRED_DIRS)


def archive_candidates(output_dir: pathlib.Path) -> list[pathlib.Path]:
    candidates = []
    archive_override = os.environ.get("ETHEREUM_BLS_TESTS_ARCHIVE")
    if archive_override:
        candidates.append(pathlib.Path(archive_override))
    candidates.append(output_dir.parent / "bls_tests_json.tar.gz")
    return candidates


def maybe_generate_from_repo(output_dir: pathlib.Path) -> bool:
    repo_override = os.environ.get("ETHEREUM_BLS_TESTS_REPO")
    if not repo_override:
        return False

    repo_dir = pathlib.Path(repo_override).resolve()
    subprocess.run(
        [
            "python3",
            str(repo_dir / "main.py"),
            f"--output-dir={output_dir}",
            "--encoding=json",
        ],
        check=True,
        cwd=repo_dir,
    )
    return True


def load_archive_bytes(output_dir: pathlib.Path) -> bytes:
    for candidate in archive_candidates(output_dir):
        if candidate.is_file():
            return candidate.read_bytes()
    return urllib.request.urlopen(ARCHIVE_URL).read()


def extract_archive(archive: tarfile.TarFile, output_dir: pathlib.Path) -> None:
    for member in archive.getmembers():
        target = (output_dir / member.name).resolve()
        if not str(target).startswith(str(output_dir.resolve())):
            raise ValueError(f"refusing to extract outside {output_dir}: {member.name}")
    archive.extractall(output_dir)


def main() -> None:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    if output_is_ready(output_dir):
        return

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if maybe_generate_from_repo(output_dir):
        return

    scratch_root = output_dir.parent / ".tmp"
    scratch_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ethereum-bls-vectors-",
        dir=scratch_root,
    ) as tempdir:
        tempdir_path = pathlib.Path(tempdir)
        archive_bytes = load_archive_bytes(output_dir)
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            extract_archive(archive, tempdir_path)

        staging_dir = tempdir_path / "staging"
        staging_dir.mkdir()
        for name in REQUIRED_DIRS:
            shutil.copytree(tempdir_path / name, staging_dir / name)

        shutil.rmtree(output_dir, ignore_errors=True)
        shutil.move(str(staging_dir), str(output_dir))


if __name__ == "__main__":
    main()
