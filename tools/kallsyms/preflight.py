#!/usr/bin/env python3
"""Read-only checks for the kernel-symbol recovery workflow."""

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import os
import platform
import sys
from pathlib import Path
from typing import Callable

from common import (
    canonical_git_url,
    command_path,
    configured_url,
    expanded_path,
    first_command,
    output_of,
    required_env,
    run,
)


MAGISK_URL = "https://github.com/topjohnwu/Magisk.git"
VMLINUX_TO_ELF_URL = "https://github.com/marin-m/vmlinux-to-elf.git"
MAGISK_ONDK_VERSION = "r30.1"


class Report:
    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def ok(self, label: str, detail: str = "") -> None:
        print(f"PASS  {label}{': ' + detail if detail else ''}")

    def warn(self, label: str, detail: str) -> None:
        self.warnings += 1
        print(f"WARN  {label}: {detail}")

    def fail(self, label: str, detail: str) -> None:
        self.failures += 1
        print(f"FAIL  {label}: {detail}")

    def check(self, label: str, callback: Callable[[], str], *, required: bool = True) -> None:
        try:
            detail = callback()
        except (OSError, RuntimeError, ValueError) as error:
            if required:
                self.fail(label, str(error))
            else:
                self.warn(label, str(error))
        else:
            self.ok(label, detail)


def git_output(repo: Path, *arguments: str, check: bool = True) -> str:
    return output_of(["git", "-C", repo, *arguments], check=check)


def check_command(name: str) -> Callable[[], str]:
    def inner() -> str:
        found = command_path(name)
        if found is None:
            raise RuntimeError("not found on PATH")
        return found

    return inner


def existing_directory(path: Path) -> str:
    if not path.is_dir():
        raise RuntimeError("directory not found")
    return str(path)


def check_repo(path: Path, label: str, expected_url: str, *, submodules: bool, report: Report) -> None:
    report.check(f"{label} exists", lambda: existing_directory(path))
    if not path.is_dir():
        return

    is_worktree = run(
        ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
        capture=True,
        check=False,
    )
    if is_worktree.returncode != 0 or is_worktree.stdout.strip() != "true":
        report.fail(f"{label} is a Git worktree", str(path))
        return
    report.ok(f"{label} is a Git worktree", str(path))

    origin = git_output(path, "config", "--get", "remote.origin.url", check=False)
    if not origin:
        report.fail(f"{label} origin", "remote.origin.url is not configured")
    elif canonical_git_url(origin) != canonical_git_url(expected_url):
        report.fail(f"{label} origin", f"found {origin!r}; expected {expected_url!r}")
    else:
        report.ok(f"{label} origin", origin)

    status = git_output(path, "status", "--porcelain", "--untracked-files=all", check=False)
    if status:
        report.fail(f"{label} clean checkout", "working tree has changes or untracked files")
    else:
        report.ok(f"{label} clean checkout")

    branch = git_output(path, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    if branch:
        report.ok(f"{label} branch", branch)
    else:
        report.fail(f"{label} branch", "detached HEAD")

    if submodules:
        submodule_status = git_output(path, "submodule", "status", "--recursive", check=False)
        bad = [line for line in submodule_status.splitlines() if line[:1] in "-+U"]
        if bad:
            report.fail(f"{label} submodules", "one or more submodules are missing or mismatched")
        else:
            report.ok(f"{label} submodules", "initialized and at the recorded commits")

    if label == "Magisk repository":
        native_boot = path / "native" / "src" / "boot"
        report.check("Magisk native boot sources", lambda: existing_directory(native_boot))


def uv_script_check(script: Path, *arguments: str) -> str:
    uv = first_command("uv")
    if uv is None:
        raise RuntimeError("uv is not on PATH")
    result = run(
        [uv, "run", "--script", script, *arguments],
        cwd=script.parent,
        capture=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(detail or f"exited with status {result.returncode}")
    return "uv selected a compatible Python and resolved the script environment"


def check_vmlinux_environment(script_dir: Path, report: Report) -> None:
    script = script_dir / "reconstruct_vmlinux.py"
    report.check("uv reconstruction environment", lambda: uv_script_check(script, "--check-upstream"))
    embedded_script = script_dir / "find_kallsyms.py"
    report.check(
        "uv embedded-kallsyms environment",
        lambda: uv_script_check(embedded_script, "--help"),
    )


def check_host_compiler(report: Report, *, required: bool) -> None:
    compiler = first_command("cc", "gcc", "clang", "cl")
    if compiler is None:
        detail = "cc, gcc, clang, or cl is not on PATH"
        if required:
            report.fail("host C compiler", detail)
        else:
            report.warn("host C compiler", detail + "; uv may still succeed if all wheels are available")
    else:
        report.ok("host C compiler", compiler)


def check_native_build(report: Report) -> None:
    check_host_compiler(report, required=True)

    sdk_value = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk_value:
        report.fail("Android SDK", "set ANDROID_HOME or ANDROID_SDK_ROOT")
        return
    sdk = expanded_path(sdk_value)
    report.check("Android SDK", lambda: existing_directory(sdk))

    ndk = sdk / "ndk" / "magisk"
    report.check("Magisk ONDK", lambda: existing_directory(ndk))

    version_file = ndk / "ONDK_VERSION"
    def ondk_version() -> str:
        if not version_file.is_file():
            raise RuntimeError(f"missing {version_file}")
        actual = version_file.read_text(encoding="utf-8").strip()
        if actual != MAGISK_ONDK_VERSION:
            raise RuntimeError(f"found {actual!r}; expected {MAGISK_ONDK_VERSION!r}")
        return actual

    report.check("Magisk ONDK version", ondk_version)

    ndk_build_candidates = [ndk / "ndk-build"]
    if os.name == "nt":
        ndk_build_candidates.insert(0, ndk / "ndk-build.cmd")
    ndk_build = next((candidate for candidate in ndk_build_candidates if candidate.is_file()), None)
    if ndk_build is not None:
        report.ok("ndk-build", str(ndk_build))
    else:
        report.fail("ndk-build", f"not found under {ndk}")

    rust_bin = ndk / "toolchains" / "rust" / "bin"
    for name in ("cargo", "rustc"):
        candidates = [name, f"{name}.exe", rust_bin / name, rust_bin / f"{name}.exe"]
        found = first_command(*[os.fspath(candidate) for candidate in candidates])
        if found is None:
            report.fail(name, f"not found on PATH or under {rust_bin}")
        else:
            report.ok(name, found)


def check_magiskboot(report: Report) -> None:
    value = os.environ.get("MAGISKBOOT_PATH")
    if not value:
        report.fail("magiskboot", "set MAGISKBOOT_PATH to a host magiskboot binary")
        return
    resolved = command_path(value)
    if resolved is None:
        report.fail("magiskboot", f"not found: {value}")
    elif os.name != "nt" and not os.access(resolved, os.X_OK):
        report.fail("magiskboot", f"not executable: {resolved}")
    else:
        report.ok("magiskboot", resolved)


def check_boot_image(path: Path) -> str:
    if not path.is_file():
        raise RuntimeError("file not found")
    with path.open("rb") as stream:
        magic = stream.read(8)
    if magic == b"ANDROID!":
        return "AOSP Android boot image"
    if magic == b"VNDRBOOT":
        return "vendor_boot image (kernel is normally in boot.img, not vendor_boot.img)"
    return f"unrecognized first 8 bytes: {magic!r}; magiskboot may still support it"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check prerequisites without changing repositories or files.")
    parser.add_argument("--boot-image", type=Path, help="optional image to identify")
    parser.add_argument("--check-native-build", action="store_true", help="also require Magisk's NDK build prerequisites")
    parser.add_argument("--require-magiskboot", action="store_true", help="require MAGISKBOOT_PATH")
    args = parser.parse_args()

    report = Report()
    print(f"Platform: {platform.platform()}")

    git_available = command_path("git") is not None
    report.check("git", check_command("git"))
    report.check("uv", check_command("uv"))

    try:
        magisk = required_env("MAGISK_REPO_DIR")
    except RuntimeError as error:
        report.fail("MAGISK_REPO_DIR", str(error))
        magisk = None
    try:
        vmlinux_to_elf = required_env("VMLINUX_TO_ELF_REPO_DIR")
    except RuntimeError as error:
        report.fail("VMLINUX_TO_ELF_REPO_DIR", str(error))
        vmlinux_to_elf = None

    if magisk is not None and git_available:
        check_repo(
            magisk,
            "Magisk repository",
            configured_url("MAGISK_REPO_URL", MAGISK_URL),
            submodules=True,
            report=report,
        )
    if vmlinux_to_elf is not None and git_available:
        check_repo(
            vmlinux_to_elf,
            "vmlinux-to-elf repository",
            configured_url("VMLINUX_TO_ELF_REPO_URL", VMLINUX_TO_ELF_URL),
            submodules=False,
            report=report,
        )
        check_vmlinux_environment(Path(__file__).resolve().parent, report)

    readelf_override = os.environ.get("READELF_PATH")
    readelf_name = readelf_override or "readelf"
    readelf = command_path(readelf_name)
    if readelf is None and readelf_override is None:
        readelf = command_path("llvm-readelf")
    if readelf is None:
        report.fail("ELF symbol reader", f"{readelf_name} (or llvm-readelf) is not available")
    else:
        report.ok("ELF symbol reader", readelf)

    nm_override = os.environ.get("NM_PATH")
    nm_name = nm_override or "nm"
    nm = command_path(nm_name)
    if nm is None and nm_override is None:
        nm = command_path("llvm-nm")
    if nm is None:
        report.warn("nm fallback", f"{nm_name} (or llvm-nm) is not available")
    else:
        report.ok("nm fallback", nm)

    if args.check_native_build:
        check_native_build(report)
    else:
        check_host_compiler(report, required=False)
        report.warn(
            "native build toolchain",
            "not required for the standard extractor; use --check-native-build only when building magiskboot",
        )

    if args.require_magiskboot:
        check_magiskboot(report)
    elif os.environ.get("MAGISKBOOT_PATH"):
        check_magiskboot(report)
    else:
        report.warn(
            "magiskboot",
            "MAGISKBOOT_PATH is unset; the standard-library AOSP extractor will be used",
        )

    if args.boot_image:
        report.check("boot image", lambda: check_boot_image(args.boot_image))

    print()
    if report.failures:
        print(f"Preflight: FAIL ({report.failures} required check(s) failed)")
        return 1
    print(f"Preflight: PASS ({report.warnings} warning(s))")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"preflight: error: {error}", file=sys.stderr)
        raise SystemExit(1)
