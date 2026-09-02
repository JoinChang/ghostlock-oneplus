#!/usr/bin/env python3
"""Run the complete boot.img -> kallsyms.txt workflow."""

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from common import command_path, ensure_file, expanded_path, run


SCRIPT_DIR = Path(__file__).resolve().parent


def run_uv_script(script_name: str, arguments: Iterable[object]) -> None:
    uv = command_path("uv")
    if uv is None:
        raise RuntimeError("uv is not on PATH; install uv before running this workflow")

    script = SCRIPT_DIR / script_name
    command = [uv, "run", "--script", script]
    command.extend(arguments)
    print(f"== {script_name} ==", flush=True)
    result = run(command, cwd=SCRIPT_DIR, check=False)
    if result.returncode:
        raise RuntimeError(f"{script_name} failed with status {result.returncode}")


def run_pipeline(boot_image: Path, output: Path, work_dir: Path, magiskboot: Optional[str]) -> None:
    work_dir.mkdir(parents=True, exist_ok=True)
    kernel = work_dir / "kernel"
    kernel_dtb = work_dir / "kernel.dtb"
    vmlinux = work_dir / "vmlinux"

    if magiskboot:
        os.environ["MAGISKBOOT_PATH"] = magiskboot

    run_uv_script("bootstrap.py", ())

    preflight_arguments = ["--boot-image", boot_image]
    if magiskboot:
        preflight_arguments.append("--require-magiskboot")
    run_uv_script("preflight.py", preflight_arguments)

    run_uv_script(
        "extract_kernel.py",
        [boot_image, kernel, "--dtb-output", kernel_dtb],
    )
    run_uv_script("reconstruct_vmlinux.py", [kernel, vmlinux])
    run_uv_script("export_kallsyms.py", [vmlinux, output])

    print()
    print(f"Completed: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automate boot.img extraction, vmlinux reconstruction, and kallsyms export."
    )
    parser.add_argument(
        "boot_image",
        type=Path,
        nargs="?",
        default=Path("boot.img"),
        help="input Android boot image (default: boot.img)",
    )
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        default=Path("kallsyms.txt"),
        help="compact readelf-format symbol output (default: kallsyms.txt)",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="preserve kernel/vmlinux intermediates in this directory",
    )
    parser.add_argument(
        "--magiskboot",
        help="use a host magiskboot executable for extraction (troubleshooting fallback)",
    )
    args = parser.parse_args()

    boot_image = expanded_path(args.boot_image)
    output = expanded_path(args.output)
    ensure_file(boot_image, "boot image")

    if args.work_dir:
        work_dir = expanded_path(args.work_dir)
        run_pipeline(boot_image, output, work_dir, args.magiskboot)
        print(f"Intermediate files: {work_dir}")
        return 0

    with tempfile.TemporaryDirectory(prefix="kallsyms-work-") as temporary:
        run_pipeline(boot_image, output, Path(temporary), args.magiskboot)
    print("Intermediate files removed; pass --work-dir to keep them")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"kallsyms: error: {error}", file=sys.stderr)
        raise SystemExit(1)
