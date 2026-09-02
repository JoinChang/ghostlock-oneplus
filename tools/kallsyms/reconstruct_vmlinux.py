#!/usr/bin/env python3
"""Reconstruct an ELF vmlinux from a kernel payload."""

# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "lz4",
#   "zstandard>=0.25.0",
#   "minilzo>=1.2",
#   "peewee>=3.17",
# ]
# ///

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import List, Union

from common import ensure_file, expanded_path, python_env, required_env, run


MODULE = "vmlinux_to_elf.scripts.vmlinux_to_elf"
CLI_MODULES = (
    MODULE,
    "vmlinux_to_elf.scripts.kallsyms_finder",
    "vmlinux_to_elf.scripts.vmlinuz_decompressor",
)


def check_upstream(repo: Path) -> None:
    for module in CLI_MODULES:
        result = run(
            [sys.executable, "-m", module, "--help"],
            env=python_env(repo),
            capture=True,
            check=False,
        )
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(
                f"{module} is not runnable: {detail or f'exited with status {result.returncode}'}"
            )


def build_command(kernel: Path, output: Path, args: argparse.Namespace) -> List[Union[str, os.PathLike[str]]]:
    command: List[Union[str, os.PathLike[str]]] = [sys.executable, "-m", MODULE, kernel, output]
    for option, value in (
        ("--e-machine", args.e_machine),
        ("--bit-size", args.bit_size),
        ("--file-offset", args.file_offset),
        ("--base-address", args.base_address),
        ("--bss-size", args.bss_size),
    ):
        if value is not None:
            command.extend([option, value])
    if args.use_absolute:
        command.append("--use-absolute")
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconstruct vmlinux with vmlinux-to-elf.")
    parser.add_argument("kernel", type=Path, nargs="?", help="extracted raw or compressed kernel")
    parser.add_argument("output", type=Path, nargs="?", help="output ELF path, usually named vmlinux")
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="verify the cloned vmlinux-to-elf CLI without processing a kernel",
    )
    parser.add_argument("--e-machine", help="override ELF e_machine, for example 183 for AArch64")
    parser.add_argument("--bit-size", choices=("32", "64"), help="override kernel bitness")
    parser.add_argument("--file-offset", help="kernel file offset, hexadecimal as accepted by vmlinux-to-elf")
    parser.add_argument("--base-address", help="kernel base address, hexadecimal as accepted by vmlinux-to-elf")
    parser.add_argument("--bss-size", help="BSS size passed to vmlinux-to-elf")
    parser.add_argument("--use-absolute", action="store_true", help="pass --use-absolute")
    args = parser.parse_args()

    repo = required_env("VMLINUX_TO_ELF_REPO_DIR")
    if not repo.is_dir():
        raise RuntimeError(f"VMLINUX_TO_ELF_REPO_DIR is not a directory: {repo}")

    if args.check_upstream:
        if args.kernel is not None or args.output is not None:
            parser.error("--check-upstream does not accept kernel or output arguments")
        check_upstream(repo)
        print("vmlinux-to-elf CLI checks passed")
        return 0
    if args.kernel is None or args.output is None:
        parser.error("kernel and output are required unless --check-upstream is used")

    kernel = expanded_path(args.kernel)
    output = expanded_path(args.output)
    ensure_file(kernel, "kernel input")

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    command = build_command(kernel, temporary, args)
    try:
        result = run(command, env=python_env(repo), check=False)
        if result.returncode:
            raise RuntimeError(f"vmlinux-to-elf exited with status {result.returncode}")
        # vmlinux-to-elf can report an unsupported architecture through a
        # zero-status exit; the output check catches that case.
        ensure_file(temporary, "reconstructed ELF")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)

    print(f"Reconstructed ELF: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"reconstruct_vmlinux: error: {error}", file=sys.stderr)
        raise SystemExit(1)
