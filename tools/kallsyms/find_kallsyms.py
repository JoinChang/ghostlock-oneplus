#!/usr/bin/env python3
"""Extract the kernel's embedded kallsyms table in /proc/kallsyms-like form."""

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


MODULE = "vmlinux_to_elf.scripts.kallsyms_finder"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract embedded kallsyms from a kernel payload."
    )
    parser.add_argument("kernel", type=Path, help="extracted raw/compressed kernel")
    parser.add_argument(
        "output",
        type=Path,
        help="output file; unlike upstream, no .kallsyms suffix is added",
    )
    parser.add_argument("--bit-size", choices=("32", "64"), help="override kernel bitness")
    parser.add_argument("--base-address", help="kernel base address in hexadecimal")
    parser.add_argument("--use-absolute", action="store_true", help="pass --use-absolute")
    args = parser.parse_args()

    kernel = expanded_path(args.kernel)
    output = expanded_path(args.output)
    ensure_file(kernel, "kernel input")
    repo = required_env("VMLINUX_TO_ELF_REPO_DIR")
    if not repo.is_dir():
        raise RuntimeError(f"VMLINUX_TO_ELF_REPO_DIR is not a directory: {repo}")

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".kallsyms", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    command: List[Union[str, os.PathLike[str]]] = [
        sys.executable,
        "-m",
        MODULE,
        kernel,
        "--output",
        temporary,
    ]
    if args.bit_size is not None:
        command.extend(["--bit-size", args.bit_size])
    if args.base_address is not None:
        command.extend(["--base-address", args.base_address])
    if args.use_absolute:
        command.append("--use-absolute")

    try:
        result = run(command, env=python_env(repo), check=False)
        if result.returncode:
            raise RuntimeError(f"kallsyms-finder exited with status {result.returncode}")
        ensure_file(temporary, "embedded kallsyms output")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)

    print(f"Extracted embedded kallsyms: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"find_kallsyms: error: {error}", file=sys.stderr)
        raise SystemExit(1)
