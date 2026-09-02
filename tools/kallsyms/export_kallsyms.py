#!/usr/bin/env python3
"""Export vmlinux symbols in the compact format consumed by extract_target.py."""

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from common import atomic_output, command_path, ensure_file, expanded_path, first_command


def resolve_tool(
    override: Optional[str],
    environment_name: str,
    candidates: tuple[str, ...],
    description: str,
) -> str:
    selected = override or os.environ.get(environment_name)
    resolved = command_path(selected) if selected else first_command(*candidates)
    if resolved is None:
        choices = ", ".join(candidates)
        raise RuntimeError(f"{description} is not available ({choices})")
    return resolved


def export_nm(vmlinux: Path, output: Path, executable: str) -> None:
    with atomic_output(output) as temporary:
        with temporary.open("w", encoding="utf-8", newline="") as stream:
            result = subprocess.run(
                [executable, "-n", vmlinux],
                stdout=stream,
                text=True,
                check=False,
            )
        if result.returncode:
            raise RuntimeError(f"{executable} exited with status {result.returncode}")


def export_readelf(vmlinux: Path, output: Path, executable: str) -> int:
    result = subprocess.run(
        [executable, "--symbols", "--wide", vmlinux],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or f"exited with status {result.returncode}"
        raise RuntimeError(f"{executable}: {detail}")

    symbols: list[tuple[int, int, str, str]] = []
    for order, line in enumerate(result.stdout.splitlines()):
        fields = line.split()
        # readelf's table is:
        # Num: Value Size Type Bind Vis Ndx Name
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        try:
            address = int(fields[1], 16)
        except ValueError:
            continue
        name = fields[7]
        if name:
            symbols.append((address, order, fields[3], name))

    if not symbols:
        detail = result.stderr.strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"{executable} produced no ELF symbols{suffix}")

    symbols.sort(key=lambda item: (item[0], item[1]))
    with atomic_output(output) as temporary:
        with temporary.open("w", encoding="utf-8", newline="") as stream:
            for address, _, symbol_type, name in symbols:
                stream.write(f"{address:016x} {symbol_type} {name}\n")
    return len(symbols)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export vmlinux symbols; compact readelf format is the default."
    )
    parser.add_argument("vmlinux", type=Path, help="reconstructed ELF vmlinux")
    parser.add_argument("output", type=Path, help="symbol-list output, usually kallsyms.txt")
    parser.add_argument(
        "--format",
        choices=("readelf", "nm"),
        default=None,
        help="symbol type convention (default: readelf; nm is the compatibility fallback)",
    )
    parser.add_argument(
        "--readelf",
        help="readelf or llvm-readelf executable; defaults to READELF_PATH, readelf, then llvm-readelf",
    )
    parser.add_argument(
        "--nm",
        help="nm or llvm-nm executable; supplying this without --format selects nm output",
    )
    args = parser.parse_args()

    vmlinux = expanded_path(args.vmlinux)
    output = expanded_path(args.output)
    ensure_file(vmlinux, "vmlinux")
    if args.nm and args.readelf:
        parser.error("--nm and --readelf cannot be used together")
    if args.nm and args.format == "readelf":
        parser.error("--nm selects nm output; omit --format or use --format nm")
    selected_format = args.format or ("nm" if args.nm else "readelf")
    if selected_format == "readelf":
        executable = resolve_tool(
            args.readelf,
            "READELF_PATH",
            ("readelf", "llvm-readelf"),
            "ELF symbol reader",
        )
        count = export_readelf(vmlinux, output, executable)
        print(f"Exported {count} symbols with {executable} (readelf format): {output}")
    else:
        if args.readelf:
            parser.error("--readelf is only valid with --format readelf")
        executable = resolve_tool(
            args.nm,
            "NM_PATH",
            ("nm", "llvm-nm"),
            "nm symbol dumper",
        )
        export_nm(vmlinux, output, executable)
        print(f"Exported symbols with {executable} (nm format): {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"export_kallsyms: error: {error}", file=sys.stderr)
        raise SystemExit(1)
