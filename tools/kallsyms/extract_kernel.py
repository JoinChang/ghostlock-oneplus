#!/usr/bin/env python3
"""Extract a boot image's kernel payload.

The default path parses standard AOSP boot images with the Python standard
library.  MAGISKBOOT_PATH can be supplied for formats that are outside that
small parser; magiskboot also performs the decompression that its unpack
command normally performs.
"""

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import os
import shutil
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from common import atomic_output, command_path, ensure_file, expanded_path, run


ANDROID_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
FDT_BEGIN_NODE = 1
MIN_NON_EMPTY_DTB_SIZE = 0x48


def u32_le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise RuntimeError(f"boot image is too small to read offset 0x{offset:x}")
    return int.from_bytes(data[offset : offset + 4], "little")


def u32_be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise RuntimeError(f"DTB is too small to read offset 0x{offset:x}")
    return int.from_bytes(data[offset : offset + 4], "big")


def plausible_legacy_page_size(page_size: int) -> bool:
    return 512 <= page_size <= 1024 * 1024 and page_size & (page_size - 1) == 0


def detect_header_version(data: bytes, forced: Optional[int]) -> int:
    if forced is not None:
        return forced

    candidate = u32_le(data, 40)
    # A v3/v4 header has a fixed 4096-byte page and reserved bytes where a
    # legacy header stores page_size.  A legacy image's page_size wins when
    # the same offset happens to contain the value 3 or 4.
    if candidate in (3, 4):
        legacy_page_size = u32_le(data, 36)
        v3_header_size = u32_le(data, 20)
        if not plausible_legacy_page_size(legacy_page_size) and 44 <= v3_header_size <= 4096:
            return candidate
        return 0
    return candidate if candidate in (1, 2) else 0


def valid_dtb(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 40 > len(data) or data[offset : offset + 4] != FDT_MAGIC:
        return False

    total_size = u32_be(data, offset + 4)
    off_struct = u32_be(data, offset + 8)
    off_strings = u32_be(data, offset + 12)
    off_mem_rsvmap = u32_be(data, offset + 16)
    version = u32_be(data, offset + 20)
    last_comp_version = u32_be(data, offset + 24)
    size_strings = u32_be(data, offset + 32)
    size_struct = u32_be(data, offset + 36)

    if total_size <= MIN_NON_EMPTY_DTB_SIZE or offset + total_size > len(data):
        return False
    if not 16 <= version <= 21 or last_comp_version > version:
        return False
    if off_mem_rsvmap + 16 > total_size:
        return False
    if off_struct + size_struct > total_size or off_strings + size_strings > total_size:
        return False

    struct_start = offset + off_struct
    if struct_start + 4 > offset + total_size:
        return False
    if u32_be(data, struct_start) != FDT_BEGIN_NODE:
        return False
    try:
        name_end = data.index(b"\0", struct_start + 4, offset + total_size)
    except ValueError:
        return False
    return name_end < offset + total_size


def find_dtb_offset(kernel: bytes) -> Optional[int]:
    search_from = 0
    while True:
        relative = kernel.find(FDT_MAGIC, search_from)
        if relative < 0:
            return None
        if relative > 0 and valid_dtb(kernel, relative):
            return relative
        search_from = relative + len(FDT_MAGIC)


def parse_aosp_kernel(data: bytes, forced_version: Optional[int]) -> Tuple[bytes, Optional[bytes], int]:
    magic_offset = data.find(ANDROID_MAGIC)
    if magic_offset < 0:
        if data.startswith(VENDOR_BOOT_MAGIC):
            raise RuntimeError(
                "this is vendor_boot.img; its kernel normally comes from boot.img, not vendor_boot.img"
            )
        raise RuntimeError("ANDROID! boot magic was not found")

    header = data[magic_offset:]
    if len(header) < 44:
        raise RuntimeError("AOSP boot header is truncated")
    version = detect_header_version(header, forced_version)
    if version >= 3:
        page_size = 4096
    else:
        page_size = u32_le(header, 36)
        if not plausible_legacy_page_size(page_size):
            raise RuntimeError(
                f"invalid legacy page size {page_size}; use MAGISKBOOT_PATH for this image"
            )

    kernel_size = u32_le(header, 8)
    kernel_start = magic_offset + page_size
    kernel_end = kernel_start + kernel_size
    if kernel_size == 0:
        raise RuntimeError("boot image contains an empty kernel section")
    if kernel_start > len(data) or kernel_end > len(data):
        raise RuntimeError(
            f"kernel section [{kernel_start}, {kernel_end}) extends past the {len(data)}-byte image"
        )

    kernel = data[kernel_start:kernel_end]
    dtb_offset = find_dtb_offset(kernel)
    if dtb_offset is None:
        return kernel, None, version
    return kernel[:dtb_offset], kernel[dtb_offset:], version


def extract_with_magiskboot(
    image: Path, output: Path, dtb_output: Optional[Path], magiskboot: str
) -> None:
    resolved = command_path(magiskboot)
    if resolved is None:
        raise RuntimeError(f"MAGISKBOOT_PATH is not an executable file: {magiskboot}")

    with tempfile.TemporaryDirectory(prefix="magiskboot-unpack-") as temporary_dir:
        work = Path(temporary_dir)
        run([resolved, "unpack", image], cwd=work)
        kernel = work / "kernel"
        ensure_file(kernel, "magiskboot's kernel output")
        with atomic_output(output) as temporary:
            shutil.copyfile(kernel, temporary)

        if dtb_output is not None:
            kernel_dtb = work / "kernel_dtb"
            if kernel_dtb.is_file() and kernel_dtb.stat().st_size:
                with atomic_output(dtb_output) as temporary:
                    shutil.copyfile(kernel_dtb, temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract the kernel payload from an Android boot image.")
    parser.add_argument("image", type=Path, help="boot.img or another supported boot image")
    parser.add_argument("output", type=Path, help="raw/compressed kernel output")
    parser.add_argument("--dtb-output", type=Path, help="optional output for an appended kernel DTB")
    parser.add_argument(
        "--magiskboot",
        help="host magiskboot executable; defaults to MAGISKBOOT_PATH when set",
    )
    parser.add_argument(
        "--header-version",
        type=int,
        choices=range(5),
        help="override AOSP header detection (0 through 4)",
    )
    args = parser.parse_args()

    image = expanded_path(args.image)
    output = expanded_path(args.output)
    dtb_output = expanded_path(args.dtb_output) if args.dtb_output else None
    ensure_file(image, "boot image")

    magiskboot = args.magiskboot or os.environ.get("MAGISKBOOT_PATH")
    if magiskboot:
        extract_with_magiskboot(image, output, dtb_output, magiskboot)
        print(f"Extracted kernel with magiskboot: {output}")
        if dtb_output and dtb_output.is_file():
            print(f"Extracted appended DTB: {dtb_output}")
        return 0

    data = image.read_bytes()
    kernel, dtb, version = parse_aosp_kernel(data, args.header_version)
    with atomic_output(output) as temporary:
        temporary.write_bytes(kernel)
    if dtb_output is not None and dtb is not None:
        with atomic_output(dtb_output) as temporary:
            temporary.write_bytes(dtb)

    print(f"Extracted AOSP boot header v{version} kernel: {output}")
    if dtb is not None:
        print(f"Extracted appended DTB: {dtb_output or '(not saved; pass --dtb-output to keep it)'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"extract_kernel: error: {error}", file=sys.stderr)
        raise SystemExit(1)
