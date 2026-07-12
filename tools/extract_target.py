#!/usr/bin/env python3
"""Extract target.h offsets from boot.img's embedded kallsyms table."""

import struct, sys, re, os

SYMBOLS_NEEDED = {
    "INIT_TASK_OFF": "init_task",
    "INIT_CRED_OFF": "init_cred",
    "INIT_UTS_NS_OFF": "init_uts_ns",
    "EMPTY_ZERO_PAGE_OFF": "empty_zero_page",
    "ROOT_TASK_GROUP_OFF": "root_task_group",
    "SELINUX_ENFORCING_OFF": "selinux_state",
    "KPTR_RESTRICT_OFF": "kptr_restrict",
    "SELINUX_BLOB_SIZES_OFF": "selinux_blob_sizes",
    "KMALLOC_CACHES_OFF": "kmalloc_caches",
    "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
    "SLIDE_NFULNL_LOGGER_OFF": "nfulnl_logger",
    "SLIDE_RANDOM_BOOT_ID_DATA_OFF": "sysctl_bootid",
    "SLIDE_SYSCTL_BOOTID_OFF": "sysctl_bootid",
}

FUNC_SYMBOLS = {
    "CONFIGFS_READ_ITER_OFF": "configfs_bin_read_iter",
    "CONFIGFS_BIN_WRITE_ITER_OFF": "configfs_bin_write_iter",
    "COPY_SPLICE_READ_OFF": "copy_splice_read",
    "NOOP_LLSEEK_OFF": "noop_llseek",
}

# Symbols needing special handling
SPECIAL_RULES = {
    # loggers[0][1] = loggers + 0x10
    "SLIDE_LOGGERS_0_1_OFF": ("loggers", 0x10),
    # Rust-mangled ashmem_fops
    "ASHMEM_FOPS_OFF": ("ASHMEM_FOPS_PTR", 0),
    # ashmem_misc = ashmem_fops - some_offset (search for pattern)
    "ASHMEM_MISC_FOPS_OFF": ("ashmem_misc", 0),
    # security_hook_heads = first security_hook_active - offset (0x68 typically)
    "SECURITY_HOOK_HEADS_OFF": ("security_hook_heads", 0),
}

def find_kallsyms_in_kernel(data):
    """Find and parse the embedded kallsyms table in a raw kernel image."""
    # Look for the linux_banner string to find kernel base
    banner_pat = b"Linux version "
    banner_idx = data.find(banner_pat)
    if banner_idx < 0:
        print(f"ERROR: linux_banner not found")
        return None, None

    banner_end = data.find(b'\x00', banner_idx)
    banner = data[banner_idx:banner_end].decode('ascii', errors='replace')
    print(f"Found: {banner[:80]}")

    # Find kallsyms markers - look for the token_table
    # The token table contains 256 entries of common substrings
    # It's followed by token_index (256 uint16 entries)

    # Strategy: search for known symbol names as raw strings
    # kallsyms stores names compressed with tokens, so search for
    # the uncompressed token fragments

    # Alternative: use the existing kallsyms file if available
    return None, banner

def parse_kallsyms_file(path):
    """Parse a kallsyms text file (from /proc/kallsyms or nm output)."""
    symbols = {}
    with open(path, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 3:
                addr = int(parts[0], 16)
                typ = parts[1]
                name = parts[2]
                if addr > 0:
                    symbols[name] = (addr, typ)
    return symbols

def find_symbol(symbols, sym_name):
    """Find a symbol by exact match, then substring match."""
    # Exact match
    if sym_name in symbols:
        return symbols[sym_name][0]
    # Substring match (for Rust-mangled names etc)
    for name, (addr, typ) in symbols.items():
        if sym_name in name and addr > 0:
            return addr
    return None

def compute_offsets(symbols, kimage_base):
    """Compute target.h offsets from symbol addresses."""
    results = {}

    # Standard symbols
    for define_name, sym_name in {**SYMBOLS_NEEDED, **FUNC_SYMBOLS}.items():
        addr = find_symbol(symbols, sym_name)
        results[define_name] = (addr - kimage_base) if addr else None

    # Special rules
    # loggers[0][1] = loggers + 0x10
    addr = find_symbol(symbols, "loggers")
    if addr:
        results["SLIDE_LOGGERS_0_1_OFF"] = addr - kimage_base + 0x10

    # ashmem_fops (Rust mangled)
    addr = find_symbol(symbols, "ASHMEM_FOPS_PTR")
    if addr:
        results["ASHMEM_FOPS_OFF"] = addr - kimage_base

    # security_hook_heads — derive from first security_hook_active symbol
    first_active = None
    for name, (addr, typ) in sorted(symbols.items(), key=lambda x: x[1][0]):
        if "security_hook_active_" in name and addr > kimage_base:
            first_active = addr
            break
    if first_active:
        # hook_heads is a struct before the active array
        # Each hook has: list_head(16) + bool(active, padded to 8) = ~24 bytes per hook
        # But the exact offset depends on the struct. Use known relationship:
        # security_hook_heads is typically 0x68 before the first active bool
        # Actually, search for the symbol directly
        hh = find_symbol(symbols, "security_hook_heads")
        if hh:
            results["SECURITY_HOOK_HEADS_OFF"] = hh - kimage_base

    # ashmem functions — Rust mangled names
    # Pattern: fops_<func>NtCs...ashmem_rust6Ashmem (the non-toggle variant)
    ashmem_rust_map = {
        "ASHMEM_IOCTL_OFF": "fops_ioctl",
        "ASHMEM_COMPAT_IOCTL_OFF": "fops_compat_ioctl",
        "ASHMEM_MMAP_OFF": "fops_mmap",
        "ASHMEM_OPEN_OFF": "fops_open",
        "ASHMEM_RELEASE_OFF": "fops_release",
        "ASHMEM_SHOW_FDINFO_OFF": "fops_show_fdinfo",
    }
    for define_name, func_frag in ashmem_rust_map.items():
        for name, (addr, typ) in symbols.items():
            # Match: fops_<func>...ashmem_rust6Ashmem (not toggle variants)
            if func_frag in name and "ashmem_rust6Ashmem" in name and "toggle" not in name.lower():
                results[define_name] = addr - kimage_base
                break

    # Old kernel uses different mangling: MiscdeviceVTable...6AshmemE5ioctl etc
    if "ASHMEM_IOCTL_OFF" not in results or results["ASHMEM_IOCTL_OFF"] is None:
        old_map = {
            "ASHMEM_IOCTL_OFF": "6AshmemE5ioctl",
            "ASHMEM_COMPAT_IOCTL_OFF": "6AshmemE12compat_ioctl",
            "ASHMEM_MMAP_OFF": "6AshmemE4mmap",
            "ASHMEM_OPEN_OFF": "6AshmemE4open",
            "ASHMEM_RELEASE_OFF": "6AshmemE7release",
            "ASHMEM_SHOW_FDINFO_OFF": "6AshmemE11show_fdinfo",
        }
        for define_name, frag in old_map.items():
            for name, (addr, typ) in symbols.items():
                if frag in name and "toggle" not in name.lower():
                    results[define_name] = addr - kimage_base
                    break

    # ASHMEM_MISC_FOPS — search for misc device registration struct
    # It's typically near ashmem_fops. Search for "ashmem_misc" or "ashmem" misc pattern
    addr = find_symbol(symbols, "ashmem_misc")
    if not addr:
        # Try Rust mangled misc device name
        for name, (a, typ) in symbols.items():
            if "AshmemModule" in name and typ in ('d', 'D', 'b', 'B'):
                addr = a
                break
    if addr:
        results["ASHMEM_MISC_FOPS_OFF"] = addr - kimage_base

    # security_hook_heads — derive from security_hook_active symbols
    if "SECURITY_HOOK_HEADS_OFF" not in results or results.get("SECURITY_HOOK_HEADS_OFF") is None:
        for name, (addr, typ) in sorted(symbols.items(), key=lambda x: x[1][0]):
            if "security_hook_heads" in name:
                results["SECURITY_HOOK_HEADS_OFF"] = addr - kimage_base
                break

    # CAP_CAPABLE_ACTIVE_OFF
    for name, (addr, typ) in symbols.items():
        if "security_hook_active_capable_0" in name:
            results["CAP_CAPABLE_ACTIVE_OFF"] = addr - kimage_base
            break

    return results

def main():
    # Check for existing kallsyms file
    kallsyms_path = None
    for p in ["C:/Android/kallsyms_fresh.txt", "C:/Android/kallsyms.txt"]:
        if os.path.exists(p):
            kallsyms_path = p
            break

    if not kallsyms_path:
        print("ERROR: No kallsyms file found. Provide /proc/kallsyms dump or extract from vmlinux.")
        print("  With root: adb shell su -c 'cat /proc/kallsyms' > kallsyms.txt")
        print("  From boot.img: nm vmlinux > kallsyms.txt")
        sys.exit(1)

    print(f"Using kallsyms: {kallsyms_path}")
    symbols = parse_kallsyms_file(kallsyms_path)
    print(f"Loaded {len(symbols)} symbols")

    # Detect KIMAGE_TEXT_BASE from _text symbol
    if "_text" in symbols:
        kimage_base = symbols["_text"][0]
    elif "_head" in symbols:
        kimage_base = symbols["_head"][0]
    else:
        # Guess from first symbol
        first_addr = min(addr for addr, _ in symbols.values() if addr > 0xffffff0000000000)
        kimage_base = first_addr & ~0xFFFFF  # Align to 1MB

    print(f"KIMAGE_TEXT_BASE = 0x{kimage_base:016X}")

    results = compute_offsets(symbols, kimage_base)

    # Read current target.h for comparison
    target_h = "C:/Users/Lxns/Downloads/ghostlock_ace6t_full (1)/exploit/src/targets/ace6t/target.h"
    current = {}
    if os.path.exists(target_h):
        with open(target_h, encoding='utf-8') as f:
            for line in f:
                m = re.match(r'#define\s+(\w+_OFF)\s+(0x[0-9a-fA-F]+)', line)
                if m:
                    current[m.group(1)] = int(m.group(2), 16)

    print("\n=== Extracted Offsets ===")
    print(f"{'Define':<40} {'Extracted':>14} {'Current':>14} {'Match':>6}")
    print("-" * 80)

    all_match = True
    for name in sorted(results.keys()):
        extracted = results[name]
        cur = current.get(name)

        if extracted is not None:
            ext_str = f"0x{extracted:08X}"
        else:
            ext_str = "NOT FOUND"

        if cur is not None:
            cur_str = f"0x{cur:08X}"
        else:
            cur_str = "N/A"

        if extracted is not None and cur is not None:
            match = "OK" if extracted == cur else "DIFF!"
            if match == "DIFF!":
                all_match = False
        elif extracted is None:
            match = "MISS"
            all_match = False
        else:
            match = "NEW"

        print(f"{name:<40} {ext_str:>14} {cur_str:>14} {match:>6}")

    print(f"\n{'ALL MATCH' if all_match else 'DIFFERENCES FOUND'}")

    verify_offsets(results, symbols, kimage_base)

def verify_offsets(results, symbols, kimage_base):
    """Cross-validate extracted offsets using symbol relationships."""
    errors = []
    warnings = []

    def check(cond, msg):
        (errors if not cond else []).append(msg) if not cond else None

    def sym_type(name):
        for n, (a, t) in symbols.items():
            if n == name:
                return t
        return None

    def sym_section(off):
        """Guess section from offset range."""
        if off is None:
            return "?"
        if off < 0x01000000:
            return ".text"
        if off < 0x02000000:
            return ".rodata/.data"
        return ".data/.bss"

    print("\n=== Verification ===")

    # 1. Symbol type checks
    type_checks = {
        "init_task": ("D", "B", "d", "b"),    # data/bss
        "init_cred": ("D", "d"),               # data (initialized)
        "selinux_state": ("B", "b"),            # bss
        "loggers": ("D", "d"),                  # data
        "noop_llseek": ("T", "t"),              # text (function)
        "copy_splice_read": ("T", "t"),         # text
    }
    for sym_name, expected_types in type_checks.items():
        t = sym_type(sym_name)
        if t and t not in expected_types:
            errors.append(f"  {sym_name}: type='{t}', expected one of {expected_types}")
        elif t:
            print(f"  [OK] {sym_name} type='{t}'")

    # 2. Function offsets should be in .text range (< ~0x01800000 typically)
    func_syms = ["NOOP_LLSEEK_OFF", "COPY_SPLICE_READ_OFF", "CONFIGFS_READ_ITER_OFF",
                 "CONFIGFS_BIN_WRITE_ITER_OFF"]
    for name in func_syms:
        off = results.get(name)
        if off and off > 0x02000000:
            errors.append(f"  {name}=0x{off:X} looks too high for .text")
        elif off:
            print(f"  [OK] {name}=0x{off:08X} in .text range")

    # 3. Data offsets should be > 0x01000000
    data_syms = ["INIT_TASK_OFF", "INIT_CRED_OFF", "SELINUX_ENFORCING_OFF",
                 "ROOT_TASK_GROUP_OFF", "EMPTY_ZERO_PAGE_OFF"]
    for name in data_syms:
        off = results.get(name)
        if off and off < 0x01000000:
            errors.append(f"  {name}=0x{off:X} looks too low for .data/.bss")
        elif off:
            print(f"  [OK] {name}=0x{off:08X} in .data/.bss range")

    # 4. SLIDE_RANDOM_BOOT_ID_DATA == SLIDE_SYSCTL_BOOTID (same symbol)
    a = results.get("SLIDE_RANDOM_BOOT_ID_DATA_OFF")
    b = results.get("SLIDE_SYSCTL_BOOTID_OFF")
    if a and b:
        if a == b:
            print(f"  [OK] SLIDE_RANDOM_BOOT_ID_DATA == SLIDE_SYSCTL_BOOTID")
        else:
            errors.append(f"  SLIDE_RANDOM_BOOT_ID_DATA (0x{a:X}) != SLIDE_SYSCTL_BOOTID (0x{b:X})")

    # 5. SLIDE_LOGGERS_0_1 should be SLIDE_NFULNL_LOGGER - 0xB0 (typically close)
    a = results.get("SLIDE_LOGGERS_0_1_OFF")
    b = results.get("SLIDE_NFULNL_LOGGER_OFF")
    if a and b:
        diff = b - a
        if 0 < diff < 0x200:
            print(f"  [OK] LOGGERS_0_1 + 0x{diff:X} = NFULNL_LOGGER (close, expected)")
        else:
            warnings.append(f"  LOGGERS_0_1 to NFULNL_LOGGER gap=0x{diff:X} (unusual)")

    # 6. INIT_TASK and INIT_CRED should be relatively close (same .data section)
    a = results.get("INIT_TASK_OFF")
    b = results.get("INIT_CRED_OFF")
    if a and b:
        diff = abs(b - a)
        if diff < 0x100000:
            print(f"  [OK] INIT_TASK to INIT_CRED gap=0x{diff:X} (same section)")
        else:
            warnings.append(f"  INIT_TASK to INIT_CRED gap=0x{diff:X} (far apart)")

    # 7. Ashmem functions should be close together (same compilation unit)
    ashmem_offs = [results.get(k) for k in
                   ["ASHMEM_IOCTL_OFF", "ASHMEM_MMAP_OFF", "ASHMEM_OPEN_OFF",
                    "ASHMEM_RELEASE_OFF", "ASHMEM_SHOW_FDINFO_OFF", "ASHMEM_COMPAT_IOCTL_OFF"]
                   if results.get(k) is not None]
    if len(ashmem_offs) >= 2:
        span = max(ashmem_offs) - min(ashmem_offs)
        if span < 0x10000:
            print(f"  [OK] ashmem functions span=0x{span:X} (tight, same module)")
        else:
            warnings.append(f"  ashmem functions span=0x{span:X} (spread out)")

    # 8. SELINUX_ENFORCING should be near SELINUX_BLOB_SIZES (same subsystem)
    a = results.get("SELINUX_ENFORCING_OFF")
    b = results.get("SELINUX_BLOB_SIZES_OFF")
    if a and b and abs(a - b) > 0x200000:
        warnings.append(f"  SELINUX_ENFORCING to BLOB_SIZES gap=0x{abs(a-b):X} (far)")

    # 9. KIMAGE_TEXT_BASE sanity
    if kimage_base & 0xFFF:
        errors.append(f"  KIMAGE_TEXT_BASE=0x{kimage_base:X} not page-aligned!")
    else:
        print(f"  [OK] KIMAGE_TEXT_BASE=0x{kimage_base:X} page-aligned")

    # 10. No offset should be zero or negative
    for name, off in results.items():
        if off is not None and off <= 0:
            errors.append(f"  {name}=0x{off:X} invalid (zero or negative)")

    # 11. No duplicates (except BOOTID pair)
    seen = {}
    for name, off in results.items():
        if off is None:
            continue
        if "BOOTID" in name:
            continue
        if off in seen:
            warnings.append(f"  {name} and {seen[off]} have same offset 0x{off:X}")
        seen[off] = name

    # Summary
    print(f"\n  Errors: {len(errors)}")
    for e in errors:
        print(f"    [FAIL] {e}")
    print(f"  Warnings: {len(warnings)}")
    for w in warnings:
        print(f"    [WARN] {w}")

    ok = len(errors) == 0
    print(f"\n  {'VERIFICATION PASSED' if ok else 'VERIFICATION FAILED'}")
    return ok


if __name__ == "__main__":
    main()
