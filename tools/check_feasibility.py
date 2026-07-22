#!/usr/bin/env python3
"""
GhostLock pselect stack overlay feasibility checker.

Given a raw ARM64 kernel Image, determines whether the pselect fd_set
stack overlay can reach the freed rt_mutex_waiter's task/lock fields.

Usage: python check_feasibility.py <kernel_image>

Requires: capstone (pip install capstone)
"""

import sys
import struct
import os

def find_kallsyms(data):
    """Extract kallsyms from raw kernel image using vmlinux_to_elf."""
    try:
        sys.argv = ['kallsyms_finder', '/dev/null']
        script = os.path.join(os.path.dirname(__file__),
                              '..', '..', '..',
                              'Python311', 'Lib', 'site-packages',
                              'vmlinux_to_elf', 'scripts', 'kallsyms_finder.py')
        # Try using vmlinux_to_elf programmatically
        pass
    except:
        pass

    # Fallback: search for kallsyms manually
    # Look for the _text symbol pattern
    syms = {}

    # Find "futex_wait_requeue_pi" string
    for name in [b'futex_wait_requeue_pi', b'core_sys_select',
                 b'do_tcp_getsockopt', b'_text']:
        pos = data.find(name + b'\x00')
        if pos >= 0:
            syms[name.decode()] = pos

    return syms


def find_function_offset(data, name_bytes):
    """Find a function's file offset by searching kallsyms name table."""
    pos = data.find(name_bytes + b'\x00')
    if pos < 0:
        return None
    return pos


def disasm_prologue(data, offset, max_bytes=200):
    """Disassemble ARM64 function prologue to find frame size and key offsets."""
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        print("ERROR: capstone not installed. Run: pip install capstone")
        sys.exit(1)

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    code = data[offset:offset + max_bytes]

    frame_size = 0
    stp_sub = 0

    for insn in md.disasm(code, 0):
        # Look for: sub sp, sp, #IMM
        if insn.mnemonic == 'sub' and 'sp' in insn.op_str and '#' in insn.op_str:
            parts = insn.op_str.split('#')
            if len(parts) >= 2:
                try:
                    val = int(parts[-1].strip().rstrip(']'), 0)
                    frame_size += val
                except:
                    pass

        # Look for: stp x29, x30, [sp, #-IMM]!
        if insn.mnemonic == 'stp' and 'sp' in insn.op_str and '-' in insn.op_str:
            parts = insn.op_str.split('#-')
            if len(parts) >= 2:
                try:
                    val = int(parts[-1].strip().rstrip(']!'), 0)
                    stp_sub = val
                except:
                    pass

        # Stop after finding the frame setup (usually first few instructions)
        if frame_size > 0 and insn.mnemonic not in ('sub', 'stp', 'mov', 'add', 'str'):
            break

    return frame_size + stp_sub


def find_variable_offset(data, func_offset, pattern_name, max_bytes=800):
    """Search for stack variable allocation patterns in ARM64 code."""
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        return None

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    code = data[func_offset:func_offset + max_bytes]

    # For waiter: look for sequences of "str xzr, [sp, #OFFSET]" (zero init)
    # or "add Xn, sp, #OFFSET" followed by use as waiter pointer
    zero_stores = []
    add_sp_offsets = []

    for insn in md.disasm(code, 0):
        op = insn.op_str

        # str xzr, [sp, #IMM]
        if insn.mnemonic == 'str' and 'xzr' in op and 'sp' in op and '#' in op:
            parts = op.split('#')
            if len(parts) >= 2:
                try:
                    val = int(parts[-1].strip().rstrip(']'), 0)
                    zero_stores.append(val)
                except:
                    pass

        # stp xzr, xzr, [sp, #IMM]
        if insn.mnemonic == 'stp' and 'xzr, xzr' in op and 'sp' in op and '#' in op:
            parts = op.split('#')
            if len(parts) >= 2:
                try:
                    val = int(parts[-1].strip().rstrip(']'), 0)
                    zero_stores.append(val)
                    zero_stores.append(val + 8)
                except:
                    pass

        # add Xn, sp, #IMM
        if insn.mnemonic == 'add' and 'sp' in op and '#' in op and 'x' in op.split(',')[0]:
            parts = op.split('#')
            if len(parts) >= 2:
                try:
                    val = int(parts[-1].strip().rstrip(']'), 0)
                    add_sp_offsets.append(val)
                except:
                    pass

    return sorted(set(zero_stores)), sorted(set(add_sp_offsets))


def extract_kernel_from_bootimg(path):
    """Extract raw kernel from boot.img if needed."""
    with open(path, 'rb') as f:
        header = f.read(16)

    if header[:8] == b'ANDROID!':
        with open(path, 'rb') as f:
            data = f.read()

        # Find ARM64 magic
        magic = bytes.fromhex('41524d64')
        pos = data.find(magic)
        if pos >= 0:
            kernel_start = pos - 0x38
            image_size = struct.unpack('<Q', data[kernel_start+0x10:kernel_start+0x18])[0]
            return data[kernel_start:kernel_start + image_size]

        # Try gzip
        gz_pos = data.find(b'\x1f\x8b\x08')
        if gz_pos >= 0:
            import gzip
            kernel_size = struct.unpack('<I', data[8:12])[0]
            return gzip.decompress(data[gz_pos:gz_pos + kernel_size])

    # Already a raw kernel
    with open(path, 'rb') as f:
        return f.read()


def find_functions_via_kallsyms(data):
    """Use vmlinux_to_elf to extract kallsyms, return dict of name->offset."""
    import tempfile, subprocess

    tmp = tempfile.NamedTemporaryFile(suffix='.raw', delete=False)
    tmp.write(data)
    tmp.close()

    try:
        result = subprocess.run(
            [sys.executable, '-c', f"""
import sys, os
sys.argv = ['kallsyms_finder', '{tmp.name}']
# Find the script
for base in [os.path.join(os.path.dirname(sys.executable), 'Lib', 'site-packages'),
             os.path.join(os.path.dirname(os.path.dirname(sys.executable)), 'lib',
                          'python' + '.'.join(map(str, sys.version_info[:2])), 'site-packages')]:
    script = os.path.join(base, 'vmlinux_to_elf', 'scripts', 'kallsyms_finder.py')
    if os.path.exists(script):
        exec(open(script).read())
        break
"""],
            capture_output=True, text=True, timeout=60
        )

        syms = {}
        text_base = None
        for line in result.stdout.split('\n'):
            parts = line.strip().split()
            if len(parts) >= 3:
                try:
                    addr = int(parts[0], 16)
                    name = parts[-1]
                    syms[name] = addr
                    if name == '_text':
                        text_base = addr
                except:
                    pass

        return syms, text_base

    except Exception as e:
        print(f"  kallsyms extraction failed: {e}")
        return {}, None
    finally:
        os.unlink(tmp.name)


def main():
    if len(sys.argv) < 2:
        print("Usage: python check_feasibility.py <kernel_image_or_boot.img>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"[*] Loading {path}...")
    data = extract_kernel_from_bootimg(path)
    print(f"[*] Kernel size: {len(data)} bytes ({len(data)/1024/1024:.1f}MB)")

    # Find kernel version
    ver_pos = data.find(b'Linux version ')
    if ver_pos >= 0:
        ver = data[ver_pos:ver_pos+200].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"[*] {ver[:120]}")

    # Extract kallsyms
    print(f"[*] Extracting kallsyms...")
    syms, text_base = find_functions_via_kallsyms(data)

    if not text_base:
        print("[-] Could not find _text base address")
        sys.exit(1)

    print(f"[+] _text base: 0x{text_base:016x}")
    print(f"[+] Total symbols: {len(syms)}")

    # Find key functions
    needed = ['futex_wait_requeue_pi', 'core_sys_select', 'do_tcp_getsockopt']
    for name in needed:
        if name not in syms:
            print(f"[-] {name} not found in kallsyms")
            if name != 'do_tcp_getsockopt':
                sys.exit(1)
        else:
            offset = syms[name] - text_base
            print(f"[+] {name}: 0x{syms[name]:016x} (file offset 0x{offset:x})")

    # Disassemble prologues
    print(f"\n[*] Analyzing stack frames...")

    futex_off = syms['futex_wait_requeue_pi'] - text_base
    select_off = syms['core_sys_select'] - text_base

    futex_frame = disasm_prologue(data, futex_off)
    select_frame = disasm_prologue(data, select_off)

    print(f"[+] futex_wait_requeue_pi: frame = 0x{futex_frame:x} ({futex_frame} bytes)")
    print(f"[+] core_sys_select:       frame = 0x{select_frame:x} ({select_frame} bytes)")

    # Find variable positions
    futex_zeros, futex_adds = find_variable_offset(data, futex_off, 'waiter')
    select_zeros, select_adds = find_variable_offset(data, select_off, 'stack_fds')

    # Heuristic: waiter is the largest contiguous zero-init region in futex
    # stack_fds is at the add Xn, sp, #OFFSET used for the buffer pointer
    waiter_offset = None
    if futex_zeros:
        # Find contiguous groups of zero stores (waiter init)
        groups = []
        current = [futex_zeros[0]]
        for z in futex_zeros[1:]:
            if z - current[-1] <= 16:
                current.append(z)
            else:
                groups.append(current)
                current = [z]
        groups.append(current)

        # Largest group is likely the waiter
        largest = max(groups, key=len)
        waiter_offset = largest[0]
        waiter_size = largest[-1] - largest[0] + 8
        print(f"[+] Likely waiter at futex sp+0x{waiter_offset:x} "
              f"(size ~0x{waiter_size:x}, {len(largest)} zero stores)")

    fds_offset = None
    if select_zeros:
        # stack_fds zero init: look for 32 consecutive zeros (256 bytes)
        groups = []
        current = [select_zeros[0]]
        for z in select_zeros[1:]:
            if z - current[-1] <= 16:
                current.append(z)
            else:
                groups.append(current)
                current = [z]
        groups.append(current)

        largest = max(groups, key=len)
        fds_offset = largest[0]
        fds_size = largest[-1] - largest[0] + 8
        print(f"[+] Likely stack_fds at select sp+0x{fds_offset:x} "
              f"(size ~0x{fds_size:x}, {len(largest)} zero stores)")

    if waiter_offset is None or fds_offset is None:
        print("[-] Could not determine variable offsets from disassembly")
        print("[*] Falling back to frame-size-only estimate...")
        # Use frame sizes as rough estimate
        # Typical: waiter near middle of futex frame, fds near start of select frame
        print(f"[*] Frame size difference: {futex_frame - select_frame:+d} bytes")
        if futex_frame > select_frame:
            print("[!] futex frame larger than select frame — waiter likely in controllable zone")
        else:
            print("[!] select frame larger — need detailed analysis")
        sys.exit(0)

    # Calculate waiter word position
    # Both functions called from the same thread, so kernel stack base is same.
    # Entry SP differs per function (from syscall dispatch depth).
    # We can't know exact entry SP without kprobe, but we CAN compute relative
    # positions using frame sizes and variable offsets.
    #
    # waiter_abs = entry_SP_futex - futex_frame + waiter_offset
    # fds_abs = entry_SP_select - select_frame + fds_offset
    # waiter_word = (waiter_abs - fds_abs) / 8
    #
    # Without kprobe, we assume entry SPs are similar (within ~128 bytes).
    # Use SP=0 as reference and compute relative.

    # For a rough estimate, assume entry SP difference is 0
    # (conservative — actual SP diff shifts the result)
    waiter_word_est = ((-futex_frame + waiter_offset) - (-select_frame + fds_offset)) // 8

    print(f"\n{'='*60}")
    print(f"  FEASIBILITY ESTIMATE (without kprobe SP measurement)")
    print(f"{'='*60}")
    print(f"  Waiter: futex sp+0x{waiter_offset:x} (frame 0x{futex_frame:x})")
    print(f"  Fds:    select sp+0x{fds_offset:x} (frame 0x{select_frame:x})")
    print(f"  Est. waiter word: {waiter_word_est} (assumes same entry SP)")
    print(f"")
    print(f"  Controllable zone: words 0-14 (NFDS=320)")
    print(f"  rt_waiter_node:    task at word+10, lock at word+11")
    print(f"  Max feasible word: 3 (3+11=14)")
    print(f"")

    # Determine struct layout
    if waiter_size and waiter_size >= 0x60:
        layout = "rt_waiter_node (0x70)"
        task_rel = 10
        lock_rel = 11
    else:
        layout = "plain rb_node (0x58)"
        task_rel = 6
        lock_rel = 7

    max_word = 14 - lock_rel

    print(f"  Waiter layout: {layout}")
    print(f"  Task at waiter+{task_rel}, Lock at waiter+{lock_rel}")
    print(f"  Max feasible waiter word: {max_word}")
    print(f"")

    # Note: this is an estimate. SP diff from kprobe adjusts the result.
    # Typical SP diffs observed: -64 (good), +16 (bad), +32 (bad)

    # Show range for different SP diffs
    print(f"  Waiter word with different SP diffs:")
    for sp_diff in [-128, -64, -32, 0, 16, 32, 64, 128]:
        word = waiter_word_est + sp_diff // 8
        feasible = "FEASIBLE" if word <= max_word and word >= -2 else "INFEASIBLE"
        marker = " <<<" if sp_diff in [-64, 0, 16, 32] else ""
        print(f"    SP diff {sp_diff:+4d}: word {word:3d}  {feasible}{marker}")

    print(f"")
    print(f"  To get exact result, run QEMU kprobe test.")
    print(f"  Quick rule: if SP diff ≤ 0, likely feasible.")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
