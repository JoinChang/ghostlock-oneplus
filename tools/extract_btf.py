#!/usr/bin/env python3
"""Extract struct field offsets from BTF - direct search approach."""
import struct, sys, re, os

def find_btf(data):
    pattern = struct.pack('<HBB', 0xEB9F, 1, 0)
    idx = 0
    while True:
        idx = data.find(pattern, idx)
        if idx < 0: return -1
        hdr_len = struct.unpack_from('<I', data, idx+4)[0]
        if hdr_len == 24:
            type_len = struct.unpack_from('<I', data, idx+12)[0]
            str_len = struct.unpack_from('<I', data, idx+20)[0]
            if type_len > 1000 and str_len > 1000:
                return idx
        idx += 1

def get_btf_string(str_data, off):
    end = str_data.find(b'\x00', off)
    return str_data[off:end].decode('ascii', errors='replace') if end > off else ""

def find_struct_in_btf(type_data, str_data, target_name):
    """Brute-force search for a STRUCT type with matching name."""
    target_bytes = target_name.encode('ascii')
    # Find all positions in str_data where target_name occurs as a null-terminated string
    name_offsets = []
    pos = 0
    while True:
        idx = str_data.find(b'\x00' + target_bytes + b'\x00', pos)
        if idx < 0: break
        name_offsets.append(idx + 1)
        pos = idx + 1

    # Also check offset 0
    if str_data.startswith(target_bytes + b'\x00'):
        name_offsets.insert(0, 0)

    results = []
    for name_off in name_offsets:
        # Search type_data for entries with this name_off and kind=4 (STRUCT)
        for p in range(0, len(type_data) - 12, 4):  # 4-byte aligned scan
            no = struct.unpack_from('<I', type_data, p)[0]
            if no != name_off: continue
            info = struct.unpack_from('<I', type_data, p+4)[0]
            kind = (info >> 24) & 0x1F
            if kind != 4: continue  # STRUCT only
            vlen = info & 0xFFFF
            size = struct.unpack_from('<I', type_data, p+8)[0]
            if size < 8 or size > 65536: continue  # sanity
            if vlen < 1 or vlen > 500: continue

            # Parse members
            members = []
            mpos = p + 12
            kflag = (info >> 31) & 1
            valid = True
            for _ in range(vlen):
                if mpos + 12 > len(type_data):
                    valid = False; break
                mn, mt, mo = struct.unpack_from('<III', type_data, mpos)
                mpos += 12
                mname = get_btf_string(str_data, mn)
                bit_off = (mo & 0xFFFFFF) if kflag else mo
                members.append((mname, bit_off // 8))

            if valid and len(members) == vlen:
                results.append((size, members))

    return results

FIELDS_NEEDED = {
    "task_struct": {
        "usage": "FAKE_TASK_USAGE_OFF",
        "prio": "FAKE_TASK_PRIO_OFF",
        "normal_prio": "FAKE_TASK_NORMAL_PRIO_OFF",
        "sched_task_group": "FAKE_TASK_TASK_GROUP_OFF",
        "pi_lock": "FAKE_TASK_PI_LOCK_OFF",
        "pi_waiters": "FAKE_TASK_PI_WAITERS_OFF",
        "pi_top_task": "FAKE_TASK_PI_TOP_TASK_OFF",
        "pi_blocked_on": "FAKE_TASK_PI_BLOCKED_ON_OFF",
        "pid": "TASK_PID_OFF",
        "tgid": "TASK_TGID_OFF",
        "real_parent": "TASK_REAL_PARENT_OFF",
        "atomic_flags": "TASK_ATOMIC_FLAGS_OFF",
        "real_cred": "TASK_REAL_CRED_OFF",
        "cred": "TASK_CRED_OFF",
        "comm": "TASK_COMM_OFF",
        "tasks": "TASK_TASKS_OFF",
        "seccomp": "TASK_SECCOMP_OFF",
    },
    "mm_struct": {
        "owner": "MM_OWNER_OFF",
    },
    "rt_mutex_waiter": {
        "tree": "WAITER_TREE_ENTRY_OFF",
        "pi_tree": "WAITER_PI_TREE_ENTRY_OFF",
        "task": "WAITER_TASK_OFF",
        "lock": "WAITER_LOCK_OFF",
        "wake_state": "WAITER_WAKE_STATE_OFF",
        "prio": "WAITER_PRIO_OFF",
        "deadline": "WAITER_DEADLINE_OFF",
        "ww_ctx": "WAITER_WW_CTX_OFF",
    },
    "cred": {
        "uid": "CRED_UID_OFF",
        "securebits": "CRED_SECUREBITS_OFF",
        "cap_inheritable": "CRED_CAPS_OFF",
        "security": "CRED_SECURITY_OFF",
    },
    "seccomp": {
        "mode": "SECCOMP_MODE_OFF",
        "filter_count": "SECCOMP_FILTER_COUNT_OFF",
        "filter": "SECCOMP_FILTER_OFF",
    },
    "pipe_inode_info": {
        "head": "PIPE_HEAD_OFF",
        "tail": "PIPE_TAIL_OFF",
        "max_usage": "PIPE_MAX_USAGE_OFF",
        "ring_size": "PIPE_RING_SIZE_OFF",
        "nr_accounted": "PIPE_NR_ACCOUNTED_OFF",
        "readers": "PIPE_READERS_OFF",
        "writers": "PIPE_WRITERS_OFF",
        "files": "PIPE_FILES_OFF",
        "tmp_page": "PIPE_TMP_PAGE_OFF",
        "bufs": "PIPE_BUFS_OFF",
        "user": "PIPE_USER_OFF",
    },
    "file_operations": {
        "owner": "FOPS_OWNER_OFF",
        "llseek": "FOPS_LLSEEK_OFF",
        "read": "FOPS_READ_OFF",
        "write": "FOPS_WRITE_OFF",
        "read_iter": "FOPS_READ_ITER_OFF",
        "write_iter": "FOPS_WRITE_ITER_OFF",
        "unlocked_ioctl": "FOPS_IOCTL_OFF",
        "compat_ioctl": "FOPS_COMPAT_IOCTL_OFF",
        "mmap": "FOPS_MMAP_OFF",
        "open": "FOPS_OPEN_OFF",
        "release": "FOPS_RELEASE_OFF",
        "splice_read": "FOPS_SPLICE_READ_OFF",
        "show_fdinfo": "FOPS_SHOW_FDINFO_OFF",
    },
}

def main():
    kernel_path = sys.argv[1] if len(sys.argv) > 1 else "C:/Android/kernel_raw"
    data = open(kernel_path, 'rb').read()
    btf_off = find_btf(data)
    if btf_off < 0:
        print("BTF not found!"); sys.exit(1)

    hdr_len = struct.unpack_from('<I', data, btf_off+4)[0]
    type_off = struct.unpack_from('<I', data, btf_off+8)[0]
    type_len = struct.unpack_from('<I', data, btf_off+12)[0]
    str_off = struct.unpack_from('<I', data, btf_off+16)[0]
    str_len = struct.unpack_from('<I', data, btf_off+20)[0]
    type_data = data[btf_off+hdr_len+type_off : btf_off+hdr_len+type_off+type_len]
    str_data = data[btf_off+hdr_len+str_off : btf_off+hdr_len+str_off+str_len]
    print(f"BTF at 0x{btf_off:x}: types={type_len}B strings={str_len}B")

    # Load current target.h
    current = {}
    target_h = "C:/Users/Lxns/Downloads/ghostlock_ace6t_full (1)/exploit/src/targets/ace6t/target.h"
    if os.path.exists(target_h):
        with open(target_h, encoding='utf-8') as f:
            for line in f:
                m = re.match(r'#define\s+(\w+_OFF)\s+(0x[0-9a-fA-F]+)', line)
                if m:
                    current[m.group(1)] = int(m.group(2), 16)

    results = {}
    for struct_name, fields in FIELDS_NEEDED.items():
        hits = find_struct_in_btf(type_data, str_data, struct_name)
        if not hits:
            print(f"\n{struct_name}: NOT FOUND")
            continue
        # Pick the largest match (most members = most complete definition)
        size, members = max(hits, key=lambda x: len(x[1]))
        member_dict = {name: off for name, off in members}
        print(f"\n{struct_name} (size={size}, {len(members)} members):")
        for field_name, define_name in sorted(fields.items(), key=lambda x: x[1]):
            off = member_dict.get(field_name)
            cur = current.get(define_name)
            b = f"0x{off:X}" if off is not None else "MISS"
            c = f"0x{cur:X}" if cur is not None else "N/A"
            match = "OK" if (off is not None and cur is not None and off == cur) else \
                    "DIFF!" if (off is not None and cur is not None and off != cur) else "MISS"
            print(f"  {define_name:<40} {b:>8} {c:>8} {match:>6}")
            if off is not None:
                results[define_name] = off

    # Handle fields in nested/anonymous structs
    # mm_struct.owner: inside anonymous inner struct, find by brute-force
    if "MM_OWNER_OFF" not in results or results["MM_OWNER_OFF"] is None:
        target_str = b'\x00owner\x00'
        idx = 0
        while True:
            idx = str_data.find(target_str, idx)
            if idx < 0: break
            owner_str_off = idx + 1
            for p in range(0, len(type_data) - 12, 4):
                mn = struct.unpack_from('<I', type_data, p)[0]
                if mn == owner_str_off:
                    mo = struct.unpack_from('<I', type_data, p+8)[0]
                    bit_off = mo & 0xFFFFFF
                    byte_off = bit_off // 8
                    if 0x100 <= byte_off <= 0x800:
                        results["MM_OWNER_OFF"] = byte_off
                        print(f"\n  MM_OWNER_OFF (brute-force): 0x{byte_off:X}")
                        break
            if "MM_OWNER_OFF" in results and results["MM_OWNER_OFF"] is not None:
                break
            idx += 1

    # rt_mutex_waiter.prio/deadline: after rb_node (24 bytes) in tree field
    # tree is at offset 0, rb_node is 24 bytes, then prio(4) + pad(4) + deadline(8)
    if "WAITER_PRIO_OFF" not in results or results["WAITER_PRIO_OFF"] is None:
        tree_off = results.get("WAITER_TREE_ENTRY_OFF", 0)
        if tree_off is not None:
            # rb_node is 24 bytes, prio follows
            results["WAITER_PRIO_OFF"] = tree_off + 0x18
            results["WAITER_DEADLINE_OFF"] = tree_off + 0x20
            print(f"\n  WAITER_PRIO_OFF (derived): 0x{tree_off + 0x18:X}")
            print(f"  WAITER_DEADLINE_OFF (derived): 0x{tree_off + 0x20:X}")

    found = sum(1 for v in results.values() if v is not None)
    total = sum(len(f) for f in FIELDS_NEEDED.values()) + 3  # +3 for special fields
    print(f"\nExtracted: {found}/{total}")

if __name__ == "__main__":
    main()
