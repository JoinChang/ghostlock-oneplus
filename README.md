# GhostLock — OnePlus Locked Bootloader Jailbreak

Kernel exploit for OnePlus/OPPO/realme devices with locked bootloader. Achieves root + KernelSU installation without unlocking bootloader or modifying boot image. Runtime auto-detection of kernel version with multi-device offset table.

<p align="center">
  <img src="assets/screenshot.jpg" width="300" alt="GhostLock running on OnePlus Ace 6T with KernelSU (LKM, Jailbreak mode)">
</p>

## Vulnerability

**CVE-2026-43499** — Futex PI (Priority Inheritance) Use-After-Free

Affects Linux kernel 2.6.39 ~ 7.1. Fixed in mainline 7.1 (commit `3bfdc63936dd`). Android GKI 6.12.x remains vulnerable.

The `pselect6` syscall copies `fd_set` data onto the kernel stack. When combined with the futex PI waiter mechanism, a freed stack frame can be reclaimed as an `rt_mutex_waiter` structure. The rb-tree rebalance during PI chain walk then writes controlled values to arbitrary kernel addresses.

## Supported Devices

### Verified

| Device | SoC | Kernel | Status |
|--------|-----|--------|--------|
| OnePlus Ace 6T (PLR110) | SM8845 | `6.12.38-...-ab14275539` | **Working** |
| OnePlus Ace 6T (PLR110) | SM8845 | `6.12.38-...-ab14552068` | **Working** |
| OnePlus 15 (CPH2745 / CPH2747 / CPH2749) | SM8850 | `6.12.23-...-ab14541642` | **Working** |
| Xiaomi 17 (pudding) | SM8850 | `6.12.23-...-abogki463945075` | **Working** |
| Xiaomi 17 (pudding) | SM8850 | `6.12.69-...-abogki514973465` | **Working** (August 2026 update) |
| OnePlus 13 (IN2060) | SM8750 | `6.6.89-...-abogki446052083` | **Working** (`PSELECT_SHIFT=-2`) |
| OPPO Pad 4 Pro | SM8750 | `6.6.89-...-ab14358676` | **Working** (`PSELECT_SHIFT=-2`) |

### Offsets Extracted (pending device test)

| Device | SoC | Kernel | Notes |
|--------|-----|--------|-------|
| OnePlus 15T (PLZ110) | SM8845 | `6.12.38-...-ab14552068` | Same kernel as Ace 6T. QEMU verified SP diff=-64. |

### Not Feasible (stack layout incompatible)

The pselect stack overlay only works when the freed `rt_mutex_waiter` lands within the user-controllable region of the `stack_fds` buffer. Where the waiter lands is determined by the compiler output (PGO + LTO), not the kernel version. See [Stack Layout](#stack-layout-feasibility) for details.

| Device | SoC | Kernel | Reason |
|--------|-----|--------|--------|
| OPPO Find X9 Ultra | SM8750 | 6.12.58-android16-6 | PGO eliminates `do_futex` frame → SP diff=+32, waiter word=14. No safe shift exists. |
| OPPO Find X7 | — | 6.1.157 | 6.1 GKI: waiter at word 13 (all 6.1 OPLUS/GKI devices) |
| realme RMX5070 | SM6650 | 6.1.141 | 6.1 GKI: waiter at word 13 |
| realme RMX3852 | SM8635 | 6.1.141 | Same 6.1 branch as RMX5070 |
| OnePlus 13R / Ace 5 | SM8650 | 6.1.x | Same 6.1 branch |
| OnePlus 12 | SM8650 | 6.1.141 | 6.1 GKI: `do_futex` PGO inlined, waiter word=13/19 |
| OPPO Pad 5 (OPD2502) | MT6878 | 6.1.134 | Same 6.1 branch |
| OPPO PKW110 | — | 5.15.180 | `do_futex` frame 0x140 (4.5x normal) → waiter word=-29, unreachable |
| Motorola Edge 60 Fusion | MT6878 | 6.1.145 | 6.1 GKI: waiter at word 13 (non-OPLUS, same result) |
| iQOO Z9 5G | — | 5.15.178 | `do_futex` frame too large, waiter unreachable. Not an OPLUS device (vivo). |

## Exploit Flow

Two root paths, selected automatically based on device capabilities:

### Path A: UMH Root (preferred, C ashmem devices)

Requires `off_ashmem_misc_fops != 0` (C ashmem with static miscdevice in BSS).

```
PI write (mode=4)  →  redirect miscdevice fops to fake fops (via W0 pi_tree)
                      configfs r/w established
                   →  pipe physrw (1-byte precise kernel r/w)
                   →  SELinux enforcing = 0 (single byte, no policycap corruption)
                   →  UMH: inject work_struct into system_unbound_wq
                      kernel executes /data/local/tmp/a/e --umh as UID 0
                   →  root script → ksud late-load → KSU installed
```

Advantages over Path B:
- **1-byte SELinux write** — does not corrupt `selinux_state.policycap` (fixes network issues on OnePlus 13)
- **No perf_event_open** — works under seccomp restrictions
- **No credential patching** — avoids modifying live task_struct

Currently available on: **OnePlus 13** (kernel 6.6, C ashmem).
Not available on Rust ashmem devices (6.12 GKI) — the miscdevice is heap-allocated, address not predictable at compile time.

### Path B: Direct PI Write (fallback, all devices)

Used when UMH offsets or C ashmem misc_fops are not available.

```
Write 1 (mode=1)  →  SELinux enforcing = 0
                      (low byte of kernel ptr = 0x00, 8-byte write)

Write 2 (mode=2)  →  task->cred = init_cred
                      (uid=0, all capabilities)

Root shell         →  ksud late-load (KernelSU LKM)
                   →  su -c load_policy (fix SELinux policycap)
                   →  dynamic manager registration
```

### Bootstrap Mode (phone standalone, optional)

```
App (seccomp)  →  Write 1 (no perf needed)
               →  mini-adb connect TCP (port from /data/local/tmp/a/adb_port, default 5555)
               →  adb shell: full exploit (perf works, no seccomp)
               →  root → KSU → network fix
```

### Optional auto-boot integration (external Anchor app)

The boot-time launcher is provided by the separate [GhostLock Anchor
app](https://github.com/byemaxx/ghostlock-anchor). It is not included in this
repository; this section describes how that companion app invokes the native
binary after boot:

```
BOOT_COMPLETED → companion-app BootCompletedReceiver
  ├─ su available → skip (soft reboot / already rooted)
  └─ no root → GhostlockService → setsid exploit --bootstrap
```

## Stack Layout Feasibility

With `NFDS=320`, the kernel's `core_sys_select` allocates a 256-byte `stack_fds` buffer:

```
stack_fds:  0    5    10   14 | 15   20   25   29
            ├─in─┤─out─┤─ex──┤ ├res_in┤res_out┤res_ex┤
            ◄── USER CONTROLLED ──►│◄── KERNEL ZEROED ──►
```

The exploit writes fake waiter fields (task, lock) into the fd_set input bitmaps. For this to work, the waiter's `task` and `lock` fields must fall in the controllable zone (words 0-14).

```
Ace 6T ✅ (waiter at word 2):
  ░░████████████████░░│░░░░░░░░░░░░░░░░░░
    ▲waiter      t  l │
    task/lock controllable

RMX5070 ❌ (waiter at word 13):
  ░░░░░░░░░░░░░████│██████████████░░░░░░
                 ▲  │    t     l
               waiter  task/lock ZEROED
```

**Feasibility rule**: waiter word + 11 (lock offset in rt_waiter_node) must be ≤ 14. Maximum feasible waiter word is **3**.

The waiter position is determined by the compiler's stack frame layout (PGO + LTO + BOLT optimization profiles), which varies per SoC branch. Same kernel version can have different layouts on different SoCs.

### kernel_phys_load

All kernel writes go through the image's linear-map alias:

```
data_addr(x) = PAGE_OFFSET + (kernel_phys_load - PHYS_OFFSET) + (x - KIMAGE_TEXT_BASE)
```

The bootloader picks `kernel_phys_load`, so it varies per SoC and is not in
boot.img or the DT. Per-device field in `struct kernel_offsets`; 0 = use the
`target.h` default.

| SoC | kernel_phys_load |
|-----|------------------|
| SM8845 (Ace 6T, 15T) | `0xa8000000` |
| SM8750 (OnePlus 13, OPPO Pad 4 Pro) | `0xa8000000` |
| SM8850 (OnePlus 15, Xiaomi 17) | `0xc7800000` |

**A wrong value fails silently** — the write still lands in mapped RAM, so
there is no crash and no effect. Don't mistake it for a `PSELECT_SHIFT`
problem. Read it on a rooted unit of the same model (`Kernel code` starts at
`_stext`; `_text` is `0x10000` lower):

```bash
su -c 'grep -i "Kernel code" /proc/iomem'   # c7810000-... -> 0xc7800000
```

### PSELECT_SHIFT

Different kernels place the waiter at different positions within the controllable zone. Use `PSELECT_SHIFT` to adjust:

```bash
# Default (Ace 6T + OnePlus 15, 6.12): shift=0
/data/local/tmp/a/e

# OnePlus 13 (6.6): shift=-2
PSELECT_SHIFT=-2 /data/local/tmp/a/e

# Override kernel_phys_load for new SoCs (when /proc/iomem is not accessible):
KPHYS=0xc7800000 /data/local/tmp/a/e
```

`check_feasibility.py`'s waiter word is unreliable: its frame arithmetic is
right, but the struct offsets it infers from zero-stores are not (on OnePlus 15
it gives word 3; measured is word 2). A wrong shift costs a kernel panic per
guess, so measure it on a rooted unit instead:

```bash
echo 'p:ds do_select fdsin=+0(%x1)' >> /sys/kernel/tracing/kprobe_events
echo 'p:rw rt_mutex_wait_proxy_lock waiter=%x2' >> /sys/kernel/tracing/kprobe_events
# trigger FUTEX_CMP_REQUEUE_PI, then:
#   PSELECT_SHIFT = ((waiter & 0x3fff) - (fdsin & 0x3fff)) / 8 - 2
```

## Build

Build from the repository root. The recommended command is:

```bash
cd /path/to/ghostlock-oneplus
make NDK_ROOT=/path/to/android-ndk
```

This creates the executable at:

```text
/path/to/ghostlock-oneplus/ghostlock
```

In other words, the output is `./ghostlock` in the directory where `make` is
run; it is not placed inside the NDK or under `src/`. On Windows, run this
build from WSL or another Linux environment and use the resulting ARM64
executable.

To invoke the compiler directly instead of `make`, run this command from the
same repository root. The `-o ./ghostlock` option writes to that same location:

```bash
NDK=/path/to/android-ndk
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
  -O2 -Wall -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"target.h\" \
  src/core/main.c src/core/util.c src/core/slide.c \
  src/core/fops.c src/core/pipe_physrw.c src/core/root.c \
  src/core/miniadb.c src/core/umh_root.c \
  -o ./ghostlock -fPIE -pie -pthread
```

## Prerequisites

### ksud (required for KSU installation)

GhostLock only provides root. KernelSU installation depends on **ksud** — a binary that contains embedded `kernelsu.ko` modules for each KMI version. The root script finds ksud on device and calls `ksud late-load --kmi android16-6.12`.

| Method | Steps |
|--------|-------|
| **ReSukiSU APK** (recommended) | Install [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) or this [fork](https://github.com/JoinChang/ReSukiSU). Official release bundles `libksud.so`. |
| **CI release** | Download `ksud-aarch64-linux-android.zip` from [ReSukiSU CI](https://github.com/cctv18/ReSukiSU_CI/releases) |

> Without ksud, the exploit achieves root (uid=0) but KSU won't be installed and `su` won't persist.

## Setup and direct ADB run

The normal run uses the connected device's ADB shell. Before starting, make
sure USB debugging is enabled, the device is unlocked enough to approve the
computer's ADB key, and `adb devices` shows the device with state `device`:

```bash
adb devices
```

If the state is `unauthorized`, unlock the phone, approve the RSA prompt, and
run `adb devices` again.

Build `ghostlock` first, then run these commands from the repository root:

```bash
# Create the directory on the phone, then copy the host binary there.
adb shell mkdir -p /data/local/tmp/a
adb push ./ghostlock /data/local/tmp/a/e
adb shell chmod 755 /data/local/tmp/a/e
```

Execute the copied binary on the phone with:

```bash
adb shell /data/local/tmp/a/e
```

`adb shell` is important: `/data/local/tmp/a/e` is a path on the phone, so
entering that path by itself in the computer's terminal will not run it. If
you rebuild the binary, repeat the `adb push` and `chmod` commands before
running it again. In PowerShell, `./ghostlock` can also be written as
`.\ghostlock`.

## Optional bootstrap mode

`--bootstrap` is for launching from an app or another restricted phone-side
process. The normal direct ADB command above is the preferred way to run the
exploit from a computer. Bootstrap mode needs a local ADB-over-TCP endpoint and
the ADB private key used to authenticate to it:

```bash
# Enable ADB TCP on the connected phone (the default port is 5555).
adb tcpip 5555

# The binary should already be installed at /data/local/tmp/a/e.
adb push ~/.android/adbkey /data/local/tmp/a/adbkey

# Optional: use another port. The two commands must use the same port.
# adb tcpip 23946
# adb shell "echo 23946 > /data/local/tmp/a/adb_port"

# Launch the phone-side bootstrap flow.
adb shell /data/local/tmp/a/e --bootstrap
```

On Windows PowerShell, the private key is usually
`$env:USERPROFILE\.android\adbkey`. Treat this file as sensitive.

A successful run changes the current kernel and can load KernelSU through
`ksud`. ReSukiSU jailbreak-mode state is tied to the current boot; after a
reboot, run the exploit again unless a separate boot-time integration is
configured. An ADB TCP setting only controls how ADB connects and does not by
itself preserve root.

## Usage

```bash
# Run from a computer through ADB.
adb shell /data/local/tmp/a/e

# Optional phone-side mode for a companion app.
adb shell /data/local/tmp/a/e --bootstrap

# Diagnostic/partial operation.
adb shell /data/local/tmp/a/e --write1

# OnePlus 13 / another profile that needs a shift override.
adb shell "PSELECT_SHIFT=-2 /data/local/tmp/a/e"
```

Start after Android has finished booting and ADB is ready. There is no fixed
30-second post-boot deadline; if a timing-sensitive attempt reports a timeout,
run the command again.

## Adding New Devices / Kernel Versions

Only `boot.img` is needed — no root, no device access required.

### Extract offsets from boot.img

```bash
# 1. Extract kernel
python -c "import struct; d=open('boot.img','rb').read(); open('kernel','wb').write(d[4096:4096+struct.unpack_from('<I',d,8)[0]])"

# 2. Global symbols (kallsyms)
python tools/extract_target.py --kallsyms kallsyms.txt    # 28 offsets, auto-validated
```

For stage 2, use the [kallsyms tools guide](tools/kallsyms/GUIDE.md) to recover
`kallsyms.txt` from `boot.img`. It covers kernel extraction, `vmlinux`
reconstruction, and symbol export, starting with the standard AOSP path.

```bash
# 3. Struct fields (BTF)
python tools/extract_btf.py kernel  # 57 offsets, auto-validated

# 4. Add to offsets.h, rebuild
```

### Coverage: 103/103 offsets from boot.img

| Source | Count | Method |
|--------|-------|--------|
| kallsyms (global symbols) | 28 | `extract_target.py` |
| BTF (struct fields) | 57 | `extract_btf.py` |
| Derived (same struct, different usage) | 9 | Automatic |
| Constants (fixed values) | 12 | No extraction needed |

### Adapting to non-OnePlus devices

The core exploit is device-agnostic. Adaptation may require:
- Different `VA_BITS` (48 vs 39) → update `target.h` memory layout
- Different `kernel_phys_load` → read from `/proc/iomem` or use `KPHYS=` env var
- Different timing parameters → tune `common.h`
- Different ashmem implementation (C vs Rust) → C ashmem enables UMH path; Rust ashmem falls back to W1+W2
- Different `PSELECT_SHIFT` → determine via QEMU kprobe test
- Different struct offsets (6.6 vs 6.12) → use `STRUCT_OFFSETS_6_6` or `STRUCT_OFFSETS_6_12` in device entry

### UMH root requirements

The UMH (call_usermodehelper) root path requires:
- `off_system_unbound_wq` and `off_call_usermodehelper_exec_work` from kallsyms
- `off_ashmem_misc_fops` = `ashmem_misc + 0x10` (C ashmem only, miscdevice.fops in BSS)
- Rust ashmem (GKI 6.12) allocates miscdevice on the heap → address not predictable → UMH unavailable

## Files

| File | Description |
|------|-------------|
| `src/core/main.c` | Exploit entry, Write 1/2, UMH path, bootstrap, root script |
| `src/core/fops.c` | pselect route, PI write mechanism, CFI stage |
| `src/core/util.c` | Heap spray, kernelsnitch, slab drain, payload setup |
| `src/core/pipe_physrw.c` | Pipe buffer-based physical memory r/w (upgrades configfs r/w) |
| `src/core/umh_root.c` | UMH root via workqueue injection + `--umh` handler |
| `src/core/miniadb.c` | Mini ADB client (TCP + RSA auth) |
| `src/core/common.h` | Timing parameters, macros |
| `src/core/target.h` | Memory layout, struct field defaults (6.12) |
| `src/core/runtime_struct_offsets.h` | Per-device struct field override (6.6 vs 6.12) |
| `src/devices/offsets.h` | Aggregates all device offset tables + `STRUCT_OFFSETS_*` macros |
| `src/devices/<device>/offsets.h` | Per-device kernel offset entries |
| `src/core/slide.c` | SLIDE kernel address leak |
| `src/core/root.c` | Root shell setup (direct cred patching via pipe physrw) |
| `tools/extract_target.py` | Offset extraction from kallsyms |
| `tools/extract_btf.py` | Struct offset extraction from BTF |
| `tools/check_feasibility.py` | Stack layout feasibility checker |

## License

For authorized security research and educational purposes only.
