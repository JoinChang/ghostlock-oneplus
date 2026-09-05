# GhostLock — Locked Bootloader Jailbreak

Kernel exploit for Android devices with locked bootloader. Achieves temporary root + KernelSU installation without unlocking bootloader or modifying boot image. Runtime auto-detection of kernel version with multi-device offset table.

<p align="center">
  <img src="assets/screenshot.jpg" width="300" alt="GhostLock running on OnePlus Ace 6T with KernelSU (LKM, Jailbreak mode)">
</p>

## Vulnerability

**CVE-2026-43499** — Futex PI (Priority Inheritance) Use-After-Free

Affects Linux kernel 5.7 ~ 7.1. Fixed in stable 6.1.175, 6.6.140, 6.12.86. Most Android devices remain unpatched as of September 2026.

The `pselect6` syscall copies `fd_set` data onto the kernel stack. When combined with the futex PI waiter mechanism, a freed stack frame can be reclaimed as an `rt_mutex_waiter` structure. The rb-tree rebalance during PI chain walk then writes controlled values to arbitrary kernel addresses.

## Supported Devices

### Verified Working

| Device | SoC | Kernel | GKI Branch | SHIFT |
|--------|-----|--------|------------|-------|
| OnePlus Ace 6T (PLR110) | SM8845 | 6.12.38 | android16-5 | 0 |
| OnePlus 15 (CPH2745/2747/2749) | SM8850 | 6.12.23 | android16-5 | 0 |
| Xiaomi 17 (pudding) | SM8850 | 6.12.23 / 6.12.69 | android16-5 / android16-6 | 0 |
| OnePlus 13 (IN2060) | SM8750 | 6.6.89 | android15-8 | -2 |
| OPPO Pad 4 Pro | SM8750 | 6.6.89 | android15-8 | -2 |

### Offsets Extracted (pending device test)

| Device | SoC | Kernel | Notes |
|--------|-----|--------|-------|
| OnePlus 15T (PLZ110) | SM8845 | 6.12.38 | Same kernel as Ace 6T |
| OPPO Reno10 Pro+ (CPH2521) | SM8475 | 5.10.236 | 5.10 compact waiter, waiter word=0 |
| Vivo X Fold3 Pro (PD2337) | SM8650 | 6.1.124 | 6.1 compact waiter, waiter word=3 |
| Vivo T4 | SM8650 | 6.1.145 | 6.1 compact waiter, waiter word=3 |

### Not Feasible

The pselect stack overlay requires the freed `rt_mutex_waiter` to land within the user-controllable `stack_fds` region (words 0–14). Where it lands is determined by compiler PGO/LTO profiles, not the kernel version. See [Stack Layout](#stack-layout-feasibility).

| Device | SoC | Kernel | Root Cause |
|--------|-----|--------|------------|
| OPPO Find X9 Ultra | SM8750 | 6.12.58 | PGO eliminates `do_futex` → waiter word=14 |
| OnePlus 12 | SM8650 | 6.1.141 | PGO inlines `do_futex` → waiter word=13/19 |
| OnePlus 13R / Ace 5 | SM8650 | 6.1.x | OPLUS 6.1: waiter word=13 |
| realme RMX5070 | SM6650 | 6.1.141 | OPLUS 6.1: waiter word=13 |
| OPPO Pad 5 (OPD2502) | MT6878 | 6.1.134 | OPLUS 6.1: waiter word=13 |
| Motorola Edge 60 Fusion | MT6878 | 6.1.145 | Non-OPLUS 6.1: same result |
| iQOO Neo 10 CN | SM8650 | 6.1.84 | `do_futex` frame 0xD0 → waiter word=-11 |
| OPPO PKW110 | — | 5.15.180 | `do_futex` frame 0x140 → waiter word=-29 |
| iQOO Z9 5G | — | 5.15.178 | `do_futex` frame too large |
| CPH2763 (OPPO) | — | 6.1.115 | OPLUS 6.1: PGO inlined, waiter word=24 |

> **Note on 6.1 feasibility:** OPLUS 6.1 kernels are consistently infeasible due to PGO inlining `do_futex`. However, some non-OPLUS 6.1 kernels (vivo) retain the standard call chain and are feasible (vivo T4, X Fold3 Pro). Feasibility must be checked per-device.

## Exploit Flow

Two root paths, selected automatically based on device capabilities:

### Path A: UMH Root (preferred, C ashmem devices)

Requires `off_ashmem_misc_fops != 0` (C ashmem with static miscdevice in BSS).

```
PI write (mode=4)  →  redirect miscdevice fops to fake fops
                   →  configfs r/w → pipe physrw (1-byte precise kernel r/w)
                   →  SELinux enforcing = 0 (single byte, no policycap corruption)
                   →  UMH: inject work_struct into system_unbound_wq
                   →  root script → ksud late-load → KSU installed
```

Available on: **OnePlus 13**, **OPPO Pad 4 Pro**, **5.10/6.1 C ashmem devices**.
Not available on Rust ashmem (6.12 GKI) — heap-allocated miscdevice.

### Path B: Direct PI Write (fallback)

```
Write 1 (mode=1)  →  SELinux enforcing = 0 (8-byte write, corrupts adjacent bytes)
Write 2 (mode=2)  →  task->cred = init_cred (uid=0, all capabilities)
Root shell         →  ksud late-load → KSU → SELinux policy fix
```

After W1+W2, the exploit patches the SELinux policy binary's config field (`|= 0xC0000000` for `ANDROID_NETLINK_ROUTE` + `GETNEIGH`) and reloads via `/sys/fs/selinux/load` to restore network connectivity.

### Bootstrap Mode (phone standalone)

```
App (seccomp)  →  Write 1 → mini-adb TCP → adb shell: full exploit → root
```

### Auto-Boot

The boot-time launcher is provided by the separate [GhostLock Anchor app](https://github.com/byemaxx/ghostlock-anchor).

## Stack Layout Feasibility

With `NFDS=320`, `core_sys_select` allocates a 256-byte `stack_fds` buffer on the kernel stack:

```
stack_fds:  0    5    10   14 | 15   20   25   29
            ├─in─┤─out─┤─ex──┤ ├res_in┤res_out┤res_ex┤
            ◄── USER CONTROLLED ──►│◄── KERNEL ZEROED ──►
```

The exploit places fake waiter fields (task, lock) in the fd_set input bitmaps. For 6.12 nested waiter (14 words): max feasible waiter word = **3**. For 5.10/6.1 compact waiter (10 words): max feasible waiter word = **7**.

The waiter position depends on the call chain depth:

| Pattern | Call Chain | Feasible |
|---------|-----------|----------|
| android16-5 (6.12) | sys_futex → do_futex → fwrpi | ✅ waiter word=2 |
| android15-8 (6.6) | sys_futex → do_futex → fwrpi | ✅ waiter word=2 (SHIFT=-2) |
| vivo 6.1 | sys_futex → do_futex → fwrpi | ✅ waiter word=3 |
| OPLUS 6.1 | sys_futex → fwrpi (PGO inlined) | ❌ waiter word=13+ |
| android16-6 (X9 Ultra) | sys_futex → fwrpi (PGO inlined) | ❌ waiter word=14 |
| 5.10 OPLUS | sys_futex → do_futex → fwrpi | ✅ waiter word=0 |

### kernel_phys_load

All kernel writes use the linear-map alias. The bootloader picks `kernel_phys_load`, which varies per SoC:

| SoC | kernel_phys_load |
|-----|------------------|
| SM8845 (Ace 6T, 15T) | `0xa8000000` |
| SM8750 (OnePlus 13, OPPO Pad 4 Pro) | `0xa8000000` |
| SM8650 (vivo T4, X Fold3 Pro) | `0xa8000000` |
| SM8850 (OnePlus 15, Xiaomi 17) | `0xc7800000` |

A wrong value fails silently. Read it on a rooted unit:

```bash
su -c 'grep -i "Kernel code" /proc/iomem'   # c7810000-... → 0xc7800000
```

Override at runtime: `KPHYS=0xc7800000 /data/local/tmp/a/e`

### PSELECT_SHIFT

```bash
/data/local/tmp/a/e                        # Default (shift=0)
PSELECT_SHIFT=-2 /data/local/tmp/a/e       # OnePlus 13 (6.6)
```

### KIMAGE_TEXT_BASE

5.10 kernels use `0xffffffc008000000` (VA_BITS=39, different from 6.x default `0xffffffc080000000`). This is handled automatically via the `kimage_text_base` field in the device offset entry.

## Build

```bash
make NDK_ROOT=/path/to/android-ndk
```

Or directly:

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

GhostLock provides temporary root. KernelSU installation requires **ksud** which bundles `kernelsu.ko` for each KMI version.

| Method | Steps |
|--------|-------|
| **ReSukiSU APK** (recommended) | Install [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) or this [fork](https://github.com/JoinChang/ReSukiSU). Bundles `libksud.so`. |
| **CI release** | Download from [ReSukiSU CI](https://github.com/cctv18/ReSukiSU_CI/releases) |

## Setup

```bash
adb shell mkdir -p /data/local/tmp/a
adb push ./ghostlock /data/local/tmp/a/e
adb shell chmod 755 /data/local/tmp/a/e
adb shell /data/local/tmp/a/e
```

Run after boot completes and ADB is ready.

## Adding New Devices

Only `boot.img` is needed — no root, no device access required.

### 1. Extract kernel and kallsyms

See [kallsyms tools guide](tools/kallsyms/GUIDE.md) for the full workflow, or:

```bash
python tools/extract_target.py --kallsyms kallsyms.txt
python tools/extract_btf.py kernel
```

### 2. Determine feasibility

Check if `do_futex` is PGO-inlined by searching the kernel binary for all branch instructions targeting `futex_wait_requeue_pi`. If `__arm64_sys_futex` calls it directly (bypassing `do_futex`), the device is likely not feasible.

### 3. Create device entry

Add `src/devices/<name>/offsets.h` with the extracted offsets and include it in `src/devices/offsets.h`. Use the appropriate struct offsets macro:

| Kernel | Waiter Layout | Macro |
|--------|--------------|-------|
| 6.12.x | Nested (14 words) | `STRUCT_OFFSETS_6_12` |
| 6.6.x | Nested (14 words) | `STRUCT_OFFSETS_6_6` |
| 6.1.x (vivo) | Compact (10 words) | `STRUCT_OFFSETS_6_1` |
| 5.10.x | Compact (10 words) | `STRUCT_OFFSETS_5_10` |

For 5.10/6.1 compact waiter devices, also set `.kimage_text_base=0xffffffc008000000ULL`.

## Files

| File | Description |
|------|-------------|
| `src/core/main.c` | Exploit entry, W1/W2, UMH path, bootstrap, root script, SELinux policy fix |
| `src/core/fops.c` | pselect route, PI write, CFI stage, compact waiter support |
| `src/core/util.c` | Heap spray, KernelSnitch, slab drain, payload setup |
| `src/core/pipe_physrw.c` | Pipe buffer physical memory r/w |
| `src/core/umh_root.c` | UMH root via workqueue injection |
| `src/core/miniadb.c` | Mini ADB client (TCP + RSA auth) |
| `src/core/target.h` | Memory layout, struct field defaults (6.12) |
| `src/core/runtime_struct_offsets.h` | Per-device struct field override |
| `src/devices/offsets.h` | Device offset tables + `STRUCT_OFFSETS_*` macros |
| `tools/extract_target.py` | Offset extraction from kallsyms |
| `tools/extract_btf.py` | Struct offset extraction from BTF |
| `tools/kallsyms/` | End-to-end kallsyms recovery workflow |

## License

For authorized security research and educational purposes only.
