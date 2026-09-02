# Recover kernel symbols from an Android boot image

This guide starts with the standard AOSP boot-image path. Try the simple path
first: it is fairly robust for ordinary `boot.img` files, and it uses the
repository's AOSP-compatible extractor, `vmlinux-to-elf`, and the host ELF
symbol reader. Its host requirements are Python/`uv`, Git, and an ELF utility;
Magisk and the Android NDK are reserved for the alternate image path.

The workflow produces these files when `analysis` is used as the work
directory:

```text
analysis/kernel       extracted raw or compressed kernel payload
analysis/kernel.dtb   optional appended device tree blob
analysis/vmlinux      reconstructed ELF
analysis/kallsyms.txt compact address-sorted symbol list
```

The generated symbol list has the form `address TYPE name`, for example
`ffff... FUNC noop_llseek`. This is the format consumed by
`tools/extract_target.py`.

## Simple path: standard AOSP `boot.img`

Run these stages in order. The first failure tells you which decision to make;
the alternate image-extraction path is documented below.

### 1. Install the host tools

On Debian or Ubuntu:

```sh
sudo apt update
sudo apt install --yes curl git binutils
```

On Fedora:

```sh
sudo dnf install curl git binutils
```

On Arch:

```sh
sudo pacman -S --needed curl git binutils
```

You need Python 3.9 or newer and `uv`. Install `uv` using its official
installer, then open a new shell if the installer asks you to refresh `PATH`:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
command -v uv
uv python install 3.12
```

`binutils` supplies `readelf` and `strings`. LLVM is also supported: set
`READELF_PATH` to `llvm-readelf` when that is the ELF tool available on the
host. On a host where `uv` selects a source build for one of its Python
packages, install the ordinary host C compiler package (for example,
`build-essential`); the Android NDK belongs to the alternate `magiskboot`
build path.

### 2. Prepare `vmlinux-to-elf`

The reconstruction wrapper imports the upstream source from a local checkout.
Clone it once and point `VMLINUX_TO_ELF_REPO_DIR` at that checkout:

```sh
mkdir -p "$HOME/repositories"
git clone https://github.com/marin-m/vmlinux-to-elf.git \
  "$HOME/repositories/vmlinux-to-elf"

export VMLINUX_TO_ELF_REPO_DIR="$HOME/repositories/vmlinux-to-elf"
export KALLSYMS_TOOLS_DIR="$HOME/repositories/ghostlock-oneplus/tools/kallsyms"
```

If the repository already exists, keep it and set the two variables to its
actual locations. The `uv` metadata in `reconstruct_vmlinux.py` supplies and
manages the Python dependencies for the upstream tool on demand.

### 3. Extract the kernel

Place the input image in the current directory or replace `boot.img` with its
full path:

```sh
cd "$HOME/repositories/ghostlock-oneplus"
mkdir -p analysis
python3 "$KALLSYMS_TOOLS_DIR/extract_kernel.py" \
  boot.img analysis/kernel \
  --dtb-output analysis/kernel.dtb
```

For standard AOSP header versions 0 through 4, the extractor reads the kernel
size and page layout, copies the kernel section, and separates a valid appended
DTB when one is present. The kernel can remain compressed for the next stage.
If you already use AOSP's `unpack_bootimg.py`, its extracted `kernel` can be
used as the input to Step 4 instead.

A successful run prints a line similar to:

```text
Extracted AOSP boot header v4 kernel: .../analysis/kernel
```

### 4. Reconstruct `vmlinux`

```sh
uv run --script "$KALLSYMS_TOOLS_DIR/reconstruct_vmlinux.py" \
  analysis/kernel analysis/vmlinux
```

For an AArch64 kernel, if the reconstruction reports an architecture
selection error, retry with the upstream overrides:

```sh
uv run --script "$KALLSYMS_TOOLS_DIR/reconstruct_vmlinux.py" \
  analysis/kernel analysis/vmlinux \
  --e-machine 183 --bit-size 64
```

Check the result when diagnosing a reconstruction failure:

```sh
file analysis/vmlinux
readelf -h analysis/vmlinux
```

### 5. Export the symbol list

```sh
python3 "$KALLSYMS_TOOLS_DIR/export_kallsyms.py" \
  analysis/vmlinux analysis/kallsyms.txt
```

The default exporter uses `readelf --symbols --wide` and writes ELF types such
as `FUNC` and `OBJECT`. This preserves the distinction between code and data
symbols needed by the offset extractor. If the host provides LLVM instead of
GNU binutils, use:

```sh
READELF_PATH=/path/to/llvm-readelf \
python3 "$KALLSYMS_TOOLS_DIR/export_kallsyms.py" \
  analysis/vmlinux analysis/kallsyms.txt
```

When a `/proc/kallsyms`-like artifact is specifically required, export the
kernel's embedded table as a separate file:

```sh
uv run --script "$KALLSYMS_TOOLS_DIR/find_kallsyms.py" \
  analysis/kernel analysis/embedded-kallsyms.txt
```

Use `analysis/kallsyms.txt` for the default `extract_target.py` workflow; the
embedded-table file is a separate representation of the same kernel symbols.

### 6. Extract the target offsets

For a device connected over ADB, get the exact kernel release and pass it to
the extractor:

```sh
kernel_release=$(adb shell uname -r | tr -d '\r')
python3 tools/extract_target.py \
  --kallsyms analysis/kallsyms.txt \
  --kernel-release "$kernel_release"
```

The release string must match the device's `uname -r` exactly. When working
from the image alone, read the same value from the reconstructed kernel:

```sh
kernel_release=$(strings -a analysis/vmlinux \
  | sed -n 's/^Linux version \([^ ]*\).*/\1/p' \
  | head -n 1)
python3 tools/extract_target.py \
  --kallsyms analysis/kallsyms.txt \
  --kernel-release "$kernel_release"
```

For a quick check on an uncompressed image, the banner may also be visible in
the image itself:

```sh
strings -a boot.img \
  | sed -n 's/^Linux version \([^ ]*\).*/\1/p' \
  | head -n 1
```

On PowerShell, the running-device equivalent is:

```powershell
$kernelRelease = (adb shell uname -r).Trim()
python tools\extract_target.py `
  --kallsyms analysis\kallsyms.txt `
  --kernel-release $kernelRelease
```

### 7. Extract BTF structure offsets

When the raw kernel contains BTF, run the companion extractor against the same
kernel payload:

```sh
python3 tools/extract_btf.py analysis/kernel
```

Use the `OK`, `MISS`, and `DIFF!` rows to decide which fields need review before
adding a new device entry. A derived field can be reported as `MISS` in the
raw BTF member list and still be printed later when the tool can derive it
from a related member.

## Optional one-command workflow

After the staged path works, `kallsyms.py` can run the same extraction,
reconstruction, and export steps together while preserving intermediates:

```sh
export MAGISK_REPO_DIR="$HOME/repositories/Magisk"
export VMLINUX_TO_ELF_REPO_DIR="$HOME/repositories/vmlinux-to-elf"

uv run --script "$KALLSYMS_TOOLS_DIR/kallsyms.py" \
  "$HOME/repositories/ghostlock-oneplus/boot.img" \
  "$HOME/repositories/ghostlock-oneplus/analysis/kallsyms.txt" \
  --work-dir "$HOME/repositories/ghostlock-oneplus/analysis"
```

This wrapper prepares clean, matching source checkouts, runs preflight, and
then executes the stages above. It also keeps the optional Magisk source
checkout synchronized for the image-format fallback. The standard extractor
remains the selected extractor when neither `--magiskboot` nor
`MAGISKBOOT_PATH` is supplied.

The wrapper writes the requested output atomically. Passing `--work-dir`
keeps `kernel`, `kernel.dtb`, and `vmlinux`; if `--work-dir` is omitted, those
intermediates are stored in a temporary directory and removed after the run.

To use a different output location:

```sh
uv run --script "$KALLSYMS_TOOLS_DIR/kallsyms.py" \
  /path/to/boot.img /path/to/kallsyms.txt \
  --work-dir /path/to/analysis
```

The repository synchronizer fast-forwards only clean checkouts with the
expected remote and a usable branch. It stops and reports the repository state
when manual changes, a detached HEAD, a different remote, or divergent history
needs attention.

## When to use the alternate image path

Try the simple AOSP path first. Move to `magiskboot` only when the image
extractor reports one of these format-specific conditions:

| Message or condition | Next step |
| --- | --- |
| `this is vendor_boot.img; its kernel normally comes from boot.img` | Locate the matching `boot.img`; `vendor_boot.img` normally carries vendor ramdisk/DTB data. |
| `ANDROID! boot magic was not found` | Verify the file and, if it is a vendor-specific image, use `magiskboot`. |
| `invalid legacy page size ...; use MAGISKBOOT_PATH for this image` | Use `magiskboot` to unpack the image. |
| A known boot-image format is accepted by `magiskboot` while the standard parser rejects it | Use `magiskboot` for extraction, then continue with reconstruction and export. |

Messages about a truncated file or a kernel section extending beyond the image
indicate an incomplete or mismatched image. Re-obtain the exact `boot.img`
before changing extraction tools.

An architecture error from `vmlinux-to-elf` is a reconstruction setting issue;
try `--e-machine 183 --bit-size 64` for AArch64 before changing image
extractors. A `readelf` error should be investigated with `file` and
`readelf -h` so the reconstruction output can be corrected first.

## Alternate extraction with `magiskboot`

Use an existing trusted host `magiskboot` executable when available:

```sh
export MAGISKBOOT_PATH=/path/to/magiskboot
python3 "$KALLSYMS_TOOLS_DIR/extract_kernel.py" \
  boot.img analysis/kernel \
  --dtb-output analysis/kernel.dtb
```

`magiskboot unpack` also decompresses compressed kernels. After extraction,
resume at [reconstruct `vmlinux`](#4-reconstruct-vmlinux) and continue through
the simple path.

If you need to build the executable, build the host target from a clean Magisk
checkout. This is the alternate route that uses the Android NDK and Rust
toolchain:

```sh
export MAGISK_REPO_DIR="$HOME/repositories/Magisk"
export ANDROID_HOME="$HOME/Android/Sdk"

git clone https://github.com/topjohnwu/Magisk.git "$MAGISK_REPO_DIR"
(cd "$MAGISK_REPO_DIR" && ./build.py ndk)
(cd "$MAGISK_REPO_DIR" && ./build.py native magiskboot)

export MAGISKBOOT_PATH="$MAGISK_REPO_DIR/native/out/x86_64/magiskboot"
```

Magisk's native build check expects its ONDK under
`$ANDROID_HOME/ndk/magisk`, with `ONDK_VERSION` set to `r30.1`. The `ndk` build
step prepares that layout. Select the ABI directory containing the host
executable; on Windows use the `.exe` build or run this alternate route in
WSL.

The optional preflight for this route is:

```sh
export VMLINUX_TO_ELF_REPO_DIR="$HOME/repositories/vmlinux-to-elf"
uv run --script "$KALLSYMS_TOOLS_DIR/preflight.py" \
  --boot-image boot.img \
  --require-magiskboot \
  --check-native-build
```

The all-in-one wrapper can select the same extractor explicitly:

```sh
uv run --script "$KALLSYMS_TOOLS_DIR/kallsyms.py" \
  boot.img kallsyms.txt \
  --work-dir analysis \
  --magiskboot "$MAGISKBOOT_PATH"
```

## Windows

The Python stages are cross-platform. Install Git, `uv`, and LLVM; use
`llvm-readelf.exe` through `READELF_PATH`. In PowerShell, the simple path is:

```powershell
uv python install 3.12

$env:KALLSYMS_TOOLS_DIR = "$PWD\tools\kallsyms"
$env:VMLINUX_TO_ELF_REPO_DIR = "$HOME\src\vmlinux-to-elf"

python "$env:KALLSYMS_TOOLS_DIR\extract_kernel.py" `
  "$PWD\boot.img" "$PWD\analysis\kernel" `
  --dtb-output "$PWD\analysis\kernel.dtb"

uv run --script "$env:KALLSYMS_TOOLS_DIR\reconstruct_vmlinux.py" `
  "$PWD\analysis\kernel" "$PWD\analysis\vmlinux"

$env:READELF_PATH = "C:\Program Files\LLVM\bin\llvm-readelf.exe"
python "$env:KALLSYMS_TOOLS_DIR\export_kallsyms.py" `
  "$PWD\analysis\vmlinux" "$PWD\analysis\kallsyms.txt"
```

Use `python` rather than `python3` in PowerShell. The Magisk native fallback
is usually simplest to build under WSL; point `MAGISKBOOT_PATH` at the
resulting host executable when using it.

## Files in this workflow

| File | Purpose |
| --- | --- |
| `extract_kernel.py` | Extract the kernel payload from a standard AOSP image or with `magiskboot`. |
| `reconstruct_vmlinux.py` | Run the synchronized `vmlinux-to-elf` source through `uv`. |
| `export_kallsyms.py` | Export an address-sorted compact symbol list. |
| `find_kallsyms.py` | Locate the kernel's embedded `/proc/kallsyms`-like table when that artifact is required. |
| `kallsyms.py` | Run repository preparation, preflight, extraction, reconstruction, and export together. |
| `preflight.py` | Check the host and optional native fallback prerequisites without changing files. |
| `bootstrap.py` | Prepare the source repositories used by the one-command workflow. |
| `common.py` | Shared path, subprocess, and atomic-output helpers. |
