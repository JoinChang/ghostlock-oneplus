#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

struct kernel_offsets {
  const char *uname_r;
  /* Physical load address of the kernel image, chosen by the bootloader.
   * Varies per SoC/board and is not derivable from boot.img — read it from
   * "Kernel code" in /proc/iomem on a rooted unit of the same model
   * (subtract _stext-_text, normally 0x10000). 0 = fall back to
   * P0_KERNEL_PHYS_LOAD from target.h. Wrong value => every write lands in
   * unrelated RAM: no crash, no effect, very hard to debug. */
  uint64_t kernel_phys_load;
  uint64_t off_init_task, off_init_cred, off_init_uts_ns, off_empty_zero_page;
  uint64_t off_root_task_group, off_selinux_enforcing, off_kptr_restrict;
  uint64_t off_selinux_blob_sizes, off_security_hook_heads, off_kmalloc_caches;
  uint64_t off_anon_pipe_buf_ops, off_ashmem_misc_fops, off_ashmem_fops;
  uint64_t off_ashmem_ioctl, off_ashmem_compat_ioctl, off_ashmem_mmap;
  uint64_t off_ashmem_open, off_ashmem_release, off_ashmem_show_fdinfo;
  uint64_t off_configfs_read_iter, off_configfs_bin_write_iter;
  uint64_t off_copy_splice_read, off_noop_llseek, off_cap_capable_active;
  uint64_t off_slide_nfulnl_logger, off_slide_loggers_0_1, off_slide_boot_id;

  /* Per-kernel-version struct field offsets. 0 = use target.h default (6.12). */
  uint32_t task_prio, task_normal_prio, task_sched_task_group;
  uint32_t task_pi_lock, task_pi_waiters, task_pi_top_task, task_pi_blocked_on;
  uint32_t task_pid, task_tgid, task_real_parent, task_atomic_flags;
  uint32_t task_real_cred, task_cred, task_comm, task_tasks, task_seccomp;
  uint32_t mm_owner;
};

#define OFFSETS_ENTRY(uname, ...) { .uname_r = uname, __VA_ARGS__ }

#define STRUCT_OFFSETS_6_12 \
  .task_prio=0x94, .task_normal_prio=0x9C, .task_sched_task_group=0x420, \
  .task_pi_lock=0x9EC, .task_pi_waiters=0xA00, \
  .task_pi_top_task=0xA10, .task_pi_blocked_on=0xA18, \
  .task_pid=0x708, .task_tgid=0x70C, .task_real_parent=0x718, \
  .task_atomic_flags=0x6C8, .task_real_cred=0x8F8, .task_cred=0x900, \
  .task_comm=0x910, .task_tasks=0x638, .task_seccomp=0x9C8, \
  .mm_owner=0x410

#define STRUCT_OFFSETS_6_6 \
  .task_prio=0x84, .task_normal_prio=0x8C, .task_sched_task_group=0x348, \
  .task_pi_lock=0x90C, .task_pi_waiters=0x920, \
  .task_pi_top_task=0x930, .task_pi_blocked_on=0x938, \
  .task_pid=0x618, .task_tgid=0x61C, .task_real_parent=0x628, \
  .task_atomic_flags=0x5D8, .task_real_cred=0x818, .task_cred=0x820, \
  .task_comm=0x830, .task_tasks=0x550, .task_seccomp=0x8E8, \
  .mm_owner=0x2B0

static const struct kernel_offsets known_offsets[] = {
  /* Add new devices by creating src/devices/<name>/offsets.h */
#include "ace6t/offsets.h"
#include "op13/offsets.h"
#include "op15/offsets.h"
#include "findx9ultra/offsets.h"
#include "pudding/offsets.h"
  { .uname_r = NULL }
};

#endif
