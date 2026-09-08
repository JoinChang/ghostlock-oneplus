#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

struct kernel_offsets {
  const char *uname_r;
  const char *build_fingerprint;

  uint64_t kernel_phys_load, phys_offset;

  uint64_t off_init_task, off_init_cred, off_init_uts_ns, off_empty_zero_page;
  uint64_t off_root_task_group, off_selinux_enforcing, off_kptr_restrict;
  uint64_t off_selinux_blob_sizes, off_security_hook_heads, off_kmalloc_caches;
  uint64_t off_anon_pipe_buf_ops, off_ashmem_misc_fops, off_ashmem_fops;
  uint64_t off_ashmem_ioctl, off_ashmem_compat_ioctl, off_ashmem_mmap;
  uint64_t off_ashmem_open, off_ashmem_release, off_ashmem_show_fdinfo;
  uint64_t off_configfs_read_iter, off_configfs_bin_write_iter;
  uint64_t off_copy_splice_read, off_noop_llseek, off_cap_capable_active;
  uint64_t off_slide_nfulnl_logger, off_slide_loggers_0_1, off_slide_boot_id;
  uint64_t off_system_unbound_wq, off_call_usermodehelper_exec_work;

  uint32_t task_prio, task_normal_prio, task_sched_task_group;
  uint32_t task_pi_lock, task_pi_waiters, task_pi_top_task, task_pi_blocked_on;
  uint32_t task_pid, task_tgid, task_real_parent, task_atomic_flags;
  uint32_t task_real_cred, task_cred, task_comm, task_tasks, task_seccomp;
};

#define OFFSETS_ENTRY(uname, fp, ...) { .uname_r = uname, .build_fingerprint = fp, __VA_ARGS__ }

#define STRUCT_OFFSETS_4_4 \
  .task_prio=0x70, .task_normal_prio=0x78, .task_sched_task_group=0x2C0, \
  .task_pi_lock=0x810, .task_pi_waiters=0x824, \
  .task_pi_top_task=0x834, .task_pi_blocked_on=0x83C, \
  .task_pid=0x520, .task_tgid=0x524, .task_real_parent=0x530, \
  .task_atomic_flags=0x500, .task_real_cred=0x6D0, .task_cred=0x6D8, \
  .task_comm=0x6E8, .task_tasks=0x4C0, .task_seccomp=0x7F8

static const struct kernel_offsets known_offsets[] = {
  /* Add new devices by creating src/devices/<name>/offsets.h */
#include "ace6t/offsets.h"
#include "op13/offsets.h"
#include "op15/offsets.h"
#include "findx9ultra/offsets.h"
#include "pudding/offsets.h"
#include "pad4pro/offsets.h"
#include "cph2521/offsets.h"
#include "vivot4/offsets.h"
#include "vivoxfold3pro/offsets.h"
#include "xperia1iv/offsets.h"
#include "findx9pro/offsets.h"
#include "vivox200ultra/offsets.h"
#include "trona/offsets.h"
  { .uname_r = NULL }
};

#endif
