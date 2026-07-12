#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

struct kernel_offsets {
  const char *uname_r;
  uint64_t off_init_task, off_init_cred, off_init_uts_ns, off_empty_zero_page;
  uint64_t off_root_task_group, off_selinux_enforcing, off_kptr_restrict;
  uint64_t off_selinux_blob_sizes, off_security_hook_heads, off_kmalloc_caches;
  uint64_t off_anon_pipe_buf_ops, off_ashmem_misc_fops, off_ashmem_fops;
  uint64_t off_ashmem_ioctl, off_ashmem_compat_ioctl, off_ashmem_mmap;
  uint64_t off_ashmem_open, off_ashmem_release, off_ashmem_show_fdinfo;
  uint64_t off_configfs_read_iter, off_configfs_bin_write_iter;
  uint64_t off_copy_splice_read, off_noop_llseek, off_cap_capable_active;
  uint64_t off_slide_nfulnl_logger, off_slide_loggers_0_1, off_slide_boot_id;
};

#define OFFSETS_ENTRY(uname, ...) { .uname_r = uname, __VA_ARGS__ }

static const struct kernel_offsets known_offsets[] = {
  OFFSETS_ENTRY("6.12.38-android16-5-g8c67d4274c0a-ab14275539-4k",
    .off_init_task=0x0240CF00, .off_init_cred=0x02422C70, .off_init_uts_ns=0x02594D88,
    .off_empty_zero_page=0x02635000, .off_root_task_group=0x0263D580,
    .off_selinux_enforcing=0x026894D0, .off_kptr_restrict=0x0240B638,
    .off_selinux_blob_sizes=0x018464E8, .off_security_hook_heads=0x01846480,
    .off_kmalloc_caches=0x018404C0, .off_anon_pipe_buf_ops=0x0121EE48,
    .off_ashmem_misc_fops=0x0133B058, .off_ashmem_fops=0x026B6A98,
    .off_ashmem_ioctl=0x00D85964, .off_ashmem_compat_ioctl=0x00D85834,
    .off_ashmem_mmap=0x00D858B0, .off_ashmem_open=0x00D854B4,
    .off_ashmem_release=0x00D85A04, .off_ashmem_show_fdinfo=0x00D8580C,
    .off_configfs_read_iter=0x005154AC, .off_configfs_bin_write_iter=0x005156E0,
    .off_copy_splice_read=0x00491578, .off_noop_llseek=0x0043E8F4,
    .off_cap_capable_active=0x02683B30,
    .off_slide_nfulnl_logger=0x024021A0, .off_slide_loggers_0_1=0x024020F0,
    .off_slide_boot_id=0x026AA868,
  ),
  OFFSETS_ENTRY("6.12.23-android16-5-gb2a876903b49-ab14541642-4k",
    .off_init_task=0x023ECF00, .off_init_cred=0x02402A68, .off_init_uts_ns=0x02574650,
    .off_empty_zero_page=0x02614000, .off_root_task_group=0x0261C580,
    .off_selinux_enforcing=0x026684F0, .off_kptr_restrict=0x023EB638,
    .off_selinux_blob_sizes=0x018304E8, .off_security_hook_heads=0,
    .off_kmalloc_caches=0x0182A4C0, .off_anon_pipe_buf_ops=0x0120ED88,
    .off_ashmem_misc_fops=0, .off_ashmem_fops=0x02695A88,
    .off_ashmem_ioctl=0x00D7E6E4, .off_ashmem_compat_ioctl=0x00D7ECCC,
    .off_ashmem_mmap=0x00D7ED48, .off_ashmem_open=0x00D7EDA4,
    .off_ashmem_release=0x00D7E7A4, .off_ashmem_show_fdinfo=0x00D7ECA4,
    .off_configfs_read_iter=0x00511F50, .off_configfs_bin_write_iter=0x00512184,
    .off_copy_splice_read=0x0048E190, .off_noop_llseek=0x0043B7D4,
    .off_cap_capable_active=0x02662B50,
    .off_slide_nfulnl_logger=0x023E2198, .off_slide_loggers_0_1=0x023E20E8,
    .off_slide_boot_id=0x02689868,
  ),
  OFFSETS_ENTRY("6.12.38-android16-5-g844001fb8721-ab14552068-4k",
    .off_init_task=0x0240CF00, .off_init_cred=0x02422C70, .off_init_uts_ns=0x02594DC8,
    .off_empty_zero_page=0x02635000, .off_root_task_group=0x0263D580,
    .off_selinux_enforcing=0x026894D0, .off_kptr_restrict=0x0240B638,
    .off_selinux_blob_sizes=0x018494E8, .off_security_hook_heads=0,
    .off_kmalloc_caches=0x018434C0, .off_anon_pipe_buf_ops=0x0121EE48,
    .off_ashmem_misc_fops=0, .off_ashmem_fops=0x026B6A98,
    .off_ashmem_ioctl=0x00D8643C, .off_ashmem_compat_ioctl=0x00D8630C,
    .off_ashmem_mmap=0x00D86388, .off_ashmem_open=0x00D863AC,
    .off_ashmem_release=0x00D864DC, .off_ashmem_show_fdinfo=0x00D862E4,
    .off_configfs_read_iter=0x00515F3C, .off_configfs_bin_write_iter=0x00516170,
    .off_copy_splice_read=0x00491DA0, .off_noop_llseek=0x0043F11C,
    .off_cap_capable_active=0x02683B30,
    .off_slide_nfulnl_logger=0x024021A0, .off_slide_loggers_0_1=0x024020F0,
    .off_slide_boot_id=0x026AA868,
  ),
  { .uname_r = NULL }
};

#endif
