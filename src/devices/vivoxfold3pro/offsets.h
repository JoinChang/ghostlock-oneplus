/* Vivo X Fold3 Pro (PD2337) — SM8650, kernel 6.1.124-android14-11-maybe-dirty
 * Compact waiter (10 words), waiter_word=3, PSELECT_SHIFT=0
 * C ashmem (ashmem_miscs), UMH root available */

OFFSETS_ENTRY("6.1.124-android14-11-maybe-dirty",
  .kernel_phys_load=0xa8000000, STRUCT_OFFSETS_6_1,
  .kimage_text_base=0xffffffc008000000ULL,
  .off_init_task=0x0219FB80, .off_init_cred=0x021B2470, .off_init_uts_ns=0x023792C0,
  .off_empty_zero_page=0x023D8000, .off_root_task_group=0x023DF740,
  .off_selinux_enforcing=0x02515250, .off_kptr_restrict=0x0219D5B8,
  .off_selinux_blob_sizes=0x016C44B8, .off_security_hook_heads=0x016C3DA8,
  .off_kmalloc_caches=0x016C38E8, .off_anon_pipe_buf_ops=0x011A7F90,
  .off_ashmem_misc_fops=0x023517A8, .off_ashmem_fops=0x0131F718,
  .off_ashmem_ioctl=0x00CB1F2C, .off_ashmem_compat_ioctl=0x00CB2818,
  .off_ashmem_mmap=0x00CB2870, .off_ashmem_open=0x00CB2A94,
  .off_ashmem_release=0x00CB2B34, .off_ashmem_show_fdinfo=0x00CB2BBC,
  .off_configfs_read_iter=0x004D24FC, .off_configfs_bin_write_iter=0x004D2708,
  .off_copy_splice_read=0, .off_noop_llseek=0x004055A4,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x02192F38, .off_slide_loggers_0_1=0x02192EA0,
  .off_slide_boot_id=0x02536848,
  .off_system_unbound_wq=0x0218AE60, .off_call_usermodehelper_exec_work=0x000D6FC8,
),
