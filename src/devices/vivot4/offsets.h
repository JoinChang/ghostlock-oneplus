/* vivo T4 — SM8650 / Snapdragon 8 Gen 3, kernel 6.1.145
 * Compact waiter (10 words), waiter_word=3, PSELECT_SHIFT=0
 * C ashmem (ashmem_miscs), UMH root available */

OFFSETS_ENTRY("6.1.145-android14-11-g74d1702dab4d-ab14669069",
  .kernel_phys_load=0xa8000000, STRUCT_OFFSETS_6_1,
  .kimage_text_base=0xffffffc008000000ULL,
  .off_init_task=0x0200F600, .off_init_cred=0x02021A68, .off_init_uts_ns=0x02192170,
  .off_empty_zero_page=0x021F0000, .off_root_task_group=0x021F7580,
  .off_selinux_enforcing=0x02249400, .off_kptr_restrict=0x0200D038,
  .off_selinux_blob_sizes=0x015CC608, .off_security_hook_heads=0x015CBEF8,
  .off_kmalloc_caches=0x015CBA38, .off_anon_pipe_buf_ops=0x011091D0,
  .off_ashmem_misc_fops=0x0216C080, .off_ashmem_fops=0x0127FE88,
  .off_ashmem_ioctl=0x00C322C8, .off_ashmem_compat_ioctl=0x00C32C00,
  .off_ashmem_mmap=0x00C32C58, .off_ashmem_open=0x00C32E78,
  .off_ashmem_release=0x00C32F00, .off_ashmem_show_fdinfo=0x00C33020,
  .off_configfs_read_iter=0x004637E0, .off_configfs_bin_write_iter=0x00463D10,
  .off_copy_splice_read=0, .off_noop_llseek=0x00397FC0,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x020029C8, .off_slide_loggers_0_1=0x02002920,
  .off_slide_boot_id=0x0226A498,
  .off_system_unbound_wq=0x01FFAE60, .off_call_usermodehelper_exec_work=0x000D3680,
),
