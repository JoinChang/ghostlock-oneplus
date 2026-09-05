/* Sony Xperia 1 IV (nagara) — SM8450, kernel 5.10.218
 * Compact waiter (10 words), waiter_word=3, PSELECT_SHIFT=0
 * C ashmem (ashmem_misc), no copy_splice_read (5.10), no cap_capable_active
 *
 * Notes:
 *   ashmem_misc_fops: ashmem_misc at 0x028E7818, miscdevice.fops at +0x10
 *   selinux_enforcing: selinux_state (0x02A41B98) + 0x10 (enforcing field in 5.10)
 *   configfs: read_iter=configfs_read_bin_file, write_iter=configfs_write_bin_file
 *             (these go in .read/.write fops slots on 5.10, not .read_iter/.write_iter)
 */

OFFSETS_ENTRY("5.10.218-android12-9-00062-ga900d8468ace-ab12946691",
  .kernel_phys_load=0, STRUCT_OFFSETS_5_10,
  .kimage_text_base=0xffffffc008000000ULL,
  .off_init_task=0x0279BE80, .off_init_cred=0x027B0A60, .off_init_uts_ns=0x0279BC28,
  .off_empty_zero_page=0x0298D000, .off_root_task_group=0x02992040,
  .off_selinux_enforcing=0x02A41BA8, .off_kptr_restrict=0x0278CDE8,
  .off_selinux_blob_sizes=0x022F2660, .off_security_hook_heads=0x022F1FC8,
  .off_kmalloc_caches=0x022F1B00, .off_anon_pipe_buf_ops=0x0215B268,
  .off_ashmem_misc_fops=0x028E7828, .off_ashmem_fops=0x022AFF18,
  .off_ashmem_ioctl=0x0119968C, .off_ashmem_compat_ioctl=0x0119A19C,
  .off_ashmem_mmap=0x0119A1FC, .off_ashmem_open=0x0119A43C,
  .off_ashmem_release=0x0119A4DC, .off_ashmem_show_fdinfo=0x0119A600,
  .off_configfs_read_iter=0x006972C8, .off_configfs_bin_write_iter=0x00697CA0,
  .off_copy_splice_read=0, .off_noop_llseek=0x00543614,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x02791338, .off_slide_loggers_0_1=0x02791270,
  .off_slide_boot_id=0x02A60BBD,
  .off_system_unbound_wq=0x02789E08, .off_call_usermodehelper_exec_work=0x00165F90,
),
