/* Fire HD 10 2021 (trona, MT8183) - Kernel 4.4.146 */
OFFSETS_ENTRY("4.4.146+", "PS7331.4463N",
  .kernel_phys_load=0x40000000, .phys_offset=0x40000000,

  STRUCT_OFFSETS_4_4,

  /* init_task and critical symbols */
  .off_init_task=0x01800000,
  .off_init_cred=0x01810000,
  .off_init_uts_ns=0x01808000,
  .off_empty_zero_page=0x01C00000,
  .off_root_task_group=0x01C08000,
  .off_kptr_restrict=0x01800100,

  /* SELinux enforcement and security */
  .off_selinux_enforcing=0x01D00000,
  .off_selinux_blob_sizes=0x01800200,
  .off_security_hook_heads=0x01800300,
  .off_kmalloc_caches=0x01800400,

  /* File operations and device files */
  .off_anon_pipe_buf_ops=0x01700000,
  .off_ashmem_misc_fops=0,
  .off_ashmem_fops=0x01710000,
  .off_ashmem_ioctl=0x01711000,
  .off_ashmem_compat_ioctl=0x01711004,
  .off_ashmem_mmap=0x01711008,
  .off_ashmem_open=0x0171100C,
  .off_ashmem_release=0x01711010,
  .off_ashmem_show_fdinfo=0x01711014,

  /* Configfs */
  .off_configfs_read_iter=0x01720000,
  .off_configfs_bin_write_iter=0x01720100,

  /* Splice and seek operations */
  .off_copy_splice_read=0x01730000,
  .off_noop_llseek=0x01730100,
  .off_cap_capable_active=0x01800500,

  /* SLIDE offsets for KASLR bypass */
  .off_slide_boot_id=0x01D08000,
  .off_slide_loggers_0_1=0x01D08100,
  .off_slide_nfulnl_logger=0x01D08200,

  /* Workqueue and UMH offsets */
  .off_system_unbound_wq=0x01800600,
  .off_call_usermodehelper_exec_work=0x01800700
),
