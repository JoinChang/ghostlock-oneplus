/* vivo X200 Ultra (V2454A/PD2454) — SM8750, kernel 6.6.89-android15-8
 * C ashmem (ashmem_misc), traditional security_hook_heads, waiter_word=0
 * kernel_phys_load: unknown (iomem masked, no su) */

OFFSETS_ENTRY("6.6.89-android15-8-g1f71897ac249-abogki467805059-4k",
  .kernel_phys_load=0, STRUCT_OFFSETS_6_6,
  .kimage_text_base=0xffffffc080000000ULL,
  .off_init_task=0x0210E280, .off_init_cred=0x021205C8, .off_init_uts_ns=0x02292290,
  .off_empty_zero_page=0x022FD000, .off_root_task_group=0x02305600,
  .off_selinux_enforcing=0x02346EE8, .off_kptr_restrict=0x0210BD20,
  .off_selinux_blob_sizes=0x016725D0, .off_security_hook_heads=0x01671E98,
  .off_kmalloc_caches=0x016719D8, .off_anon_pipe_buf_ops=0x0115BAC8,
  .off_ashmem_misc_fops=0x0226B4E8, .off_ashmem_fops=0x012EBB18,
  .off_ashmem_ioctl=0x00C814B4, .off_ashmem_compat_ioctl=0x00C81B70,
  .off_ashmem_mmap=0x00C81BC4, .off_ashmem_open=0x00C81DE4,
  .off_ashmem_release=0x00C81E6C, .off_ashmem_show_fdinfo=0x00C81EF8,
  .off_configfs_read_iter=0x0048CEDC, .off_configfs_bin_write_iter=0x0048D0E4,
  .off_copy_splice_read=0x004113D4, .off_noop_llseek=0x003C4174,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x02102268, .off_slide_loggers_0_1=0x021021C0,
  .off_slide_boot_id=0x02367EE0,
  .off_system_unbound_wq=0x020FAE70, .off_call_usermodehelper_exec_work=0x000CFA5C,
),
