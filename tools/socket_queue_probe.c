/*
 * Non-privileged loopback probe for socket send-queue backpressure and
 * POLLOUT readiness. Build with: cc -O2 -Wall -Wextra
 * tools/socket_queue_probe.c -o socket_queue_probe
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double elapsed_ms(struct timespec start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - start.tv_sec) * 1000.0 +
      (now.tv_nsec - start.tv_nsec) / 1000000.0;
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int get_int_opt(int fd, int level, int option, int *value) {
  socklen_t length = sizeof(*value);
  return getsockopt(fd, level, option, value, &length);
}

static int get_queue(int fd, int *value) {
  return ioctl(fd, SIOCOUTQ, value);
}

static int run_probe(const char *transport, int is_tcp,
                     int requested_sndbuf, int requested_rcvbuf,
                     int tcp_nodelay) {
  int listener = -1, peer = -1, server = -1;
  int result = 1;
  if (is_tcp) {
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) goto fail;

    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0) goto fail;
    socklen_t addrlen = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) != 0) {
      goto fail;
    }

    peer = socket(AF_INET, SOCK_STREAM, 0);
    if (peer < 0 || connect(peer, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
      goto fail;
    }
    server = accept(listener, NULL, NULL);
    if (server < 0) goto fail;
    close(listener);
    listener = -1;
  } else {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) goto fail;
    server = pair[0];
    peer = pair[1];
  }

  int rcvbuf = requested_rcvbuf;
  int oobinline = 1;
  if (setsockopt(server, SOL_SOCKET, SO_SNDBUF,
                 &requested_sndbuf, sizeof(requested_sndbuf)) != 0 ||
      setsockopt(peer, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0 ||
      (is_tcp && setsockopt(server, SOL_SOCKET, SO_OOBINLINE,
                            &oobinline, sizeof(oobinline)) != 0) ||
      set_nonblocking(server) != 0 || set_nonblocking(peer) != 0) {
    goto fail;
  }
  if (is_tcp && tcp_nodelay) {
    int enabled = 1;
    if (setsockopt(server, IPPROTO_TCP, TCP_NODELAY,
                   &enabled, sizeof(enabled)) != 0 ||
        setsockopt(peer, IPPROTO_TCP, TCP_NODELAY,
                   &enabled, sizeof(enabled)) != 0) goto fail;
  }

  int actual_sndbuf = 0, actual_rcvbuf = 0;
  if (get_int_opt(server, SOL_SOCKET, SO_SNDBUF, &actual_sndbuf) != 0 ||
      get_int_opt(peer, SOL_SOCKET, SO_RCVBUF, &actual_rcvbuf) != 0) {
    goto fail;
  }

  char fill[16384];
  memset(fill, 'Q', sizeof(fill));
  size_t sent = 0;
  for (;;) {
    ssize_t n = send(server, fill, sizeof(fill), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n > 0) {
      sent += (size_t)n;
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
    goto fail;
  }

  int initial_queue = -1, initial_readable = -1;
  int outq_supported = get_queue(server, &initial_queue) == 0;
  if (ioctl(peer, FIONREAD, &initial_readable) != 0) goto fail;
  struct pollfd initial = {.fd = server, .events = POLLOUT};
  int initial_poll = poll(&initial, 1, 0);
  if (initial_poll < 0) goto fail;
  printf("transport=%s tcp_nodelay=%d requested_sndbuf=%d actual_sndbuf=%d "
         "requested_peer_rcvbuf=%d actual_peer_rcvbuf=%d filled=%zu "
         "outq_supported=%d outq=%d "
         "peer_fionread=%d initial_poll=%d "
         "initial_revents=0x%x\n",
         transport, tcp_nodelay, requested_sndbuf, actual_sndbuf, requested_rcvbuf,
         actual_rcvbuf, sent,
         outq_supported, initial_queue, initial_readable, initial_poll,
         initial.revents);
  fflush(stdout);

  /* Match the harmless readiness stimulus after the POLLOUT baseline. */
  if ((is_tcp && send(peer, "!", 1, MSG_OOB | MSG_NOSIGNAL) != 1) ||
      send(peer, "R", 1, MSG_NOSIGNAL) != 1) goto fail;

  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  size_t drained = 0;
  int outq_at_1s = -1;
  int saw_writable = 0;
  int final_queue = initial_queue;
  double next_report_ms = 1000.0;
  char drain[16384];
  struct pollfd fds[2] = {
    {.fd = server, .events = POLLOUT},
    {.fd = peer, .events = POLLIN},
  };

  while (elapsed_ms(start) < 60000.0) {
    int ready = poll(fds, 2, 10);
    if (ready < 0 && errno == EINTR) continue;
    if (ready < 0) goto fail;

    if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
      for (;;) {
        ssize_t n = recv(peer, drain, sizeof(drain), MSG_DONTWAIT);
        if (n > 0) {
          drained += (size_t)n;
          continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n == 0) break;
        goto fail;
      }
    }

    double ms = elapsed_ms(start);
    if (outq_supported && get_queue(server, &final_queue) != 0) {
      outq_supported = 0;
      final_queue = -1;
    }
    if (outq_supported && outq_at_1s < 0 && ms >= 1000.0) {
      outq_at_1s = final_queue;
    }

    if (fds[0].revents & POLLOUT) {
      saw_writable = 1;
      printf("POLLOUT transport=%s at_ms=%.1f outq=%d drained=%zu "
             "within_1s=%d\n",
             transport, ms, final_queue, drained, ms <= 1000.0);
      break;
    }

    if (ms >= next_report_ms) {
      printf("progress transport=%s at_ms=%.1f outq=%d drained=%zu "
             "poll_server=0x%x poll_peer=0x%x\n",
             transport, ms, final_queue, drained,
             fds[0].revents, fds[1].revents);
      fflush(stdout);
      next_report_ms += 1000.0;
    }
    fds[0].revents = fds[1].revents = 0;
  }

  printf("summary transport=%s requested_sndbuf=%d sent=%zu drained=%zu "
         "outq_supported=%d outq_at_1s=%d final_outq=%d writable=%d "
         "elapsed_ms=%.1f\n",
         transport, requested_sndbuf, sent, drained, outq_supported,
         outq_at_1s, final_queue, saw_writable, elapsed_ms(start));
  result = 0;
  goto done;

fail:
  fprintf(stderr, "probe failed transport=%s tcp_nodelay=%d "
          "requested_sndbuf=%d requested_rcvbuf=%d errno=%d (%s)\n",
          transport, tcp_nodelay, requested_sndbuf, requested_rcvbuf,
          errno, strerror(errno));
done:
  if (server >= 0) close(server);
  if (peer >= 0) close(peer);
  if (listener >= 0) close(listener);
  return result;
}

int main(void) {
  if (run_probe("tcp-loopback", 1, 8192, 4096, 0) != 0) return 1;
  if (run_probe("tcp-loopback", 1, 8192, 4096, 1) != 0) return 1;
  if (run_probe("tcp-loopback", 1, 8192, 65536, 0) != 0) return 1;
  if (run_probe("tcp-loopback", 1, 8192, 65536, 1) != 0) return 1;
  if (run_probe("tcp-loopback", 1, 8192, 262144, 0) != 0) return 1;
  if (run_probe("tcp-loopback", 1, 1024 * 1024, 4096, 0) != 0) return 1;
  if (run_probe("tcp-loopback", 1, 1024 * 1024, 65536, 0) != 0) return 1;
  if (run_probe("tcp-loopback", 1, 1024 * 1024, 262144, 0) != 0) return 1;
  if (run_probe("tcp-loopback", 1, 1024 * 1024, 1024 * 1024, 0) != 0) return 1;
  if (run_probe("unix-socketpair", 0, 8192, 4096, 0) != 0) return 1;
  return run_probe("unix-socketpair", 0, 1024 * 1024, 4096, 0);
}
