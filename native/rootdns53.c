#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t g_running = 1;
static int g_udp_fd = -1;
static int g_tcp_fd = -1;
static int g_target_port = 5454;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_udp_fd >= 0) close(g_udp_fd);
    if (g_tcp_fd >= 0) close(g_tcp_fd);
}

static void log_errno(const char *what) {
    fprintf(stderr, "%s: errno=%d %s\n", what, errno, strerror(errno));
    fflush(stderr);
}

static int set_timeout(int fd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) return -1;
    return 0;
}

static ssize_t read_exact(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, (char *)buf + off, len - off, 0);
        if (n == 0) return 0;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static ssize_t write_exact(int fd, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, (const char *)buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

typedef struct {
    size_t len;
    unsigned char query[65535];
    struct sockaddr_in client;
    socklen_t client_len;
} udp_job_t;

static void *udp_worker(void *arg) {
    udp_job_t *job = (udp_job_t *)arg;
    int fd = -1;
    if (!job) return NULL;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_errno("udp upstream socket");
        free(job);
        return NULL;
    }
    set_timeout(fd, 12);

    struct sockaddr_in upstream;
    memset(&upstream, 0, sizeof(upstream));
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons((uint16_t)g_target_port);
    inet_pton(AF_INET, "127.0.0.1", &upstream.sin_addr);

    if (sendto(fd, job->query, job->len, 0, (struct sockaddr *)&upstream, sizeof(upstream)) < 0) {
        log_errno("udp send to 127.0.0.1 backend");
        close(fd);
        free(job);
        return NULL;
    }

    unsigned char answer[65535];
    ssize_t n = recvfrom(fd, answer, sizeof(answer), 0, NULL, NULL);
    if (n < 0) {
        log_errno("udp receive from 127.0.0.1 backend");
        close(fd);
        free(job);
        return NULL;
    }

    if (g_running && g_udp_fd >= 0) {
        if (sendto(g_udp_fd, answer, (size_t)n, 0,
                   (struct sockaddr *)&job->client, job->client_len) < 0) {
            log_errno("udp reply to DNS client");
        }
    }

    close(fd);
    free(job);
    return NULL;
}

static void *tcp_worker(void *arg) {
    int client = (int)(intptr_t)arg;
    int upstream = -1;

    set_timeout(client, 15);
    upstream = socket(AF_INET, SOCK_STREAM, 0);
    if (upstream < 0) {
        log_errno("tcp upstream socket");
        close(client);
        return NULL;
    }
    set_timeout(upstream, 15);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_target_port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(upstream, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        log_errno("tcp connect 127.0.0.1 backend");
        close(upstream);
        close(client);
        return NULL;
    }

    while (g_running) {
        unsigned char hdr[2];
        ssize_t got = read_exact(client, hdr, 2);
        if (got <= 0) break;
        uint16_t len = (uint16_t)(((uint16_t)hdr[0] << 8) | hdr[1]);
        if (len < 12) break;

        unsigned char *query = (unsigned char *)malloc(len);
        if (!query) break;
        if (read_exact(client, query, len) != len) {
            free(query);
            break;
        }
        if (write_exact(upstream, hdr, 2) != 2 || write_exact(upstream, query, len) != len) {
            free(query);
            log_errno("tcp write backend");
            break;
        }
        free(query);

        if (read_exact(upstream, hdr, 2) != 2) {
            log_errno("tcp read backend length");
            break;
        }
        uint16_t ans_len = (uint16_t)(((uint16_t)hdr[0] << 8) | hdr[1]);
        if (ans_len < 12) break;
        unsigned char *answer = (unsigned char *)malloc(ans_len);
        if (!answer) break;
        if (read_exact(upstream, answer, ans_len) != ans_len) {
            free(answer);
            log_errno("tcp read backend answer");
            break;
        }
        if (write_exact(client, hdr, 2) != 2 || write_exact(client, answer, ans_len) != ans_len) {
            free(answer);
            log_errno("tcp reply client");
            break;
        }
        free(answer);
    }

    close(upstream);
    close(client);
    return NULL;
}

static int bind_udp(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int bind_tcp(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void *tcp_accept_loop(void *unused) {
    (void)unused;
    while (g_running) {
        int client = accept(g_tcp_fd, NULL, NULL);
        if (client < 0) {
            if (!g_running) break;
            if (errno == EINTR) continue;
            log_errno("tcp accept");
            usleep(100000);
            continue;
        }
        pthread_t thread;
        if (pthread_create(&thread, NULL, tcp_worker, (void *)(intptr_t)client) == 0) {
            pthread_detach(thread);
        } else {
            log_errno("pthread_create tcp");
            close(client);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc >= 2) {
        long p = strtol(argv[1], NULL, 10);
        if (p >= 1 && p <= 65535) g_target_port = (int)p;
    }

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGPIPE, SIG_IGN);

    g_udp_fd = bind_udp();
    if (g_udp_fd < 0) {
        log_errno("bind UDP 127.0.0.1:53");
        return 20;
    }
    g_tcp_fd = bind_tcp();
    if (g_tcp_fd < 0) {
        log_errno("bind TCP 127.0.0.1:53");
        close(g_udp_fd);
        return 21;
    }

    fprintf(stdout, "READY native pid=%d udp=127.0.0.1:53 tcp=127.0.0.1:53 target=127.0.0.1:%d\n",
            (int)getpid(), g_target_port);
    fflush(stdout);

    pthread_t tcp_thread;
    if (pthread_create(&tcp_thread, NULL, tcp_accept_loop, NULL) != 0) {
        log_errno("pthread_create tcp accept");
        return 22;
    }
    pthread_detach(tcp_thread);

    while (g_running) {
        udp_job_t *job = (udp_job_t *)calloc(1, sizeof(udp_job_t));
        if (!job) {
            usleep(100000);
            continue;
        }
        job->client_len = sizeof(job->client);
        ssize_t n = recvfrom(g_udp_fd, job->query, sizeof(job->query), 0,
                             (struct sockaddr *)&job->client, &job->client_len);
        if (n < 0) {
            free(job);
            if (!g_running) break;
            if (errno == EINTR) continue;
            log_errno("udp receive client");
            usleep(100000);
            continue;
        }
        job->len = (size_t)n;
        pthread_t thread;
        if (pthread_create(&thread, NULL, udp_worker, job) == 0) {
            pthread_detach(thread);
        } else {
            log_errno("pthread_create udp");
            free(job);
        }
    }

    if (g_udp_fd >= 0) close(g_udp_fd);
    if (g_tcp_fd >= 0) close(g_tcp_fd);
    return 0;
}
