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
static const char *g_bind_mode = "loopback";
static volatile unsigned long g_udp_queries = 0;
static volatile unsigned long g_tcp_queries = 0;

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

static void log_identity(void) {
    char context[256];
    context[0] = '\0';
    FILE *fp = fopen("/proc/self/attr/current", "r");
    if (fp) {
        if (fgets(context, sizeof(context), fp)) {
            size_t n = strlen(context);
            while (n > 0 && (context[n - 1] == '\n' || context[n - 1] == '\r')) context[--n] = '\0';
        }
        fclose(fp);
    }
    fprintf(stderr, "START native pid=%d uid=%d gid=%d context=%s target=127.0.0.1:%d\n",
            (int)getpid(), (int)geteuid(), (int)getegid(), context[0] ? context : "unknown", g_target_port);
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

static int is_loopback_client(const struct sockaddr_in *client) {
    if (!client) return 0;
    uint32_t host = ntohl(client->sin_addr.s_addr);
    return (host & 0xff000000u) == 0x7f000000u;
}

typedef struct {
    size_t len;
    unsigned char query[65535];
    struct sockaddr_in client;
    socklen_t client_len;
} udp_job_t;

static int query_backend_tcp(const unsigned char *query, size_t query_len,
                             unsigned char *answer, size_t answer_cap, size_t *answer_len) {
    if (!query || query_len < 12 || query_len > 65535 || !answer || answer_cap < 12 || !answer_len) {
        errno = EINVAL;
        return -1;
    }

    int upstream = socket(AF_INET, SOCK_STREAM, 0);
    if (upstream < 0) return -1;
    set_timeout(upstream, 15);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_target_port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(upstream, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(upstream);
        return -1;
    }

    unsigned char hdr[2];
    hdr[0] = (unsigned char)((query_len >> 8) & 0xffu);
    hdr[1] = (unsigned char)(query_len & 0xffu);
    if (write_exact(upstream, hdr, 2) != 2 || write_exact(upstream, query, query_len) != (ssize_t)query_len) {
        close(upstream);
        return -1;
    }

    if (read_exact(upstream, hdr, 2) != 2) {
        close(upstream);
        return -1;
    }
    size_t len = (size_t)(((uint16_t)hdr[0] << 8) | hdr[1]);
    if (len < 12 || len > answer_cap) {
        close(upstream);
        errno = EMSGSIZE;
        return -1;
    }
    if (read_exact(upstream, answer, len) != (ssize_t)len) {
        close(upstream);
        return -1;
    }

    close(upstream);
    *answer_len = len;
    return 0;
}

static void *udp_worker(void *arg) {
    udp_job_t *job = (udp_job_t *)arg;
    if (!job) return NULL;

    unsigned char answer[65535];
    size_t answer_len = 0;
    if (query_backend_tcp(job->query, job->len, answer, sizeof(answer), &answer_len) != 0) {
        log_errno("udp client -> tcp backend query");
        free(job);
        return NULL;
    }

    if (g_running && g_udp_fd >= 0) {
        if (sendto(g_udp_fd, answer, answer_len, 0,
                   (struct sockaddr *)&job->client, job->client_len) < 0) {
            log_errno("udp reply to DNS client");
        }
    }

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
        unsigned long qn = __sync_add_and_fetch(&g_tcp_queries, 1);
        if (qn <= 24) { fprintf(stderr, "QUERY tcp count=%lu\n", qn); fflush(stderr); }

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

static int bind_one(int socktype, uint32_t address, int *saved_errno) {
    int fd = socket(AF_INET, socktype, 0);
    if (fd < 0) {
        if (saved_errno) *saved_errno = errno;
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(address);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (saved_errno) *saved_errno = errno;
        close(fd);
        return -1;
    }
    if (socktype == SOCK_STREAM && listen(fd, 64) != 0) {
        if (saved_errno) *saved_errno = errno;
        close(fd);
        return -1;
    }
    return fd;
}

static int bind_pair(uint32_t address, const char *mode) {
    int udp_errno = 0;
    int tcp_errno = 0;
    int udp = bind_one(SOCK_DGRAM, address, &udp_errno);
    int tcp = bind_one(SOCK_STREAM, address, &tcp_errno);

    if (udp < 0) {
        errno = udp_errno;
        fprintf(stderr, "bind UDP %s:53: errno=%d %s\n", mode, errno, strerror(errno));
    }
    if (tcp < 0) {
        errno = tcp_errno;
        fprintf(stderr, "bind TCP %s:53: errno=%d %s\n", mode, errno, strerror(errno));
    }
    fflush(stderr);

    if (udp < 0 || tcp < 0) {
        if (udp >= 0) close(udp);
        if (tcp >= 0) close(tcp);
        return -1;
    }

    g_udp_fd = udp;
    g_tcp_fd = tcp;
    g_bind_mode = mode;
    return 0;
}

static int bind_frontend(void) {
    if (bind_pair(0x7f000001u, "127.0.0.1") == 0) return 0;

    /*
     * Some vendor SELinux policies deny node_bind specifically on loopback while
     * still allowing the DNS port itself. As a compatibility fallback bind to
     * INADDR_ANY, but reject every non-loopback client in userspace. This keeps
     * the service inaccessible from Wi-Fi/LAN even though the kernel socket is
     * wildcard-bound.
     */
    fprintf(stderr, "retry bind using 0.0.0.0 with strict loopback-client filter\n");
    fflush(stderr);
    if (bind_pair(INADDR_ANY, "0.0.0.0") == 0) return 0;
    return -1;
}

static void *tcp_accept_loop(void *unused) {
    (void)unused;
    while (g_running) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        memset(&peer, 0, sizeof(peer));
        int client = accept(g_tcp_fd, (struct sockaddr *)&peer, &peer_len);
        if (client < 0) {
            if (!g_running) break;
            if (errno == EINTR) continue;
            log_errno("tcp accept");
            usleep(100000);
            continue;
        }
        if (!is_loopback_client(&peer)) {
            fprintf(stderr, "drop non-loopback TCP DNS client\n");
            fflush(stderr);
            close(client);
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

    log_identity();
    if (bind_frontend() != 0) return 20;

    fprintf(stdout, "READY native pid=%d udp=%s:53 tcp=%s:53 target=127.0.0.1:%d backend=tcp clients=loopback-only\n",
            (int)getpid(), g_bind_mode, g_bind_mode, g_target_port);
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
        if (!is_loopback_client(&job->client)) {
            fprintf(stderr, "drop non-loopback UDP DNS client\n");
            fflush(stderr);
            free(job);
            continue;
        }
        unsigned long qn = __sync_add_and_fetch(&g_udp_queries, 1);
        if (qn <= 24) { fprintf(stderr, "QUERY udp count=%lu\n", qn); fflush(stderr); }
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
