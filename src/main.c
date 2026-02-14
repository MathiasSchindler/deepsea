#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "snapshot.h"

#define MAX_EVENTS 256
#define MAX_HEADER_BYTES 16384
#define MAX_METHOD_LEN 16
#define MAX_TARGET_LEN 4096
#define MAX_VERSION_LEN 16
#define MAX_QUERY_LEN 4096
#define MAX_QUERY_PARAMS 128
#define MAX_FILTER_VALUES 32
#define LIST_PAGE_LIMIT_DEFAULT 100
#define LIST_PAGE_LIMIT_TEXT 10

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef enum {
    SRC_LISTENER = 1,
    SRC_CONN = 2,
} source_type_t;

typedef struct worker worker_t;

typedef struct {
    source_type_t type;
    int fd;
    worker_t *worker;
} listener_source_t;

typedef struct {
    source_type_t type;
    int fd;
    worker_t *worker;
    char buffer[MAX_HEADER_BYTES + 1];
    size_t used;
    bool request_started;
    uint64_t request_start_ns;
} connection_t;

struct worker {
    int index;
    int port;
    int backlog;
    bool pin_cpu;
    int epoll_fd;
    listener_source_t listener;
    pthread_t thread;
};

typedef struct {
    int port;
    int workers;
    int backlog;
    bool pin_cpu;
} server_config_t;

typedef enum {
    ROUTE_NONE = 0,
    ROUTE_LIST = 1,
    ROUTE_DETAIL = 2,
} route_kind_t;

typedef struct {
    route_kind_t kind;
    const char *entity;
    long id;
} route_match_t;

typedef struct {
    char key[64];
    char value[256];
} query_param_t;

typedef struct {
    query_param_t items[MAX_QUERY_PARAMS];
    size_t count;
} query_params_t;

typedef struct {
    long ids[MAX_FILTER_VALUES];
    size_t ids_count;
    long person_ids[MAX_FILTER_VALUES];
    size_t person_ids_count;
    long vorgang_ids[MAX_FILTER_VALUES];
    size_t vorgang_ids_count;
    long vorgangsposition_ids[MAX_FILTER_VALUES];
    size_t vorgangsposition_ids_count;
    long drucksache_ids[MAX_FILTER_VALUES];
    size_t drucksache_ids_count;
    long plenarprotokoll_ids[MAX_FILTER_VALUES];
    size_t plenarprotokoll_ids_count;
    long aktivitaet_ids[MAX_FILTER_VALUES];
    size_t aktivitaet_ids_count;
    int wahlperioden[MAX_FILTER_VALUES];
    size_t wahlperioden_count;
    bool wahlperioden_mask[256];
    char dokumentnummer[64];
    bool has_dokumentnummer;
    char datum_start[16];
    bool has_datum_start;
    char datum_end[16];
    bool has_datum_end;
    char aktualisiert_start[16];
    bool has_aktualisiert_start;
    char aktualisiert_end[16];
    bool has_aktualisiert_end;
    char urheber[128];
    bool has_urheber;
    char titel[128];
    bool has_titel;
    char person_terms[MAX_FILTER_VALUES][128];
    size_t person_terms_count;
    long vorgangstyp_notationen[MAX_FILTER_VALUES];
    size_t vorgangstyp_notationen_count;
    char beratungsstand_terms[MAX_FILTER_VALUES][128];
    size_t beratungsstand_terms_count;
    char gesta_terms[MAX_FILTER_VALUES][128];
    size_t gesta_terms_count;
    char initiative_terms[MAX_FILTER_VALUES][128];
    size_t initiative_terms_count;
    char sachgebiet_terms[MAX_FILTER_VALUES][128];
    size_t sachgebiet_terms_count;
    char deskriptor_terms[MAX_FILTER_VALUES][128];
    size_t deskriptor_terms_count;
    char vorgangstyp_terms[MAX_FILTER_VALUES][128];
    size_t vorgangstyp_terms_count;
    char zuordnung_terms[MAX_FILTER_VALUES][128];
    size_t zuordnung_terms_count;
    size_t offset;
} list_filter_t;

static volatile sig_atomic_t g_stop = 0;
static dip_snapshot_t g_snapshot;
static pthread_rwlock_t g_snapshot_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t g_rebuild_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t g_rebuild_requested = 0;
static uint64_t g_snapshot_version = 1;
static int g_rebuild_interval_sec = 0;
static pthread_t g_rebuild_thread;
static bool g_rebuild_thread_started = false;
static char g_data_root[PATH_MAX] = "..";
static char g_snapshot_dir[PATH_MAX] = "./data/snapshots";
static bool g_require_api_key_for_read = false;

static const dip_person_t *pick_related_person(const dip_snapshot_t *snapshot, long doc_id);

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double ns_to_ms(uint64_t ns) {
    return (double)ns / 1000000.0;
}

static void handle_signal(int signum) {
    (void)signum;
    g_stop = 1;
}

static void handle_rebuild_signal(int signum) {
    (void)signum;
    g_rebuild_requested = 1;
}

static int persist_active_snapshot(const char *reason) {
    char err[256];
    pthread_rwlock_rdlock(&g_snapshot_lock);
    uint64_t version = g_snapshot_version;
    int rc = dip_snapshot_write_files(&g_snapshot, g_snapshot_dir, version, err, sizeof(err));
    pthread_rwlock_unlock(&g_snapshot_lock);

    if (rc != 0) {
        fprintf(stderr, "snapshot persist failed reason=%s error=%s\n", reason ? reason : "-", err);
        fflush(stderr);
        return -1;
    }

    fprintf(stdout, "snapshot persist done reason=%s version=%llu dir=%s\n", reason ? reason : "-", (unsigned long long)version, g_snapshot_dir);
    fflush(stdout);
    return 0;
}

static void write_m3_validation_report(const dip_snapshot_t *snapshot, const char *snapshot_dir, const char *source_tag) {
    if (!snapshot || !snapshot_dir || !*snapshot_dir) {
        return;
    }

    size_t missing_doc_titel = 0;
    size_t missing_doc_text = 0;
    size_t default_doc_datum = 0;
    size_t default_doc_urheber = 0;
    size_t missing_person_nachname = 0;
    size_t missing_person_vorname = 0;
    size_t default_person_basisdatum = 0;
    size_t default_person_datum = 0;
    size_t non_monotonic_doc_ids = 0;
    size_t non_monotonic_pp_ids = 0;
    size_t non_monotonic_person_ids = 0;

    for (size_t i = 0; i < snapshot->drucksachen_count; i++) {
        const dip_document_t *d = &snapshot->drucksachen[i];
        if (d->titel[0] == '\0') {
            missing_doc_titel++;
        }
        if (d->text_preview[0] == '\0') {
            missing_doc_text++;
        }
        if (strcmp(d->datum, "1970-01-01") == 0) {
            default_doc_datum++;
        }
        if (strcmp(d->urheber, "Unbekannt") == 0) {
            default_doc_urheber++;
        }
        if (i > 0 && snapshot->drucksachen[i - 1].id >= d->id) {
            non_monotonic_doc_ids++;
        }
    }

    for (size_t i = 0; i < snapshot->plenarprotokolle_count; i++) {
        if (i > 0 && snapshot->plenarprotokolle[i - 1].id >= snapshot->plenarprotokolle[i].id) {
            non_monotonic_pp_ids++;
        }
    }

    for (size_t i = 0; i < snapshot->personen_count; i++) {
        const dip_person_t *p = &snapshot->personen[i];
        if (p->nachname[0] == '\0') {
            missing_person_nachname++;
        }
        if (p->vorname[0] == '\0') {
            missing_person_vorname++;
        }
        if (strcmp(p->basisdatum, "1970-01-01") == 0) {
            default_person_basisdatum++;
        }
        if (strcmp(p->datum, "1970-01-01") == 0) {
            default_person_datum++;
        }
        if (i > 0 && snapshot->personen[i - 1].id >= p->id) {
            non_monotonic_person_ids++;
        }
    }

    char report_path[PATH_MAX];
    const char report_suffix[] = "/m3_validation_report.json";
    size_t dir_len = strlen(snapshot_dir);
    if (dir_len + sizeof(report_suffix) > sizeof(report_path)) {
        return;
    }
    memcpy(report_path, snapshot_dir, dir_len);
    memcpy(report_path + dir_len, report_suffix, sizeof(report_suffix));
    FILE *fp = fopen(report_path, "wb");
    if (!fp) {
        return;
    }

    time_t now = time(NULL);
    fprintf(
        fp,
        "{\n"
        "  \"timestamp_epoch\": %lld,\n"
        "  \"source\": \"%s\",\n"
        "  \"snapshot\": {\n"
        "    \"drucksachen_count\": %zu,\n"
        "    \"plenarprotokolle_count\": %zu,\n"
        "    \"personen_count\": %zu\n"
        "  },\n"
        "  \"checks\": {\n"
        "    \"drucksache_ids_strictly_increasing\": %s,\n"
        "    \"plenarprotokoll_ids_strictly_increasing\": %s,\n"
        "    \"person_ids_strictly_increasing\": %s\n"
        "  },\n"
        "  \"defaults_and_missing\": {\n"
        "    \"drucksache_missing_titel\": %zu,\n"
        "    \"drucksache_missing_text_preview\": %zu,\n"
        "    \"drucksache_default_datum_1970\": %zu,\n"
        "    \"drucksache_default_urheber_unbekannt\": %zu,\n"
        "    \"person_missing_nachname\": %zu,\n"
        "    \"person_missing_vorname\": %zu,\n"
        "    \"person_default_basisdatum_1970\": %zu,\n"
        "    \"person_default_datum_1970\": %zu\n"
        "  }\n"
        "}\n",
        (long long)now,
        source_tag ? source_tag : "unknown",
        snapshot->drucksachen_count,
        snapshot->plenarprotokolle_count,
        snapshot->personen_count,
        non_monotonic_doc_ids == 0 ? "true" : "false",
        non_monotonic_pp_ids == 0 ? "true" : "false",
        non_monotonic_person_ids == 0 ? "true" : "false",
        missing_doc_titel,
        missing_doc_text,
        default_doc_datum,
        default_doc_urheber,
        missing_person_nachname,
        missing_person_vorname,
        default_person_basisdatum,
        default_person_datum);

    fclose(fp);
}

static int try_rebuild_snapshot(const char *reason) {
    if (pthread_mutex_trylock(&g_rebuild_mutex) != 0) {
        return 1;
    }

    dip_snapshot_t next_snapshot;
    dip_snapshot_init(&next_snapshot);

    char err[256];
    if (dip_snapshot_load(&next_snapshot, g_data_root, err, sizeof(err)) != 0) {
        fprintf(stderr, "snapshot rebuild failed reason=%s error=%s\n", reason ? reason : "-", err);
        fflush(stderr);
        pthread_mutex_unlock(&g_rebuild_mutex);
        return -1;
    }

    dip_snapshot_t old_snapshot;
    uint64_t new_version;
    pthread_rwlock_wrlock(&g_snapshot_lock);
    old_snapshot = g_snapshot;
    g_snapshot = next_snapshot;
    g_snapshot_version++;
    new_version = g_snapshot_version;
    pthread_rwlock_unlock(&g_snapshot_lock);

    dip_snapshot_free(&old_snapshot);

    fprintf(
        stdout,
        "snapshot rebuild done reason=%s version=%llu drs=%zu pp=%zu persons=%zu\n",
        reason ? reason : "-",
        (unsigned long long)new_version,
        g_snapshot.drucksachen_count,
        g_snapshot.plenarprotokolle_count,
        g_snapshot.personen_count);
    fflush(stdout);

    persist_active_snapshot("rebuild");
    write_m3_validation_report(&g_snapshot, g_snapshot_dir, "rebuild");

    pthread_mutex_unlock(&g_rebuild_mutex);
    return 0;
}

static void *rebuild_thread_main(void *arg) {
    (void)arg;
    int elapsed = 0;
    while (!g_stop) {
        sleep(1);
        if (g_stop) {
            break;
        }

        if (g_rebuild_requested) {
            g_rebuild_requested = 0;
            try_rebuild_snapshot("signal_or_admin");
            elapsed = 0;
            continue;
        }

        if (g_rebuild_interval_sec > 0) {
            elapsed++;
            if (elapsed >= g_rebuild_interval_sec) {
                elapsed = 0;
                try_rebuild_snapshot("periodic");
            }
        }
    }
    return NULL;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
}

static int setup_listener(int port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        close(fd);
        return -1;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) {
        close(fd);
        return -1;
    }
#endif

    if (set_nonblocking(fd) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int ci_starts_with(const char *s, const char *prefix) {
    size_t n = strlen(prefix);
    return strncasecmp(s, prefix, n) == 0;
}

static const char *find_header_end(const char *buf, size_t len) {
    if (len < 4) {
        return NULL;
    }
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

static const char *status_text(int status) {
    switch (status) {
        case 200:
            return "OK";
        case 202:
            return "Accepted";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 500:
            return "Internal Server Error";
        default:
            return "Error";
    }
}

static size_t json_error(char *out, size_t out_size, int status, const char *message) {
    return (size_t)snprintf(out, out_size, "{\"code\":%d,\"message\":\"%s\"}", status, message);
}

static ssize_t send_simple_response(int fd, int status, const char *content_type, const char *body, bool keep_alive) {
    char header[512];
    size_t body_len = strlen(body);
    const char *conn = keep_alive ? "keep-alive" : "close";
    int header_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "Server: dip-c-server/0.1\r\n"
        "\r\n",
        status,
        status_text(status),
        content_type,
        body_len,
        conn);

    if (header_len <= 0 || (size_t)header_len >= sizeof(header)) {
        return -1;
    }

    ssize_t total = 0;
    ssize_t n = send(fd, header, (size_t)header_len, MSG_NOSIGNAL);
    if (n <= 0) {
        return -1;
    }
    total += n;

    if (body_len > 0) {
        n = send(fd, body, body_len, MSG_NOSIGNAL);
        if (n <= 0) {
            return -1;
        }
        total += n;
    }

    return total;
}

static void close_connection(worker_t *worker, connection_t *conn) {
    if (conn == NULL) {
        return;
    }
    epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);
    free(conn);
}

static void log_request(
    worker_t *worker,
    const char *method,
    const char *target,
    int status,
    ssize_t bytes_sent,
    uint64_t started_ns,
    const char *note) {
    uint64_t elapsed_ns = 0;
    if (started_ns > 0) {
        uint64_t end = now_ns();
        elapsed_ns = (end >= started_ns) ? (end - started_ns) : 0;
    }
    fprintf(
        stdout,
        "worker=%d method=%s target=%s status=%d bytes=%zd duration_ms=%.3f note=%s\n",
        worker->index,
        method ? method : "-",
        target ? target : "-",
        status,
        bytes_sent,
        ns_to_ms(elapsed_ns),
        note ? note : "-"
    );
    fflush(stdout);
}

static bool parse_request_line(char *line, char *method, size_t method_len, char *target, size_t target_len, char *version, size_t version_len) {
    char *sp1 = strchr(line, ' ');
    if (!sp1) {
        return false;
    }
    *sp1 = '\0';

    char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) {
        return false;
    }
    *sp2 = '\0';

    size_t method_src_len = strlen(line);
    size_t target_src_len = strlen(sp1 + 1);
    size_t version_src_len = strlen(sp2 + 1);

    if (method_src_len == 0 || target_src_len == 0 || version_src_len == 0) {
        return false;
    }

    if (method_src_len >= method_len || target_src_len >= target_len || version_src_len >= version_len) {
        return false;
    }

    memcpy(method, line, method_src_len + 1);
    memcpy(target, sp1 + 1, target_src_len + 1);
    memcpy(version, sp2 + 1, version_src_len + 1);

    return true;
}

static void extract_path(const char *target, char *path, size_t path_len) {
    const char *q = strchr(target, '?');
    size_t n = q ? (size_t)(q - target) : strlen(target);
    if (n >= path_len) {
        n = path_len - 1;
    }
    memcpy(path, target, n);
    path[n] = '\0';
}

static void extract_query(const char *target, char *query, size_t query_len) {
    const char *q = strchr(target, '?');
    if (!q) {
        query[0] = '\0';
        return;
    }
    q++;
    size_t n = strlen(q);
    if (n >= query_len) {
        n = query_len - 1;
    }
    memcpy(query, q, n);
    query[n] = '\0';
}

static bool is_all_digits(const char *s) {
    if (!s || *s == '\0') {
        return false;
    }
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }
    return true;
}

static bool match_detail_route(const char *path, const char *prefix, long *out_id) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0) {
        return false;
    }
    const char *id_str = path + prefix_len;
    if (!is_all_digits(id_str)) {
        return false;
    }
    char *endptr = NULL;
    long parsed = strtol(id_str, &endptr, 10);
    if (endptr == id_str || *endptr != '\0' || parsed <= 0) {
        return false;
    }
    *out_id = parsed;
    return true;
}

static route_match_t match_dip_route(const char *path) {
    route_match_t match;
    match.kind = ROUTE_NONE;
    match.entity = NULL;
    match.id = -1;

    if (strcmp(path, "/vorgang") == 0) {
        match.kind = ROUTE_LIST;
        match.entity = "Vorgang";
        return match;
    }
    if (strcmp(path, "/vorgangsposition") == 0) {
        match.kind = ROUTE_LIST;
        match.entity = "Vorgangsposition";
        return match;
    }
    if (strcmp(path, "/drucksache") == 0) {
        match.kind = ROUTE_LIST;
        match.entity = "Drucksache";
        return match;
    }
    if (strcmp(path, "/drucksache-text") == 0) {
        match.kind = ROUTE_LIST;
        match.entity = "DrucksacheText";
        return match;
    }
    if (strcmp(path, "/plenarprotokoll") == 0) {
        match.kind = ROUTE_LIST;
        match.entity = "Plenarprotokoll";
        return match;
    }
    if (strcmp(path, "/plenarprotokoll-text") == 0) {
        match.kind = ROUTE_LIST;
        match.entity = "PlenarprotokollText";
        return match;
    }
    if (strcmp(path, "/aktivitaet") == 0) {
        match.kind = ROUTE_LIST;
        match.entity = "Aktivitaet";
        return match;
    }
    if (strcmp(path, "/person") == 0) {
        match.kind = ROUTE_LIST;
        match.entity = "Person";
        return match;
    }

    long id = -1;
    if (match_detail_route(path, "/vorgang/", &id)) {
        match.kind = ROUTE_DETAIL;
        match.entity = "Vorgang";
        match.id = id;
        return match;
    }
    if (match_detail_route(path, "/vorgangsposition/", &id)) {
        match.kind = ROUTE_DETAIL;
        match.entity = "Vorgangsposition";
        match.id = id;
        return match;
    }
    if (match_detail_route(path, "/drucksache/", &id)) {
        match.kind = ROUTE_DETAIL;
        match.entity = "Drucksache";
        match.id = id;
        return match;
    }
    if (match_detail_route(path, "/drucksache-text/", &id)) {
        match.kind = ROUTE_DETAIL;
        match.entity = "DrucksacheText";
        match.id = id;
        return match;
    }
    if (match_detail_route(path, "/plenarprotokoll/", &id)) {
        match.kind = ROUTE_DETAIL;
        match.entity = "Plenarprotokoll";
        match.id = id;
        return match;
    }
    if (match_detail_route(path, "/plenarprotokoll-text/", &id)) {
        match.kind = ROUTE_DETAIL;
        match.entity = "PlenarprotokollText";
        match.id = id;
        return match;
    }
    if (match_detail_route(path, "/aktivitaet/", &id)) {
        match.kind = ROUTE_DETAIL;
        match.entity = "Aktivitaet";
        match.id = id;
        return match;
    }
    if (match_detail_route(path, "/person/", &id)) {
        match.kind = ROUTE_DETAIL;
        match.entity = "Person";
        match.id = id;
        return match;
    }

    return match;
}

static bool parse_query_params(const char *query, query_params_t *out_params) {
    out_params->count = 0;
    if (!query || !*query) {
        return true;
    }

    char local[MAX_QUERY_LEN + 1];
    size_t n = strlen(query);
    if (n > MAX_QUERY_LEN) {
        n = MAX_QUERY_LEN;
    }
    memcpy(local, query, n);
    local[n] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(local, "&", &saveptr);
    while (token) {
        if (out_params->count >= MAX_QUERY_PARAMS) {
            break;
        }

        const char *k = token;
        const char *v = "";
        char *eq = strchr(token, '=');
        if (eq) {
            *eq = '\0';
            v = eq + 1;
        }

        query_param_t *dst = &out_params->items[out_params->count++];
        snprintf(dst->key, sizeof(dst->key), "%s", k);
        snprintf(dst->value, sizeof(dst->value), "%s", v);

        token = strtok_r(NULL, "&", &saveptr);
    }
    return true;
}

static bool query_param_get_first(const query_params_t *params, const char *key, char *out, size_t out_size) {
    if (!params || !key || !out || out_size == 0) {
        return false;
    }
    for (size_t i = 0; i < params->count; i++) {
        const query_param_t *item = &params->items[i];
        if (strcmp(item->key, key) == 0) {
            size_t vn = strlen(item->value);
            if (vn >= out_size) {
                vn = out_size - 1;
            }
            memcpy(out, item->value, vn);
            out[vn] = '\0';
            return true;
        }
    }
    return false;
}

static bool query_param_all_integer_values(const query_params_t *params, const char *key) {
    if (!params || !key) {
        return true;
    }
    for (size_t i = 0; i < params->count; i++) {
        const query_param_t *item = &params->items[i];
        if (strcmp(item->key, key) == 0 && !is_all_digits(item->value)) {
            return false;
        }
    }
    return true;
}

static bool find_invalid_integer_filter(const query_params_t *params, char *bad_key, size_t bad_key_size) {
    const char *keys[] = {
        "f.wahlperiode",
        "f.id",
        "f.person_id",
        "f.vorgang",
        "f.vorgangsposition_id",
        "f.vorgangstyp_notation",
        "f.drucksache",
        "f.plenarprotokoll",
        "f.aktivitaet",
    };
    size_t key_count = sizeof(keys) / sizeof(keys[0]);
    for (size_t i = 0; i < key_count; i++) {
        if (!query_param_all_integer_values(params, keys[i])) {
            snprintf(bad_key, bad_key_size, "%s", keys[i]);
            return true;
        }
    }
    return false;
}

static bool is_valid_format_param(const query_params_t *params) {
    char format[64];
    if (!query_param_get_first(params, "format", format, sizeof(format))) {
        return true;
    }
    return strcmp(format, "json") == 0 || strcmp(format, "xml") == 0;
}

static bool is_xml_format_param(const query_params_t *params) {
    char format[64];
    if (!query_param_get_first(params, "format", format, sizeof(format))) {
        return false;
    }
    return strcmp(format, "xml") == 0;
}

static bool is_valid_date_yyyy_mm_dd(const char *s) {
    if (!s) {
        return false;
    }
    if (strlen(s) != 10) {
        return false;
    }
    for (int i = 0; i < 10; i++) {
        if (i == 4 || i == 7) {
            if (s[i] != '-') {
                return false;
            }
        } else if (s[i] < '0' || s[i] > '9') {
            return false;
        }
    }
    return true;
}

static bool normalize_date_or_datetime_to_date(const char *in, char *out, size_t out_size) {
    if (!in || !out || out_size < 11) {
        return false;
    }
    if (strlen(in) >= 10 &&
        in[4] == '-' &&
        in[7] == '-' &&
        in[0] >= '0' && in[0] <= '9' &&
        in[1] >= '0' && in[1] <= '9' &&
        in[2] >= '0' && in[2] <= '9' &&
        in[3] >= '0' && in[3] <= '9' &&
        in[5] >= '0' && in[5] <= '9' &&
        in[6] >= '0' && in[6] <= '9' &&
        in[8] >= '0' && in[8] <= '9' &&
        in[9] >= '0' && in[9] <= '9') {
        memcpy(out, in, 10);
        out[10] = '\0';
        return true;
    }
    return false;
}

static bool find_invalid_date_filter(const query_params_t *params, char *bad_key, size_t bad_key_size) {
    char tmp[32];
    if (query_param_get_first(params, "f.datum.start", tmp, sizeof(tmp)) && !is_valid_date_yyyy_mm_dd(tmp)) {
        snprintf(bad_key, bad_key_size, "%s", "f.datum.start");
        return true;
    }
    if (query_param_get_first(params, "f.datum.end", tmp, sizeof(tmp)) && !is_valid_date_yyyy_mm_dd(tmp)) {
        snprintf(bad_key, bad_key_size, "%s", "f.datum.end");
        return true;
    }
    if (query_param_get_first(params, "f.aktualisiert.start", tmp, sizeof(tmp))) {
        char norm[16];
        if (!normalize_date_or_datetime_to_date(tmp, norm, sizeof(norm))) {
            snprintf(bad_key, bad_key_size, "%s", "f.aktualisiert.start");
            return true;
        }
    }
    if (query_param_get_first(params, "f.aktualisiert.end", tmp, sizeof(tmp))) {
        char norm[16];
        if (!normalize_date_or_datetime_to_date(tmp, norm, sizeof(norm))) {
            snprintf(bad_key, bad_key_size, "%s", "f.aktualisiert.end");
            return true;
        }
    }
    return false;
}

static bool has_valid_auth(const char *authorization_header, const query_params_t *params) {
    if (authorization_header && *authorization_header) {
        return true;
    }
    char apikey[256];
    if (query_param_get_first(params, "apikey", apikey, sizeof(apikey)) && apikey[0] != '\0') {
        return true;
    }
    return false;
}

static bool query_param_collect_longs(const query_params_t *params, const char *key, long *out, size_t out_max, size_t *out_count) {
    *out_count = 0;
    if (!params || !key) {
        return true;
    }

    for (size_t i = 0; i < params->count; i++) {
        const query_param_t *item = &params->items[i];
        if (strcmp(item->key, key) == 0) {
            if (!is_all_digits(item->value)) {
                return false;
            }
            if (*out_count < out_max) {
                out[*out_count] = strtol(item->value, NULL, 10);
                (*out_count)++;
            }
        }
    }

    return true;
}

static bool query_param_collect_strings(const query_params_t *params, const char *key, char out[][128], size_t out_max, size_t *out_count) {
    *out_count = 0;
    if (!params || !key) {
        return true;
    }

    for (size_t i = 0; i < params->count; i++) {
        const query_param_t *item = &params->items[i];
        if (strcmp(item->key, key) == 0 && item->value[0] != '\0') {
            if (*out_count < out_max) {
                size_t m = strlen(item->value);
                if (m >= 128) {
                    m = 127;
                }
                memcpy(out[*out_count], item->value, m);
                out[*out_count][m] = '\0';
                (*out_count)++;
            }
        }
    }

    return true;
}

static bool contains_long(const long *arr, size_t count, long value) {
    for (size_t i = 0; i < count; i++) {
        if (arr[i] == value) {
            return true;
        }
    }
    return false;
}

static bool contains_int(const int *arr, size_t count, int value) {
    for (size_t i = 0; i < count; i++) {
        if (arr[i] == value) {
            return true;
        }
    }
    return false;
}

static bool filter_contains_wahlperiode(const list_filter_t *filter, int value) {
    if (!filter) {
        return false;
    }
    if (value >= 0 && value < (int)(sizeof(filter->wahlperioden_mask) / sizeof(filter->wahlperioden_mask[0]))) {
        return filter->wahlperioden_mask[(size_t)value];
    }
    return contains_int(filter->wahlperioden, filter->wahlperioden_count, value);
}

static bool collect_documents_for_wahlperioden(
    const dip_snapshot_t *snapshot,
    const list_filter_t *filter,
    bool use_plenarprotokolle,
    const dip_document_t *const **out_docs,
    size_t *out_count,
    bool *out_owned) {

    *out_docs = NULL;
    *out_count = 0;
    *out_owned = false;

    if (!snapshot || !filter || filter->wahlperioden_count == 0) {
        return true;
    }

    const dip_document_t ***by_wp = use_plenarprotokolle
        ? (const dip_document_t ***)snapshot->plenarprotokolle_by_wahlperiode
        : (const dip_document_t ***)snapshot->drucksachen_by_wahlperiode;
    const size_t *by_wp_count = use_plenarprotokolle
        ? snapshot->plenarprotokolle_by_wahlperiode_count
        : snapshot->drucksachen_by_wahlperiode_count;

    bool seen_wp[256] = {0};
    int unique_wp_values[MAX_FILTER_VALUES];
    size_t unique_wp_count = 0;
    for (size_t i = 0; i < filter->wahlperioden_count; i++) {
        int wp = filter->wahlperioden[i];
        if (wp < 0 || wp >= 256) {
            continue;
        }
        if (!seen_wp[(size_t)wp]) {
            seen_wp[(size_t)wp] = true;
            unique_wp_values[unique_wp_count++] = wp;
        }
    }

    if (unique_wp_count == 0) {
        return true;
    }

    if (unique_wp_count == 1) {
        int wp = unique_wp_values[0];
        *out_docs = by_wp[(size_t)wp];
        *out_count = by_wp_count[(size_t)wp];
        return true;
    }

    size_t merged_count = 0;
    for (size_t i = 0; i < unique_wp_count; i++) {
        int wp = unique_wp_values[i];
        merged_count += by_wp_count[(size_t)wp];
    }

    if (merged_count == 0) {
        return true;
    }

    const dip_document_t **merged = (const dip_document_t **)calloc(merged_count, sizeof(*merged));
    if (!merged) {
        return false;
    }

    size_t at = 0;
    for (size_t i = 0; i < unique_wp_count; i++) {
        int wp = unique_wp_values[i];
        const dip_document_t *const *bucket = by_wp[(size_t)wp];
        size_t bucket_count = by_wp_count[(size_t)wp];
        for (size_t j = 0; j < bucket_count; j++) {
            merged[at++] = bucket[j];
        }
    }

    *out_docs = merged;
    *out_count = merged_count;
    *out_owned = true;
    return true;
}

static bool matches_document_date_window(const dip_document_t *doc, const list_filter_t *filter) {
    if (!doc || !filter) {
        return false;
    }
    if (filter->has_datum_start && strcmp(doc->datum, filter->datum_start) < 0) {
        return false;
    }
    if (filter->has_datum_end && strcmp(doc->datum, filter->datum_end) > 0) {
        return false;
    }
    if (filter->has_aktualisiert_start && strcmp(doc->datum, filter->aktualisiert_start) < 0) {
        return false;
    }
    if (filter->has_aktualisiert_end && strcmp(doc->datum, filter->aktualisiert_end) > 0) {
        return false;
    }
    return true;
}

static size_t lower_bound_date(const dip_document_t *const *docs, size_t count, const char *date_value) {
    size_t left = 0;
    size_t right = count;
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (strcmp(docs[mid]->datum, date_value) < 0) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return left;
}

static size_t upper_bound_date(const dip_document_t *const *docs, size_t count, const char *date_value) {
    size_t left = 0;
    size_t right = count;
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (strcmp(docs[mid]->datum, date_value) <= 0) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return left;
}

static bool collect_documents_for_date_range(
    const dip_snapshot_t *snapshot,
    const list_filter_t *filter,
    bool use_plenarprotokolle,
    const dip_document_t *const **out_docs,
    size_t *out_count,
    bool *out_owned) {

    *out_docs = NULL;
    *out_count = 0;
    *out_owned = false;

    if (!snapshot || !filter ||
        (!filter->has_datum_start && !filter->has_datum_end && !filter->has_aktualisiert_start && !filter->has_aktualisiert_end)) {
        return true;
    }

    const dip_document_t *const *by_date = use_plenarprotokolle ? snapshot->plenarprotokolle_by_datum : snapshot->drucksachen_by_datum;
    size_t by_date_count = use_plenarprotokolle ? snapshot->plenarprotokolle_by_datum_count : snapshot->drucksachen_by_datum_count;
    if (!by_date || by_date_count == 0) {
        return true;
    }

    const char *start = NULL;
    const char *end = NULL;
    if (filter->has_datum_start) {
        start = filter->datum_start;
    }
    if (filter->has_aktualisiert_start && (!start || strcmp(filter->aktualisiert_start, start) > 0)) {
        start = filter->aktualisiert_start;
    }
    if (filter->has_datum_end) {
        end = filter->datum_end;
    }
    if (filter->has_aktualisiert_end && (!end || strcmp(filter->aktualisiert_end, end) < 0)) {
        end = filter->aktualisiert_end;
    }

    if (start && end && strcmp(start, end) > 0) {
        *out_docs = by_date;
        *out_count = 0;
        return true;
    }

    size_t left = start ? lower_bound_date(by_date, by_date_count, start) : 0;
    size_t right = end ? upper_bound_date(by_date, by_date_count, end) : by_date_count;
    if (right < left) {
        right = left;
    }

    *out_docs = by_date + left;
    *out_count = right - left;
    return true;
}

static bool collect_documents_for_filters(
    const dip_snapshot_t *snapshot,
    const list_filter_t *filter,
    bool use_plenarprotokolle,
    const dip_document_t *const **out_docs,
    size_t *out_count,
    bool *out_owned,
    size_t fallback_count) {

    *out_docs = NULL;
    *out_count = fallback_count;
    *out_owned = false;

    const dip_document_t *const *wp_docs = NULL;
    size_t wp_count = 0;
    bool wp_owned = false;
    if (!collect_documents_for_wahlperioden(snapshot, filter, use_plenarprotokolle, &wp_docs, &wp_count, &wp_owned)) {
        return false;
    }
    if (!wp_docs) {
        wp_count = fallback_count;
    }

    const dip_document_t *const *date_docs = NULL;
    size_t date_count = 0;
    bool date_owned = false;
    if (!collect_documents_for_date_range(snapshot, filter, use_plenarprotokolle, &date_docs, &date_count, &date_owned)) {
        if (wp_owned) {
            free((void *)wp_docs);
        }
        return false;
    }
    if (!date_docs) {
        date_count = fallback_count;
    }

    if (!wp_docs && !date_docs) {
        return true;
    }
    if (wp_docs && !date_docs) {
        *out_docs = wp_docs;
        *out_count = wp_count;
        *out_owned = wp_owned;
        return true;
    }
    if (!wp_docs && date_docs) {
        *out_docs = date_docs;
        *out_count = date_count;
        *out_owned = date_owned;
        return true;
    }

    const dip_document_t *const *base_docs = wp_docs;
    size_t base_count = wp_count;
    if (date_count < wp_count) {
        base_docs = date_docs;
        base_count = date_count;
    }

    const dip_document_t **merged = (const dip_document_t **)calloc(base_count, sizeof(*merged));
    if (!merged) {
        if (wp_owned) {
            free((void *)wp_docs);
        }
        if (date_owned) {
            free((void *)date_docs);
        }
        return false;
    }

    size_t merged_count = 0;
    for (size_t i = 0; i < base_count; i++) {
        const dip_document_t *doc = base_docs[i];
        if (!filter_contains_wahlperiode(filter, doc->wahlperiode)) {
            continue;
        }
        if (!matches_document_date_window(doc, filter)) {
            continue;
        }
        merged[merged_count++] = doc;
    }

    if (wp_owned) {
        free((void *)wp_docs);
    }
    if (date_owned) {
        free((void *)date_docs);
    }

    *out_docs = merged;
    *out_count = merged_count;
    *out_owned = true;
    return true;
}

static bool collect_persons_for_wahlperioden(
    const dip_snapshot_t *snapshot,
    const list_filter_t *filter,
    const dip_person_t *const **out_personen,
    size_t *out_count,
    bool *out_owned,
    size_t fallback_count) {

    *out_personen = NULL;
    *out_count = fallback_count;
    *out_owned = false;

    if (!snapshot || !filter || filter->wahlperioden_count == 0) {
        return true;
    }

    bool seen_wp[256] = {0};
    int unique_wp_values[MAX_FILTER_VALUES];
    size_t unique_wp_count = 0;
    for (size_t i = 0; i < filter->wahlperioden_count; i++) {
        int wp = filter->wahlperioden[i];
        if (wp < 0 || wp >= 256) {
            continue;
        }
        if (!seen_wp[(size_t)wp]) {
            seen_wp[(size_t)wp] = true;
            unique_wp_values[unique_wp_count++] = wp;
        }
    }

    if (unique_wp_count == 0) {
        return true;
    }

    if (unique_wp_count == 1) {
        int wp = unique_wp_values[0];
        *out_personen = snapshot->personen_by_wahlperiode[(size_t)wp];
        *out_count = snapshot->personen_by_wahlperiode_count[(size_t)wp];
        *out_owned = false;
        return true;
    }

    size_t merged_count = 0;
    for (size_t i = 0; i < unique_wp_count; i++) {
        int wp = unique_wp_values[i];
        merged_count += snapshot->personen_by_wahlperiode_count[(size_t)wp];
    }

    if (merged_count == 0) {
        *out_personen = NULL;
        *out_count = 0;
        return true;
    }

    if (snapshot->personen_count > 0 && merged_count * 4 >= snapshot->personen_count * 3) {
        return true;
    }

    const dip_person_t **merged = (const dip_person_t **)calloc(merged_count, sizeof(*merged));
    if (!merged) {
        return false;
    }

    bool *seen_person = (bool *)calloc(snapshot->personen_count, sizeof(*seen_person));
    if (!seen_person) {
        free(merged);
        return false;
    }

    size_t at = 0;
    for (size_t i = 0; i < unique_wp_count; i++) {
        int wp = unique_wp_values[i];
        const dip_person_t *const *bucket = snapshot->personen_by_wahlperiode[(size_t)wp];
        size_t bucket_count = snapshot->personen_by_wahlperiode_count[(size_t)wp];
        for (size_t j = 0; j < bucket_count; j++) {
            const dip_person_t *p = bucket[j];
            ptrdiff_t idx = p - snapshot->personen;
            if (idx < 0 || (size_t)idx >= snapshot->personen_count) {
                continue;
            }
            if (seen_person[(size_t)idx]) {
                continue;
            }
            seen_person[(size_t)idx] = true;
            merged[at++] = p;
        }
    }

    free(seen_person);

    *out_personen = merged;
    *out_count = at;
    *out_owned = true;
    return true;
}

static void encode_cursor(uint64_t snapshot_version, size_t offset, char *out, size_t out_size) {
    snprintf(out, out_size, "snapshot-%llu-%zu", (unsigned long long)snapshot_version, offset);
}

static bool parse_cursor(const query_params_t *params, uint64_t snapshot_version, size_t *out_offset) {
    char cursor[128];
    if (!query_param_get_first(params, "cursor", cursor, sizeof(cursor))) {
        *out_offset = 0;
        return true;
    }

    const char *prefix = "snapshot-";
    if (strncmp(cursor, prefix, strlen(prefix)) != 0) {
        return false;
    }

    char *sep = strrchr(cursor, '-');
    if (!sep || sep == cursor) {
        return false;
    }
    *sep = '\0';
    const char *version_part = cursor + strlen(prefix);
    const char *offset_part = sep + 1;

    if (!is_all_digits(version_part) || !is_all_digits(offset_part)) {
        return false;
    }

    unsigned long long parsed_version = strtoull(version_part, NULL, 10);
    if ((uint64_t)parsed_version != snapshot_version) {
        return false;
    }

    *out_offset = (size_t)strtoull(offset_part, NULL, 10);
    return true;
}

static bool init_list_filter(const query_params_t *params, uint64_t snapshot_version, list_filter_t *out_filter) {
    memset(out_filter, 0, sizeof(*out_filter));

    if (!parse_cursor(params, snapshot_version, &out_filter->offset)) {
        return false;
    }

    if (!query_param_collect_longs(params, "f.id", out_filter->ids, MAX_FILTER_VALUES, &out_filter->ids_count)) {
        return false;
    }
    if (!query_param_collect_longs(params, "f.person_id", out_filter->person_ids, MAX_FILTER_VALUES, &out_filter->person_ids_count)) {
        return false;
    }
    if (!query_param_collect_longs(params, "f.vorgang", out_filter->vorgang_ids, MAX_FILTER_VALUES, &out_filter->vorgang_ids_count)) {
        return false;
    }
    if (!query_param_collect_longs(params, "f.vorgangsposition_id", out_filter->vorgangsposition_ids, MAX_FILTER_VALUES, &out_filter->vorgangsposition_ids_count)) {
        return false;
    }
    if (!query_param_collect_longs(params, "f.drucksache", out_filter->drucksache_ids, MAX_FILTER_VALUES, &out_filter->drucksache_ids_count)) {
        return false;
    }
    if (!query_param_collect_longs(params, "f.plenarprotokoll", out_filter->plenarprotokoll_ids, MAX_FILTER_VALUES, &out_filter->plenarprotokoll_ids_count)) {
        return false;
    }
    if (!query_param_collect_longs(params, "f.aktivitaet", out_filter->aktivitaet_ids, MAX_FILTER_VALUES, &out_filter->aktivitaet_ids_count)) {
        return false;
    }
    if (!query_param_collect_longs(params, "f.vorgangstyp_notation", out_filter->vorgangstyp_notationen, MAX_FILTER_VALUES, &out_filter->vorgangstyp_notationen_count)) {
        return false;
    }

    long wp_longs[MAX_FILTER_VALUES];
    size_t wp_count = 0;
    if (!query_param_collect_longs(params, "f.wahlperiode", wp_longs, MAX_FILTER_VALUES, &wp_count)) {
        return false;
    }
    out_filter->wahlperioden_count = wp_count;
    for (size_t i = 0; i < wp_count; i++) {
        out_filter->wahlperioden[i] = (int)wp_longs[i];
        if (wp_longs[i] >= 0 && wp_longs[i] < (long)(sizeof(out_filter->wahlperioden_mask) / sizeof(out_filter->wahlperioden_mask[0]))) {
            out_filter->wahlperioden_mask[wp_longs[i]] = true;
        }
    }

    if (query_param_get_first(params, "f.dokumentnummer", out_filter->dokumentnummer, sizeof(out_filter->dokumentnummer))
        && out_filter->dokumentnummer[0] != '\0') {
        out_filter->has_dokumentnummer = true;
    }

    if (query_param_get_first(params, "f.datum.start", out_filter->datum_start, sizeof(out_filter->datum_start))
        && out_filter->datum_start[0] != '\0') {
        out_filter->has_datum_start = true;
    }

    if (query_param_get_first(params, "f.datum.end", out_filter->datum_end, sizeof(out_filter->datum_end))
        && out_filter->datum_end[0] != '\0') {
        out_filter->has_datum_end = true;
    }

    char aktualisiert_tmp[32];
    if (query_param_get_first(params, "f.aktualisiert.start", aktualisiert_tmp, sizeof(aktualisiert_tmp))
        && aktualisiert_tmp[0] != '\0') {
        if (!normalize_date_or_datetime_to_date(aktualisiert_tmp, out_filter->aktualisiert_start, sizeof(out_filter->aktualisiert_start))) {
            return false;
        }
        out_filter->has_aktualisiert_start = true;
    }
    if (query_param_get_first(params, "f.aktualisiert.end", aktualisiert_tmp, sizeof(aktualisiert_tmp))
        && aktualisiert_tmp[0] != '\0') {
        if (!normalize_date_or_datetime_to_date(aktualisiert_tmp, out_filter->aktualisiert_end, sizeof(out_filter->aktualisiert_end))) {
            return false;
        }
        out_filter->has_aktualisiert_end = true;
    }

    if (query_param_get_first(params, "f.urheber", out_filter->urheber, sizeof(out_filter->urheber))
        && out_filter->urheber[0] != '\0') {
        out_filter->has_urheber = true;
    }

    if (query_param_get_first(params, "f.titel", out_filter->titel, sizeof(out_filter->titel))
        && out_filter->titel[0] != '\0') {
        out_filter->has_titel = true;
    }

    if (!query_param_collect_strings(params, "f.person", out_filter->person_terms, MAX_FILTER_VALUES, &out_filter->person_terms_count)) {
        return false;
    }
    if (!query_param_collect_strings(params, "f.beratungsstand", out_filter->beratungsstand_terms, MAX_FILTER_VALUES, &out_filter->beratungsstand_terms_count)) {
        return false;
    }
    if (!query_param_collect_strings(params, "f.gesta", out_filter->gesta_terms, MAX_FILTER_VALUES, &out_filter->gesta_terms_count)) {
        return false;
    }
    if (!query_param_collect_strings(params, "f.initiative", out_filter->initiative_terms, MAX_FILTER_VALUES, &out_filter->initiative_terms_count)) {
        return false;
    }
    if (!query_param_collect_strings(params, "f.sachgebiet", out_filter->sachgebiet_terms, MAX_FILTER_VALUES, &out_filter->sachgebiet_terms_count)) {
        return false;
    }
    if (!query_param_collect_strings(params, "f.deskriptor", out_filter->deskriptor_terms, MAX_FILTER_VALUES, &out_filter->deskriptor_terms_count)) {
        return false;
    }
    if (!query_param_collect_strings(params, "f.vorgangstyp", out_filter->vorgangstyp_terms, MAX_FILTER_VALUES, &out_filter->vorgangstyp_terms_count)) {
        return false;
    }
    if (!query_param_collect_strings(params, "f.zuordnung", out_filter->zuordnung_terms, MAX_FILTER_VALUES, &out_filter->zuordnung_terms_count)) {
        return false;
    }

    return true;
}

static bool match_document_filter(const dip_document_t *doc, const list_filter_t *filter);

static bool matches_any_term_ci(const char *value, const char terms[][128], size_t term_count) {
    if (term_count == 0) {
        return true;
    }
    if (!value) {
        return false;
    }
    for (size_t i = 0; i < term_count; i++) {
        if (strcasestr(value, terms[i]) != NULL) {
            return true;
        }
    }
    return false;
}

static bool matches_all_terms_ci(const char *value, const char terms[][128], size_t term_count) {
    if (term_count == 0) {
        return true;
    }
    if (!value) {
        return false;
    }
    for (size_t i = 0; i < term_count; i++) {
        if (strcasestr(value, terms[i]) == NULL) {
            return false;
        }
    }
    return true;
}

static void derive_vorgang_gesta(const dip_document_t *doc, char *out, size_t out_size) {
    if (!doc || !out || out_size == 0) {
        return;
    }
    long n = doc->id % 900;
    if (n < 0) {
        n = -n;
    }
    snprintf(out, out_size, "B%03ld", 100 + n);
}

static bool match_vorgang_filter(const dip_document_t *doc, const list_filter_t *filter) {
    if (!match_document_filter(doc, filter)) {
        return false;
    }

    const char *vorgangstyp = "Gesetzgebung";
    const char *beratungsstand = "In Beratung";
    const char *initiative = doc->urheber;
    const char *sachgebiet = "Bundestag";

    char deskriptor_text[1024];
    snprintf(deskriptor_text, sizeof(deskriptor_text), "%s %s", doc->titel, doc->urheber);

    char gesta[32];
    derive_vorgang_gesta(doc, gesta, sizeof(gesta));

    if (!matches_any_term_ci(vorgangstyp, filter->vorgangstyp_terms, filter->vorgangstyp_terms_count)) {
        return false;
    }
    if (!matches_any_term_ci(beratungsstand, filter->beratungsstand_terms, filter->beratungsstand_terms_count)) {
        return false;
    }
    if (!matches_any_term_ci(gesta, filter->gesta_terms, filter->gesta_terms_count)) {
        return false;
    }
    if (!matches_all_terms_ci(initiative, filter->initiative_terms, filter->initiative_terms_count)) {
        return false;
    }
    if (!matches_all_terms_ci(sachgebiet, filter->sachgebiet_terms, filter->sachgebiet_terms_count)) {
        return false;
    }
    if (!matches_all_terms_ci(deskriptor_text, filter->deskriptor_terms, filter->deskriptor_terms_count)) {
        return false;
    }
    if (filter->vorgangstyp_notationen_count > 0 && !contains_long(filter->vorgangstyp_notationen, filter->vorgangstyp_notationen_count, 100)) {
        return false;
    }
    return true;
}

static void derive_vorgangsposition_vorgangstyp(const dip_document_t *doc, char *out, size_t out_size) {
    if (!doc || !out || out_size == 0) {
        return;
    }
    if (strcasestr(doc->titel, "Antrag") != NULL) {
        snprintf(out, out_size, "%s", "Antrag");
        return;
    }
    if ((doc->id % 3) == 0) {
        snprintf(out, out_size, "%s", "Beschlussempfehlung");
        return;
    }
    snprintf(out, out_size, "%s", "Drucksache");
}

static void derive_vorgangsposition_zuordnung(const dip_document_t *doc, char *out, size_t out_size) {
    if (!doc || !out || out_size == 0) {
        return;
    }
    if ((doc->id % 7) == 0) {
        snprintf(out, out_size, "%s", "BR");
        return;
    }
    snprintf(out, out_size, "%s", "BT");
}

static bool match_vorgangsposition_filter(const dip_document_t *doc, const list_filter_t *filter) {
    if (!match_document_filter(doc, filter)) {
        return false;
    }

    char vorgangstyp[64];
    char zuordnung[16];
    derive_vorgangsposition_vorgangstyp(doc, vorgangstyp, sizeof(vorgangstyp));
    derive_vorgangsposition_zuordnung(doc, zuordnung, sizeof(zuordnung));

    if (!matches_any_term_ci(vorgangstyp, filter->vorgangstyp_terms, filter->vorgangstyp_terms_count)) {
        return false;
    }
    if (!matches_any_term_ci(zuordnung, filter->zuordnung_terms, filter->zuordnung_terms_count)) {
        return false;
    }
    return true;
}

static bool match_document_filter(const dip_document_t *doc, const list_filter_t *filter) {
    if (filter->ids_count > 0 && !contains_long(filter->ids, filter->ids_count, doc->id)) {
        return false;
    }
    if (filter->vorgang_ids_count > 0 && !contains_long(filter->vorgang_ids, filter->vorgang_ids_count, doc->id)) {
        return false;
    }
    if (filter->vorgangsposition_ids_count > 0 && !contains_long(filter->vorgangsposition_ids, filter->vorgangsposition_ids_count, doc->id)) {
        return false;
    }
    if (filter->drucksache_ids_count > 0 && !contains_long(filter->drucksache_ids, filter->drucksache_ids_count, doc->id)) {
        return false;
    }
    if (filter->plenarprotokoll_ids_count > 0 && !contains_long(filter->plenarprotokoll_ids, filter->plenarprotokoll_ids_count, doc->id)) {
        return false;
    }
    if (filter->aktivitaet_ids_count > 0 && !contains_long(filter->aktivitaet_ids, filter->aktivitaet_ids_count, doc->id)) {
        return false;
    }
    if (filter->wahlperioden_count > 0 && !filter_contains_wahlperiode(filter, doc->wahlperiode)) {
        return false;
    }
    if (filter->has_dokumentnummer && strcmp(doc->dokumentnummer, filter->dokumentnummer) != 0) {
        return false;
    }
    if (filter->has_datum_start && strcmp(doc->datum, filter->datum_start) < 0) {
        return false;
    }
    if (filter->has_datum_end && strcmp(doc->datum, filter->datum_end) > 0) {
        return false;
    }
    if (filter->has_aktualisiert_start && strcmp(doc->datum, filter->aktualisiert_start) < 0) {
        return false;
    }
    if (filter->has_aktualisiert_end && strcmp(doc->datum, filter->aktualisiert_end) > 0) {
        return false;
    }
    if (filter->has_urheber && strcasestr(doc->urheber, filter->urheber) == NULL) {
        return false;
    }
    if (filter->has_titel && strcasestr(doc->titel, filter->titel) == NULL) {
        return false;
    }
    return true;
}

static bool match_person_filter(const dip_person_t *person, const list_filter_t *filter) {
    if (filter->ids_count > 0 && !contains_long(filter->ids, filter->ids_count, person->id)) {
        return false;
    }
    if (filter->person_ids_count > 0 && !contains_long(filter->person_ids, filter->person_ids_count, person->id)) {
        return false;
    }
    if (filter->wahlperioden_count > 0) {
        bool any_wp = false;
        for (size_t i = 0; i < person->wahlperioden_count; i++) {
            if (filter_contains_wahlperiode(filter, person->wahlperioden[i])) {
                any_wp = true;
                break;
            }
        }
        if (!any_wp) {
            return false;
        }
    }
    if (filter->has_datum_start && strcmp(person->datum, filter->datum_start) < 0) {
        return false;
    }
    if (filter->has_datum_end && strcmp(person->datum, filter->datum_end) > 0) {
        return false;
    }
    char aktualisiert_date[16] = {0};
    if (person->aktualisiert[0] != '\0') {
        memcpy(aktualisiert_date, person->aktualisiert, 10);
        aktualisiert_date[10] = '\0';
    } else {
        snprintf(aktualisiert_date, sizeof(aktualisiert_date), "%s", person->datum);
    }

    if (filter->has_aktualisiert_start && strcmp(aktualisiert_date, filter->aktualisiert_start) < 0) {
        return false;
    }
    if (filter->has_aktualisiert_end && strcmp(aktualisiert_date, filter->aktualisiert_end) > 0) {
        return false;
    }

    if (filter->person_terms_count > 0) {
        bool any_term_match = false;
        for (size_t i = 0; i < filter->person_terms_count; i++) {
            const char *term = filter->person_terms[i];
            if (strcasestr(person->nachname, term) != NULL ||
                strcasestr(person->vorname, term) != NULL ||
                strcasestr(person->titel_prefix, term) != NULL ||
                strcasestr(person->akad_titel, term) != NULL ||
                strcasestr(person->namenszusatz, term) != NULL ||
                strcasestr(person->funktionszusatz, term) != NULL) {
                any_term_match = true;
                break;
            }
        }
        if (!any_term_match) {
            return false;
        }
    }
    return true;
}

static size_t count_matching_documents(const dip_document_t *docs, const dip_document_t *const *ordered_docs, size_t docs_count, const list_filter_t *filter) {
    size_t total = 0;
    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (match_document_filter(doc, filter)) {
            total++;
        }
    }
    return total;
}

static size_t count_matching_vorgaenge(const dip_document_t *docs, const dip_document_t *const *ordered_docs, size_t docs_count, const list_filter_t *filter) {
    size_t total = 0;
    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (match_vorgang_filter(doc, filter)) {
            total++;
        }
    }
    return total;
}

static size_t count_matching_vorgangspositionen(const dip_document_t *docs, const dip_document_t *const *ordered_docs, size_t docs_count, const list_filter_t *filter) {
    size_t total = 0;
    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (match_vorgangsposition_filter(doc, filter)) {
            total++;
        }
    }
    return total;
}

static size_t count_matching_personen(const dip_person_t *personen, size_t personen_count, const list_filter_t *filter) {
    size_t total = 0;
    for (size_t i = 0; i < personen_count; i++) {
        if (match_person_filter(&personen[i], filter)) {
            total++;
        }
    }
    return total;
}

static size_t count_matching_personen_ordered(const dip_person_t *const *ordered_personen, size_t personen_count, const list_filter_t *filter) {
    size_t total = 0;
    for (size_t i = 0; i < personen_count; i++) {
        if (match_person_filter(ordered_personen[i], filter)) {
            total++;
        }
    }
    return total;
}

static bool match_aktivitaet_filter(const dip_document_t *doc, const dip_snapshot_t *snapshot, const list_filter_t *filter) {
    if (!match_document_filter(doc, filter)) {
        return false;
    }
    if (filter->person_ids_count > 0) {
        const dip_person_t *person = pick_related_person(snapshot, doc->id);
        if (!person || !contains_long(filter->person_ids, filter->person_ids_count, person->id)) {
            return false;
        }
    }
    return true;
}

static size_t count_matching_aktivitaet(const dip_document_t *docs, const dip_document_t *const *ordered_docs, size_t docs_count, const dip_snapshot_t *snapshot, const list_filter_t *filter) {
    size_t total = 0;
    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (match_aktivitaet_filter(doc, snapshot, filter)) {
            total++;
        }
    }
    return total;
}

static const char *default_aktualisiert(void) {
    return "1970-01-01T00:00:00+00:00";
}

static int appendf(char *out, size_t out_size, size_t *used, const char *fmt, ...) {
    if (*used >= out_size) {
        return -1;
    }
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(out + *used, out_size - *used, fmt, args);
    va_end(args);
    if (n < 0) {
        return -1;
    }
    if ((size_t)n >= out_size - *used) {
        *used = out_size;
        return -1;
    }
    *used += (size_t)n;
    return 0;
}

static void json_escape_to_buffer(const char *src, char *dst, size_t dst_size) {
    if (dst_size == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }

    size_t w = 0;
    for (size_t i = 0; src[i] != '\0' && w + 1 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (w + 2 >= dst_size) {
                break;
            }
            dst[w++] = '\\';
            dst[w++] = (char)c;
        } else if (c == '\n') {
            if (w + 2 >= dst_size) {
                break;
            }
            dst[w++] = '\\';
            dst[w++] = 'n';
        } else if (c == '\r') {
            if (w + 2 >= dst_size) {
                break;
            }
            dst[w++] = '\\';
            dst[w++] = 'r';
        } else if (c == '\t') {
            if (w + 2 >= dst_size) {
                break;
            }
            dst[w++] = '\\';
            dst[w++] = 't';
        } else if (c < 0x20) {
            if (w + 6 >= dst_size) {
                break;
            }
            int written = snprintf(dst + w, dst_size - w, "\\u%04x", c);
            if (written <= 0 || (size_t)written >= dst_size - w) {
                break;
            }
            w += (size_t)written;
        } else {
            dst[w++] = (char)c;
        }
    }
    dst[w] = '\0';
}

static void xml_escape_to_buffer(const char *src, char *dst, size_t dst_size) {
    if (dst_size == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }

    size_t w = 0;
    for (size_t i = 0; src[i] != '\0' && w + 1 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        const char *repl = NULL;
        if (c == '&') {
            repl = "&amp;";
        } else if (c == '<') {
            repl = "&lt;";
        } else if (c == '>') {
            repl = "&gt;";
        } else if (c == '"') {
            repl = "&quot;";
        } else if (c == '\'') {
            repl = "&apos;";
        }

        if (repl) {
            size_t rn = strlen(repl);
            if (w + rn >= dst_size) {
                break;
            }
            memcpy(dst + w, repl, rn);
            w += rn;
            continue;
        }

        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
            continue;
        }
        dst[w++] = (char)c;
    }
    dst[w] = '\0';
}

static void copy_bounded(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen(src);
    if (n >= dst_size) {
        n = dst_size - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void build_document_list_body_xml(
    char *out,
    size_t out_size,
    const dip_document_t *docs,
    const dip_document_t *const *ordered_docs,
    size_t docs_count,
    const char *entity,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total,
    bool include_text) {

    size_t page_limit = include_text ? LIST_PAGE_LIMIT_TEXT : LIST_PAGE_LIMIT_DEFAULT;

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > page_limit) {
            take = page_limit;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));

    appendf(out, out_size, &used, "<response><numFound>%zu</numFound><cursor>%s</cursor><documents>", total, cursor_buf);

    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (!match_document_filter(doc, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= page_limit) {
            break;
        }

        char titel_esc[2048];
        char dokumentnummer_esc[256];
        char datum_esc[64];
        char fundstelle_esc[512];
        char urheber_esc[512];
        char text_esc[4096];
        xml_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
        xml_escape_to_buffer(doc->dokumentnummer, dokumentnummer_esc, sizeof(dokumentnummer_esc));
        xml_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
        xml_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));
        xml_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
        xml_escape_to_buffer(doc->text_preview, text_esc, sizeof(text_esc));

        appendf(out, out_size, &used, "<document>");
        appendf(out, out_size, &used, "<id>%ld</id><typ>%s</typ>", doc->id, entity);
        appendf(out, out_size, &used, "<titel>%s</titel><dokumentnummer>%s</dokumentnummer>", titel_esc, dokumentnummer_esc);
        appendf(out, out_size, &used, "<wahlperiode>%d</wahlperiode><datum>%s</datum><urheber>%s</urheber><fundstelle>%s</fundstelle>", doc->wahlperiode, datum_esc, urheber_esc, fundstelle_esc);
        if (include_text) {
            appendf(out, out_size, &used, "<text>%s</text>", text_esc);
        }
        appendf(out, out_size, &used, "</document>");
        shown++;
    }

    appendf(out, out_size, &used, "</documents></response>");

}

static void build_document_detail_body_xml(char *out, size_t out_size, const dip_document_t *doc, const char *entity, bool include_text) {
    char titel_esc[2048];
    char dokumentnummer_esc[256];
    char datum_esc[64];
    char fundstelle_esc[512];
    char urheber_esc[512];
    char text_esc[4096];
    xml_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
    xml_escape_to_buffer(doc->dokumentnummer, dokumentnummer_esc, sizeof(dokumentnummer_esc));
    xml_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
    xml_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));
    xml_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
    xml_escape_to_buffer(doc->text_preview, text_esc, sizeof(text_esc));

    size_t used = 0;
    appendf(out, out_size, &used, "<document>");
    appendf(out, out_size, &used, "<id>%ld</id><typ>%s</typ>", doc->id, entity);
    appendf(out, out_size, &used, "<aktualisiert>%s</aktualisiert>", default_aktualisiert());
    appendf(out, out_size, &used, "<dokumentart>%s</dokumentart><herausgeber>BT</herausgeber>", strcmp(entity, "Drucksache") == 0 ? "Drucksache" : "Plenarprotokoll");
    appendf(out, out_size, &used, "<titel>%s</titel><dokumentnummer>%s</dokumentnummer>", titel_esc, dokumentnummer_esc);
    appendf(out, out_size, &used, "<wahlperiode>%d</wahlperiode><datum>%s</datum><urheber>%s</urheber><fundstelle>%s</fundstelle>", doc->wahlperiode, datum_esc, urheber_esc, fundstelle_esc);
    appendf(out, out_size, &used, "<vorgangsbezug_anzahl>0</vorgangsbezug_anzahl>");
    if (include_text) {
        appendf(out, out_size, &used, "<text>%s</text>", text_esc);
    }
    appendf(out, out_size, &used, "</document>");
}

static void build_person_list_body_xml(
    char *out,
    size_t out_size,
    const dip_person_t *personen,
    const dip_person_t *const *ordered_personen,
    size_t personen_count,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total) {

    size_t page_limit = LIST_PAGE_LIMIT_DEFAULT;
    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > page_limit) {
            take = page_limit;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "<response><numFound>%zu</numFound><cursor>%s</cursor><documents>", total, cursor_buf);

    for (size_t i = 0; i < personen_count; i++) {
        const dip_person_t *p = ordered_personen ? ordered_personen[i] : &personen[i];
        if (!match_person_filter(p, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= page_limit) {
            break;
        }

        char nachname_esc[256];
        char vorname_esc[256];
        char basisdatum_esc[64];
        char datum_esc[64];
        char aktualisiert_esc[64];
        char funktion_esc[256];
        char namenszusatz_esc[256];
        char fraktion_esc[256];
        xml_escape_to_buffer(p->nachname, nachname_esc, sizeof(nachname_esc));
        xml_escape_to_buffer(p->vorname, vorname_esc, sizeof(vorname_esc));
        xml_escape_to_buffer(p->basisdatum, basisdatum_esc, sizeof(basisdatum_esc));
        xml_escape_to_buffer(p->datum, datum_esc, sizeof(datum_esc));
        xml_escape_to_buffer(p->aktualisiert, aktualisiert_esc, sizeof(aktualisiert_esc));
        xml_escape_to_buffer(p->funktion, funktion_esc, sizeof(funktion_esc));
        xml_escape_to_buffer(p->namenszusatz, namenszusatz_esc, sizeof(namenszusatz_esc));
        xml_escape_to_buffer(p->fraktion, fraktion_esc, sizeof(fraktion_esc));

        appendf(out, out_size, &used, "<document><id>%ld</id><typ>Person</typ><nachname>%s</nachname><vorname>%s</vorname>", p->id, nachname_esc, vorname_esc);
        if (p->namenszusatz[0] != '\0') {
            appendf(out, out_size, &used, "<namenszusatz>%s</namenszusatz>", namenszusatz_esc);
        }
        appendf(out, out_size, &used, "<basisdatum>%s</basisdatum><datum>%s</datum><aktualisiert>%s</aktualisiert><titel>%s, %s</titel><funktion>%s</funktion>", basisdatum_esc, datum_esc, aktualisiert_esc, nachname_esc, vorname_esc, funktion_esc);
        if (p->fraktion[0] != '\0') {
            appendf(out, out_size, &used, "<fraktion>%s</fraktion>", fraktion_esc);
        }
        appendf(out, out_size, &used, "<wahlperiode>");
        for (size_t wp_idx = 0; wp_idx < p->wahlperioden_count; wp_idx++) {
            appendf(out, out_size, &used, "<eintrag>%d</eintrag>", p->wahlperioden[wp_idx]);
        }
        appendf(out, out_size, &used, "</wahlperiode></document>");
        shown++;
    }

    appendf(out, out_size, &used, "</documents></response>");
}

static void build_person_detail_body_xml(char *out, size_t out_size, const dip_person_t *person) {
    char nachname_esc[256];
    char vorname_esc[256];
    char basisdatum_esc[64];
    char datum_esc[64];
    char aktualisiert_esc[64];
    char namenszusatz_esc[256];
    char funktion_esc[256];
    char funktionszusatz_esc[256];
    char fraktion_esc[256];
    char wahlkreiszusatz_esc[256];
    char ressort_esc[320];
    char bundesland_esc[128];
    xml_escape_to_buffer(person->nachname, nachname_esc, sizeof(nachname_esc));
    xml_escape_to_buffer(person->vorname, vorname_esc, sizeof(vorname_esc));
    xml_escape_to_buffer(person->basisdatum, basisdatum_esc, sizeof(basisdatum_esc));
    xml_escape_to_buffer(person->datum, datum_esc, sizeof(datum_esc));
    xml_escape_to_buffer(person->aktualisiert, aktualisiert_esc, sizeof(aktualisiert_esc));
    xml_escape_to_buffer(person->namenszusatz, namenszusatz_esc, sizeof(namenszusatz_esc));
    xml_escape_to_buffer(person->funktion, funktion_esc, sizeof(funktion_esc));
    xml_escape_to_buffer(person->funktionszusatz, funktionszusatz_esc, sizeof(funktionszusatz_esc));
    xml_escape_to_buffer(person->fraktion, fraktion_esc, sizeof(fraktion_esc));
    xml_escape_to_buffer(person->wahlkreiszusatz, wahlkreiszusatz_esc, sizeof(wahlkreiszusatz_esc));
    xml_escape_to_buffer(person->ressort, ressort_esc, sizeof(ressort_esc));
    xml_escape_to_buffer(person->bundesland, bundesland_esc, sizeof(bundesland_esc));

    size_t used = 0;
    appendf(out, out_size, &used, "<document><id>%ld</id><nachname>%s</nachname><vorname>%s</vorname>", person->id, nachname_esc, vorname_esc);
    if (person->namenszusatz[0] != '\0') {
        appendf(out, out_size, &used, "<namenszusatz>%s</namenszusatz>", namenszusatz_esc);
    }
    appendf(out, out_size, &used, "<typ>Person</typ><wahlperiode>");
    for (size_t wp_idx = 0; wp_idx < person->wahlperioden_count; wp_idx++) {
        appendf(out, out_size, &used, "<eintrag>%d</eintrag>", person->wahlperioden[wp_idx]);
    }
    appendf(out, out_size, &used, "</wahlperiode><basisdatum>%s</basisdatum><datum>%s</datum><aktualisiert>%s</aktualisiert><titel>%s, %s</titel><funktion>%s</funktion>", basisdatum_esc, datum_esc, aktualisiert_esc, nachname_esc, vorname_esc, funktion_esc);
    appendf(out, out_size, &used, "<funktionszusatz>%s</funktionszusatz><fraktion>%s</fraktion><wahlkreiszusatz>%s</wahlkreiszusatz><ressort>%s</ressort><bundesland>%s</bundesland>", funktionszusatz_esc, fraktion_esc, wahlkreiszusatz_esc, ressort_esc, bundesland_esc);
    appendf(out, out_size, &used, "<person_roles><eintrag><funktion>%s</funktion><nachname>%s</nachname><vorname>%s</vorname></eintrag></person_roles></document>", funktion_esc, nachname_esc, vorname_esc);
}

static const dip_person_t *pick_related_person(const dip_snapshot_t *snapshot, long doc_id) {
    if (!snapshot || snapshot->personen_count == 0 || !snapshot->personen) {
        return NULL;
    }
    size_t idx = (size_t)((doc_id - 1) % (long)snapshot->personen_count);
    return &snapshot->personen[idx];
}

static void build_vorgang_list_body(
    char *out,
    size_t out_size,
    const dip_document_t *docs,
    const dip_document_t *const *ordered_docs,
    size_t docs_count,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total) {

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;
    appendf(out, out_size, &used, "{\"numFound\":%zu,\"cursor\":\"", total);

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > LIST_PAGE_LIMIT_DEFAULT) {
            take = LIST_PAGE_LIMIT_DEFAULT;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "%s\",\"documents\":[", cursor_buf);

    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (!match_vorgang_filter(doc, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= LIST_PAGE_LIMIT_DEFAULT) {
            break;
        }
        if (shown > 0) {
            appendf(out, out_size, &used, ",");
        }

        char titel_esc[2048];
        char datum_esc[64];
        char urheber_esc[512];
        char gesta_esc[64];
        json_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
        json_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
        json_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
        char gesta_raw[32];
        derive_vorgang_gesta(doc, gesta_raw, sizeof(gesta_raw));
        json_escape_to_buffer(gesta_raw, gesta_esc, sizeof(gesta_esc));

        appendf(
            out,
            out_size,
            &used,
            "{\"aktualisiert\":\"%sT00:00:00+00:00\",\"beratungsstand\":\"In Beratung\",\"datum\":\"%s\",\"id\":\"%ld\",\"initiative\":[\"%s\"],\"titel\":\"%s\",\"typ\":\"Vorgang\",\"vorgangstyp\":\"Gesetzgebung\",\"wahlperiode\":%d,\"abstract\":\"%s\",\"sachgebiet\":[\"Bundestag\"],\"deskriptor\":[{\"name\":\"%s\",\"typ\":\"Sachbegriffe\",\"fundstelle\":true}],\"gesta\":\"%s\",\"zustimmungsbeduerftigkeit\":[],\"vorgang_verlinkung\":[]}",
            datum_esc,
            datum_esc,
            doc->id,
            urheber_esc,
            titel_esc,
            doc->wahlperiode,
            titel_esc,
            titel_esc,
            gesta_esc);
        shown++;
    }

    appendf(out, out_size, &used, "]}");
}

static void build_vorgang_list_body_xml(
    char *out,
    size_t out_size,
    const dip_document_t *docs,
    const dip_document_t *const *ordered_docs,
    size_t docs_count,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total) {

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > LIST_PAGE_LIMIT_DEFAULT) {
            take = LIST_PAGE_LIMIT_DEFAULT;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "<response><numFound>%zu</numFound><cursor>%s</cursor><documents>", total, cursor_buf);

    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (!match_vorgang_filter(doc, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= LIST_PAGE_LIMIT_DEFAULT) {
            break;
        }

        char titel_esc[2048];
        char datum_esc[64];
        char urheber_esc[512];
        char gesta_esc[64];
        xml_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
        xml_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
        xml_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
        char gesta_raw[32];
        derive_vorgang_gesta(doc, gesta_raw, sizeof(gesta_raw));
        xml_escape_to_buffer(gesta_raw, gesta_esc, sizeof(gesta_esc));

        appendf(out, out_size, &used, "<document><id>%ld</id><typ>Vorgang</typ><titel>%s</titel><datum>%s</datum><wahlperiode>%d</wahlperiode><vorgangstyp>Gesetzgebung</vorgangstyp><beratungsstand>In Beratung</beratungsstand><initiative><eintrag>%s</eintrag></initiative><abstract>%s</abstract><sachgebiet><eintrag>Bundestag</eintrag></sachgebiet><deskriptor><eintrag><name>%s</name><typ>Sachbegriffe</typ><fundstelle>true</fundstelle></eintrag></deskriptor><gesta>%s</gesta><zustimmungsbeduerftigkeit></zustimmungsbeduerftigkeit><vorgang_verlinkung></vorgang_verlinkung></document>", doc->id, titel_esc, datum_esc, doc->wahlperiode, urheber_esc, titel_esc, titel_esc, gesta_esc);
        shown++;
    }

    appendf(out, out_size, &used, "</documents></response>");
}

static void build_vorgang_detail_body(char *out, size_t out_size, const dip_document_t *doc) {
    char titel_esc[2048];
    char datum_esc[64];
    char urheber_esc[512];
    char gesta_esc[64];
    json_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
    json_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
    json_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
    char gesta_raw[32];
    derive_vorgang_gesta(doc, gesta_raw, sizeof(gesta_raw));
    json_escape_to_buffer(gesta_raw, gesta_esc, sizeof(gesta_esc));

    snprintf(
        out,
        out_size,
        "{\"aktualisiert\":\"%sT00:00:00+00:00\",\"beratungsstand\":\"In Beratung\",\"datum\":\"%s\",\"id\":\"%ld\",\"initiative\":[\"%s\"],\"titel\":\"%s\",\"typ\":\"Vorgang\",\"vorgangstyp\":\"Gesetzgebung\",\"wahlperiode\":%d,\"abstract\":\"%s\",\"sachgebiet\":[\"Bundestag\"],\"deskriptor\":[{\"name\":\"%s\",\"typ\":\"Sachbegriffe\",\"fundstelle\":true}],\"gesta\":\"%s\",\"zustimmungsbeduerftigkeit\":[],\"vorgang_verlinkung\":[]}",
        datum_esc,
        datum_esc,
        doc->id,
        urheber_esc,
        titel_esc,
        doc->wahlperiode,
        titel_esc,
        titel_esc,
        gesta_esc);
}

static void build_vorgang_detail_body_xml(char *out, size_t out_size, const dip_document_t *doc) {
    char titel_esc[2048];
    char datum_esc[64];
    char urheber_esc[512];
    char gesta_esc[64];
    xml_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
    xml_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
    xml_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
    char gesta_raw[32];
    derive_vorgang_gesta(doc, gesta_raw, sizeof(gesta_raw));
    xml_escape_to_buffer(gesta_raw, gesta_esc, sizeof(gesta_esc));

    snprintf(
        out,
        out_size,
        "<document><aktualisiert>%sT00:00:00+00:00</aktualisiert><beratungsstand>In Beratung</beratungsstand><datum>%s</datum><id>%ld</id><initiative><eintrag>%s</eintrag></initiative><titel>%s</titel><typ>Vorgang</typ><vorgangstyp>Gesetzgebung</vorgangstyp><wahlperiode>%d</wahlperiode><abstract>%s</abstract><sachgebiet><eintrag>Bundestag</eintrag></sachgebiet><deskriptor><eintrag><name>%s</name><typ>Sachbegriffe</typ><fundstelle>true</fundstelle></eintrag></deskriptor><gesta>%s</gesta><zustimmungsbeduerftigkeit></zustimmungsbeduerftigkeit><vorgang_verlinkung></vorgang_verlinkung></document>",
        datum_esc,
        datum_esc,
        doc->id,
        urheber_esc,
        titel_esc,
        doc->wahlperiode,
        titel_esc,
        titel_esc,
        gesta_esc);
}

static void build_vorgangsposition_list_body(
    char *out,
    size_t out_size,
    const dip_document_t *docs,
    const dip_document_t *const *ordered_docs,
    size_t docs_count,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total,
    size_t personen_count) {

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;
    appendf(out, out_size, &used, "{\"numFound\":%zu,\"cursor\":\"", total);

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > LIST_PAGE_LIMIT_DEFAULT) {
            take = LIST_PAGE_LIMIT_DEFAULT;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "%s\",\"documents\":[", cursor_buf);

    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (!match_vorgangsposition_filter(doc, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= LIST_PAGE_LIMIT_DEFAULT) {
            break;
        }
        if (shown > 0) {
            appendf(out, out_size, &used, ",");
        }

        char titel_esc[2048];
        char datum_esc[64];
        char urheber_esc[512];
        char fundstelle_esc[512];
        char dokumentnummer_esc[256];
        char vorgangstyp_esc[128];
        char zuordnung_esc[32];
        char vorgangsposition_esc[2048];
        json_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
        json_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
        json_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
        json_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));
        json_escape_to_buffer(doc->dokumentnummer, dokumentnummer_esc, sizeof(dokumentnummer_esc));

        char vorgangstyp_raw[64];
        char zuordnung_raw[16];
        derive_vorgangsposition_vorgangstyp(doc, vorgangstyp_raw, sizeof(vorgangstyp_raw));
        derive_vorgangsposition_zuordnung(doc, zuordnung_raw, sizeof(zuordnung_raw));
        json_escape_to_buffer(vorgangstyp_raw, vorgangstyp_esc, sizeof(vorgangstyp_esc));
        json_escape_to_buffer(zuordnung_raw, zuordnung_esc, sizeof(zuordnung_esc));

        if (doc->fundstelle[0] != '\0') {
            copy_bounded(vorgangsposition_esc, sizeof(vorgangsposition_esc), fundstelle_esc);
        } else {
            copy_bounded(vorgangsposition_esc, sizeof(vorgangsposition_esc), titel_esc);
        }

        bool fortsetzung = ((doc->id % 2) == 0);
        bool nachtrag = ((doc->id % 5) == 0);
        bool gang = ((doc->id % 3) == 0);
        bool has_urheber = doc->urheber[0] != '\0' && strcmp(doc->urheber, "Unbekannt") != 0;

        char fundstelle_urheber_json[1536];
        char urheber_json[1536];
        if (has_urheber) {
            snprintf(
                fundstelle_urheber_json,
                sizeof(fundstelle_urheber_json),
                "[{\"bezeichnung\":\"%s\",\"titel\":\"%s\"}]",
                urheber_esc,
                urheber_esc);
            snprintf(
                urheber_json,
                sizeof(urheber_json),
                "[{\"bezeichnung\":\"%s\",\"titel\":\"%s\",\"ist_initiative\":true}]",
                urheber_esc,
                urheber_esc);
        } else {
            snprintf(fundstelle_urheber_json, sizeof(fundstelle_urheber_json), "[]");
            snprintf(urheber_json, sizeof(urheber_json), "[]");
        }

        appendf(
            out,
            out_size,
            &used,
            "{\"aktivitaet_anzahl\":%d,\"aktualisiert\":\"%sT00:00:00+00:00\",\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"fortsetzung\":%s,\"fundstelle\":{\"id\":\"%ld\",\"dokumentnummer\":\"%s\",\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"herausgeber\":\"BT\",\"urheber\":%s},\"gang\":%s,\"id\":\"%ld\",\"nachtrag\":%s,\"titel\":\"%s\",\"typ\":\"Vorgangsposition\",\"urheber\":%s,\"urheber_anzahl\":%d,\"vorgang_id\":\"%ld\",\"vorgangsposition\":\"%s\",\"vorgangstyp\":\"%s\",\"zuordnung\":\"%s\",\"wahlperiode\":%d}",
            personen_count > 0 ? 1 : 0,
            datum_esc,
            datum_esc,
            fortsetzung ? "true" : "false",
            doc->id,
            dokumentnummer_esc,
            datum_esc,
            fundstelle_urheber_json,
            gang ? "true" : "false",
            doc->id,
            nachtrag ? "true" : "false",
            titel_esc,
            urheber_json,
            has_urheber ? 1 : 0,
            doc->id,
            vorgangsposition_esc,
            vorgangstyp_esc,
            zuordnung_esc,
            doc->wahlperiode);
        shown++;
    }

    appendf(out, out_size, &used, "]}");
}

static void build_vorgangsposition_list_body_xml(
    char *out,
    size_t out_size,
    const dip_document_t *docs,
    const dip_document_t *const *ordered_docs,
    size_t docs_count,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total,
    size_t personen_count) {

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > LIST_PAGE_LIMIT_DEFAULT) {
            take = LIST_PAGE_LIMIT_DEFAULT;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "<response><numFound>%zu</numFound><cursor>%s</cursor><documents>", total, cursor_buf);

    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (!match_vorgangsposition_filter(doc, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= LIST_PAGE_LIMIT_DEFAULT) {
            break;
        }

        char titel_esc[2048];
        char datum_esc[64];
        char urheber_esc[512];
        char fundstelle_esc[512];
        char dokumentnummer_esc[256];
        char vorgangstyp_esc[128];
        char zuordnung_esc[32];
        char vorgangsposition_esc[2048];
        xml_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
        xml_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
        xml_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
        xml_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));
        xml_escape_to_buffer(doc->dokumentnummer, dokumentnummer_esc, sizeof(dokumentnummer_esc));

        char vorgangstyp_raw[64];
        char zuordnung_raw[16];
        derive_vorgangsposition_vorgangstyp(doc, vorgangstyp_raw, sizeof(vorgangstyp_raw));
        derive_vorgangsposition_zuordnung(doc, zuordnung_raw, sizeof(zuordnung_raw));
        xml_escape_to_buffer(vorgangstyp_raw, vorgangstyp_esc, sizeof(vorgangstyp_esc));
        xml_escape_to_buffer(zuordnung_raw, zuordnung_esc, sizeof(zuordnung_esc));

        if (doc->fundstelle[0] != '\0') {
            copy_bounded(vorgangsposition_esc, sizeof(vorgangsposition_esc), fundstelle_esc);
        } else {
            copy_bounded(vorgangsposition_esc, sizeof(vorgangsposition_esc), titel_esc);
        }

        bool fortsetzung = ((doc->id % 2) == 0);
        bool nachtrag = ((doc->id % 5) == 0);
        bool gang = ((doc->id % 3) == 0);
        bool has_urheber = doc->urheber[0] != '\0' && strcmp(doc->urheber, "Unbekannt") != 0;

        appendf(out, out_size, &used, "<document><id>%ld</id><typ>Vorgangsposition</typ><titel>%s</titel><datum>%s</datum><wahlperiode>%d</wahlperiode><dokumentart>Drucksache</dokumentart><fortsetzung>%s</fortsetzung><nachtrag>%s</nachtrag><gang>%s</gang><fundstelle><id>%ld</id><dokumentnummer>%s</dokumentnummer><datum>%s</datum><dokumentart>Drucksache</dokumentart><herausgeber>BT</herausgeber>", doc->id, titel_esc, datum_esc, doc->wahlperiode, fortsetzung ? "true" : "false", nachtrag ? "true" : "false", gang ? "true" : "false", doc->id, dokumentnummer_esc, datum_esc);
        if (has_urheber) {
            appendf(out, out_size, &used, "<urheber><eintrag><bezeichnung>%s</bezeichnung><titel>%s</titel></eintrag></urheber>", urheber_esc, urheber_esc);
        } else {
            appendf(out, out_size, &used, "<urheber></urheber>");
        }
        appendf(out, out_size, &used, "</fundstelle><vorgang_id>%ld</vorgang_id><vorgangstyp>%s</vorgangstyp><zuordnung>%s</zuordnung><aktivitaet_anzahl>%d</aktivitaet_anzahl><urheber_anzahl>%d</urheber_anzahl><vorgangsposition>%s</vorgangsposition>", doc->id, vorgangstyp_esc, zuordnung_esc, personen_count > 0 ? 1 : 0, has_urheber ? 1 : 0, vorgangsposition_esc);
        if (has_urheber) {
            appendf(out, out_size, &used, "<urheber><eintrag><bezeichnung>%s</bezeichnung><titel>%s</titel><ist_initiative>true</ist_initiative></eintrag></urheber>", urheber_esc, urheber_esc);
        } else {
            appendf(out, out_size, &used, "<urheber></urheber>");
        }
        appendf(out, out_size, &used, "</document>");
        shown++;
    }

    appendf(out, out_size, &used, "</documents></response>");
}

static void build_vorgangsposition_detail_body(char *out, size_t out_size, const dip_document_t *doc, size_t personen_count) {
    char titel_esc[2048];
    char datum_esc[64];
    char urheber_esc[512];
    char fundstelle_esc[512];
    char dokumentnummer_esc[256];
    char vorgangstyp_esc[128];
    char zuordnung_esc[32];
    char vorgangsposition_esc[2048];
    json_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
    json_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
    json_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
    json_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));
    json_escape_to_buffer(doc->dokumentnummer, dokumentnummer_esc, sizeof(dokumentnummer_esc));

    char vorgangstyp_raw[64];
    char zuordnung_raw[16];
    derive_vorgangsposition_vorgangstyp(doc, vorgangstyp_raw, sizeof(vorgangstyp_raw));
    derive_vorgangsposition_zuordnung(doc, zuordnung_raw, sizeof(zuordnung_raw));
    json_escape_to_buffer(vorgangstyp_raw, vorgangstyp_esc, sizeof(vorgangstyp_esc));
    json_escape_to_buffer(zuordnung_raw, zuordnung_esc, sizeof(zuordnung_esc));

    if (doc->fundstelle[0] != '\0') {
        copy_bounded(vorgangsposition_esc, sizeof(vorgangsposition_esc), fundstelle_esc);
    } else {
        copy_bounded(vorgangsposition_esc, sizeof(vorgangsposition_esc), titel_esc);
    }

    bool fortsetzung = ((doc->id % 2) == 0);
    bool nachtrag = ((doc->id % 5) == 0);
    bool gang = ((doc->id % 3) == 0);
    bool has_urheber = doc->urheber[0] != '\0' && strcmp(doc->urheber, "Unbekannt") != 0;

    char fundstelle_urheber_json[1536];
    char urheber_json[1536];
    if (has_urheber) {
        snprintf(
            fundstelle_urheber_json,
            sizeof(fundstelle_urheber_json),
            "[{\"bezeichnung\":\"%s\",\"titel\":\"%s\"}]",
            urheber_esc,
            urheber_esc);
        snprintf(
            urheber_json,
            sizeof(urheber_json),
            "[{\"bezeichnung\":\"%s\",\"titel\":\"%s\",\"ist_initiative\":true}]",
            urheber_esc,
            urheber_esc);
    } else {
        snprintf(fundstelle_urheber_json, sizeof(fundstelle_urheber_json), "[]");
        snprintf(urheber_json, sizeof(urheber_json), "[]");
    }

    snprintf(
        out,
        out_size,
        "{\"aktivitaet_anzahl\":%d,\"aktualisiert\":\"%sT00:00:00+00:00\",\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"fortsetzung\":%s,\"fundstelle\":{\"id\":\"%ld\",\"dokumentnummer\":\"%s\",\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"herausgeber\":\"BT\",\"urheber\":%s},\"gang\":%s,\"id\":\"%ld\",\"nachtrag\":%s,\"titel\":\"%s\",\"typ\":\"Vorgangsposition\",\"urheber\":%s,\"urheber_anzahl\":%d,\"vorgang_id\":\"%ld\",\"vorgangsposition\":\"%s\",\"vorgangstyp\":\"%s\",\"zuordnung\":\"%s\",\"wahlperiode\":%d}",
        personen_count > 0 ? 1 : 0,
        datum_esc,
        datum_esc,
        fortsetzung ? "true" : "false",
        doc->id,
        dokumentnummer_esc,
        datum_esc,
        fundstelle_urheber_json,
        gang ? "true" : "false",
        doc->id,
        nachtrag ? "true" : "false",
        titel_esc,
        urheber_json,
        has_urheber ? 1 : 0,
        doc->id,
        vorgangsposition_esc,
        vorgangstyp_esc,
        zuordnung_esc,
        doc->wahlperiode);
}

static void build_vorgangsposition_detail_body_xml(char *out, size_t out_size, const dip_document_t *doc, size_t personen_count) {
    char titel_esc[2048];
    char datum_esc[64];
    char urheber_esc[512];
    char fundstelle_esc[512];
    char dokumentnummer_esc[256];
    char vorgangstyp_esc[128];
    char zuordnung_esc[32];
    char vorgangsposition_esc[2048];
    xml_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
    xml_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
    xml_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
    xml_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));
    xml_escape_to_buffer(doc->dokumentnummer, dokumentnummer_esc, sizeof(dokumentnummer_esc));

    char vorgangstyp_raw[64];
    char zuordnung_raw[16];
    derive_vorgangsposition_vorgangstyp(doc, vorgangstyp_raw, sizeof(vorgangstyp_raw));
    derive_vorgangsposition_zuordnung(doc, zuordnung_raw, sizeof(zuordnung_raw));
    xml_escape_to_buffer(vorgangstyp_raw, vorgangstyp_esc, sizeof(vorgangstyp_esc));
    xml_escape_to_buffer(zuordnung_raw, zuordnung_esc, sizeof(zuordnung_esc));

    if (doc->fundstelle[0] != '\0') {
        copy_bounded(vorgangsposition_esc, sizeof(vorgangsposition_esc), fundstelle_esc);
    } else {
        copy_bounded(vorgangsposition_esc, sizeof(vorgangsposition_esc), titel_esc);
    }

    bool fortsetzung = ((doc->id % 2) == 0);
    bool nachtrag = ((doc->id % 5) == 0);
    bool gang = ((doc->id % 3) == 0);
    bool has_urheber = doc->urheber[0] != '\0' && strcmp(doc->urheber, "Unbekannt") != 0;

    size_t used = 0;
    appendf(out, out_size, &used, "<document><aktivitaet_anzahl>%d</aktivitaet_anzahl><aktualisiert>%sT00:00:00+00:00</aktualisiert><datum>%s</datum><wahlperiode>%d</wahlperiode><dokumentart>Drucksache</dokumentart><fortsetzung>%s</fortsetzung><fundstelle><id>%ld</id><dokumentnummer>%s</dokumentnummer><datum>%s</datum><dokumentart>Drucksache</dokumentart><herausgeber>BT</herausgeber>", personen_count > 0 ? 1 : 0, datum_esc, datum_esc, doc->wahlperiode, fortsetzung ? "true" : "false", doc->id, dokumentnummer_esc, datum_esc);
    if (has_urheber) {
        appendf(out, out_size, &used, "<urheber><eintrag><bezeichnung>%s</bezeichnung><titel>%s</titel></eintrag></urheber>", urheber_esc, urheber_esc);
    } else {
        appendf(out, out_size, &used, "<urheber></urheber>");
    }
    appendf(out, out_size, &used, "</fundstelle><gang>%s</gang><id>%ld</id><nachtrag>%s</nachtrag><titel>%s</titel><typ>Vorgangsposition</typ>", gang ? "true" : "false", doc->id, nachtrag ? "true" : "false", titel_esc);
    if (has_urheber) {
        appendf(out, out_size, &used, "<urheber><eintrag><bezeichnung>%s</bezeichnung><titel>%s</titel><ist_initiative>true</ist_initiative></eintrag></urheber><urheber_anzahl>1</urheber_anzahl>", urheber_esc, urheber_esc);
    } else {
        appendf(out, out_size, &used, "<urheber></urheber><urheber_anzahl>0</urheber_anzahl>");
    }
    appendf(out, out_size, &used, "<vorgang_id>%ld</vorgang_id><vorgangsposition>%s</vorgangsposition><vorgangstyp>%s</vorgangstyp><zuordnung>%s</zuordnung></document>", doc->id, vorgangsposition_esc, vorgangstyp_esc, zuordnung_esc);
}

static void build_aktivitaet_list_body(
    char *out,
    size_t out_size,
    const dip_document_t *docs,
    const dip_document_t *const *ordered_docs,
    size_t docs_count,
    const dip_snapshot_t *snapshot,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total) {

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;
    appendf(out, out_size, &used, "{\"numFound\":%zu,\"cursor\":\"", total);

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > LIST_PAGE_LIMIT_DEFAULT) {
            take = LIST_PAGE_LIMIT_DEFAULT;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "%s\",\"documents\":[", cursor_buf);

    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (!match_aktivitaet_filter(doc, snapshot, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= LIST_PAGE_LIMIT_DEFAULT) {
            break;
        }
        if (shown > 0) {
            appendf(out, out_size, &used, ",");
        }

        const dip_person_t *person = pick_related_person(snapshot, doc->id);
        long person_id = person ? person->id : 0;

        char titel_esc[2048];
        char datum_esc[64];
        char fundstelle_esc[512];
        json_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
        json_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
        json_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));

        appendf(
            out,
            out_size,
            &used,
            "{\"aktivitaetsart\":\"Dokumentbezug\",\"aktualisiert\":\"1970-01-01T00:00:00\",\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"fundstelle\":\"%s\",\"id\":\"%ld\",\"person_id\":\"%ld\",\"titel\":\"%s\",\"typ\":\"Aktivitaet\",\"vorgangsbezug\":[{\"id\":\"%ld\",\"titel\":\"%s\"}],\"vorgangsbezug_anzahl\":1,\"wahlperiode\":%d}",
            datum_esc,
            fundstelle_esc,
            doc->id,
            person_id,
            titel_esc,
            doc->id,
            titel_esc,
            doc->wahlperiode);
        shown++;
    }

    appendf(out, out_size, &used, "]}");
}

static void build_aktivitaet_list_body_xml(
    char *out,
    size_t out_size,
    const dip_document_t *docs,
    const dip_document_t *const *ordered_docs,
    size_t docs_count,
    const dip_snapshot_t *snapshot,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total) {

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > LIST_PAGE_LIMIT_DEFAULT) {
            take = LIST_PAGE_LIMIT_DEFAULT;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "<response><numFound>%zu</numFound><cursor>%s</cursor><documents>", total, cursor_buf);

    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (!match_aktivitaet_filter(doc, snapshot, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= LIST_PAGE_LIMIT_DEFAULT) {
            break;
        }

        const dip_person_t *person = pick_related_person(snapshot, doc->id);
        long person_id = person ? person->id : 0;

        char titel_esc[2048];
        char datum_esc[64];
        char fundstelle_esc[512];
        xml_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
        xml_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
        xml_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));

        appendf(out, out_size, &used, "<document><id>%ld</id><typ>Aktivitaet</typ><titel>%s</titel><datum>%s</datum><fundstelle>%s</fundstelle><dokumentart>Drucksache</dokumentart><aktivitaetsart>Dokumentbezug</aktivitaetsart><person_id>%ld</person_id><wahlperiode>%d</wahlperiode><vorgangsbezug><vorgang><id>%ld</id><titel>%s</titel></vorgang></vorgangsbezug><vorgangsbezug_anzahl>1</vorgangsbezug_anzahl></document>", doc->id, titel_esc, datum_esc, fundstelle_esc, person_id, doc->wahlperiode, doc->id, titel_esc);
        shown++;
    }

    appendf(out, out_size, &used, "</documents></response>");
}

static void build_aktivitaet_detail_body(char *out, size_t out_size, const dip_document_t *doc, const dip_snapshot_t *snapshot) {
    const dip_person_t *person = pick_related_person(snapshot, doc->id);
    long person_id = person ? person->id : 0;

    char titel_esc[2048];
    char datum_esc[64];
    char fundstelle_esc[512];
    json_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
    json_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
    json_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));

    snprintf(
        out,
        out_size,
        "{\"aktivitaetsart\":\"Dokumentbezug\",\"aktualisiert\":\"1970-01-01T00:00:00\",\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"fundstelle\":\"%s\",\"id\":\"%ld\",\"person_id\":\"%ld\",\"titel\":\"%s\",\"typ\":\"Aktivitaet\",\"vorgangsbezug\":[{\"id\":\"%ld\",\"titel\":\"%s\"}],\"vorgangsbezug_anzahl\":1,\"wahlperiode\":%d}",
        datum_esc,
        fundstelle_esc,
        doc->id,
        person_id,
        titel_esc,
        doc->id,
        titel_esc,
        doc->wahlperiode);
}

static void build_aktivitaet_detail_body_xml(char *out, size_t out_size, const dip_document_t *doc, const dip_snapshot_t *snapshot) {
    const dip_person_t *person = pick_related_person(snapshot, doc->id);
    long person_id = person ? person->id : 0;

    char titel_esc[2048];
    char datum_esc[64];
    char fundstelle_esc[512];
    xml_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
    xml_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
    xml_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));

    snprintf(
        out,
        out_size,
        "<document><aktivitaetsart>Dokumentbezug</aktivitaetsart><aktualisiert>%s</aktualisiert><datum>%s</datum><dokumentart>Drucksache</dokumentart><fundstelle>%s</fundstelle><id>%ld</id><person_id>%ld</person_id><titel>%s</titel><typ>Aktivitaet</typ><vorgangsbezug><vorgang><id>%ld</id><titel>%s</titel></vorgang></vorgangsbezug><vorgangsbezug_anzahl>1</vorgangsbezug_anzahl><wahlperiode>%d</wahlperiode></document>",
        default_aktualisiert(),
        datum_esc,
        fundstelle_esc,
        doc->id,
        person_id,
        titel_esc,
        doc->id,
        titel_esc,
        doc->wahlperiode);
}

static void build_list_stub_body_xml(char *out, size_t out_size, const char *entity, uint64_t snapshot_version, const list_filter_t *filter) {
    size_t total = (filter->ids_count > 0 && !contains_long(filter->ids, filter->ids_count, 1)) ? 0 : 1;
    if (filter->offset > total) {
        total = 0;
    }

    size_t next_offset = filter->offset;
    if (total > 0 && filter->offset == 0) {
        next_offset = 0;
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));

    if (total == 0 || filter->offset > 0) {
        snprintf(out, out_size, "<response><numFound>%zu</numFound><cursor>%s</cursor><documents></documents></response>", total, cursor_buf);
    } else {
        snprintf(out, out_size, "<response><numFound>1</numFound><cursor>%s</cursor><documents><document><id>1</id><typ>%s</typ><titel>Stub</titel></document></documents></response>", cursor_buf, entity);
    }
}

static void build_detail_stub_body_xml(char *out, size_t out_size, const char *entity, long id) {
    snprintf(out, out_size, "<document><id>%ld</id><typ>%s</typ><titel>Stub</titel></document>", id, entity);
}

static void build_api_index_html(char *out, size_t out_size) {
    size_t used = 0;
    appendf(out, out_size, &used,
            "<!doctype html><html lang=\"de\"><head>"
            "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>DIP API – Endpoint Übersicht</title>"
            "<style>"
            "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;line-height:1.4;color:#111;}"
            "h1,h2{margin:0 0 12px 0;}"
            "p{margin:0 0 12px 0;}"
            "table{border-collapse:collapse;width:100%%;margin:12px 0 20px 0;}"
            "th,td{border:1px solid #ddd;padding:8px;vertical-align:top;text-align:left;}"
            "th{background:#f5f5f5;}"
            "code{background:#f6f8fa;padding:1px 4px;border-radius:4px;}"
            "small{color:#555;}"
            "</style></head><body>");

    appendf(out, out_size, &used, "<h1>DIP-kompatible API Übersicht</h1>");
    appendf(out, out_size, &used, "<p>Diese Seite ist das lokale Analog zur OpenAPI-Spezifikation und listet die aktuell bereitgestellten Endpunkte mit Kurzbeschreibung.</p>");
    appendf(out, out_size, &used, "<p><strong>Authentifizierung:</strong> Lese-Endpunkte sind standardmäßig ohne API-Key erreichbar; optional kann via <code>REQUIRE_API_KEY_FOR_READ=1</code> ein API-Key für Read-Routen erzwungen werden. Der administrative Rebuild-Endpunkt bleibt geschützt.</p>");

    appendf(out, out_size, &used, "<h2>System</h2>");
    appendf(out, out_size, &used, "<table><thead><tr><th>Methode</th><th>Pfad</th><th>Beschreibung</th><th>Statuscodes</th></tr></thead><tbody>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/</code></td><td>Diese API-Übersichtsseite.</td><td>200</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/health</code>, <code>/healthz</code></td><td>Health-Check des Servers.</td><td>200</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/admin/rebuild</code></td><td>Trigger für Snapshot-Rebuild (asynchron, API-Key erforderlich).</td><td>202, 401</td></tr>");
    appendf(out, out_size, &used, "</tbody></table>");

    appendf(out, out_size, &used, "<h2>DIP-Endpunkte (v1)</h2>");
    appendf(out, out_size, &used, "<table><thead><tr><th>Methode</th><th>Pfad</th><th>Beschreibung</th><th>Statuscodes</th></tr></thead><tbody>");

    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/vorgang</code></td><td>Liste von Metadaten zu Vorgängen.</td><td>200, 400</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/vorgang/{id}</code></td><td>Metadaten zu einem Vorgang.</td><td>200, 404</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/vorgangsposition</code></td><td>Liste von Metadaten zu Vorgangspositionen.</td><td>200, 400</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/vorgangsposition/{id}</code></td><td>Metadaten zu einer Vorgangsposition.</td><td>200, 404</td></tr>");

    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/drucksache</code></td><td>Liste von Metadaten zu Drucksachen.</td><td>200, 400</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/drucksache/{id}</code></td><td>Metadaten zu einer Drucksache.</td><td>200, 404</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/drucksache-text</code></td><td>Liste von Volltexten und Metadaten zu Drucksachen.</td><td>200, 400</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/drucksache-text/{id}</code></td><td>Volltext und Metadaten zu einer Drucksache.</td><td>200, 404</td></tr>");

    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/plenarprotokoll</code></td><td>Liste von Metadaten zu Plenarprotokollen.</td><td>200, 400</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/plenarprotokoll/{id}</code></td><td>Metadaten zu einem Plenarprotokoll.</td><td>200, 404</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/plenarprotokoll-text</code></td><td>Liste von Volltexten und Metadaten zu Plenarprotokollen.</td><td>200, 400</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/plenarprotokoll-text/{id}</code></td><td>Volltext und Metadaten zu einem Plenarprotokoll.</td><td>200, 404</td></tr>");

    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/aktivitaet</code></td><td>Liste von Metadaten zu Aktivitäten.</td><td>200, 400</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/aktivitaet/{id}</code></td><td>Metadaten zu einer Aktivität.</td><td>200, 404</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/person</code></td><td>Liste von Personenstammdaten.</td><td>200, 400</td></tr>");
    appendf(out, out_size, &used, "<tr><td>GET</td><td><code>/person/{id}</code></td><td>Personenstammdaten zu einer Person.</td><td>200, 404</td></tr>");

    appendf(out, out_size, &used, "</tbody></table>");
    appendf(out, out_size, &used, "<p><small>Hinweis: Diese Übersicht spiegelt die lokal implementierten DIP-Routen wider und orientiert sich an <code>openapi.yaml</code>.</small></p>");
    appendf(out, out_size, &used, "</body></html>");
}

static void build_document_list_body(
    char *out,
    size_t out_size,
    const dip_document_t *docs,
    const dip_document_t *const *ordered_docs,
    size_t docs_count,
    const char *entity,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total,
    bool include_text) {

    size_t page_limit = include_text ? LIST_PAGE_LIMIT_TEXT : LIST_PAGE_LIMIT_DEFAULT;

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;
    appendf(out, out_size, &used, "{\"numFound\":%zu,\"cursor\":\"", total);

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > page_limit) {
            take = page_limit;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "%s\",\"documents\":[", cursor_buf);

    matched_before_page = 0;
    shown = 0;
    for (size_t i = 0; i < docs_count; i++) {
        const dip_document_t *doc = ordered_docs ? ordered_docs[i] : &docs[i];
        if (!match_document_filter(doc, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= page_limit) {
            break;
        }

        char titel_esc[2048];
        char dokumentnummer_esc[256];
        char datum_esc[64];
        char fundstelle_esc[512];
        char urheber_esc[512];
        char text_esc[4096];
        char urheber_json[1536];
        char urheber_titles_json[768];
        char fundstelle_json[2048];
        int autoren_anzahl = 0;
        json_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
        json_escape_to_buffer(doc->dokumentnummer, dokumentnummer_esc, sizeof(dokumentnummer_esc));
        json_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
        json_escape_to_buffer(doc->fundstelle, fundstelle_esc, sizeof(fundstelle_esc));
        json_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
        json_escape_to_buffer(doc->text_preview, text_esc, sizeof(text_esc));

        if (doc->urheber[0] != '\0' && strcmp(doc->urheber, "Unbekannt") != 0) {
            autoren_anzahl = 1;
            snprintf(
                urheber_json,
                sizeof(urheber_json),
                "[{\"einbringer\":false,\"bezeichnung\":\"%s\",\"titel\":\"%s\"}]",
                urheber_esc,
                urheber_esc);
            snprintf(urheber_titles_json, sizeof(urheber_titles_json), "[\"%s\"]", urheber_esc);
        } else {
            snprintf(urheber_json, sizeof(urheber_json), "[]");
            snprintf(urheber_titles_json, sizeof(urheber_titles_json), "[]");
        }
        snprintf(
            fundstelle_json,
            sizeof(fundstelle_json),
            "{\"pdf_url\":\"\",\"id\":\"%ld\",\"dokumentnummer\":\"%s\",\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"drucksachetyp\":\"Unbekannt\",\"herausgeber\":\"BT\",\"urheber\":%s}",
            doc->id,
            dokumentnummer_esc,
            datum_esc,
            urheber_titles_json);
        if (shown > 0) {
            appendf(out, out_size, &used, ",");
        }
        if (strcmp(entity, "Drucksache") == 0) {
            if (include_text) {
                appendf(
                    out,
                    out_size,
                    &used,
                    "{\"aktualisiert\":\"1970-01-01T00:00:00\",\"autoren_anzahl\":%d,\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"dokumentnummer\":\"%s\",\"drucksachetyp\":\"Unbekannt\",\"fundstelle\":%s,\"herausgeber\":\"BT\",\"id\":\"%ld\",\"pdf_hash\":\"\",\"titel\":\"%s\",\"typ\":\"Dokument\",\"urheber\":%s,\"vorgangsbezug_anzahl\":0,\"wahlperiode\":%d,\"text\":\"%s\"}",
                    autoren_anzahl,
                    datum_esc,
                    dokumentnummer_esc,
                    fundstelle_json,
                    doc->id,
                    titel_esc,
                    urheber_json,
                    doc->wahlperiode,
                    text_esc);
            } else {
                appendf(
                    out,
                    out_size,
                    &used,
                    "{\"aktualisiert\":\"1970-01-01T00:00:00\",\"autoren_anzahl\":%d,\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"dokumentnummer\":\"%s\",\"drucksachetyp\":\"Unbekannt\",\"fundstelle\":%s,\"herausgeber\":\"BT\",\"id\":\"%ld\",\"pdf_hash\":\"\",\"titel\":\"%s\",\"typ\":\"Dokument\",\"urheber\":%s,\"vorgangsbezug_anzahl\":0,\"wahlperiode\":%d}",
                    autoren_anzahl,
                    datum_esc,
                    dokumentnummer_esc,
                    fundstelle_json,
                    doc->id,
                    titel_esc,
                    urheber_json,
                    doc->wahlperiode);
            }
        } else if (include_text) {
            appendf(
                out,
                out_size,
                &used,
                "{\"id\":\"%ld\",\"typ\":\"%s\",\"titel\":\"%s\",\"dokumentnummer\":\"%s\",\"wahlperiode\":%d,\"datum\":\"%s\",\"urheber\":\"%s\",\"fundstelle\":\"%s\",\"text\":\"%s\"}",
                doc->id,
                entity,
                titel_esc,
                dokumentnummer_esc,
                doc->wahlperiode,
                datum_esc,
                urheber_esc,
                fundstelle_esc,
                text_esc);
        } else {
            appendf(
                out,
                out_size,
                &used,
                "{\"id\":\"%ld\",\"typ\":\"%s\",\"titel\":\"%s\",\"dokumentnummer\":\"%s\",\"wahlperiode\":%d,\"datum\":\"%s\",\"urheber\":\"%s\",\"fundstelle\":\"%s\"}",
                doc->id,
                entity,
                titel_esc,
                dokumentnummer_esc,
                doc->wahlperiode,
                datum_esc,
                urheber_esc,
                fundstelle_esc);
        }
        shown++;
    }

    appendf(out, out_size, &used, "]}");

}

static void build_document_detail_body(char *out, size_t out_size, const dip_document_t *doc, const char *entity, bool include_text) {
    char titel_esc[2048];
    char dokumentnummer_esc[256];
    char datum_esc[64];
    char urheber_esc[512];
    char text_esc[4096];
    char fundstelle_json[2048];
    char urheber_json[1536];
    int autoren_anzahl = 0;

    json_escape_to_buffer(doc->titel, titel_esc, sizeof(titel_esc));
    json_escape_to_buffer(doc->dokumentnummer, dokumentnummer_esc, sizeof(dokumentnummer_esc));
    json_escape_to_buffer(doc->datum, datum_esc, sizeof(datum_esc));
    json_escape_to_buffer(doc->urheber, urheber_esc, sizeof(urheber_esc));
    json_escape_to_buffer(doc->text_preview, text_esc, sizeof(text_esc));

    if (doc->urheber[0] != '\0' && strcmp(doc->urheber, "Unbekannt") != 0) {
        autoren_anzahl = 1;
        snprintf(
            urheber_json,
            sizeof(urheber_json),
            "[{\"einbringer\":false,\"bezeichnung\":\"%s\",\"titel\":\"%s\"}]",
            urheber_esc,
            urheber_esc);
    } else {
        snprintf(urheber_json, sizeof(urheber_json), "[]");
    }

    snprintf(
        fundstelle_json,
        sizeof(fundstelle_json),
        "{\"pdf_url\":\"\",\"id\":\"%ld\",\"dokumentnummer\":\"%s\",\"datum\":\"%s\",\"dokumentart\":\"%s\",\"drucksachetyp\":\"Unbekannt\",\"herausgeber\":\"BT\",\"urheber\":[\"%s\"]}",
        doc->id,
        dokumentnummer_esc,
        datum_esc,
        strcmp(entity, "Drucksache") == 0 ? "Drucksache" : "Plenarprotokoll",
        urheber_esc);

    if (strcmp(entity, "Drucksache") == 0) {
        if (include_text) {
            snprintf(
                out,
                out_size,
                "{\"aktualisiert\":\"%s\",\"autoren_anzahl\":%d,\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"dokumentnummer\":\"%s\",\"drucksachetyp\":\"Unbekannt\",\"fundstelle\":%s,\"herausgeber\":\"BT\",\"id\":\"%ld\",\"titel\":\"%s\",\"typ\":\"Dokument\",\"urheber\":%s,\"vorgangsbezug\":[],\"vorgangsbezug_anzahl\":0,\"wahlperiode\":%d,\"pdf_hash\":\"\",\"text\":\"%s\"}",
                default_aktualisiert(),
                autoren_anzahl,
                datum_esc,
                dokumentnummer_esc,
                fundstelle_json,
                doc->id,
                titel_esc,
                urheber_json,
                doc->wahlperiode,
                text_esc);
        } else {
            snprintf(
                out,
                out_size,
                "{\"aktualisiert\":\"%s\",\"autoren_anzahl\":%d,\"datum\":\"%s\",\"dokumentart\":\"Drucksache\",\"dokumentnummer\":\"%s\",\"drucksachetyp\":\"Unbekannt\",\"fundstelle\":%s,\"herausgeber\":\"BT\",\"id\":\"%ld\",\"titel\":\"%s\",\"typ\":\"Dokument\",\"urheber\":%s,\"vorgangsbezug\":[],\"vorgangsbezug_anzahl\":0,\"wahlperiode\":%d,\"pdf_hash\":\"\"}",
                default_aktualisiert(),
                autoren_anzahl,
                datum_esc,
                dokumentnummer_esc,
                fundstelle_json,
                doc->id,
                titel_esc,
                urheber_json,
                doc->wahlperiode);
        }
        return;
    }

    if (include_text) {
        snprintf(
            out,
            out_size,
            "{\"aktualisiert\":\"%s\",\"datum\":\"%s\",\"dokumentart\":\"Plenarprotokoll\",\"dokumentnummer\":\"%s\",\"fundstelle\":%s,\"herausgeber\":\"BT\",\"id\":\"%ld\",\"pdf_hash\":\"\",\"text\":\"%s\",\"titel\":\"%s\",\"typ\":\"Dokument\",\"vorgangsbezug\":[],\"vorgangsbezug_anzahl\":0,\"wahlperiode\":%d}",
            default_aktualisiert(),
            datum_esc,
            dokumentnummer_esc,
            fundstelle_json,
            doc->id,
            text_esc,
            titel_esc,
            doc->wahlperiode);
    } else {
        snprintf(
            out,
            out_size,
            "{\"aktualisiert\":\"%s\",\"datum\":\"%s\",\"dokumentart\":\"Plenarprotokoll\",\"dokumentnummer\":\"%s\",\"fundstelle\":%s,\"herausgeber\":\"BT\",\"id\":\"%ld\",\"pdf_hash\":\"\",\"titel\":\"%s\",\"typ\":\"Dokument\",\"vorgangsbezug\":[],\"vorgangsbezug_anzahl\":0,\"wahlperiode\":%d}",
            default_aktualisiert(),
            datum_esc,
            dokumentnummer_esc,
            fundstelle_json,
            doc->id,
            titel_esc,
            doc->wahlperiode);
    }
}

static void build_person_list_body(
    char *out,
    size_t out_size,
    const dip_person_t *personen,
    const dip_person_t *const *ordered_personen,
    size_t personen_count,
    uint64_t snapshot_version,
    const list_filter_t *filter,
    size_t total) {

    size_t page_limit = LIST_PAGE_LIMIT_DEFAULT;

    size_t used = 0;
    size_t shown = 0;
    size_t matched_before_page = 0;
    appendf(out, out_size, &used, "{\"numFound\":%zu,\"cursor\":\"", total);

    size_t next_offset = filter->offset;
    if (total > 0) {
        size_t take = total - filter->offset;
        if (take > page_limit) {
            take = page_limit;
        }
        if (filter->offset + take < total) {
            next_offset = filter->offset + take;
        }
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));
    appendf(out, out_size, &used, "%s\",\"documents\":[", cursor_buf);

    for (size_t i = 0; i < personen_count; i++) {
        const dip_person_t *p = ordered_personen ? ordered_personen[i] : &personen[i];
        if (!match_person_filter(p, filter)) {
            continue;
        }
        if (matched_before_page < filter->offset) {
            matched_before_page++;
            continue;
        }
        if (shown >= page_limit) {
            break;
        }
        if (shown > 0) {
            appendf(out, out_size, &used, ",");
        }
        char nachname_esc[256];
        char vorname_esc[256];
        char basisdatum_esc[64];
        char datum_esc[64];
        char aktualisiert_esc[64];
        char funktion_esc[256];
        char namenszusatz_esc[256];
        char fraktion_esc[256];
        json_escape_to_buffer(p->nachname, nachname_esc, sizeof(nachname_esc));
        json_escape_to_buffer(p->vorname, vorname_esc, sizeof(vorname_esc));
        json_escape_to_buffer(p->basisdatum, basisdatum_esc, sizeof(basisdatum_esc));
        json_escape_to_buffer(p->datum, datum_esc, sizeof(datum_esc));
        json_escape_to_buffer(p->aktualisiert, aktualisiert_esc, sizeof(aktualisiert_esc));
        json_escape_to_buffer(p->funktion, funktion_esc, sizeof(funktion_esc));
        json_escape_to_buffer(p->namenszusatz, namenszusatz_esc, sizeof(namenszusatz_esc));
        json_escape_to_buffer(p->fraktion, fraktion_esc, sizeof(fraktion_esc));

        char wp_json[256];
        size_t wp_used = 0;
        wp_json[0] = '\0';
        appendf(wp_json, sizeof(wp_json), &wp_used, "[");
        for (size_t wp_idx = 0; wp_idx < p->wahlperioden_count; wp_idx++) {
            if (wp_idx > 0) {
                appendf(wp_json, sizeof(wp_json), &wp_used, ",");
            }
            appendf(wp_json, sizeof(wp_json), &wp_used, "%d", p->wahlperioden[wp_idx]);
        }
        appendf(wp_json, sizeof(wp_json), &wp_used, "]");

        appendf(out, out_size, &used, "{\"id\":\"%ld\",\"typ\":\"Person\",\"nachname\":\"%s\",\"vorname\":\"%s\",\"namenszusatz\":\"%s\",\"basisdatum\":\"%s\",\"datum\":\"%s\",\"aktualisiert\":\"%s\",\"titel\":\"%s, %s\",\"funktion\":\"%s\",\"fraktion\":\"%s\",\"wahlperiode\":%s}", p->id, nachname_esc, vorname_esc, namenszusatz_esc, basisdatum_esc, datum_esc, aktualisiert_esc, nachname_esc, vorname_esc, funktion_esc, fraktion_esc, wp_json);
        shown++;
    }
    appendf(out, out_size, &used, "]}");
}

static void build_person_detail_body(char *out, size_t out_size, const dip_person_t *person) {
    char nachname_esc[256];
    char vorname_esc[256];
    char basisdatum_esc[64];
    char datum_esc[64];
    char aktualisiert_esc[64];
    char namenszusatz_esc[256];
    char funktion_esc[256];
    char funktionszusatz_esc[256];
    char fraktion_esc[256];
    char wahlkreiszusatz_esc[256];
    char ressort_esc[320];
    char bundesland_esc[128];
    json_escape_to_buffer(person->nachname, nachname_esc, sizeof(nachname_esc));
    json_escape_to_buffer(person->vorname, vorname_esc, sizeof(vorname_esc));
    json_escape_to_buffer(person->basisdatum, basisdatum_esc, sizeof(basisdatum_esc));
    json_escape_to_buffer(person->datum, datum_esc, sizeof(datum_esc));
    json_escape_to_buffer(person->aktualisiert, aktualisiert_esc, sizeof(aktualisiert_esc));
    json_escape_to_buffer(person->namenszusatz, namenszusatz_esc, sizeof(namenszusatz_esc));
    json_escape_to_buffer(person->funktion, funktion_esc, sizeof(funktion_esc));
    json_escape_to_buffer(person->funktionszusatz, funktionszusatz_esc, sizeof(funktionszusatz_esc));
    json_escape_to_buffer(person->fraktion, fraktion_esc, sizeof(fraktion_esc));
    json_escape_to_buffer(person->wahlkreiszusatz, wahlkreiszusatz_esc, sizeof(wahlkreiszusatz_esc));
    json_escape_to_buffer(person->ressort, ressort_esc, sizeof(ressort_esc));
    json_escape_to_buffer(person->bundesland, bundesland_esc, sizeof(bundesland_esc));

    char wp_json[256];
    size_t wp_used = 0;
    wp_json[0] = '\0';
    appendf(wp_json, sizeof(wp_json), &wp_used, "[");
    for (size_t wp_idx = 0; wp_idx < person->wahlperioden_count; wp_idx++) {
        if (wp_idx > 0) {
            appendf(wp_json, sizeof(wp_json), &wp_used, ",");
        }
        appendf(wp_json, sizeof(wp_json), &wp_used, "%d", person->wahlperioden[wp_idx]);
    }
    appendf(wp_json, sizeof(wp_json), &wp_used, "]");

    char person_roles_json[1024];
    size_t roles_used = 0;
    person_roles_json[0] = '\0';
    appendf(person_roles_json, sizeof(person_roles_json), &roles_used, "[{\"funktion\":\"%s\",\"funktionszusatz\":\"%s\",\"fraktion\":\"%s\",\"nachname\":\"%s\",\"vorname\":\"%s\",\"namenszusatz\":\"%s\",\"wahlperiode_nummer\":%s,\"wahlkreiszusatz\":\"%s\",\"ressort_titel\":\"%s\",\"bundesland\":\"%s\"}]", funktion_esc, funktionszusatz_esc, fraktion_esc, nachname_esc, vorname_esc, namenszusatz_esc, wp_json, wahlkreiszusatz_esc, ressort_esc, bundesland_esc);

    snprintf(
        out,
        out_size,
        "{\"id\":\"%ld\",\"nachname\":\"%s\",\"vorname\":\"%s\",\"namenszusatz\":\"%s\",\"typ\":\"Person\",\"wahlperiode\":%s,\"basisdatum\":\"%s\",\"datum\":\"%s\",\"aktualisiert\":\"%s\",\"titel\":\"%s, %s\",\"funktion\":\"%s\",\"funktionszusatz\":\"%s\",\"fraktion\":\"%s\",\"wahlkreiszusatz\":\"%s\",\"ressort\":\"%s\",\"bundesland\":\"%s\",\"person_roles\":%s}",
        person->id,
        nachname_esc,
        vorname_esc,
        namenszusatz_esc,
        wp_json,
        basisdatum_esc,
        datum_esc,
        aktualisiert_esc,
        nachname_esc,
        vorname_esc,
        funktion_esc,
        funktionszusatz_esc,
        fraktion_esc,
        wahlkreiszusatz_esc,
        ressort_esc,
        bundesland_esc,
        person_roles_json);
}

static void build_vorgang_detail_stub(char *out, size_t out_size, long id) {
    snprintf(out, out_size, "{\"aktualisiert\":\"1970-01-01T00:00:00\",\"beratungsstand\":\"Unbekannt\",\"datum\":\"1970-01-01\",\"id\":\"%ld\",\"initiative\":[],\"titel\":\"Stub\",\"typ\":\"Vorgang\",\"vorgangstyp\":\"Unbekannt\",\"wahlperiode\":1,\"zustimmungsbeduerftigkeit\":[]}", id);
}

static void build_vorgangsposition_detail_stub(char *out, size_t out_size, long id) {
    snprintf(out, out_size, "{\"aktivitaet_anzahl\":0,\"aktualisiert\":\"1970-01-01T00:00:00\",\"datum\":\"1970-01-01\",\"dokumentart\":\"Drucksache\",\"fortsetzung\":false,\"fundstelle\":\"\",\"gang\":false,\"id\":\"%ld\",\"nachtrag\":false,\"titel\":\"Stub\",\"typ\":\"Vorgangsposition\",\"urheber\":[],\"vorgang_id\":\"1\",\"vorgangsposition\":\"Stub\",\"vorgangstyp\":\"Unbekannt\",\"zuordnung\":\"BT\"}", id);
}

static void build_aktivitaet_detail_stub(char *out, size_t out_size, long id) {
    snprintf(out, out_size, "{\"aktivitaetsart\":\"Unbekannt\",\"aktualisiert\":\"1970-01-01T00:00:00\",\"datum\":\"1970-01-01\",\"dokumentart\":\"Drucksache\",\"fundstelle\":\"\",\"id\":\"%ld\",\"person_id\":\"1\",\"titel\":\"Stub\",\"typ\":\"Aktivitaet\",\"vorgangsbezug\":[],\"vorgangsbezug_anzahl\":0,\"wahlperiode\":1}", id);
}

static void build_list_stub_body(char *out, size_t out_size, const char *entity, uint64_t snapshot_version, const list_filter_t *filter) {
    size_t total = (filter->ids_count > 0 && !contains_long(filter->ids, filter->ids_count, 1)) ? 0 : 1;
    if (filter->offset > total) {
        total = 0;
    }

    size_t next_offset = filter->offset;
    if (total > 0 && filter->offset == 0) {
        next_offset = 0;
    }

    char cursor_buf[128];
    encode_cursor(snapshot_version, next_offset, cursor_buf, sizeof(cursor_buf));

    if (total == 0 || filter->offset > 0) {
        snprintf(out, out_size, "{\"numFound\":%zu,\"cursor\":\"%s\",\"documents\":[]}", total, cursor_buf);
    } else {
        snprintf(out, out_size, "{\"numFound\":1,\"cursor\":\"%s\",\"documents\":[{\"id\":\"1\",\"typ\":\"%s\",\"titel\":\"Stub\"}]}", cursor_buf, entity);
    }
}

static void build_detail_stub_body(char *out, size_t out_size, const char *entity, long id) {
    snprintf(out, out_size, "{\"id\":\"%ld\",\"typ\":\"%s\",\"titel\":\"Stub\"}", id, entity);
}

static int handle_http_request(worker_t *worker, connection_t *conn, const char *header_end) {
    char method[MAX_METHOD_LEN] = {0};
    char target[MAX_TARGET_LEN] = {0};
    char version[MAX_VERSION_LEN] = {0};
    char path[MAX_TARGET_LEN] = {0};
    char query[MAX_QUERY_LEN + 1] = {0};
    char authorization[512] = {0};
    bool keep_alive = true;

    size_t header_len = (size_t)(header_end - conn->buffer) + 4;
    conn->buffer[header_len] = '\0';

    char *line_end = strstr(conn->buffer, "\r\n");
    if (!line_end) {
        char body[128];
        json_error(body, sizeof(body), 400, "Malformed request line");
        ssize_t bytes = send_simple_response(conn->fd, 400, "application/json", body, false);
        log_request(worker, "-", "-", 400, bytes, conn->request_start_ns, "bad_request_line");
        return -400;
    }

    *line_end = '\0';
    if (!parse_request_line(conn->buffer, method, sizeof(method), target, sizeof(target), version, sizeof(version))) {
        char body[128];
        json_error(body, sizeof(body), 400, "Malformed request line");
        ssize_t bytes = send_simple_response(conn->fd, 400, "application/json", body, false);
        log_request(worker, "-", "-", 400, bytes, conn->request_start_ns, "bad_request_line");
        return -400;
    }

    if (strcmp(method, "GET") != 0) {
        char body[128];
        json_error(body, sizeof(body), 405, "Method not allowed");
        ssize_t bytes = send_simple_response(conn->fd, 405, "application/json", body, false);
        log_request(worker, method, target, 405, bytes, conn->request_start_ns, "method_not_allowed");
        return -405;
    }

    if (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0) {
        char body[128];
        json_error(body, sizeof(body), 400, "Unsupported HTTP version");
        ssize_t bytes = send_simple_response(conn->fd, 400, "application/json", body, false);
        log_request(worker, method, target, 400, bytes, conn->request_start_ns, "bad_http_version");
        return -400;
    }

    keep_alive = (strcmp(version, "HTTP/1.1") == 0);

    char *headers = line_end + 2;
    char *cur = headers;
    while (cur && *cur) {
        char *next = strstr(cur, "\r\n");
        if (!next) {
            break;
        }
        if (next == cur) {
            break;
        }
        *next = '\0';

        if (ci_starts_with(cur, "Connection:")) {
            const char *v = cur + strlen("Connection:");
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            if (strcasestr(v, "close") != NULL) {
                keep_alive = false;
            } else if (strcasestr(v, "keep-alive") != NULL) {
                keep_alive = true;
            }
        } else if (ci_starts_with(cur, "Authorization:")) {
            const char *v = cur + strlen("Authorization:");
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            size_t vn = strlen(v);
            if (vn >= sizeof(authorization)) {
                vn = sizeof(authorization) - 1;
            }
            memcpy(authorization, v, vn);
            authorization[vn] = '\0';
        }

        cur = next + 2;
    }

    extract_path(target, path, sizeof(path));
    extract_query(target, query, sizeof(query));

    query_params_t query_params;
    parse_query_params(query, &query_params);

    int status = 404;
    ssize_t bytes = -1;

    route_match_t dip_route = match_dip_route(path);

    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        char body[32768];
        build_api_index_html(body, sizeof(body));
        status = 200;
        bytes = send_simple_response(conn->fd, 200, "text/html; charset=utf-8", body, keep_alive);
        log_request(worker, method, target, status, bytes, conn->request_start_ns, "api_index");
    } else if (strcmp(path, "/admin/rebuild") == 0) {
        if (!has_valid_auth(authorization, &query_params)) {
            char body[128];
            json_error(body, sizeof(body), 401, "API key required");
            status = 401;
            bytes = send_simple_response(conn->fd, 401, "application/json", body, keep_alive);
            log_request(worker, method, target, status, bytes, conn->request_start_ns, "admin_auth_required");
        } else {
            g_rebuild_requested = 1;
            const char *body = "{\"status\":202,\"message\":\"rebuild scheduled\"}";
            status = 202;
            bytes = send_simple_response(conn->fd, 202, "application/json", body, keep_alive);
            log_request(worker, method, target, status, bytes, conn->request_start_ns, "admin_rebuild_scheduled");
        }
    } else if (dip_route.kind != ROUTE_NONE) {
        list_filter_t filter;

        if (g_require_api_key_for_read && !has_valid_auth(authorization, &query_params)) {
            char body[256];
            json_error(body, sizeof(body), 401, "An API key is required to access this service");
            status = 401;
            bytes = send_simple_response(conn->fd, 401, "application/json", body, keep_alive);
            log_request(worker, method, target, status, bytes, conn->request_start_ns, "read_auth_required");
        } else if (!is_valid_format_param(&query_params)) {
            char body[128];
            json_error(body, sizeof(body), 400, "Invalid format parameter");
            status = 400;
            bytes = send_simple_response(conn->fd, 400, "application/json", body, keep_alive);
            log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_format");
        } else {
            bool xml_format = is_xml_format_param(&query_params);
            const char *response_content_type = xml_format ? "application/xml; charset=utf-8" : "application/json";
            char bad_key[64];
            bad_key[0] = '\0';
            if (find_invalid_integer_filter(&query_params, bad_key, sizeof(bad_key))) {
                char body[192];
                char message[128];
                snprintf(message, sizeof(message), "Invalid parameter %s", bad_key);
                json_error(body, sizeof(body), 400, message);
                status = 400;
                bytes = send_simple_response(conn->fd, 400, "application/json", body, keep_alive);
                log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_param");
            } else if (find_invalid_date_filter(&query_params, bad_key, sizeof(bad_key))) {
                char body[192];
                char message[128];
                snprintf(message, sizeof(message), "Invalid parameter %s", bad_key);
                json_error(body, sizeof(body), 400, message);
                status = 400;
                bytes = send_simple_response(conn->fd, 400, "application/json", body, keep_alive);
                log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_param");
            } else if (dip_route.kind == ROUTE_LIST) {
                char body[262144];
                uint64_t snapshot_version = 0;
                pthread_rwlock_rdlock(&g_snapshot_lock);
                snapshot_version = g_snapshot_version;

                if (!init_list_filter(&query_params, snapshot_version, &filter)) {
                    pthread_rwlock_unlock(&g_snapshot_lock);
                    char err_body[128];
                    json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                    status = 400;
                    bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                    log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                    goto done_request;
                }

                if (strcmp(dip_route.entity, "Drucksache") == 0) {
                    const dip_document_t *const *candidate_docs = NULL;
                    size_t candidate_count = g_snapshot.drucksachen_count;
                    bool candidate_owned = false;
                    if (!collect_documents_for_filters(&g_snapshot, &filter, false, &candidate_docs, &candidate_count, &candidate_owned, g_snapshot.drucksachen_count)) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 500, "Out of memory");
                        status = 500;
                        bytes = send_simple_response(conn->fd, 500, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_oom");
                        goto done_request;
                    }
                    if (!candidate_docs) {
                        candidate_docs = g_snapshot.drucksachen_docnr_desc;
                        candidate_count = g_snapshot.drucksachen_count;
                    }
                    size_t total = count_matching_documents(g_snapshot.drucksachen, candidate_docs, candidate_count, &filter);
                    if (filter.offset > total) {
                        if (candidate_owned) {
                            free((void *)candidate_docs);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                        status = 400;
                        bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                        goto done_request;
                    }
                    if (xml_format) {
                        build_document_list_body_xml(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, "Drucksache", snapshot_version, &filter, total, false);
                    } else {
                        build_document_list_body(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, "Drucksache", snapshot_version, &filter, total, false);
                    }
                    if (candidate_owned) {
                        free((void *)candidate_docs);
                    }
                } else if (strcmp(dip_route.entity, "DrucksacheText") == 0) {
                    const dip_document_t *const *candidate_docs = NULL;
                    size_t candidate_count = g_snapshot.drucksachen_count;
                    bool candidate_owned = false;
                    if (!collect_documents_for_filters(&g_snapshot, &filter, false, &candidate_docs, &candidate_count, &candidate_owned, g_snapshot.drucksachen_count)) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 500, "Out of memory");
                        status = 500;
                        bytes = send_simple_response(conn->fd, 500, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_oom");
                        goto done_request;
                    }
                    if (!candidate_docs) {
                        candidate_docs = g_snapshot.drucksachen_docnr_desc;
                        candidate_count = g_snapshot.drucksachen_count;
                    }
                    size_t total = count_matching_documents(g_snapshot.drucksachen, candidate_docs, candidate_count, &filter);
                    if (filter.offset > total) {
                        if (candidate_owned) {
                            free((void *)candidate_docs);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                        status = 400;
                        bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                        goto done_request;
                    }
                    if (xml_format) {
                        build_document_list_body_xml(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, "Drucksache", snapshot_version, &filter, total, true);
                    } else {
                        build_document_list_body(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, "Drucksache", snapshot_version, &filter, total, true);
                    }
                    if (candidate_owned) {
                        free((void *)candidate_docs);
                    }
                } else if (strcmp(dip_route.entity, "Plenarprotokoll") == 0) {
                    const dip_document_t *const *candidate_docs = NULL;
                    size_t candidate_count = g_snapshot.plenarprotokolle_count;
                    bool candidate_owned = false;
                    if (!collect_documents_for_filters(&g_snapshot, &filter, true, &candidate_docs, &candidate_count, &candidate_owned, g_snapshot.plenarprotokolle_count)) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 500, "Out of memory");
                        status = 500;
                        bytes = send_simple_response(conn->fd, 500, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_oom");
                        goto done_request;
                    }
                    size_t total = count_matching_documents(g_snapshot.plenarprotokolle, candidate_docs, candidate_count, &filter);
                    if (filter.offset > total) {
                        if (candidate_owned) {
                            free((void *)candidate_docs);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                        status = 400;
                        bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                        goto done_request;
                    }
                    if (xml_format) {
                        build_document_list_body_xml(body, sizeof(body), g_snapshot.plenarprotokolle, candidate_docs, candidate_count, "Plenarprotokoll", snapshot_version, &filter, total, false);
                    } else {
                        build_document_list_body(body, sizeof(body), g_snapshot.plenarprotokolle, candidate_docs, candidate_count, "Plenarprotokoll", snapshot_version, &filter, total, false);
                    }
                    if (candidate_owned) {
                        free((void *)candidate_docs);
                    }
                } else if (strcmp(dip_route.entity, "PlenarprotokollText") == 0) {
                    const dip_document_t *const *candidate_docs = NULL;
                    size_t candidate_count = g_snapshot.plenarprotokolle_count;
                    bool candidate_owned = false;
                    if (!collect_documents_for_filters(&g_snapshot, &filter, true, &candidate_docs, &candidate_count, &candidate_owned, g_snapshot.plenarprotokolle_count)) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 500, "Out of memory");
                        status = 500;
                        bytes = send_simple_response(conn->fd, 500, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_oom");
                        goto done_request;
                    }
                    size_t total = count_matching_documents(g_snapshot.plenarprotokolle, candidate_docs, candidate_count, &filter);
                    if (filter.offset > total) {
                        if (candidate_owned) {
                            free((void *)candidate_docs);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                        status = 400;
                        bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                        goto done_request;
                    }
                    if (xml_format) {
                        build_document_list_body_xml(body, sizeof(body), g_snapshot.plenarprotokolle, candidate_docs, candidate_count, "Plenarprotokoll", snapshot_version, &filter, total, true);
                    } else {
                        build_document_list_body(body, sizeof(body), g_snapshot.plenarprotokolle, candidate_docs, candidate_count, "Plenarprotokoll", snapshot_version, &filter, total, true);
                    }
                    if (candidate_owned) {
                        free((void *)candidate_docs);
                    }
                } else if (strcmp(dip_route.entity, "Vorgang") == 0) {
                    const dip_document_t *const *candidate_docs = NULL;
                    size_t candidate_count = g_snapshot.drucksachen_count;
                    bool candidate_owned = false;
                    if (!collect_documents_for_filters(&g_snapshot, &filter, false, &candidate_docs, &candidate_count, &candidate_owned, g_snapshot.drucksachen_count)) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 500, "Out of memory");
                        status = 500;
                        bytes = send_simple_response(conn->fd, 500, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_oom");
                        goto done_request;
                    }
                    size_t total = count_matching_vorgaenge(g_snapshot.drucksachen, candidate_docs, candidate_count, &filter);
                    if (filter.offset > total) {
                        if (candidate_owned) {
                            free((void *)candidate_docs);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                        status = 400;
                        bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                        goto done_request;
                    }
                    if (xml_format) {
                        build_vorgang_list_body_xml(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, snapshot_version, &filter, total);
                    } else {
                        build_vorgang_list_body(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, snapshot_version, &filter, total);
                    }
                    if (candidate_owned) {
                        free((void *)candidate_docs);
                    }
                } else if (strcmp(dip_route.entity, "Vorgangsposition") == 0) {
                    const dip_document_t *const *candidate_docs = NULL;
                    size_t candidate_count = g_snapshot.drucksachen_count;
                    bool candidate_owned = false;
                    if (!collect_documents_for_filters(&g_snapshot, &filter, false, &candidate_docs, &candidate_count, &candidate_owned, g_snapshot.drucksachen_count)) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 500, "Out of memory");
                        status = 500;
                        bytes = send_simple_response(conn->fd, 500, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_oom");
                        goto done_request;
                    }
                    size_t total = count_matching_vorgangspositionen(g_snapshot.drucksachen, candidate_docs, candidate_count, &filter);
                    if (filter.offset > total) {
                        if (candidate_owned) {
                            free((void *)candidate_docs);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                        status = 400;
                        bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                        goto done_request;
                    }
                    if (xml_format) {
                        build_vorgangsposition_list_body_xml(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, snapshot_version, &filter, total, g_snapshot.personen_count);
                    } else {
                        build_vorgangsposition_list_body(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, snapshot_version, &filter, total, g_snapshot.personen_count);
                    }
                    if (candidate_owned) {
                        free((void *)candidate_docs);
                    }
                } else if (strcmp(dip_route.entity, "Aktivitaet") == 0) {
                    const dip_document_t *const *candidate_docs = NULL;
                    size_t candidate_count = g_snapshot.drucksachen_count;
                    bool candidate_owned = false;
                    if (!collect_documents_for_filters(&g_snapshot, &filter, false, &candidate_docs, &candidate_count, &candidate_owned, g_snapshot.drucksachen_count)) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 500, "Out of memory");
                        status = 500;
                        bytes = send_simple_response(conn->fd, 500, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_oom");
                        goto done_request;
                    }
                    size_t total = count_matching_aktivitaet(g_snapshot.drucksachen, candidate_docs, candidate_count, &g_snapshot, &filter);
                    if (filter.offset > total) {
                        if (candidate_owned) {
                            free((void *)candidate_docs);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                        status = 400;
                        bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                        goto done_request;
                    }
                    if (xml_format) {
                        build_aktivitaet_list_body_xml(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, &g_snapshot, snapshot_version, &filter, total);
                    } else {
                        build_aktivitaet_list_body(body, sizeof(body), g_snapshot.drucksachen, candidate_docs, candidate_count, &g_snapshot, snapshot_version, &filter, total);
                    }
                    if (candidate_owned) {
                        free((void *)candidate_docs);
                    }
                } else if (strcmp(dip_route.entity, "Person") == 0) {
                    const dip_person_t *const *candidate_personen = NULL;
                    size_t candidate_count = g_snapshot.personen_count;
                    bool candidate_owned = false;
                    if (!collect_persons_for_wahlperioden(&g_snapshot, &filter, &candidate_personen, &candidate_count, &candidate_owned, g_snapshot.personen_count)) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 500, "Out of memory");
                        status = 500;
                        bytes = send_simple_response(conn->fd, 500, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_oom");
                        goto done_request;
                    }
                    size_t total = candidate_personen
                        ? count_matching_personen_ordered(candidate_personen, candidate_count, &filter)
                        : count_matching_personen(g_snapshot.personen, candidate_count, &filter);
                    if (filter.offset > total) {
                        if (candidate_owned) {
                            free((void *)candidate_personen);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char err_body[128];
                        json_error(err_body, sizeof(err_body), 400, "Invalid cursor");
                        status = 400;
                        bytes = send_simple_response(conn->fd, 400, "application/json", err_body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_bad_cursor");
                        goto done_request;
                    }
                    if (xml_format) {
                        build_person_list_body_xml(body, sizeof(body), g_snapshot.personen, candidate_personen, candidate_count, snapshot_version, &filter, total);
                    } else {
                        build_person_list_body(body, sizeof(body), g_snapshot.personen, candidate_personen, candidate_count, snapshot_version, &filter, total);
                    }
                    if (candidate_owned) {
                        free((void *)candidate_personen);
                    }
                } else {
                    if (xml_format) {
                        build_list_stub_body_xml(body, sizeof(body), dip_route.entity, snapshot_version, &filter);
                    } else {
                        build_list_stub_body(body, sizeof(body), dip_route.entity, snapshot_version, &filter);
                    }
                }
                pthread_rwlock_unlock(&g_snapshot_lock);
                status = 200;
                bytes = send_simple_response(conn->fd, 200, response_content_type, body, keep_alive);
                log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_list");
            } else {
                if (strcmp(dip_route.entity, "Drucksache") == 0 || strcmp(dip_route.entity, "DrucksacheText") == 0) {
                    pthread_rwlock_rdlock(&g_snapshot_lock);
                    const dip_document_t *doc = dip_snapshot_find_drucksache(&g_snapshot, dip_route.id);
                    if (!doc) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char body[128];
                        json_error(body, sizeof(body), 404, "Entity not found");
                        status = 404;
                        bytes = send_simple_response(conn->fd, 404, "application/json", body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail_not_found");
                    } else {
                        char body[16384];
                        bool include_text = strcmp(dip_route.entity, "DrucksacheText") == 0;
                        if (xml_format) {
                            build_document_detail_body_xml(body, sizeof(body), doc, "Drucksache", include_text);
                        } else {
                            build_document_detail_body(body, sizeof(body), doc, "Drucksache", include_text);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        status = 200;
                        bytes = send_simple_response(conn->fd, 200, response_content_type, body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail");
                    }
                } else if (strcmp(dip_route.entity, "Plenarprotokoll") == 0 || strcmp(dip_route.entity, "PlenarprotokollText") == 0) {
                    pthread_rwlock_rdlock(&g_snapshot_lock);
                    const dip_document_t *doc = dip_snapshot_find_plenarprotokoll(&g_snapshot, dip_route.id);
                    if (!doc) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char body[128];
                        json_error(body, sizeof(body), 404, "Entity not found");
                        status = 404;
                        bytes = send_simple_response(conn->fd, 404, "application/json", body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail_not_found");
                    } else {
                        char body[16384];
                        bool include_text = strcmp(dip_route.entity, "PlenarprotokollText") == 0;
                        if (xml_format) {
                            build_document_detail_body_xml(body, sizeof(body), doc, "Plenarprotokoll", include_text);
                        } else {
                            build_document_detail_body(body, sizeof(body), doc, "Plenarprotokoll", include_text);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        status = 200;
                        bytes = send_simple_response(conn->fd, 200, response_content_type, body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail");
                    }
                } else if (strcmp(dip_route.entity, "Person") == 0) {
                    pthread_rwlock_rdlock(&g_snapshot_lock);
                    const dip_person_t *person = dip_snapshot_find_person(&g_snapshot, dip_route.id);
                    if (!person) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char body[128];
                        json_error(body, sizeof(body), 404, "Entity not found");
                        status = 404;
                        bytes = send_simple_response(conn->fd, 404, "application/json", body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail_not_found");
                    } else {
                        char body[16384];
                        if (xml_format) {
                            build_person_detail_body_xml(body, sizeof(body), person);
                        } else {
                            build_person_detail_body(body, sizeof(body), person);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        status = 200;
                        bytes = send_simple_response(conn->fd, 200, response_content_type, body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail");
                    }
                } else if (strcmp(dip_route.entity, "Vorgang") == 0) {
                    pthread_rwlock_rdlock(&g_snapshot_lock);
                    const dip_document_t *doc = dip_snapshot_find_drucksache(&g_snapshot, dip_route.id);
                    if (!doc) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char body[128];
                        json_error(body, sizeof(body), 404, "Entity not found");
                        status = 404;
                        bytes = send_simple_response(conn->fd, 404, "application/json", body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail_not_found");
                    } else {
                        char body[16384];
                        if (xml_format) {
                            build_vorgang_detail_body_xml(body, sizeof(body), doc);
                        } else {
                            build_vorgang_detail_body(body, sizeof(body), doc);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        status = 200;
                        bytes = send_simple_response(conn->fd, 200, response_content_type, body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail");
                    }
                } else if (strcmp(dip_route.entity, "Vorgangsposition") == 0) {
                    pthread_rwlock_rdlock(&g_snapshot_lock);
                    const dip_document_t *doc = dip_snapshot_find_drucksache(&g_snapshot, dip_route.id);
                    if (!doc) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char body[128];
                        json_error(body, sizeof(body), 404, "Entity not found");
                        status = 404;
                        bytes = send_simple_response(conn->fd, 404, "application/json", body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail_not_found");
                    } else {
                        char body[16384];
                        if (xml_format) {
                            build_vorgangsposition_detail_body_xml(body, sizeof(body), doc, g_snapshot.personen_count);
                        } else {
                            build_vorgangsposition_detail_body(body, sizeof(body), doc, g_snapshot.personen_count);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        status = 200;
                        bytes = send_simple_response(conn->fd, 200, response_content_type, body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail");
                    }
                } else if (strcmp(dip_route.entity, "Aktivitaet") == 0) {
                    pthread_rwlock_rdlock(&g_snapshot_lock);
                    const dip_document_t *doc = dip_snapshot_find_drucksache(&g_snapshot, dip_route.id);
                    if (!doc) {
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        char body[128];
                        json_error(body, sizeof(body), 404, "Entity not found");
                        status = 404;
                        bytes = send_simple_response(conn->fd, 404, "application/json", body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail_not_found");
                    } else {
                        char body[16384];
                        if (xml_format) {
                            build_aktivitaet_detail_body_xml(body, sizeof(body), doc, &g_snapshot);
                        } else {
                            build_aktivitaet_detail_body(body, sizeof(body), doc, &g_snapshot);
                        }
                        pthread_rwlock_unlock(&g_snapshot_lock);
                        status = 200;
                        bytes = send_simple_response(conn->fd, 200, response_content_type, body, keep_alive);
                        log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail");
                    }
                } else if (dip_route.id >= 900000000L) {
                    char body[128];
                    json_error(body, sizeof(body), 404, "Entity not found");
                    status = 404;
                    bytes = send_simple_response(conn->fd, 404, "application/json", body, keep_alive);
                    log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail_not_found");
                } else {
                    char body[2048];
                    if (strcmp(dip_route.entity, "Vorgang") == 0) {
                        build_vorgang_detail_stub(body, sizeof(body), dip_route.id);
                    } else if (strcmp(dip_route.entity, "Vorgangsposition") == 0) {
                        build_vorgangsposition_detail_stub(body, sizeof(body), dip_route.id);
                    } else if (strcmp(dip_route.entity, "Aktivitaet") == 0) {
                        build_aktivitaet_detail_stub(body, sizeof(body), dip_route.id);
                    } else {
                        build_detail_stub_body(body, sizeof(body), dip_route.entity, dip_route.id);
                    }
                    status = 200;
                    if (xml_format) {
                        build_detail_stub_body_xml(body, sizeof(body), dip_route.entity, dip_route.id);
                    }
                    bytes = send_simple_response(conn->fd, 200, response_content_type, body, keep_alive);
                    log_request(worker, method, target, status, bytes, conn->request_start_ns, "dip_detail_stub");
                }
            }
        }
    } else if (strcmp(path, "/health") == 0 || strcmp(path, "/healthz") == 0) {
        const char *body = "{\"status\":\"ok\",\"service\":\"dip-c-server\"}";
        status = 200;
        bytes = send_simple_response(conn->fd, 200, "application/json", body, keep_alive);
        log_request(worker, method, target, status, bytes, conn->request_start_ns, "health");
    } else if (strcmp(path, "/internal-error") == 0) {
        char body[128];
        json_error(body, sizeof(body), 500, "Internal server error");
        status = 500;
        bytes = send_simple_response(conn->fd, 500, "application/json", body, false);
        keep_alive = false;
        log_request(worker, method, target, status, bytes, conn->request_start_ns, "forced_500");
    } else {
        char body[128];
        json_error(body, sizeof(body), 404, "Not found");
        status = 404;
        bytes = send_simple_response(conn->fd, 404, "application/json", body, keep_alive);
        log_request(worker, method, target, status, bytes, conn->request_start_ns, "route_not_found");
    }

done_request:

    if (bytes < 0) {
        char body[128];
        json_error(body, sizeof(body), 500, "Write failed");
        bytes = send_simple_response(conn->fd, 500, "application/json", body, false);
        status = 500;
        keep_alive = false;
        log_request(worker, method, target, status, bytes, conn->request_start_ns, "write_failed");
    }

    size_t remaining = conn->used - header_len;
    if (remaining > 0 && remaining < MAX_HEADER_BYTES) {
        memmove(conn->buffer, conn->buffer + header_len, remaining);
    }
    conn->used = remaining;
    conn->request_started = conn->used > 0;
    conn->request_start_ns = conn->request_started ? now_ns() : 0;

    return keep_alive ? status : -status;
}

static void process_connection_event(worker_t *worker, connection_t *conn, uint32_t events) {
    if ((events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) != 0U) {
        close_connection(worker, conn);
        return;
    }

    if ((events & EPOLLIN) == 0U) {
        return;
    }

    while (1) {
        if (conn->used >= MAX_HEADER_BYTES) {
            char body[128];
            json_error(body, sizeof(body), 400, "Header too large");
            ssize_t bytes = send_simple_response(conn->fd, 400, "application/json", body, false);
            log_request(worker, "-", "-", 400, bytes, conn->request_start_ns, "header_too_large");
            close_connection(worker, conn);
            return;
        }

        ssize_t n = recv(conn->fd, conn->buffer + conn->used, MAX_HEADER_BYTES - conn->used, 0);
        if (n > 0) {
            if (!conn->request_started) {
                conn->request_started = true;
                conn->request_start_ns = now_ns();
            }
            conn->used += (size_t)n;
            conn->buffer[conn->used] = '\0';

            const char *header_end = find_header_end(conn->buffer, conn->used);
            if (header_end) {
                int status = handle_http_request(worker, conn, header_end);
                if (status < 0) {
                    close_connection(worker, conn);
                    return;
                }

                while (1) {
                    const char *next_header_end = find_header_end(conn->buffer, conn->used);
                    if (!next_header_end) {
                        break;
                    }
                    int piped_status = handle_http_request(worker, conn, next_header_end);
                    if (piped_status < 0) {
                        close_connection(worker, conn);
                        return;
                    }
                }
            }
            continue;
        }

        if (n == 0) {
            close_connection(worker, conn);
            return;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }

        close_connection(worker, conn);
        return;
    }
}

static void accept_connections(worker_t *worker) {
    while (1) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int client_fd = accept4(worker->listener.fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            return;
        }

        connection_t *conn = (connection_t *)calloc(1, sizeof(connection_t));
        if (!conn) {
            close(client_fd);
            continue;
        }

        conn->type = SRC_CONN;
        conn->fd = client_fd;
        conn->worker = worker;

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.ptr = conn;

        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            close(client_fd);
            free(conn);
            continue;
        }
    }
}

static void maybe_pin_thread_to_cpu(worker_t *worker) {
    if (!worker->pin_cpu) {
        return;
    }
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0) {
        return;
    }
    int cpu = worker->index % (int)ncpu;
    CPU_SET(cpu, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
}

static void *worker_main(void *arg) {
    worker_t *worker = (worker_t *)arg;

    maybe_pin_thread_to_cpu(worker);

    worker->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (worker->epoll_fd < 0) {
        perror("epoll_create1");
        return NULL;
    }

    worker->listener.type = SRC_LISTENER;
    worker->listener.worker = worker;
    worker->listener.fd = setup_listener(worker->port, worker->backlog);
    if (worker->listener.fd < 0) {
        perror("setup_listener");
        close(worker->epoll_fd);
        worker->epoll_fd = -1;
        return NULL;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = &worker->listener;

    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, worker->listener.fd, &ev) < 0) {
        perror("epoll_ctl add listener");
        close(worker->listener.fd);
        close(worker->epoll_fd);
        worker->listener.fd = -1;
        worker->epoll_fd = -1;
        return NULL;
    }

    struct epoll_event events[MAX_EVENTS];

    while (!g_stop) {
        int n = epoll_wait(worker->epoll_fd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        for (int i = 0; i < n; i++) {
            void *ptr = events[i].data.ptr;
            if (!ptr) {
                continue;
            }

            source_type_t type = *((source_type_t *)ptr);
            if (type == SRC_LISTENER) {
                accept_connections(worker);
            } else if (type == SRC_CONN) {
                process_connection_event(worker, (connection_t *)ptr, events[i].events);
            }
        }
    }

    if (worker->listener.fd >= 0) {
        close(worker->listener.fd);
        worker->listener.fd = -1;
    }
    if (worker->epoll_fd >= 0) {
        close(worker->epoll_fd);
        worker->epoll_fd = -1;
    }

    return NULL;
}

static int env_to_int(const char *name, int default_value) {
    const char *v = getenv(name);
    if (!v || *v == '\0') {
        return default_value;
    }
    char *endptr = NULL;
    long parsed = strtol(v, &endptr, 10);
    if (endptr == v || parsed <= 0 || parsed > 65535) {
        return default_value;
    }
    return (int)parsed;
}

static bool env_to_bool(const char *name, bool default_value) {
    const char *v = getenv(name);
    if (!v || *v == '\0') {
        return default_value;
    }
    if (strcasecmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0) {
        return true;
    }
    if (strcasecmp(v, "0") == 0 || strcasecmp(v, "false") == 0 || strcasecmp(v, "no") == 0 || strcasecmp(v, "off") == 0) {
        return false;
    }
    return default_value;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--port N] [--workers N] [--backlog N] [--pin-cpu]\n", prog);
}

static server_config_t parse_config(int argc, char **argv) {
    server_config_t cfg;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus <= 0) {
        cpus = 1;
    }

    cfg.port = env_to_int("SERVER_PORT", 8080);
    cfg.workers = env_to_int("SERVER_WORKERS", (int)cpus);
    cfg.backlog = env_to_int("SERVER_BACKLOG", 1024);
    cfg.pin_cpu = env_to_bool("SERVER_PIN_CPU", false);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            cfg.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            cfg.workers = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--backlog") == 0 && i + 1 < argc) {
            cfg.backlog = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--pin-cpu") == 0) {
            cfg.pin_cpu = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            print_usage(argv[0]);
            exit(2);
        }
    }

    if (cfg.port <= 0 || cfg.port > 65535) {
        fprintf(stderr, "Invalid port: %d\n", cfg.port);
        exit(2);
    }
    if (cfg.workers <= 0) {
        fprintf(stderr, "Invalid workers: %d\n", cfg.workers);
        exit(2);
    }
    if (cfg.backlog <= 0) {
        fprintf(stderr, "Invalid backlog: %d\n", cfg.backlog);
        exit(2);
    }

    return cfg;
}

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct sigaction sa_rebuild;
    memset(&sa_rebuild, 0, sizeof(sa_rebuild));
    sa_rebuild.sa_handler = handle_rebuild_signal;
    sigemptyset(&sa_rebuild.sa_mask);
    sigaction(SIGHUP, &sa_rebuild, NULL);

    server_config_t cfg = parse_config(argc, argv);

    dip_snapshot_init(&g_snapshot);
    const char *data_root = getenv("DATA_ROOT");
    if (!data_root || *data_root == '\0') {
        data_root = "..";
    }
    snprintf(g_data_root, sizeof(g_data_root), "%s", data_root);
    const char *snapshot_dir = getenv("SNAPSHOT_DIR");
    if (snapshot_dir && *snapshot_dir != '\0') {
        snprintf(g_snapshot_dir, sizeof(g_snapshot_dir), "%s", snapshot_dir);
    }
    g_rebuild_interval_sec = env_to_int("REBUILD_INTERVAL_SEC", 0);
    g_require_api_key_for_read = env_to_bool("REQUIRE_API_KEY_FOR_READ", false);

    char snapshot_err[256];
    uint64_t loaded_version = 0;
    if (dip_snapshot_load_files(&g_snapshot, g_snapshot_dir, &loaded_version, snapshot_err, sizeof(snapshot_err)) == 0) {
        g_snapshot_version = loaded_version > 0 ? loaded_version : 1;
        fprintf(stdout, "snapshot load source=bin version=%llu dir=%s\n", (unsigned long long)g_snapshot_version, g_snapshot_dir);
        fflush(stdout);
        write_m3_validation_report(&g_snapshot, g_snapshot_dir, "startup_bin");
    } else {
        fprintf(stderr, "snapshot bin unavailable, falling back to xml load: %s\n", snapshot_err);
        if (dip_snapshot_load(&g_snapshot, data_root, snapshot_err, sizeof(snapshot_err)) != 0) {
            fprintf(stderr, "snapshot load warning: %s\n", snapshot_err);
        } else {
            g_snapshot_version = 1;
            persist_active_snapshot("startup_xml_fallback");
            write_m3_validation_report(&g_snapshot, g_snapshot_dir, "startup_xml");
        }
    }

    fprintf(
        stdout,
        "starting dip-c-server port=%d workers=%d backlog=%d pin_cpu=%d data_root=%s snapshot_dir=%s drs=%zu pp=%zu persons=%zu snapshot_version=%llu rebuild_interval=%d require_api_key_for_read=%d\n",
        cfg.port,
        cfg.workers,
        cfg.backlog,
        cfg.pin_cpu ? 1 : 0,
        data_root,
        g_snapshot_dir,
        g_snapshot.drucksachen_count,
        g_snapshot.plenarprotokolle_count,
        g_snapshot.personen_count,
        (unsigned long long)g_snapshot_version,
        g_rebuild_interval_sec,
        g_require_api_key_for_read ? 1 : 0);
    fflush(stdout);

    if (pthread_create(&g_rebuild_thread, NULL, rebuild_thread_main, NULL) == 0) {
        g_rebuild_thread_started = true;
    } else {
        fprintf(stderr, "warning: could not start rebuild thread\n");
    }

    worker_t *workers = (worker_t *)calloc((size_t)cfg.workers, sizeof(worker_t));
    if (!workers) {
        perror("calloc workers");
        return 1;
    }

    for (int i = 0; i < cfg.workers; i++) {
        workers[i].index = i;
        workers[i].port = cfg.port;
        workers[i].backlog = cfg.backlog;
        workers[i].pin_cpu = cfg.pin_cpu;
        workers[i].epoll_fd = -1;
        workers[i].listener.fd = -1;

        int rc = pthread_create(&workers[i].thread, NULL, worker_main, &workers[i]);
        if (rc != 0) {
            fprintf(stderr, "pthread_create failed for worker %d: %s\n", i, strerror(rc));
            g_stop = 1;
            cfg.workers = i;
            break;
        }
    }

    for (int i = 0; i < cfg.workers; i++) {
        pthread_join(workers[i].thread, NULL);
    }

    g_stop = 1;
    if (g_rebuild_thread_started) {
        pthread_join(g_rebuild_thread, NULL);
        g_rebuild_thread_started = false;
    }

    free(workers);
    pthread_rwlock_wrlock(&g_snapshot_lock);
    dip_snapshot_free(&g_snapshot);
    pthread_rwlock_unlock(&g_snapshot_lock);
    fprintf(stdout, "server stopped\n");
    fflush(stdout);

    return 0;
}
