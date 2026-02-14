#define _GNU_SOURCE

#include "snapshot.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define READ_BUF_SIZE 65536

typedef struct {
    uint64_t magic;
    uint64_t version;
    uint64_t drs_count;
    uint64_t pp_count;
    uint64_t person_count;
    uint64_t checksum;
} snapshot_file_header_t;

static const uint64_t SNAPSHOT_MAGIC = 0x4450534E41503031ULL;

static uint64_t fnv1a_update(uint64_t hash, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)p[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static uint64_t snapshot_checksum(const dip_snapshot_t *snapshot) {
    uint64_t hash = 1469598103934665603ULL;
    hash = fnv1a_update(hash, &snapshot->drucksachen_count, sizeof(snapshot->drucksachen_count));
    hash = fnv1a_update(hash, &snapshot->plenarprotokolle_count, sizeof(snapshot->plenarprotokolle_count));
    hash = fnv1a_update(hash, &snapshot->personen_count, sizeof(snapshot->personen_count));
    if (snapshot->drucksachen_count > 0 && snapshot->drucksachen) {
        hash = fnv1a_update(hash, snapshot->drucksachen, snapshot->drucksachen_count * sizeof(dip_document_t));
    }
    if (snapshot->plenarprotokolle_count > 0 && snapshot->plenarprotokolle) {
        hash = fnv1a_update(hash, snapshot->plenarprotokolle, snapshot->plenarprotokolle_count * sizeof(dip_document_t));
    }
    if (snapshot->personen_count > 0 && snapshot->personen) {
        hash = fnv1a_update(hash, snapshot->personen, snapshot->personen_count * sizeof(dip_person_t));
    }
    return hash;
}

static int ensure_dir_recursive(const char *path) {
    char tmp[PATH_MAX];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, path, n + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int write_manifest(
    const char *snapshot_dir,
    uint64_t version,
    size_t drs_count,
    size_t pp_count,
    size_t person_count,
    uint64_t checksum,
    char *err,
    size_t err_size) {

    char manifest_path[PATH_MAX];
    snprintf(manifest_path, sizeof(manifest_path), "%s/snapshot_manifest.json", snapshot_dir);
    FILE *mf = fopen(manifest_path, "wb");
    if (!mf) {
        snprintf(err, err_size, "cannot write manifest: %s", manifest_path);
        return -1;
    }
    time_t now = time(NULL);
    fprintf(
        mf,
        "{\n"
        "  \"version\": %llu,\n"
        "  \"created_at_epoch\": %lld,\n"
        "  \"drucksachen_count\": %zu,\n"
        "  \"plenarprotokolle_count\": %zu,\n"
        "  \"personen_count\": %zu,\n"
        "  \"checksum\": \"%016llx\",\n"
        "  \"format\": \"snapshot-bin-v1\"\n"
        "}\n",
        (unsigned long long)version,
        (long long)now,
        drs_count,
        pp_count,
        person_count,
        (unsigned long long)checksum);
    fclose(mf);
    return 0;
}

static void safe_copy(char *dst, size_t dst_size, const char *src) {
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

static void sanitize_inline(char *s) {
    if (!s) {
        return;
    }
    char *w = s;
    for (char *r = s; *r; r++) {
        char c = *r;
        if (c == '\n' || c == '\r' || c == '\t') {
            c = ' ';
        }
        if ((unsigned char)c < 32) {
            continue;
        }
        if (c == '"') {
            c = '\'';
        }
        *w++ = c;
    }
    *w = '\0';

    while (*s == ' ') {
        memmove(s, s + 1, strlen(s));
    }
    size_t len = strlen(s);
    while (len > 0 && s[len - 1] == ' ') {
        s[len - 1] = '\0';
        len--;
    }
}

static void add_person_wahlperiode(dip_person_t *person, int wp) {
    if (!person || wp <= 0) {
        return;
    }
    for (size_t i = 0; i < person->wahlperioden_count; i++) {
        if (person->wahlperioden[i] == wp) {
            return;
        }
    }
    if (person->wahlperioden_count < (sizeof(person->wahlperioden) / sizeof(person->wahlperioden[0]))) {
        person->wahlperioden[person->wahlperioden_count++] = wp;
    }
}

static void add_person_name_alias(dip_person_t *person, const char *alias) {
    if (!person || !alias || alias[0] == '\0') {
        return;
    }

    char clean[128];
    safe_copy(clean, sizeof(clean), alias);
    sanitize_inline(clean);
    if (clean[0] == '\0') {
        return;
    }

    if (strcasestr(person->funktionszusatz, clean) != NULL) {
        return;
    }

    if (person->funktionszusatz[0] == '\0') {
        safe_copy(person->funktionszusatz, sizeof(person->funktionszusatz), clean);
        return;
    }

    size_t used = strlen(person->funktionszusatz);
    if (used + 1 < sizeof(person->funktionszusatz)) {
        person->funktionszusatz[used++] = '|';
        person->funktionszusatz[used] = '\0';
    }
    size_t remain = sizeof(person->funktionszusatz) - used;
    if (remain > 1) {
        safe_copy(person->funktionszusatz + used, remain, clean);
    }
}

static void normalize_date_iso(char *date_buf, size_t size) {
    if (!date_buf || date_buf[0] == '\0') {
        return;
    }

    if (strlen(date_buf) == 10 &&
        isdigit((unsigned char)date_buf[0]) && isdigit((unsigned char)date_buf[1]) &&
        date_buf[2] == '.' &&
        isdigit((unsigned char)date_buf[3]) && isdigit((unsigned char)date_buf[4]) &&
        date_buf[5] == '.' &&
        isdigit((unsigned char)date_buf[6]) && isdigit((unsigned char)date_buf[7]) &&
        isdigit((unsigned char)date_buf[8]) && isdigit((unsigned char)date_buf[9])) {
        char iso[16];
        snprintf(iso, sizeof(iso), "%c%c%c%c-%c%c-%c%c",
                 date_buf[6], date_buf[7], date_buf[8], date_buf[9],
                 date_buf[3], date_buf[4],
                 date_buf[0], date_buf[1]);
        safe_copy(date_buf, size, iso);
        return;
    }

    if (strlen(date_buf) >= 10 &&
        isdigit((unsigned char)date_buf[0]) && isdigit((unsigned char)date_buf[1]) &&
        isdigit((unsigned char)date_buf[2]) && isdigit((unsigned char)date_buf[3]) &&
        date_buf[4] == '-' &&
        isdigit((unsigned char)date_buf[5]) && isdigit((unsigned char)date_buf[6]) &&
        date_buf[7] == '-' &&
        isdigit((unsigned char)date_buf[8]) && isdigit((unsigned char)date_buf[9])) {
        date_buf[10] = '\0';
        return;
    }
}

static bool parse_wp_dir(const char *name, const char *prefix, int *wp) {
    size_t p = strlen(prefix);
    if (strncmp(name, prefix, p) != 0) {
        return false;
    }
    if (!isdigit((unsigned char)name[p]) || !isdigit((unsigned char)name[p + 1]) || name[p + 2] != '\0') {
        return false;
    }
    *wp = (name[p] - '0') * 10 + (name[p + 1] - '0');
    return true;
}

static bool parse_leading_digits(const char *filename, char *digits, size_t digits_size) {
    size_t i = 0;
    while (filename[i] && isdigit((unsigned char)filename[i]) && i + 1 < digits_size) {
        digits[i] = filename[i];
        i++;
    }
    digits[i] = '\0';
    return i > 0;
}

static void make_doc_number(int wp, const char *digits, char *out, size_t out_size) {
    long number = 0;
    if (digits && strlen(digits) > 2) {
        number = strtol(digits + 2, NULL, 10);
    }
    if (number <= 0) {
        snprintf(out, out_size, "%02d/0", wp);
    } else {
        snprintf(out, out_size, "%02d/%ld", wp, number);
    }
}

static void extract_xml_tag_value(const char *xml, const char *tag, char *out, size_t out_size) {
    char open[64];
    char close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);

    const char *start = strstr(xml, open);
    if (!start) {
        out[0] = '\0';
        return;
    }
    start += strlen(open);
    const char *end = strstr(start, close);
    if (!end || end <= start) {
        out[0] = '\0';
        return;
    }

    size_t n = (size_t)(end - start);
    if (n >= out_size) {
        n = out_size - 1;
    }
    memcpy(out, start, n);
    out[n] = '\0';
    sanitize_inline(out);
}

static void extract_title_and_text(
    const char *path,
    char *title,
    size_t title_size,
    char *text_preview,
    size_t text_preview_size,
    char *datum,
    size_t datum_size,
    char *urheber,
    size_t urheber_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        title[0] = '\0';
        text_preview[0] = '\0';
        datum[0] = '\0';
        urheber[0] = '\0';
        return;
    }

    char *buf = (char *)calloc(1, READ_BUF_SIZE + 1);
    if (!buf) {
        fclose(f);
        title[0] = '\0';
        text_preview[0] = '\0';
        datum[0] = '\0';
        urheber[0] = '\0';
        return;
    }

    size_t n = fread(buf, 1, READ_BUF_SIZE, f);
    buf[n] = '\0';
    fclose(f);

    extract_xml_tag_value(buf, "TITEL", title, title_size);
    extract_xml_tag_value(buf, "TEXT", text_preview, text_preview_size);
    extract_xml_tag_value(buf, "DATUM", datum, datum_size);
    extract_xml_tag_value(buf, "URHEBER", urheber, urheber_size);

    if (title[0] == '\0') {
        extract_xml_tag_value(buf, "KURZTITEL", title, title_size);
    }

    free(buf);
}

static int add_document(dip_document_t **arr, size_t *count, size_t *capacity, const dip_document_t *doc) {
    if (*count >= *capacity) {
        size_t new_capacity = (*capacity == 0) ? 1024 : (*capacity * 2);
        dip_document_t *next = (dip_document_t *)realloc(*arr, new_capacity * sizeof(dip_document_t));
        if (!next) {
            return -1;
        }
        *arr = next;
        *capacity = new_capacity;
    }
    (*arr)[*count] = *doc;
    (*count)++;
    return 0;
}

static int add_person(dip_person_t **arr, size_t *count, size_t *capacity, const dip_person_t *person) {
    for (size_t i = 0; i < *count; i++) {
        if ((*arr)[i].id != person->id) {
            continue;
        }

        dip_person_t *dst = &(*arr)[i];

        if (person->nachname[0] != '\0') {
            if (dst->nachname[0] != '\0' && strcasecmp(dst->nachname, person->nachname) != 0) {
                add_person_name_alias(dst, dst->nachname);
                add_person_name_alias(dst, person->nachname);
            }
            safe_copy(dst->nachname, sizeof(dst->nachname), person->nachname);
        }
        if (person->vorname[0] != '\0') {
            safe_copy(dst->vorname, sizeof(dst->vorname), person->vorname);
        }
        if (person->namenszusatz[0] != '\0' && dst->namenszusatz[0] == '\0') {
            safe_copy(dst->namenszusatz, sizeof(dst->namenszusatz), person->namenszusatz);
        }
        if (person->titel_prefix[0] != '\0' && dst->titel_prefix[0] == '\0') {
            safe_copy(dst->titel_prefix, sizeof(dst->titel_prefix), person->titel_prefix);
        }
        if (person->akad_titel[0] != '\0' && dst->akad_titel[0] == '\0') {
            safe_copy(dst->akad_titel, sizeof(dst->akad_titel), person->akad_titel);
        }
        if (person->funktion[0] != '\0') {
            safe_copy(dst->funktion, sizeof(dst->funktion), person->funktion);
        }
        if (person->funktionszusatz[0] != '\0') {
            add_person_name_alias(dst, person->funktionszusatz);
        }
        if (person->fraktion[0] != '\0') {
            safe_copy(dst->fraktion, sizeof(dst->fraktion), person->fraktion);
        }
        if (person->wahlkreiszusatz[0] != '\0' && dst->wahlkreiszusatz[0] == '\0') {
            safe_copy(dst->wahlkreiszusatz, sizeof(dst->wahlkreiszusatz), person->wahlkreiszusatz);
        }
        if (person->ressort[0] != '\0' && dst->ressort[0] == '\0') {
            safe_copy(dst->ressort, sizeof(dst->ressort), person->ressort);
        }
        if (person->bundesland[0] != '\0' && dst->bundesland[0] == '\0') {
            safe_copy(dst->bundesland, sizeof(dst->bundesland), person->bundesland);
        }

        if (person->basisdatum[0] != '\0') {
            if (dst->basisdatum[0] == '\0' || strcmp(dst->basisdatum, "1970-01-01") == 0 || strcmp(person->basisdatum, dst->basisdatum) < 0) {
                safe_copy(dst->basisdatum, sizeof(dst->basisdatum), person->basisdatum);
            }
        }
        if (person->datum[0] != '\0') {
            if (dst->datum[0] == '\0' || strcmp(person->datum, dst->datum) > 0) {
                safe_copy(dst->datum, sizeof(dst->datum), person->datum);
            }
        }
        if (person->aktualisiert[0] != '\0') {
            if (dst->aktualisiert[0] == '\0' || strcmp(person->aktualisiert, dst->aktualisiert) > 0) {
                safe_copy(dst->aktualisiert, sizeof(dst->aktualisiert), person->aktualisiert);
            }
        }
        for (size_t wp_idx = 0; wp_idx < person->wahlperioden_count; wp_idx++) {
            add_person_wahlperiode(dst, person->wahlperioden[wp_idx]);
        }

        return 0;
    }

    if (*count >= *capacity) {
        size_t new_capacity = (*capacity == 0) ? 1024 : (*capacity * 2);
        dip_person_t *next = (dip_person_t *)realloc(*arr, new_capacity * sizeof(dip_person_t));
        if (!next) {
            return -1;
        }
        *arr = next;
        *capacity = new_capacity;
    }
    (*arr)[*count] = *person;
    (*count)++;
    return 0;
}

static int cmp_document_id(const void *a, const void *b) {
    const dip_document_t *left = (const dip_document_t *)a;
    const dip_document_t *right = (const dip_document_t *)b;
    if (left->id < right->id) {
        return -1;
    }
    if (left->id > right->id) {
        return 1;
    }
    return 0;
}

static int cmp_person_id(const void *a, const void *b) {
    const dip_person_t *left = (const dip_person_t *)a;
    const dip_person_t *right = (const dip_person_t *)b;
    if (left->id < right->id) {
        return -1;
    }
    if (left->id > right->id) {
        return 1;
    }
    return 0;
}

static void parse_drucksache_docnr(const char *docnr, long *wp, long *nr, const char **suffix) {
    *wp = -1;
    *nr = -1;
    *suffix = "";
    if (!docnr || docnr[0] == '\0') {
        return;
    }

    char *end = NULL;
    long first = strtol(docnr, &end, 10);
    if (end == docnr) {
        return;
    }

    if (*end == '/') {
        char *end2 = NULL;
        long second = strtol(end + 1, &end2, 10);
        if (end2 == end + 1) {
            *wp = first;
            *nr = -1;
            *suffix = end + 1;
            return;
        }
        *wp = first;
        *nr = second;
        *suffix = end2;
        return;
    }

    *wp = 0;
    *nr = first;
    *suffix = end;
}

static int cmp_document_docnr_desc_ptr(const void *a, const void *b) {
    const dip_document_t *da = *(const dip_document_t *const *)a;
    const dip_document_t *db = *(const dip_document_t *const *)b;

    long wp_a, nr_a, wp_b, nr_b;
    const char *suffix_a;
    const char *suffix_b;
    parse_drucksache_docnr(da->dokumentnummer, &wp_a, &nr_a, &suffix_a);
    parse_drucksache_docnr(db->dokumentnummer, &wp_b, &nr_b, &suffix_b);

    if (wp_a != wp_b) {
        return (wp_a < wp_b) ? 1 : -1;
    }
    if (nr_a != nr_b) {
        return (nr_a < nr_b) ? 1 : -1;
    }

    bool suffix_a_empty = !suffix_a || suffix_a[0] == '\0';
    bool suffix_b_empty = !suffix_b || suffix_b[0] == '\0';
    if (suffix_a_empty != suffix_b_empty) {
        return suffix_a_empty ? -1 : 1;
    }

    int suffix_cmp = strcmp(suffix_a ? suffix_a : "", suffix_b ? suffix_b : "");
    if (suffix_cmp != 0) {
        return suffix_cmp;
    }

    if (da->id != db->id) {
        return (da->id < db->id) ? 1 : -1;
    }

    return strcmp(db->dokumentnummer, da->dokumentnummer);
}

static int cmp_document_datum_asc_ptr(const void *a, const void *b) {
    const dip_document_t *da = *(const dip_document_t *const *)a;
    const dip_document_t *db = *(const dip_document_t *const *)b;

    int cmp = strcmp(da->datum, db->datum);
    if (cmp != 0) {
        return cmp;
    }
    if (da->id < db->id) {
        return -1;
    }
    if (da->id > db->id) {
        return 1;
    }
    return 0;
}

static int build_drucksache_docnr_index(dip_snapshot_t *snapshot) {
    free((void *)snapshot->drucksachen_docnr_desc);
    snapshot->drucksachen_docnr_desc = NULL;

    if (!snapshot->drucksachen || snapshot->drucksachen_count == 0) {
        return 0;
    }

    const dip_document_t **index = (const dip_document_t **)calloc(snapshot->drucksachen_count, sizeof(*index));
    if (!index) {
        return -1;
    }

    for (size_t i = 0; i < snapshot->drucksachen_count; i++) {
        index[i] = &snapshot->drucksachen[i];
    }

    if (snapshot->drucksachen_count > 1) {
        qsort(index, snapshot->drucksachen_count, sizeof(*index), cmp_document_docnr_desc_ptr);
    }

    snapshot->drucksachen_docnr_desc = index;
    return 0;
}

static int build_document_date_index(const dip_document_t *docs, size_t docs_count, const dip_document_t ***out_index, size_t *out_count) {
    free((void *)*out_index);
    *out_index = NULL;
    *out_count = 0;

    if (!docs || docs_count == 0) {
        return 0;
    }

    const dip_document_t **index = (const dip_document_t **)calloc(docs_count, sizeof(*index));
    if (!index) {
        return -1;
    }

    for (size_t i = 0; i < docs_count; i++) {
        index[i] = &docs[i];
    }

    if (docs_count > 1) {
        qsort(index, docs_count, sizeof(*index), cmp_document_datum_asc_ptr);
    }

    *out_index = index;
    *out_count = docs_count;
    return 0;
}

static void free_document_wahlperiode_index(const dip_document_t ***by_wahlperiode, size_t *by_wahlperiode_count) {
    if (!by_wahlperiode || !by_wahlperiode_count) {
        return;
    }
    for (size_t wp = 0; wp < 256; wp++) {
        free((void *)by_wahlperiode[wp]);
        by_wahlperiode[wp] = NULL;
        by_wahlperiode_count[wp] = 0;
    }
}

static void free_person_wahlperiode_index(const dip_person_t ***by_wahlperiode, size_t *by_wahlperiode_count) {
    if (!by_wahlperiode || !by_wahlperiode_count) {
        return;
    }
    for (size_t wp = 0; wp < 256; wp++) {
        free((void *)by_wahlperiode[wp]);
        by_wahlperiode[wp] = NULL;
        by_wahlperiode_count[wp] = 0;
    }
}

static int build_document_wahlperiode_index(
    const dip_document_t *docs,
    size_t docs_count,
    const dip_document_t ***by_wahlperiode,
    size_t *by_wahlperiode_count) {

    free_document_wahlperiode_index(by_wahlperiode, by_wahlperiode_count);

    if (!docs || docs_count == 0) {
        return 0;
    }

    for (size_t i = 0; i < docs_count; i++) {
        int wp = docs[i].wahlperiode;
        if (wp >= 0 && wp < 256) {
            by_wahlperiode_count[(size_t)wp]++;
        }
    }

    for (size_t wp = 0; wp < 256; wp++) {
        if (by_wahlperiode_count[wp] == 0) {
            continue;
        }
        by_wahlperiode[wp] = (const dip_document_t **)calloc(by_wahlperiode_count[wp], sizeof(*by_wahlperiode[wp]));
        if (!by_wahlperiode[wp]) {
            free_document_wahlperiode_index(by_wahlperiode, by_wahlperiode_count);
            return -1;
        }
        by_wahlperiode_count[wp] = 0;
    }

    for (size_t i = 0; i < docs_count; i++) {
        int wp = docs[i].wahlperiode;
        if (wp < 0 || wp >= 256 || !by_wahlperiode[(size_t)wp]) {
            continue;
        }
        size_t idx = by_wahlperiode_count[(size_t)wp]++;
        by_wahlperiode[(size_t)wp][idx] = &docs[i];
    }

    return 0;
}

static int build_person_wahlperiode_index(
    const dip_person_t *personen,
    size_t personen_count,
    const dip_person_t ***by_wahlperiode,
    size_t *by_wahlperiode_count) {

    free_person_wahlperiode_index(by_wahlperiode, by_wahlperiode_count);

    if (!personen || personen_count == 0) {
        return 0;
    }

    for (size_t i = 0; i < personen_count; i++) {
        const dip_person_t *p = &personen[i];
        for (size_t j = 0; j < p->wahlperioden_count; j++) {
            int wp = p->wahlperioden[j];
            if (wp >= 0 && wp < 256) {
                by_wahlperiode_count[(size_t)wp]++;
            }
        }
    }

    for (size_t wp = 0; wp < 256; wp++) {
        if (by_wahlperiode_count[wp] == 0) {
            continue;
        }
        by_wahlperiode[wp] = (const dip_person_t **)calloc(by_wahlperiode_count[wp], sizeof(*by_wahlperiode[wp]));
        if (!by_wahlperiode[wp]) {
            free_person_wahlperiode_index(by_wahlperiode, by_wahlperiode_count);
            return -1;
        }
        by_wahlperiode_count[wp] = 0;
    }

    for (size_t i = 0; i < personen_count; i++) {
        const dip_person_t *p = &personen[i];
        for (size_t j = 0; j < p->wahlperioden_count; j++) {
            int wp = p->wahlperioden[j];
            if (wp < 0 || wp >= 256 || !by_wahlperiode[(size_t)wp]) {
                continue;
            }
            size_t idx = by_wahlperiode_count[(size_t)wp]++;
            by_wahlperiode[(size_t)wp][idx] = p;
        }
    }

    return 0;
}

static int load_doc_family(
    const char *data_root,
    const char *prefix,
    const char *fundstelle_prefix,
    dip_document_t **out_docs,
    size_t *out_count,
    char *err,
    size_t err_size) {

    size_t cap = 0;
    size_t count = 0;
    dip_document_t *docs = NULL;
    long next_id = 1;

    DIR *root = opendir(data_root);
    if (!root) {
        snprintf(err, err_size, "cannot open data root: %s", data_root);
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(root)) != NULL) {
        int wp = 0;
        if (!parse_wp_dir(ent->d_name, prefix, &wp)) {
            continue;
        }

        char dir_path[PATH_MAX];
        snprintf(dir_path, sizeof(dir_path), "%s/%s", data_root, ent->d_name);

        DIR *dir = opendir(dir_path);
        if (!dir) {
            continue;
        }

        struct dirent *file_ent;
        while ((file_ent = readdir(dir)) != NULL) {
            const char *name = file_ent->d_name;
            size_t len = strlen(name);
            if (len < 5) {
                continue;
            }
            if (strcmp(name + len - 4, ".xml") != 0 && strcmp(name + len - 4, ".XML") != 0) {
                continue;
            }

            char digits[64];
            if (!parse_leading_digits(name, digits, sizeof(digits))) {
                continue;
            }

            dip_document_t doc;
            memset(&doc, 0, sizeof(doc));
            doc.id = next_id++;
            doc.wahlperiode = wp;
            make_doc_number(wp, digits, doc.dokumentnummer, sizeof(doc.dokumentnummer));
            snprintf(doc.fundstelle, sizeof(doc.fundstelle), "%s %s", fundstelle_prefix, doc.dokumentnummer);
            size_t root_len = strlen(data_root);
            size_t dir_len = strlen(ent->d_name);
            size_t name_len = strlen(name);
            if (root_len + 1 + dir_len + 1 + name_len + 1 > sizeof(doc.path)) {
                continue;
            }
            memcpy(doc.path, data_root, root_len);
            doc.path[root_len] = '/';
            memcpy(doc.path + root_len + 1, ent->d_name, dir_len);
            doc.path[root_len + 1 + dir_len] = '/';
            memcpy(doc.path + root_len + 1 + dir_len + 1, name, name_len);
            doc.path[root_len + 1 + dir_len + 1 + name_len] = '\0';
            extract_title_and_text(
                doc.path,
                doc.titel,
                sizeof(doc.titel),
                doc.text_preview,
                sizeof(doc.text_preview),
                doc.datum,
                sizeof(doc.datum),
                doc.urheber,
                sizeof(doc.urheber));

            if (doc.datum[0] == '\0') {
                snprintf(doc.datum, sizeof(doc.datum), "1970-01-01");
            } else {
                normalize_date_iso(doc.datum, sizeof(doc.datum));
            }
            if (doc.urheber[0] == '\0') {
                snprintf(doc.urheber, sizeof(doc.urheber), "Unbekannt");
            }

            if (doc.titel[0] == '\0') {
                snprintf(doc.titel, sizeof(doc.titel), "%s %s", fundstelle_prefix, doc.dokumentnummer);
            }
            if (doc.text_preview[0] == '\0') {
                snprintf(doc.text_preview, sizeof(doc.text_preview), "Volltext-Vorschau nicht verfügbar");
            }

            if (add_document(&docs, &count, &cap, &doc) != 0) {
                snprintf(err, err_size, "out of memory while loading %s", prefix);
                closedir(dir);
                closedir(root);
                free(docs);
                return -1;
            }
        }
        closedir(dir);
    }

    closedir(root);

    *out_docs = docs;
    *out_count = count;
    return 0;
}

static int load_personen(const char *data_root, dip_person_t **out_personen, size_t *out_count) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/stammdaten/MDB_STAMMDATEN.XML", data_root);

    FILE *f = fopen(path, "rb");
    if (!f) {
        *out_personen = NULL;
        *out_count = 0;
        return 0;
    }

    dip_person_t *arr = NULL;
    size_t count = 0;
    size_t cap = 0;

    char *line = NULL;
    size_t line_cap = 0;

    dip_person_t current;
    memset(&current, 0, sizeof(current));
    bool in_mdb = false;

    while (getline(&line, &line_cap, f) != -1) {
        if (strstr(line, "<MDB>") != NULL) {
            in_mdb = true;
            memset(&current, 0, sizeof(current));
            continue;
        }
        if (strstr(line, "</MDB>") != NULL) {
            if (in_mdb && current.id > 0 && current.nachname[0] != '\0') {
                add_person(&arr, &count, &cap, &current);
            }
            in_mdb = false;
            continue;
        }
        if (!in_mdb) {
            continue;
        }

        char tmp[256];
        tmp[0] = '\0';
        extract_xml_tag_value(line, "ID", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            current.id = strtol(tmp, NULL, 10);
            continue;
        }

        extract_xml_tag_value(line, "NACHNAME", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            if (current.nachname[0] != '\0' && strcasecmp(current.nachname, tmp) != 0) {
                add_person_name_alias(&current, current.nachname);
            }
            safe_copy(current.nachname, sizeof(current.nachname), tmp);
            continue;
        }

        extract_xml_tag_value(line, "VORNAME", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            safe_copy(current.vorname, sizeof(current.vorname), tmp);
            continue;
        }

        extract_xml_tag_value(line, "ADEL", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            safe_copy(current.namenszusatz, sizeof(current.namenszusatz), tmp);
            continue;
        }

        extract_xml_tag_value(line, "PRAEFIX", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.namenszusatz[0] == '\0') {
            safe_copy(current.namenszusatz, sizeof(current.namenszusatz), tmp);
            continue;
        }

        extract_xml_tag_value(line, "ANREDE_TITEL", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            safe_copy(current.titel_prefix, sizeof(current.titel_prefix), tmp);
            continue;
        }

        extract_xml_tag_value(line, "AKAD_TITEL", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            safe_copy(current.akad_titel, sizeof(current.akad_titel), tmp);
            continue;
        }

        extract_xml_tag_value(line, "BASISDATUM", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            safe_copy(current.basisdatum, sizeof(current.basisdatum), tmp);
            normalize_date_iso(current.basisdatum, sizeof(current.basisdatum));
            continue;
        }

        extract_xml_tag_value(line, "HISTORIE_VON", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.basisdatum[0] == '\0') {
            safe_copy(current.basisdatum, sizeof(current.basisdatum), tmp);
            normalize_date_iso(current.basisdatum, sizeof(current.basisdatum));
            continue;
        }

        extract_xml_tag_value(line, "DATUM", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            safe_copy(current.datum, sizeof(current.datum), tmp);
            normalize_date_iso(current.datum, sizeof(current.datum));
            continue;
        }

        extract_xml_tag_value(line, "WP", tmp, sizeof(tmp));
        if (tmp[0] != '\0') {
            int wp = (int)strtol(tmp, NULL, 10);
            add_person_wahlperiode(&current, wp);
            continue;
        }

        extract_xml_tag_value(line, "WKR_NAME", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.wahlkreiszusatz[0] == '\0') {
            safe_copy(current.wahlkreiszusatz, sizeof(current.wahlkreiszusatz), tmp);
            continue;
        }

        extract_xml_tag_value(line, "WKR_LAND", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.bundesland[0] == '\0') {
            safe_copy(current.bundesland, sizeof(current.bundesland), tmp);
            continue;
        }

        extract_xml_tag_value(line, "LISTE", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.bundesland[0] == '\0') {
            safe_copy(current.bundesland, sizeof(current.bundesland), tmp);
            continue;
        }

        extract_xml_tag_value(line, "PARTEI_KURZ", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.fraktion[0] == '\0') {
            safe_copy(current.fraktion, sizeof(current.fraktion), tmp);
            continue;
        }

        extract_xml_tag_value(line, "INS_LANG", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.fraktion[0] == '\0') {
            safe_copy(current.fraktion, sizeof(current.fraktion), tmp);
            continue;
        }

        extract_xml_tag_value(line, "FKT_LANG", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.funktion[0] == '\0') {
            safe_copy(current.funktion, sizeof(current.funktion), tmp);
            continue;
        }

        extract_xml_tag_value(line, "BERUF", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.funktion[0] == '\0') {
            safe_copy(current.funktion, sizeof(current.funktion), tmp);
            continue;
        }

        extract_xml_tag_value(line, "RESSORT_TITEL", tmp, sizeof(tmp));
        if (tmp[0] != '\0' && current.ressort[0] == '\0') {
            safe_copy(current.ressort, sizeof(current.ressort), tmp);
            continue;
        }
    }

    free(line);
    fclose(f);

    *out_personen = arr;
    *out_count = count;

    for (size_t i = 0; i < count; i++) {
        if (arr[i].basisdatum[0] == '\0') {
            safe_copy(arr[i].basisdatum, sizeof(arr[i].basisdatum), "1970-01-01");
        }
        if (arr[i].datum[0] == '\0') {
            if (arr[i].basisdatum[0] != '\0') {
                safe_copy(arr[i].datum, sizeof(arr[i].datum), arr[i].basisdatum);
            } else {
                safe_copy(arr[i].datum, sizeof(arr[i].datum), "1970-01-01");
            }
        }
        if (arr[i].funktion[0] == '\0') {
            safe_copy(arr[i].funktion, sizeof(arr[i].funktion), "Unbekannt");
        }
        if (arr[i].fraktion[0] == '\0') {
            safe_copy(arr[i].fraktion, sizeof(arr[i].fraktion), "");
        }
        if (arr[i].wahlperioden_count == 0) {
            add_person_wahlperiode(&arr[i], 1);
        }
        snprintf(arr[i].aktualisiert, sizeof(arr[i].aktualisiert), "%sT00:00:00+00:00", arr[i].datum);
    }

    return 0;
}

void dip_snapshot_init(dip_snapshot_t *snapshot) {
    memset(snapshot, 0, sizeof(*snapshot));
}

void dip_snapshot_free(dip_snapshot_t *snapshot) {
    if (!snapshot) {
        return;
    }
    free((void *)snapshot->drucksachen_docnr_desc);
    snapshot->drucksachen_docnr_desc = NULL;
    free((void *)snapshot->drucksachen_by_datum);
    snapshot->drucksachen_by_datum = NULL;
    snapshot->drucksachen_by_datum_count = 0;
    free((void *)snapshot->plenarprotokolle_by_datum);
    snapshot->plenarprotokolle_by_datum = NULL;
    snapshot->plenarprotokolle_by_datum_count = 0;
    free_document_wahlperiode_index(snapshot->drucksachen_by_wahlperiode, snapshot->drucksachen_by_wahlperiode_count);
    free_document_wahlperiode_index(snapshot->plenarprotokolle_by_wahlperiode, snapshot->plenarprotokolle_by_wahlperiode_count);
    free_person_wahlperiode_index(snapshot->personen_by_wahlperiode, snapshot->personen_by_wahlperiode_count);
    if (snapshot->mmap_backed) {
        if (snapshot->mmap_addr && snapshot->mmap_size > 0) {
            munmap(snapshot->mmap_addr, snapshot->mmap_size);
        }
    } else {
        free(snapshot->drucksachen);
        free(snapshot->plenarprotokolle);
        free(snapshot->personen);
    }
    dip_snapshot_init(snapshot);
}

int dip_snapshot_load(dip_snapshot_t *snapshot, const char *data_root, char *err, size_t err_size) {
    dip_snapshot_free(snapshot);

    if (load_doc_family(data_root, "drs", "BT-Drucksache", &snapshot->drucksachen, &snapshot->drucksachen_count, err, err_size) != 0) {
        return -1;
    }
    if (load_doc_family(data_root, "pp", "BT-Plenarprotokoll", &snapshot->plenarprotokolle, &snapshot->plenarprotokolle_count, err, err_size) != 0) {
        dip_snapshot_free(snapshot);
        return -1;
    }
    if (load_personen(data_root, &snapshot->personen, &snapshot->personen_count) != 0) {
        dip_snapshot_free(snapshot);
        snprintf(err, err_size, "failed to load personen");
        return -1;
    }

    if (snapshot->drucksachen_count > 1) {
        qsort(snapshot->drucksachen, snapshot->drucksachen_count, sizeof(dip_document_t), cmp_document_id);
    }
    if (snapshot->plenarprotokolle_count > 1) {
        qsort(snapshot->plenarprotokolle, snapshot->plenarprotokolle_count, sizeof(dip_document_t), cmp_document_id);
    }
    if (snapshot->personen_count > 1) {
        qsort(snapshot->personen, snapshot->personen_count, sizeof(dip_person_t), cmp_person_id);
    }

    if (build_drucksache_docnr_index(snapshot) != 0) {
        dip_snapshot_free(snapshot);
        snprintf(err, err_size, "failed to build drucksache index");
        return -1;
    }

    if (build_document_wahlperiode_index(
            snapshot->drucksachen,
            snapshot->drucksachen_count,
            snapshot->drucksachen_by_wahlperiode,
            snapshot->drucksachen_by_wahlperiode_count) != 0) {
        dip_snapshot_free(snapshot);
        snprintf(err, err_size, "failed to build drucksache wahlperiode index");
        return -1;
    }

    if (build_document_wahlperiode_index(
            snapshot->plenarprotokolle,
            snapshot->plenarprotokolle_count,
            snapshot->plenarprotokolle_by_wahlperiode,
            snapshot->plenarprotokolle_by_wahlperiode_count) != 0) {
        dip_snapshot_free(snapshot);
        snprintf(err, err_size, "failed to build plenarprotokoll wahlperiode index");
        return -1;
    }

    if (build_document_date_index(
            snapshot->drucksachen,
            snapshot->drucksachen_count,
            &snapshot->drucksachen_by_datum,
            &snapshot->drucksachen_by_datum_count) != 0) {
        dip_snapshot_free(snapshot);
        snprintf(err, err_size, "failed to build drucksache date index");
        return -1;
    }

    if (build_document_date_index(
            snapshot->plenarprotokolle,
            snapshot->plenarprotokolle_count,
            &snapshot->plenarprotokolle_by_datum,
            &snapshot->plenarprotokolle_by_datum_count) != 0) {
        dip_snapshot_free(snapshot);
        snprintf(err, err_size, "failed to build plenarprotokoll date index");
        return -1;
    }

    if (build_person_wahlperiode_index(
            snapshot->personen,
            snapshot->personen_count,
            snapshot->personen_by_wahlperiode,
            snapshot->personen_by_wahlperiode_count) != 0) {
        dip_snapshot_free(snapshot);
        snprintf(err, err_size, "failed to build personen wahlperiode index");
        return -1;
    }

    snapshot->loaded = true;
    return 0;
}

int dip_snapshot_write_files(const dip_snapshot_t *snapshot, const char *snapshot_dir, uint64_t version, char *err, size_t err_size) {
    if (ensure_dir_recursive(snapshot_dir) != 0) {
        snprintf(err, err_size, "cannot create snapshot dir: %s", snapshot_dir);
        return -1;
    }

    char bin_path[PATH_MAX];
    snprintf(bin_path, sizeof(bin_path), "%s/snapshot.bin", snapshot_dir);

    FILE *f = fopen(bin_path, "wb");
    if (!f) {
        snprintf(err, err_size, "cannot write snapshot bin: %s", bin_path);
        return -1;
    }

    snapshot_file_header_t header;
    memset(&header, 0, sizeof(header));
    header.magic = SNAPSHOT_MAGIC;
    header.version = version;
    header.drs_count = (uint64_t)snapshot->drucksachen_count;
    header.pp_count = (uint64_t)snapshot->plenarprotokolle_count;
    header.person_count = (uint64_t)snapshot->personen_count;
    header.checksum = snapshot_checksum(snapshot);

    if (fwrite(&header, sizeof(header), 1, f) != 1) {
        fclose(f);
        snprintf(err, err_size, "failed writing snapshot header");
        return -1;
    }

    if (snapshot->drucksachen_count > 0 && fwrite(snapshot->drucksachen, sizeof(dip_document_t), snapshot->drucksachen_count, f) != snapshot->drucksachen_count) {
        fclose(f);
        snprintf(err, err_size, "failed writing drucksachen array");
        return -1;
    }
    if (snapshot->plenarprotokolle_count > 0 && fwrite(snapshot->plenarprotokolle, sizeof(dip_document_t), snapshot->plenarprotokolle_count, f) != snapshot->plenarprotokolle_count) {
        fclose(f);
        snprintf(err, err_size, "failed writing plenarprotokolle array");
        return -1;
    }
    if (snapshot->personen_count > 0 && fwrite(snapshot->personen, sizeof(dip_person_t), snapshot->personen_count, f) != snapshot->personen_count) {
        fclose(f);
        snprintf(err, err_size, "failed writing personen array");
        return -1;
    }
    fclose(f);

    if (write_manifest(
            snapshot_dir,
            version,
            snapshot->drucksachen_count,
            snapshot->plenarprotokolle_count,
            snapshot->personen_count,
            header.checksum,
            err,
            err_size) != 0) {
        return -1;
    }

    return 0;
}

int dip_snapshot_load_files(dip_snapshot_t *snapshot, const char *snapshot_dir, uint64_t *out_version, char *err, size_t err_size) {
    char bin_path[PATH_MAX];
    snprintf(bin_path, sizeof(bin_path), "%s/snapshot.bin", snapshot_dir);

    int fd = open(bin_path, O_RDONLY);
    if (fd < 0) {
        snprintf(err, err_size, "snapshot bin not found: %s", bin_path);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(snapshot_file_header_t)) {
        close(fd);
        snprintf(err, err_size, "invalid snapshot file: %s", bin_path);
        return -1;
    }

    size_t map_size = (size_t)st.st_size;
    void *mapped = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) {
        snprintf(err, err_size, "mmap failed for snapshot: %s", bin_path);
        return -1;
    }

    const unsigned char *cursor = (const unsigned char *)mapped;
    const snapshot_file_header_t *header = (const snapshot_file_header_t *)cursor;

    if (header->magic != SNAPSHOT_MAGIC) {
        munmap(mapped, map_size);
        snprintf(err, err_size, "invalid snapshot magic");
        return -1;
    }

    size_t need = sizeof(snapshot_file_header_t);
    size_t drs_bytes = (size_t)header->drs_count * sizeof(dip_document_t);
    size_t pp_bytes = (size_t)header->pp_count * sizeof(dip_document_t);
    size_t person_bytes = (size_t)header->person_count * sizeof(dip_person_t);

    if (drs_bytes > SIZE_MAX - need || pp_bytes > SIZE_MAX - need - drs_bytes || person_bytes > SIZE_MAX - need - drs_bytes - pp_bytes) {
        munmap(mapped, map_size);
        snprintf(err, err_size, "snapshot size overflow");
        return -1;
    }
    need += drs_bytes + pp_bytes + person_bytes;
    if (need > map_size) {
        munmap(mapped, map_size);
        snprintf(err, err_size, "snapshot truncated");
        return -1;
    }

    dip_snapshot_t loaded;
    dip_snapshot_init(&loaded);
    loaded.drucksachen_count = (size_t)header->drs_count;
    loaded.plenarprotokolle_count = (size_t)header->pp_count;
    loaded.personen_count = (size_t)header->person_count;
    loaded.mmap_backed = true;
    loaded.mmap_addr = mapped;
    loaded.mmap_size = map_size;

    size_t offset = sizeof(snapshot_file_header_t);
    loaded.drucksachen = loaded.drucksachen_count > 0 ? (dip_document_t *)(cursor + offset) : NULL;
    offset += drs_bytes;
    loaded.plenarprotokolle = loaded.plenarprotokolle_count > 0 ? (dip_document_t *)(cursor + offset) : NULL;
    offset += pp_bytes;
    loaded.personen = loaded.personen_count > 0 ? (dip_person_t *)(cursor + offset) : NULL;

    uint64_t checksum = snapshot_checksum(&loaded);
    if (checksum != header->checksum) {
        munmap(mapped, map_size);
        snprintf(err, err_size, "snapshot checksum mismatch");
        return -1;
    }

    loaded.loaded = true;

    if (build_drucksache_docnr_index(&loaded) != 0) {
        dip_snapshot_free(&loaded);
        snprintf(err, err_size, "failed to build drucksache index");
        return -1;
    }

    if (build_document_wahlperiode_index(
            loaded.drucksachen,
            loaded.drucksachen_count,
            loaded.drucksachen_by_wahlperiode,
            loaded.drucksachen_by_wahlperiode_count) != 0) {
        dip_snapshot_free(&loaded);
        snprintf(err, err_size, "failed to build drucksache wahlperiode index");
        return -1;
    }

    if (build_document_wahlperiode_index(
            loaded.plenarprotokolle,
            loaded.plenarprotokolle_count,
            loaded.plenarprotokolle_by_wahlperiode,
            loaded.plenarprotokolle_by_wahlperiode_count) != 0) {
        dip_snapshot_free(&loaded);
        snprintf(err, err_size, "failed to build plenarprotokoll wahlperiode index");
        return -1;
    }

    if (build_document_date_index(
            loaded.drucksachen,
            loaded.drucksachen_count,
            &loaded.drucksachen_by_datum,
            &loaded.drucksachen_by_datum_count) != 0) {
        dip_snapshot_free(&loaded);
        snprintf(err, err_size, "failed to build drucksache date index");
        return -1;
    }

    if (build_document_date_index(
            loaded.plenarprotokolle,
            loaded.plenarprotokolle_count,
            &loaded.plenarprotokolle_by_datum,
            &loaded.plenarprotokolle_by_datum_count) != 0) {
        dip_snapshot_free(&loaded);
        snprintf(err, err_size, "failed to build plenarprotokoll date index");
        return -1;
    }

    if (build_person_wahlperiode_index(
            loaded.personen,
            loaded.personen_count,
            loaded.personen_by_wahlperiode,
            loaded.personen_by_wahlperiode_count) != 0) {
        dip_snapshot_free(&loaded);
        snprintf(err, err_size, "failed to build personen wahlperiode index");
        return -1;
    }

    dip_snapshot_free(snapshot);
    *snapshot = loaded;
    if (out_version) {
        *out_version = header->version;
    }

    return 0;
}

static const dip_document_t *find_document_by_id(const dip_document_t *docs, size_t count, long id) {
    size_t left = 0;
    size_t right = count;
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        long value = docs[mid].id;
        if (value == id) {
            return &docs[mid];
        }
        if (value < id) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return NULL;
}

static const dip_person_t *find_person_by_id(const dip_person_t *docs, size_t count, long id) {
    size_t left = 0;
    size_t right = count;
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        long value = docs[mid].id;
        if (value == id) {
            return &docs[mid];
        }
        if (value < id) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return NULL;
}

const dip_document_t *dip_snapshot_find_drucksache(const dip_snapshot_t *snapshot, long id) {
    if (!snapshot || !snapshot->drucksachen || snapshot->drucksachen_count == 0) {
        return NULL;
    }
    return find_document_by_id(snapshot->drucksachen, snapshot->drucksachen_count, id);
}

const dip_document_t *dip_snapshot_find_plenarprotokoll(const dip_snapshot_t *snapshot, long id) {
    if (!snapshot || !snapshot->plenarprotokolle || snapshot->plenarprotokolle_count == 0) {
        return NULL;
    }
    return find_document_by_id(snapshot->plenarprotokolle, snapshot->plenarprotokolle_count, id);
}

const dip_person_t *dip_snapshot_find_person(const dip_snapshot_t *snapshot, long id) {
    if (!snapshot || !snapshot->personen || snapshot->personen_count == 0) {
        return NULL;
    }
    return find_person_by_id(snapshot->personen, snapshot->personen_count, id);
}
