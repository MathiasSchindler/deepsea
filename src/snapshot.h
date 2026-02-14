#ifndef DIP_SNAPSHOT_H
#define DIP_SNAPSHOT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    long id;
    int wahlperiode;
    char datum[16];
    char urheber[256];
    char dokumentnummer[64];
    char titel[256];
    char fundstelle[256];
    char path[512];
    char text_preview[256];
} dip_document_t;

typedef struct {
    long id;
    char nachname[128];
    char vorname[128];
    char namenszusatz[128];
    char titel_prefix[64];
    char akad_titel[64];
    char funktion[128];
    char funktionszusatz[128];
    char fraktion[128];
    char wahlkreiszusatz[128];
    char ressort[160];
    char bundesland[64];
    char aktualisiert[40];
    int wahlperioden[16];
    size_t wahlperioden_count;
    char basisdatum[16];
    char datum[16];
} dip_person_t;

typedef struct {
    dip_document_t *drucksachen;
    const dip_document_t **drucksachen_docnr_desc;
    const dip_document_t **drucksachen_by_datum;
    size_t drucksachen_by_datum_count;
    const dip_document_t **drucksachen_by_wahlperiode[256];
    size_t drucksachen_by_wahlperiode_count[256];
    size_t drucksachen_count;
    dip_document_t *plenarprotokolle;
    const dip_document_t **plenarprotokolle_by_datum;
    size_t plenarprotokolle_by_datum_count;
    const dip_document_t **plenarprotokolle_by_wahlperiode[256];
    size_t plenarprotokolle_by_wahlperiode_count[256];
    size_t plenarprotokolle_count;
    dip_person_t *personen;
    const dip_person_t **personen_by_wahlperiode[256];
    size_t personen_by_wahlperiode_count[256];
    size_t personen_count;
    bool mmap_backed;
    void *mmap_addr;
    size_t mmap_size;
    bool loaded;
} dip_snapshot_t;

void dip_snapshot_init(dip_snapshot_t *snapshot);
void dip_snapshot_free(dip_snapshot_t *snapshot);
int dip_snapshot_load(dip_snapshot_t *snapshot, const char *data_root, char *err, size_t err_size);
int dip_snapshot_write_files(const dip_snapshot_t *snapshot, const char *snapshot_dir, uint64_t version, char *err, size_t err_size);
int dip_snapshot_load_files(dip_snapshot_t *snapshot, const char *snapshot_dir, uint64_t *out_version, char *err, size_t err_size);

const dip_document_t *dip_snapshot_find_drucksache(const dip_snapshot_t *snapshot, long id);
const dip_document_t *dip_snapshot_find_plenarprotokoll(const dip_snapshot_t *snapshot, long id);
const dip_person_t *dip_snapshot_find_person(const dip_snapshot_t *snapshot, long id);

#endif
