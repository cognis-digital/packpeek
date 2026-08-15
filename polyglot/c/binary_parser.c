/*
 * polyglot/c/binary_parser.c
 * 
 * Static packer/loader fingerprinter for packpeek tool.
 * Detects UPX/ASPack/Themida/MPRESS/VMProtect + entropy analysis.
 * Outputs JSON, YARA rules, and SARIF 2.1.0 format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>

#define MAX_SECTIONS    64
#define MAX_ENTRIES     512
#define BUFFER_SIZE    (8 * 1024)
#define PE_OFFSET      0x40
#define UPX_MAGIC      0x5A4C
#define ASPACK_MAGIC   0x1490

/* ============================================================================
 * Data Structures
 */

typedef struct {
    char name[64];
    uint32_t vaddr;
    uint32_t size;
    uint8_t  entropy;
    uint8_t  flags;
} SectionInfo;

typedef struct {
    char name[128];
    uint64_t offset;
    uint64_t size;
    uint8_t  entropy;
    uint8_t  type;      /* 0=unknown, 1=UPX, 2=ASPack, etc */
} FileEntry;

typedef struct {
    char name[32];
    uint64_t offset;
    uint64_t size;
    uint8_t  entropy;
    uint8_t  flags;     /* 0x1=UPX, 0x2=ASPack, etc */
} PackerInfo;

typedef struct {
    char name[32];
    uint64_t offset;
    uint64_t size;
    uint8_t  entropy;
    uint8_t  type;      /* 0=normal, 1=suspicious */
} SuspiciousSection;

/* ============================================================================
 * Utility Functions
 */

static inline int is_le32(uint32_t val) {
    return (val & 0x80000000) ? 1 : 0;
}

static inline uint32_t read_le32(const void *p) {
    const unsigned char *b = p;
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
}

static inline uint64_t read_le64(const void *p) {
    const unsigned char *b = p;
    return b[0] | (uint64_t)b[1] << 8 | 
           (uint64_t)b[2] << 16 | (uint64_t)b[3] << 24 |
           (uint64_t)b[4] << 32 | (uint64_t)b[5] << 40 |
           (uint64_t)b[6] << 48 | (uint64_t)b[7] << 56;
}

static inline double calculate_entropy(const uint8_t *data, size_t len) {
    if (!data || !len) return 0.0;
    
    unsigned char freq[256] = {0};
    int i;
    
    for (i = 0; i < (int)len; i++) {
        freq[data[i]]++;
    }
    
    double entropy = 0.0;
    double total = len;
    
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / total;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

static inline int compare_sections(const void *a, const void *b) {
    SectionInfo *sa = (SectionInfo *)a;
    SectionInfo *sb = (SectionInfo *)b;
    if (sa->vaddr < sb->vaddr) return -1;
    if (sa->vaddr > sb->vaddr) return 1;
    return 0;
}

/* ============================================================================
 * PE Header Parsing
 */

typedef struct {
    char name[8];
    uint32_t offset;
    uint64_t size;
    uint8_t  entropy;
} DosHeader;

typedef struct {
    uint16_t signature;
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t pointer_to_symbol_table;
    uint32_t num_symbols;
    uint32_t size_of_optional_header;
    uint16_t characteristics;
} PeHeader;

typedef struct {
    uint16_t magic;
    uint16_t linkersize;
    uint32_t addressofentrypoint;
    uint32_t baseofcode;
    uint32_t baserelocsize;
    uint32_t numrelocations;
    uint32_t imagebase;
} PeOptionalHeader;

typedef struct {
    DosHeader dos;
    PeHeader pe;
    PeOptionalHeader opt;
    SectionInfo sections[MAX_SECTIONS];
    int section_count;
    uint64_t file_size;
    double overall_entropy;
} ParsedPE;

static int parse_dos_header(const void *data, size_t len) {
    DosHeader *dos = &((ParsedPE *)0)->dos;
    
    if (len < 64) return -1;
    
    memcpy(dos->name, data + 3, 8);
    dos->offset = read_le32(data + 6);
    dos->size = read_le32(data + 10);
    
    /* Check for valid MZ signature */
    if (dos->offset != 0x40) {
        return -1;
    }
    
    return 0;
}

static int parse_pe_header(const void *data, size_t len) {
    ParsedPE *pe = (ParsedPE *)0;
    PeHeader *hdr = &pe->pe;
    PeOptionalHeader *opt = &pe->opt;
    
    if (len < PE_OFFSET + 248) return -1;
    
    /* Check NT signature */
    uint32_t sig = read_le32(data + PE_OFFSET);
    if (sig != 0x00004550 && sig != 0x4550) {
        return -1;
    }
    
    hdr->signature = sig;
    hdr->machine = read_le16(data + PE_OFFSET + 4);
    hdr->num_sections = read_le16(data + PE_OFFSET + 2);
    hdr->timestamp = read_le32(data + PE_OFFSET + 6);
    hdr->pointer_to_symbol_table = read_le32(data + PE_OFFSET + 8);
    hdr->num_symbols = read_le32(data + PE_OFFSET + 10);
    hdr->size_of_optional_header = read_le32(data + PE_OFFSET + 12);
    hdr->characteristics = read_le16(data + PE_OFFSET + 14);
    
    /* Parse optional header */
    if (hdr->size_of_optional_header >= 224) {
        opt->magic = read_le16(data + PE_OFFSET + 248);
        opt->linkersize = read_le32(data + PE_OFFSET + 250);
        opt->addressofentrypoint = read_le32(data + PE_OFFSET + 254);
        opt->baseofcode = read_le32(data + PE_OFFSET + 258);
        opt->baserelocsize = read_le32(data + PE_OFFSET + 262);
        opt->numrelocations = read_le32(data + PE_OFFSET + 266);
        opt->imagebase = read_le32(data + PE_OFFSET + 270);
    }
    
    return 0;
}

static int parse_sections(const void *data, size_t len) {
    ParsedPE *pe = (ParsedPE *)0;
    PeHeader *hdr = &pe->pe;
    SectionInfo *sec = pe->sections;
    const uint8_t *p = data + PE_OFFSET;
    
    if (!hdr || !hdr->num_sections) return 0;
    
    int i, j;
    for (i = 0; i < hdr->num_sections && i < MAX_SECTIONS; i++) {
        /* Calculate section offset */
        uint32_t sec_offset = PE_OFFSET + 64 + (hdr->num_sections - i) * 40;
        
        if (sec_offset >= len) break;
        
        sec[i].name[0] = '\0';
        memcpy(sec[i].name, p + sec_offset, 8);
        sec[i].vaddr = read_le32(p + sec_offset + 16);
        sec[i].size = read_le32(p + sec_offset + 20);
        
        /* Calculate entropy for this section */
        if (sec[i].size > 0 && sec_offset + 40 < len) {
            uint8_t *sect_data = (uint8_t *)data + PE_OFFSET + 64 + i * 40;
            double ent = calculate_entropy(sect_data, 40);
            sec[i].entropy = (uint8_t)(ent * 15.97) / 255.0; /* Scale to 0-255 */
        } else {
            sec[i].entropy = 0;
        }
        
        /* Mark suspicious sections */
        if (strstr(sec[i].name, ".vmp") || 
            strstr(sec[i].name, ".thm") ||
            strstr(sec[i].name, ".themida")) {
            sec[i].flags |= 0x10; /* Suspicious: packer section */
        }
    }
    
    pe->section_count = i;
    return 0;
}

/* ============================================================================
 * Packer Detection
 */

static int detect_upx(const void *data, size_t len) {
    const uint8_t *p = data + PE_OFFSET;
    
    /* Check for UPX magic at offset 0x40 (PE header start) */
    if (len >= PE_OFFSET + 256) {
        uint16_t magic = read_le16(p + 248);
        if (magic == UPX_MAGIC) {
            return 1; /* Found UPX */
        }
    }
    
    /* Check for UPX compression header pattern */
    const unsigned char *upx_sig = "\x5A\x4C";
    size_t i, j;
    
    for (i = 0; i < len - 2; i++) {
        if (!memcmp(data + i, upx_sig, 2)) {
            /* Check context around UPX signature */
            uint32_t offset = read_le32(data + PE_OFFSET + 254);
            
            /* UPX typically compresses at specific offsets */
            if (offset > 0 && offset < len) {
                return 1;
            }
        }
    }
    
    return 0;
}

static int detect_aspack(const void *data, size_t len) {
    const uint8_t *p = data + PE_OFFSET;
    
    /* Check for ASPack magic in optional header */
    if (len >= PE_OFFSET + 256) {
        uint16_t magic = read_le16(p + 248);
        if (magic == ASPACK_MAGIC) {
            return 1;
        }
    }
    
    /* Check for ASPack section names */
    const char *aspak_names[] = {".aspack", ".aspk", NULL};
    int i, j;
    
    ParsedPE pe = {0};
    parse_sections(data, len);
    
    for (i = 0; i < MAX_SECTIONS && aspak_names[i]; i++) {
        for (j = 0; j < pe.section_count; j++) {
            if (!strcmp(pe.sections[j].name, aspak_names[i])) {
                return 1;
            }
        }
    }
    
    return 0;
}

static int detect_themida(const void *data, size_t len) {
    ParsedPE pe = {0};
    parse_sections(data, len);
    
    /* Check for Themida section names */
    const char *themida_names[] = {".themida", ".thm", ".thm2", NULL};
    int i, j;
    
    for (i = 0; i < MAX_SECTIONS && themida_names[i]; i++) {
        for (j = 0; j < pe.section_count; j++) {
            if (!strcmp(pe.sections[j].name, themida_names[i])) {
                return 1;
            }
        }
    }
    
    /* Check for Themida magic bytes */
    const unsigned char *themida_sig = "\x54\x68\x6D";
    size_t k;
    
    for (k = 0; k < len - 3; k++) {
        if (!memcmp(data + k, themida_sig, 3)) {
            return 1;
        }
    }
    
    return 0;
}

static int detect_vmprotect(const void *data, size_t len) {
    ParsedPE pe = {0};
    parse_sections(data, len);
    
    /* Check for VMProtect section names */
    const char *vmp_names[] = {".vmp", ".vmp2", ".vmp3", NULL};
    int i, j;
    
    for (i = 0; i < MAX_SECTIONS && vmp_names[i]; i++) {
        for (j = 0; j < pe.section_count; j++) {
            if (!strcmp(pe.sections[j].name, vmp_names[i])) {
                return 1;
            }
        }
    }
    
    /* Check for VMProtect magic */
    const unsigned char *vmp_sig = "\x56\x4D\x50";
    size_t k;
    
    for (k = 0; k < len - 3; k++) {
        if (!memcmp(data + k, vmp_sig, 3)) {
            return 1;
        }
    }
    
    return 0;
}

static int detect_mpress(const void *data, size_t len) {
    ParsedPE pe = {0};
    parse_sections(data, len);
    
    /* Check for MPRESS section names */
    const char *mpress_names[] = {".mpress", ".mprs", NULL};
    int i, j;
    
    for (i = 0; i < MAX_SECTIONS && mpress_names[i]; i++) {
        for (j = 0; j < pe.section_count; j++) {
            if (!strcmp(pe.sections[j].name, mpress_names[i])) {
                return 1;
            }
        }
    }
    
    /* Check for MPRESS magic */
    const unsigned char *mpress_sig = "\x4D\x50\x52";
    size_t k;
    
    for (k = 0; k < len - 3; k++) {
        if (!memcmp(data + k, mpress_sig, 3)) {
            return 1;
        }
    }
    
    return 0;
}

/* ============================================================================
 * File Entry Analysis
 */

static int analyze_files(const void *data, size_t len) {
    ParsedPE pe = {0};
    parse_sections(data, len);
    
    FileEntry entries[MAX_ENTRIES];
    int entry_count = 0;
    
    /* Analyze each section as a potential file entry */
    for (int i = 0; i < MAX_SECTIONS && i < pe.section_count; i++) {
        if (!pe.sections[i].size) continue;
        
        FileEntry *e = &entries[entry_count];
        e->name[0] = '\0';
        strncpy(e->name, pe.sections[i].name, sizeof(e->name) - 1);
        e->offset = PE_OFFSET + 64 + i * 40;
        e