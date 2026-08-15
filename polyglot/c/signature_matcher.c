/*
 * polyglot/c/signature_matcher.c
 * 
 * Static packer/loader fingerprinter - signature matcher component
 * Detects UPX, ASPack, Themida, MPRESS, VMProtect in PE binaries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_PACKERS 8
#define MAX_SIGNATURES 256
#define BUFFER_SIZE (1 << 16)

/* Packer detection results */
typedef struct {
    const char *name;
    bool detected;
    uint32_t confidence;
    uint64_t signature_offset;
} packer_result_t;

/* PE header structures */
#pragma pack(push, 1)
typedef struct {
    unsigned short magic;
    unsigned short machine;
    unsigned short num_sections;
    unsigned short timestamp;
    unsigned short pointer_to_symbol_table;
    unsigned short num_symbols;
    unsigned short optional_header_magic;
} pe_header_t;

typedef struct {
    uint32_t major_linker_version;
    uint32_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
} optional_header_fields_t;

typedef struct {
    unsigned short magic;
    unsigned short major_linker_version;
    unsigned short minor_linker_version;
    unsigned int size_of_code;
    unsigned int size_of_initialized_data;
    unsigned int size_of_uninitialized_data;
    unsigned int address_of_entry_point;
    unsigned int base_of_code;
} optional_header_t;

typedef struct {
    uint16_t magic;
    uint16_t major_linker_version;
    uint16_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
} optional_header_64_t;

#pragma pack(pop)

/* Global state */
static pe_header_t g_pe_header = {0};
static optional_header_t g_optional_header = {0};
static bool g_is_valid_pe = false;
static char g_filename[256] = "";

/* Signature database - packed patterns for each known packer */
typedef struct {
    const char *name;
    uint8_t *patterns[MAX_SIGNATURES];
    int num_patterns;
    int pattern_size;  /* bytes per pattern */
} signature_db_t;

static signature_db_t g_signatures[] = {
    /* UPX signatures - magic and header patterns */
    {
        "UPX",
        {
            (uint8_t*)"UPX0!",           /* Magic in optional header */
            (uint8_t*)"\x52\x4D",         /* PE signature */
            (uint8_t*)"\x14\x00\x00\x00", /* Optional header magic 3.0 */
        },
        3,
        4
    },
    
    /* ASPack signatures */
    {
        "ASPack",
        {
            (uint8_t*)".aspack",          /* Section name */
            (uint8_t*)"ASPack",           /* String in PE */
            (uint8_t*)"\x52\x4D",         /* PE header */
        },
        3,
        6
    },
    
    /* Themida/VMProtect signatures */
    {
        "Themida",
        {
            (uint8_t*)"Themida",          /* String signature */
            (uint8_t*)"\x52\x4D",         /* PE header */
        },
        2,
        7
    },
    
    /* MPRESS signatures */
    {
        "MPRESS",
        {
            (uint8_t*)"MPress",           /* String signature */
            (uint8_t*)"\x52\x4D",         /* PE header */
        },
        2,
        6
    },
    
    /* VMProtect signatures */
    {
        "VMProtect",
        {
            (uint8_t*)"VMProtect",        /* String signature */
            (uint8_t*)"\x52\x4D",         /* PE header */
        },
        2,
        7
    },
    
    {0}  /* Terminator */
};

/* Initialize the matcher with a filename */
static void init_matcher(const char *filename)
{
    memset(&g_pe_header, 0, sizeof(g_pe_header));
    memset(&g_optional_header, 0, sizeof(g_optional_header));
    memset(g_filename, 0, sizeof(g_filename));
    
    if (filename && filename[0]) {
        strncpy(g_filename, filename, sizeof(g_filename) - 1);
    }
}

/* Read PE header from file */
static bool read_pe_header(FILE *fp)
{
    unsigned char buffer[64];
    int bytes_read;
    
    if (!fp || !g_is_valid_pe) {
        return false;
    }
    
    /* Read the DOS header and check for PE signature */
    bytes_read = fread(buffer, 1, 64, fp);
    if (bytes_read < 62) {
        return false;
    }
    
    /* Check PE magic at offset 0x3C */
    if (buffer[0x3C] != 'P' || buffer[0x3D] != 'E') {
        g_is_valid_pe = false;
        return false;
    }
    
    /* Read PE header at offset 0x40 */
    bytes_read = fread(&g_pe_header, 1, sizeof(pe_header_t), fp);
    if (bytes_read < (int)sizeof(pe_header_t)) {
        g_is_valid_pe = false;
        return false;
    }
    
    /* Verify magic for PE32 vs PE32+ */
    unsigned short opt_magic = 0;
    bytes_read = fread(&opt_magic, 1, 2, fp);
    if (bytes_read < 2) {
        g_is_valid_pe = false;
        return false;
    }
    
    /* PE32: 0x10b, PE32+: 0x20b */
    g_optional_header.magic = opt_magic;
    if (opt_magic == 0x10b) {
        g_is_valid_pe = true;
    } else if (opt_magic == 0x20b) {
        /* PE32+ - need to read extended optional header */
        optional_header_64_t opt64 = {0};
        bytes_read = fread(&opt64, 1, sizeof(optional_header_64_t), fp);
        if (bytes_read >= (int)sizeof(optional_header_64_t)) {
            g_optional_header.magic = opt_magic;
            g_is_valid_pe = true;
        }
    } else {
        g_is_valid_pe = false;
    }
    
    return g_is_valid_pe;
}

/* Check if a pattern exists in data */
static bool find_pattern_in_data(const uint8_t *data, int len, 
                                  const uint8_t *pattern, int psize)
{
    for (int i = 0; i <= len - psize; i++) {
        bool match = true;
        for (int j = 0; j < psize && match; j++) {
            if (data[i + j] != pattern[j]) {
                match = false;
            }
        }
        if (match) return true;
    }
    return false;
}

/* Check for UPX detection */
static bool check_upx(const uint8_t *data, int len)
{
    /* Check optional header magic 0x14000000 = "UPX0!" */
    if (len >= 62 && data[0x5C] == 'U' && 
        data[0x5D] == 'P' && data[0x5E] == 'X' && 
        data[0x5F] == '0' && data[0x60] == '!') {
        return true;
    }
    
    /* Check for UPX compression info in optional header */
    if (len >= 82) {
        uint32_t upx_magic = 0;
        memcpy(&upx_magic, &data[0x74], sizeof(uint32_t));
        
        /* Magic 0x14000000 indicates UPX */
        if (upx_magic == 0x14000000) {
            return true;
        }
    }
    
    return false;
}

/* Check for ASPack detection */
static bool check_aspack(const uint8_t *data, int len)
{
    /* Look for ".aspack" section name */
    if (len >= 64) {
        const char *section_names[] = {
            ".text", ".rsrc", ".idata", ".reloc", ".debug",
            ".aspack", ".upx", ".data", ".bss", ".comment"
        };
        
        for (int i = 0; section_names[i][0] != 0; i++) {
            if (!memcmp(&data[0x48 + i * sizeof(section_names[0])], 
                       section_names[i], strlen(section_names[i])) &&
                strcmp(section_names[i], ".text") != 0) {
                return true;
            }
        }
    }
    
    /* Check for "ASPack" string in PE */
    if (len >= 64) {
        const char *search_str = "ASPack";
        for (int i = 0; i <= len - 7; i++) {
            if (!memcmp(&data[i], search_str, 6)) {
                return true;
            }
        }
    }
    
    return false;
}

/* Check for Themida detection */
static bool check_themida(const uint8_t *data, int len)
{
    /* Look for "Themida" string */
    if (len >= 64) {
        const char *search_str = "Themida";
        for (int i = 0; i <= len - 8; i++) {
            if (!memcmp(&data[i], search_str, 7)) {
                return true;
            }
        }
    }
    
    /* Check for VMProtect header patterns */
    if (len >= 64) {
        uint32_t magic = 0;
        memcpy(&magic, &data[0x5C], sizeof(uint32_t));
        
        /* Magic 0x14000000 can also indicate Themida/VMProtect */
        if (magic == 0x14000000) {
            return true;
        }
    }
    
    return false;
}

/* Check for MPRESS detection */
static bool check_mpress(const uint8_t *data, int len)
{
    /* Look for "MPress" string */
    if (len >= 64) {
        const char *search_str = "MPress";
        for (int i = 0; i <= len - 7; i++) {
            if (!memcmp(&data[i], search_str, 6)) {
                return true;
            }
        }
    }
    
    /* Check for MPRESS magic in optional header */
    if (len >= 82) {
        uint32_t upx_magic = 0;
        memcpy(&upx_magic, &data[0x74], sizeof(uint32_t));
        
        /* Magic 0x15000000 indicates MPRESS */
        if (upx_magic == 0x15000000) {
            return true;
        }
    }
    
    return false;
}

/* Check for VMProtect detection */
static bool check_vmprotect(const uint8_t *data, int len)
{
    /* Look for "VMProtect" string */
    if (len >= 64) {
        const char *search_str = "VMProtect";
        for (int i = 0; i <= len - 9; i++) {
            if (!memcmp(&data[i], search_str, 10)) {
                return true;
            }
        }
    }
    
    /* Check for VMProtect header patterns */
    if (len >= 64) {
        uint32_t magic = 0;
        memcpy(&magic, &data[0x5C], sizeof(uint32_t));
        
        /* Magic 0x14000000 can indicate VMProtect */
        if (magic == 0x14000000) {
            return true;
        }
    }
    
    return false;
}

/* Main detection function - returns array of detected packers */
static int detect_packers(const uint8_t *data, int len, 
                          packer_result_t *results)
{
    memset(results, 0, sizeof(packer_result_t) * MAX_PACKERS);
    
    /* Check each known packer */
    if (check_upx(data, len)) {
        results[0].name = "UPX";
        results[0].detected = true;
        results[0].confidence = 95;
        results[0].signature_offset = 0x5C;
    }
    
    if (check_aspack(data, len)) {
        results[1].name = "ASPack";
        results[1].detected = true;
        results[1].confidence = 90;
        results[1].signature_offset = 0x48;
    }
    
    if (check_themida(data, len)) {
        results[2].name = "Themida";
        results[2].detected = true;
        results[2].confidence = 95;
        results[2].signature_offset = 0x5C;
    }
    
    if (check_mpress(data, len)) {
        results[3].name = "MPRESS";
        results[3].detected = true;
        results[3].confidence = 90;
        results[3].signature_offset = 0x74;
    }
    
    if (check_vmprotect(data, len)) {
        results[4].name = "VMProtect";
        results[4].detected = true;
        results[4].confidence = 95;
        results[4].signature_offset = 0x5C;
    }
    
    /* Count detected packers */
    int count = 0;
    for (int i = 0; i < MAX_PACKERS && results[i].name != NULL; i++) {
        if (results[i].detected) {
            count++;
        }
    }
    
    return count;
}

/* Output detection results as JSON */
static void output_json_results(const char *filename, 
                                 const packer_result_t *results,
                                 int count)
{
    FILE *fp = fopen("packpeek_output.json", "w");
    if (!fp) {
        fprintf(stderr, "Warning: Could not open output file\n");
        return;
    }
    
    /* Write JSON header */
    fprintf(fp, "{\n  \"tool\": \"packpeek\",\n  \"version\": \"1.0.0\",\n");
    fprintf(fp, "  \"target\": {\n    \"filename\": \"%s\",\n", 
            filename ? filename : "<unknown>");
    
    /* Write detected packers */
    fprintf(fp, "    \"packers_detected\": [\n");
    for (int i = 0; i < count; i++) {
        if (results[i].name) {
            fprintf(fp, "      {\n");
            fprintf(fp, "        \"name\": \"%s\",\n", results[i].name);
            fprintf(fp, "        \"confidence\": %d,\n", 
                    results[i].confidence);
            fprintf(fp, "        \"signature_offset\": 0x%lx\n", 
                    (unsigned long)results[i].signature_offset);
            fprintf(fp, "      }");
            
            if (i < count - 1) {
                fprintf(fp, ",\n");
            } else {
                fprintf(fp, "\n");
            }
        }
    }
    
    /* Write PE header info */
    fprintf(fp, "    \"pe_info\": {\n");
    if (g_is_valid_pe) {
        fprintf(fp, "      \"is_pe\": true,\n");
        fprintf(fp, "      \"magic\": 0x%x,\n", g_optional_header.magic);
        fprintf(fp, "      \"machine\": %d\n", g_pe_header