/* polyglot/c/entropy_analyzer.c
 * 
 * Complete entropy analyzer for packer/loader fingerprinting.
 * Supports memory, file, and stream sources with JSON/SARIF output.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define MAX_BYTES 1024 * 1024 * 1024    /* 1GB max per analysis */
#define CHUNK_SIZE 4096                  /* Read chunk size for files */
#define FREQUENCY_TABLE_SIZE 256         /* Byte frequency table */

/* ============================================================================
 * Data structures
 */

typedef struct {
    uint8_t bytes[FREQUENCY_TABLE_SIZE];
    uint64_t total;
} FrequencyTable;

typedef struct {
    double entropy;
    uint64_t byte_count;
    double max_freq_ratio;  /* Most common / average frequency */
    char source[256];
    time_t timestamp;
} EntropyResult;

/* ============================================================================
 * Utility functions
 */

static inline int is_zero(double x) {
    return x == 0.0 || fabs(x) < 1e-30;
}

static inline double clamp(double x, double min_val, double max_val) {
    if (x < min_val) return min_val;
    if (x > max_val) return max_val;
    return x;
}

/* ============================================================================
 * Entropy calculation - Shannon entropy with fixed-point precision
 */

static void calculate_entropy(const FrequencyTable *freq, double *entropy_out, 
                              uint64_t *byte_count_out, double *max_ratio_out) {
    if (is_zero(freq->total)) {
        *entropy_out = 0.0;
        *byte_count_out = 0;
        *max_ratio_out = 0.0;
        return;
    }

    uint64_t total = freq->total;
    double max_freq = 0.0;
    double sum_p_log_p = 0.0;
    
    for (int i = 0; i < FREQUENCY_TABLE_SIZE; i++) {
        if (freq->bytes[i] > 0) {
            double p = (double)freq->bytes[i] / total;
            max_freq = fmax(max_freq, p);
            sum_p_log_p += p * log2(p);
        }
    }

    /* Shannon entropy: H = -Σ(p * log2(p)) */
    *entropy_out = -sum_p_log_p;
    *byte_count_out = total;
    
    /* Max frequency ratio (heuristic for packer detection) */
    double avg_freq = (double)total / FREQUENCY_TABLE_SIZE;
    if (avg_freq > 0.0) {
        *max_ratio_out = max_freq / avg_freq;
    } else {
        *max_ratio_out = 0.0;
    }
}

/* ============================================================================
 * Frequency table initialization and reset
 */

static void freq_init(FrequencyTable *freq) {
    memset(freq->bytes, 0, sizeof(freq->bytes));
    freq->total = 0;
}

static void freq_add(FrequencyTable *freq, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len && freq->total < MAX_BYTES; i++) {
        freq->bytes[data[i]]++;
        freq->total++;
    }
}

static void freq_reset(FrequencyTable *freq) {
    memset(freq, 0, sizeof(*freq));
}

/* ============================================================================
 * Source: File (with streaming for large files)
 */

static int analyze_file(const char *path, EntropyResult *result) {
    result->byte_count = 0;
    result->entropy = 0.0;
    result->max_freq_ratio = 0.0;
    
    if (strlen(path) == 0 || path[0] == '\0') {
        strcpy(result->source, "empty");
        return -1;
    }

    /* Check file size first */
    struct stat st;
    if (stat(path, &st) < 0) {
        strcpy(result->source, strerror(errno));
        result->entropy = -1.0;  /* Error indicator */
        return -2;
    }

    uint64_t file_size = (uint64_t)st.st_size;
    
    if (file_size == 0) {
        strcpy(result->source, "empty");
        result->entropy = 0.0;
        return 1;
    }

    /* Handle very large files */
    if (file_size > MAX_BYTES) {
        strcpy(result->source, "truncated_large_file");
        
        /* Sample first and last 256KB for entropy estimate */
        uint8_t sample[CHUNK_SIZE * 4];
        int fd = open(path, O_RDONLY);
        
        if (fd < 0) {
            strcpy(result->source, strerror(errno));
            result->entropy = -1.0;
            return -2;
        }

        /* Read first chunk */
        size_t read_len = fread(sample, 1, CHUNK_SIZE * 4, fd);
        freq_init(&result->bytes);
        
        if (read_len > 0) {
            freq_add(&result->bytes, sample, read_len);
        }

        /* Read last chunk */
        lseek(fd, file_size - CHUNK_SIZE * 4, SEEK_SET);
        read_len = fread(sample, 1, CHUNK_SIZE * 4, fd);
        
        if (read_len > 0) {
            freq_add(&result->bytes, sample, read_len);
        }

        close(fd);
    } else {
        /* Normal file analysis */
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            strcpy(result->source, strerror(errno));
            result->entropy = -1.0;
            return -2;
        }

        freq_init(&result->bytes);
        
        /* Stream through file */
        uint8_t buffer[CHUNK_SIZE];
        ssize_t nread;
        while ((nread = read(fd, buffer, CHUNK_SIZE)) > 0) {
            if (result->byte_count >= MAX_BYTES) break;
            freq_add(&result->bytes, buffer, nread);
        }

        close(fd);
    }

    /* Calculate entropy */
    double ent, max_r;
    calculate_entropy(&result->bytes, &ent, &result->byte_count, &max_r);
    result->entropy = ent;
    result->max_freq_ratio = max_r;
    
    snprintf(result->source, sizeof(result->source), "file:%s", path);
    result->timestamp = time(NULL);

    return 1;
}

/* ============================================================================
 * Source: Memory buffer
 */

static int analyze_memory(const void *data, size_t len, EntropyResult *result) {
    if (len == 0 || data == NULL) {
        strcpy(result->source, "empty");
        result->entropy = 0.0;
        return 1;
    }

    freq_init(&result->bytes);
    freq_add(&result->bytes, (const uint8_t *)data, len);

    double ent, max_r;
    calculate_entropy(&result->bytes, &ent, &result->byte_count, &max_r);
    
    result->entropy = ent;
    result->max_freq_ratio = max_r;
    snprintf(result->source, sizeof(result->source), "memory:%zu bytes", len);
    result->timestamp = time(NULL);

    return 1;
}

/* ============================================================================
 * Source: STDIN (for piped input)
 */

static int analyze_stdin(EntropyResult *result) {
    freq_init(&result->bytes);
    
    uint8_t buffer[CHUNK_SIZE];
    ssize_t nread;
    while ((nread = read(STDIN_FILENO, buffer, CHUNK_SIZE)) > 0) {
        if (result->byte_count >= MAX_BYTES) break;
        freq_add(&result->bytes, buffer, nread);
    }

    double ent, max_r;
    calculate_entropy(&result->bytes, &ent, &result->byte_count, &max_r);
    
    result->entropy = ent;
    result->max_freq_ratio = max_r;
    strcpy(result->source, "stdin");
    result->timestamp = time(NULL);

    return 1;
}

/* ============================================================================
 * Source: Stream (file descriptor)
 */

static int analyze_stream(int fd, EntropyResult *result) {
    if (fd < 0) {
        strcpy(result->source, "invalid_fd");
        result->entropy = -1.0;
        return -2;
    }

    freq_init(&result->bytes);
    
    uint8_t buffer[CHUNK_SIZE];
    ssize_t nread;
    while ((nread = read(fd, buffer, CHUNK_SIZE)) > 0) {
        if (result->byte_count >= MAX_BYTES) break;
        freq_add(&result->bytes, buffer, nread);
    }

    double ent, max_r;
    calculate_entropy(&result->bytes, &ent, &result->byte_count, &max_r);
    
    result->entropy = ent;
    result->max_freq_ratio = max_r;
    snprintf(result->source, sizeof(result->source), "stream:fd=%d", fd);
    result->timestamp = time(NULL);

    return 1;
}

/* ============================================================================
 * Output: JSON format (for CI/automation)
 */

static void output_json(const EntropyResult *result, FILE *out) {
    double ent = is_zero(result->entropy) ? 0.0 : result->entropy;
    
    fprintf(out, "{\n");
    fprintf(out, "  \"source\": \"%s\",\n", result->source);
    fprintf(out, "  \"byte_count\": %lu,\n", (unsigned long)result->byte_count);
    fprintf(out, "  \"entropy\": %.6f,\n", ent);
    
    /* Packery heuristic: high entropy + low max_ratio = likely packed */
    double packer_score;
    if (result->max_freq_ratio > 0.1 && result->entropy < 4.5) {
        packer_score = (result->max_freq_ratio - 0.1) * 10.0;
    } else {
        packer_score = is_zero(ent) ? 0.0 : ent / 8.0;
    }
    
    fprintf(out, "  \"packer_heuristic\": %.2f,\n", packer_score);
    fprintf(out, "  \"timestamp\": %ld\n", (long)result->timestamp);
    fprintf(out, "}\n");
}

/* ============================================================================
 * Output: SARIF format (for IDE/CI tooling like GitHub Actions)
 */

static void output_sarif(const EntropyResult *result, FILE *out, 
                         const char *run_id, const char *tool_name) {
    double ent = is_zero(result->entropy) ? 0.0 : result->entropy;
    
    fprintf(out, "{\n");
    fprintf(out, "  \"$schema\": \"https://schemastore.azure.com/2.1.0/schema.sarif\",\n");
    fprintf(out, "  \"version\": \"2.1.0\",\n");
    fprintf(out, "  \"runs\": [\n");
    fprintf(out, "    {\n");
    fprintf(out, "      \"tool\": {\n");
    fprintf(out, "        \"driver\": {\n");
    fprintf(out, "          \"name\": \"%s\",\n", tool_name);
    fprintf(out, "          \"version\": \"1.0.0\",\n");
    fprintf(out, "          \"informationUri\": \"https://github.com/packpeek/entropy-analyzer\"\n");
    fprintf(out, "        }\n");
    fprintf(out, "      },\n");
    fprintf(out, "      \"results\": [\n");
    
    /* Determine rule ID based on entropy level */
    const char *rule_id;
    if (ent < 1.0) {
        rule_id = "Entropy.LOW";
    } else if (ent < 4.0) {
        rule_id = "Entropy.MEDIUM";
    } else {
        rule_id = "Entropy.HIGH";
    }

    fprintf(out, "        {\n");
    fprintf(out, "          \"ruleId\": \"%s\",\n", rule_id);
    fprintf(out, "          \"name\": \"Packer Heuristic Check\",\n");
    fprintf(out, "          \"message\": {\n");
    fprintf(out, "            \"text\": \"Entropy: %.6f\", \n", ent);
    fprintf(out, "            \"arguments\": [\n");
    fprintf(out, "              {\"id\": 1, \"value\": %.6f}\n", ent);
    fprintf(out, "            ]\n");
    fprintf(out, "          },\n");
    
    /* Determine level based on packer heuristic */
    double ph = result->packer_heuristic;
    const char *level;
    if (ph > 5.0) {
        level = "error";
    } else if (ph > 2.0) {
        level = "warning";
    } else {
        level = "note";
    }

    fprintf(out, "          \"level\": \"%s\",\n", level);
    
    /* Create a virtual location for the source */
    char loc[512];
    snprintf(loc, sizeof(loc), 
             "{\n"
             "  \"$id\": \"entropy-%ld\",\n"
             "  \"uri\": \"file://%s\",\n"
             "  \"region\": {\n"
             "    \"startLine\": 1,\n"
             "    \"endLine\": %lu\n"
             "  }\n"
             "}", 
             (long)result->timestamp, result->source, 
             (unsigned long)(result->byte_count / CHUNK_SIZE + 1));

    fprintf(out, "          \"locations\": [\n");
    fprintf(out, "            {\n");
    fprintf(out, "              \"physicalLocation\": %s\n", loc);
    fprintf(out, "            }\n");
    fprintf(out, "          ],\n");
    
    /* Add properties for detailed analysis */
    fprintf(out, "          \"properties\": {\n");
    fprintf(out, "            \"entropy\": %.6f,\n", ent);
    fprintf(out, "            \"byte_count\": %lu,\n", (unsigned long)result->byte_count);
    fprintf(out, "            \"max_freq_ratio\": %.6f\n", result->max_freq_ratio);
    fprintf(out, "          },\n");

    fprintf(out, "          \"kind\": \"detection\",\n");
    fprintf(out, "          \"semanticVersion\": \"2.1.0\"\n");
    fprintf(out, "        }\n");
    
    fprintf(out, "      ]\n");
    fprintf(out, "    }\n");
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

/* ============================================================================
 * Output: Human-readable summary
 */

static void output_summary(const EntropyResult *result) {
    printf("=== ENTROPY ANALYSIS SUMMARY ===\n\n");
    
    double ent = is_zero(result->entropy) ? 0.0 : result->entropy;
    uint64_t bytes = result->byte_count;
    
    /* Format byte count */
    const char *size_unit = "B";
    if (bytes >= 1024) { size_unit = "KB"; bytes /= 1024; }
    else if (bytes >= 1048576) { size_unit = "MB"; bytes /= 1048576; }
    else if (bytes >= 1073741824) { size_unit = "GB"; bytes /= 1073741824; }

    printf("Source:     %s\n", result->source);
    printf("Size:       %.2f %s\n", (double)bytes, size_unit);
    printf("Entropy:    %.6f bits/byte\n", ent);
    printf("Max Ratio:  %.4f\n", result->max_freq_ratio);
    
    /* Interpretation */
    printf("\n--- INTERPRETATION ---\n");
    
    if (is_zero(ent)) {
        printf("  [INFO]   Empty or single-byte input\n");
    } else if (ent < 1.0) {
        printf("  [LOW]    Very low entropy - likely repetitive data, header, or stub\n");
    } else if (ent < 2.5) {
        printf("  [MEDIUM] Moderate entropy - normal executable or mixed content\n");
    } else if (ent < 4.0) {
        printf("  [HIGH]   High entropy - compressed, encrypted, or packed data\n");
    } else {