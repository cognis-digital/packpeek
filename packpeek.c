/* packpeek — static packer / loader fingerprinter (C, C99, stdlib-only)
 * Part of the Cognis Neural Suite. Single-purpose, JSON-out, CI-tested.
 *
 * Format-agnostic triage of a binary: searches for the documented signatures
 * of common runtime packers/protectors (UPX, ASPack, Themida, MPRESS, FSG,
 * PECompact, Petite, NsPack, Enigma, VMProtect, MEW) and measures Shannon
 * entropy. High entropy + a packer marker = a strong "this is packed" signal,
 * the classic first step before deeper malware analysis.
 *
 * Defensive triage only — reads a file, makes no network calls, runs nothing.
 *
 * Usage:
 *   packpeek <file> [--threshold F]
 *     --threshold  entropy (bits, 0..8) above which a file is "high entropy"
 *                  (default 7.2)
 *
 * Output: JSON object on stdout. Exit 2 if packed/likely-packed, 0 if clean,
 *         1 on error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

struct sig { const char *name; const char *bytes; size_t len; };

/* Documented, public packer/protector markers (section names / magic). */
static const struct sig SIGS[] = {
    {"UPX",        "UPX!",      4},
    {"UPX",        "UPX0",      4},
    {"UPX",        "UPX1",      4},
    {"ASPack",     ".aspack",   7},
    {"ASPack",     ".adata",    6},
    {"Themida",    ".themida",  8},
    {"WinLicense", ".winlice",  8},
    {"MPRESS",     ".MPRESS1",  8},
    {"MPRESS",     ".MPRESS2",  8},
    {"PECompact",  "PEC2",      4},
    {"Petite",     ".petite",   7},
    {"FSG",        "FSG!",      4},
    {"MEW",        "MEW",       3},
    {"NsPack",     ".nsp0",     5},
    {"NsPack",     ".nsp1",     5},
    {"Enigma",     ".enigma1",  8},
    {"VMProtect",  ".vmp0",     5},
    {"VMProtect",  ".vmp1",     5},
    {"Armadillo",  "PDATA000",  8},
};
static const size_t NSIGS = sizeof(SIGS) / sizeof(SIGS[0]);

/* Portable memmem (no _GNU_SOURCE dependency). */
static const unsigned char *find(const unsigned char *hay, size_t hn,
                                 const unsigned char *needle, size_t nn) {
    if (nn == 0 || hn < nn) return NULL;
    for (size_t i = 0; i + nn <= hn; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nn) == 0)
            return hay + i;
    return NULL;
}

static double entropy(const unsigned char *buf, size_t n) {
    if (n == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < n; i++) freq[buf[i]]++;
    double h = 0.0;
    for (int b = 0; b < 256; b++) {
        if (!freq[b]) continue;
        double p = (double)freq[b] / (double)n;
        h -= p * log2(p);
    }
    return h;
}

int main(int argc, char **argv) {
    const char *path = NULL;
    double threshold = 7.2;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) threshold = atof(argv[++i]);
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            fprintf(stderr, "usage: packpeek <file> [--threshold F]\n");
            return 0;
        } else if (argv[i][0] != '-') path = argv[i];
    }
    if (!path) { fprintf(stderr, "packpeek: no input file\n"); return 1; }

    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "packpeek: cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); fprintf(stderr, "packpeek: empty/unreadable\n"); return 1; }
    unsigned char *data = malloc((size_t)sz);
    if (!data) { fclose(f); fprintf(stderr, "packpeek: oom\n"); return 1; }
    size_t n = fread(data, 1, (size_t)sz, f);
    fclose(f);

    double h = entropy(data, n);
    int high_entropy = (h >= threshold);

    /* dedupe packer names while preserving first-seen order */
    const char *found[32]; size_t found_off[32]; int nf = 0;
    for (size_t s = 0; s < NSIGS && nf < 32; s++) {
        const unsigned char *p = find(data, n,
            (const unsigned char *)SIGS[s].bytes, SIGS[s].len);
        if (!p) continue;
        int dup = 0;
        for (int k = 0; k < nf; k++)
            if (strcmp(found[k], SIGS[s].name) == 0) { dup = 1; break; }
        if (dup) continue;
        found[nf] = SIGS[s].name;
        found_off[nf] = (size_t)(p - data);
        nf++;
    }

    const char *verdict;
    if (nf > 0 && high_entropy)      verdict = "packed";
    else if (nf > 0 || high_entropy) verdict = "likely-packed";
    else                             verdict = "clean";

    printf("{\"tool\":\"packpeek\",\"file\":\"%s\",\"size\":%zu,"
           "\"entropy\":%.4f,\"high_entropy\":%s,\"threshold\":%.2f,"
           "\"packers\":[", path, n, h, high_entropy ? "true" : "false", threshold);
    for (int k = 0; k < nf; k++)
        printf("%s{\"name\":\"%s\",\"offset\":%zu}", k ? "," : "", found[k], found_off[k]);
    printf("],\"packer_count\":%d,\"verdict\":\"%s\"}\n", nf, verdict);

    free(data);
    return (strcmp(verdict, "clean") == 0) ? 0 : 2;
}
