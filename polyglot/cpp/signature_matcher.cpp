#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <memory>
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

// ============================================================================
// Configuration and Constants
// ============================================================================

constexpr size_t DEFAULT_BUFFER_SIZE = 1024 * 1024; // 1MB chunks
constexpr double ENTROPY_THRESHOLD_PACKED = 7.5;      // High entropy = likely packed
constexpr int MATCH_WINDOW = 64;                      // Context for signature matching

// ============================================================================
// Data Structures
// ============================================================================

struct Signature {
    std::string name;
    std::vector<uint8_t> data;
    size_t min_length = 0;
    bool case_sensitive = true;
    
    bool matches(const uint8_t* buffer, size_t offset) const {
        if (offset + data.size() > buffer_size(buffer)) return false;
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (!case_sensitive && std::isalpha(data[i])) {
                uint8_t c = static_cast<uint8_t>(std::tolower(data[i]));
                if (buffer[offset + i] != c) return false;
            } else if (data[i] != buffer[offset + i]) {
                return false;
            }
        }
        return true;
    }
};

struct MatchResult {
    std::string signature_name;
    size_t offset;
    double entropy = 0.0;
    bool is_packed_region;
    
    nlohmann::json to_json() const {
        return {
            {"name", name},
            {"offset", static_cast<uint64_t>(offset)},
            {"entropy", entropy},
            {"is_packed", is_packed_region}
        };
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

inline size_t buffer_size(const uint8_t* buf) {
    return static_cast<size_t>(buf[0] | (buf[1] << 8) | 
                              (buf[2] << 16) | (buf[3] << 24));
}

inline std::string hex_dump(const uint8_t* data, size_t len, int width = 16) {
    std::ostringstream oss;
    for (size_t i = 0; i < len && i < static_cast<size_t>(width); ++i) {
        if (i > 0 && i % width == 0) oss << "\n";
        oss << std::setw(2) << std::setfill('0') << std::hex 
            << static_cast<int>(data[i]) << " ";
    }
    return oss.str();
}

// ============================================================================
// Entropy Analyzer - Detects compressed/encrypted regions
// ============================================================================

class EntropyAnalyzer {
public:
    static double calculate_entropy(const uint8_t* data, size_t len) {
        if (len == 0) return 0.0;
        
        // Count byte frequencies
        std::vector<uint32_t> freq(256, 0);
        for (size_t i = 0; i < len; ++i) {
            freq[data[i]]++;
        }
        
        double entropy = 0.0;
        double total = static_cast<double>(len);
        for (uint32_t count : freq) {
            if (count > 0) {
                double p = static_cast<double>(count) / total;
                entropy -= p * std::log2(p);
            }
        }
        
        return entropy;
    }
    
    static bool is_high_entropy(const uint8_t* data, size_t len) {
        if (len < 64) return false;
        double e = calculate_entropy(data, len);
        return e > ENTROPY_THRESHOLD_PACKED;
    }
};

// ============================================================================
// Signature Matcher - Core matching engine
// ============================================================================

class SignatureMatcher {
private:
    std::vector<Signature> signatures;
    
public:
    void add_signature(const Signature& sig) {
        signatures.push_back(sig);
    }
    
    // Scan entire buffer for all signatures
    std::vector<MatchResult> scan(const uint8_t* data, size_t size) {
        std::vector<MatchResult> results;
        
        // Sort by length (longest first) - better cache locality
        auto sorted = signatures;
        std::sort(sorted.begin(), sorted.end(), 
                  [](const Signature& a, const Signature& b) {
                      return a.data.size() > b.data.size();
                  });
        
        for (auto& sig : sorted) {
            // Use string_view-like behavior without copying
            auto it = std::find(data, data + size - sig.min_length, 
                               static_cast<uint8_t>(sig.data[0]));
            
            while (it != data + size - sig.min_length) {
                if (sig.matches(data, static_cast<size_t>(it - data))) {
                    results.push_back({sig.name, it - data});
                    // Skip ahead to avoid overlapping matches for same signature
                    it += std::max(sig.data.size(), 1);
                } else {
                    ++it;
                }
            }
        }
        
        return results;
    }
    
    // Scan with context window (for more reliable detection)
    std::vector<MatchResult> scan_with_context(const uint8_t* data, size_t size) {
        auto results = scan(data, size);
        
        for (auto& match : results) {
            // Check entropy around the match
            size_t start = std::max(0LL, static_cast<long long>(match.offset) - 32);
            size_t end = std::min(size, 
                                  static_cast<size_t>(match.offset + 64));
            
            double e = EntropyAnalyzer::calculate_entropy(data, end - start);
            match.entropy = e;
            match.is_packed_region = e > ENTROPY_THRESHOLD_PACKED;
        }
        
        return results;
    }
};

// ============================================================================
// Output Formatters
// ============================================================================

class OutputFormatter {
public:
    static std::string format_json(const std::vector<MatchResult>& matches, 
                                   const uint8_t* data, size_t size) {
        nlohmann::json root;
        
        // Summary
        root["summary"] = {
            {"total_matches", static_cast<uint64_t>(matches.size())},
            {"file_size", static_cast<uint64_t>(size)},
            {"high_entropy_regions", count_high_entropy(matches, data, size)}
        };
        
        // Detailed matches
        root["matches"] = nlohmann::json::array();
        for (const auto& m : matches) {
            root["matches"].push_back(m.to_json());
        }
        
        return root.dump(2);
    }
    
private:
    static int count_high_entropy(const std::vector<MatchResult>& matches,
                                  const uint8_t* data, size_t size) {
        int count = 0;
        for (const auto& m : matches) {
            if (m.entropy > ENTROPY_THRESHOLD_PACKED) {
                ++count;
            }
        }
        return count;
    }
};

// ============================================================================
// File I/O Handler
// ============================================================================

class FileReader {
public:
    static std::vector<uint8_t> read_file(const fs::path& path, 
                                          size_t chunk_size = DEFAULT_BUFFER_SIZE) {
        if (!fs::exists(path)) {
            throw std::runtime_error("File not found: " + path.string());
        }
        
        auto file_size = fs::file_size(path);
        if (file_size == 0) return {};
        
        std::vector<uint8_t> buffer(file_size);
        
        // Read in chunks for large files
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + path.string());
        }
        
        size_t offset = 0;
        while (offset < file_size) {
            size_t chunk_len = std::min(chunk_size, file_size - offset);
            file.read(reinterpret_cast<char*>(buffer.data() + offset), 
                      static_cast<std::streamsize>(chunk_len));
            if (!file.gcount()) break;
            offset += chunk_len;
        }
        
        return buffer;
    }
    
    static std::vector<uint8_t> read_from_stream(std::istream& stream,
                                                  size_t expected_size) {
        std::vector<uint8_t> buffer(expected_size);
        if (expected_size > 0) {
            stream.read(reinterpret_cast<char*>(buffer.data()), 
                        static_cast<std::streamsize>(expected_size));
        }
        return buffer;
    }
};

// ============================================================================
// Main Engine - Orchestrates the matching process
// ============================================================================

class PackPeekEngine {
private:
    SignatureMatcher matcher;
    
public:
    void load_signatures() {
        // Default signatures for common packers
        add_packer_signature("UPX", "UPX0!", 5);
        add_packer_signature("ASPack", "ASPack", 6);
        add_packer_signature("Themida", "Themida", 7);
        add_packer_signature("MPRESS", "MPRESS", 6);
        add_packer_signature("VMProtect", "VMProtect", 10);
        
        // Common loader signatures
        add_loader_signature("PE Loader", "\x4d\x5a", 2); // MZ header check
        
        // Entropy-based detection (no specific signature needed)
    }
    
    void add_packer_signature(const std::string& name, 
                             const std::vector<uint8_t>& data,
                             size_t min_len = 0) {
        matcher.add_signature({name, data, min_len});
    }
    
    void add_loader_signature(const std::string& name,
                            const std::vector<uint8_t>& data,
                            size_t min_len = 0) {
        matcher.add_signature({name, data, min_len});
    }
    
    // Main analysis function
    std::pair<std::vector<MatchResult>, double> analyze(
            const fs::path& filepath, 
            bool verbose = false) {
        
        auto buffer = FileReader::read_file(filepath);
        if (buffer.empty()) {
            return {{}, 0.0};
        }
        
        // Calculate overall entropy for context
        double file_entropy = EntropyAnalyzer::calculate_entropy(
            buffer.data(), buffer.size());
        
        // Scan with context window
        auto matches = matcher.scan_with_context(buffer.data(), 
                                                 static_cast<size_t>(buffer.size()));
        
        if (verbose) {
            std::cout << "File: " << filepath.filename().string() << "\n";
            std::cout << "Size: " << buffer.size() << " bytes\n";
            std::cout << "Overall entropy: " << file_entropy << "\n";
            std::cout << "Matches found: " << matches.size() << "\n";
        }
        
        return {matches, file_entropy};
    }
    
    // Get formatted output
    std::string get_output(const fs::path& filepath) {
        auto [matches, entropy] = analyze(filepath);
        return OutputFormatter::format_json(matches, 
                                            matches.empty() ? nullptr : 
                                            reinterpret_cast<const uint8_t*>(
                                                /* would need buffer here */
                                                0), 0);
    }
};

// ============================================================================
// Default Signatures Database (Embedded)
// ============================================================================

namespace {

struct DefaultSignatures {
    // UPX variants
    Signature upx_1 = {"UPX 1.0", {'U', 'P', 'X', '0', '!', 0, 1, 5}};
    Signature upx_2 = {"UPX 2.0", {'U', 'P', 'X', '0', '!', 0, 1, 6}};
    
    // ASPack variants  
    Signature aspack_1 = {"ASPack v3.0", {'A', 'S', 'P', 'a', 'c', 'k'}};
    Signature aspack_2 = {"ASPack v4.0", {'A', 'S', 'P', 'a', 'c', 'k', 0, 1, 7}};
    
    // Themida
    Signature themida_1 = {"Themida", {'T', 'h', 'e', 'm', 'i', 'd', 'a'}};
    Signature themida_2 = {"Themida v8.0", {'T', 'h', 'e', 'm', 'i', 'd', 'a', 0, 1, 9}};
    
    // MPRESS
    Signature mpress_1 = {"MPRESS", {'M', 'P', 'R', 'E', 'S', 'S'}};
    Signature mpress_2 = {"MPRESS v3.0", {'M', 'P', 'R', 'E', 'S', 'S', 0, 1, 7}};
    
    // VMProtect
    Signature vmprotect_1 = {"VMProtect", {'V', 'M', 'P', 'r', 'o', 't', 'e', 'c', 't'}};
    Signature vmprotect_2 = {"VMProtect v9.0", {'V', 'M', 'P', 'r', 'o', 't', 'e', 'c', 't', 0, 1, 10}};
    
    // Common PE headers (for context)
    Signature pe_mz = {"PE MZ Header", {'M', 'Z'}};
    Signature pe_pe = {"PE Header", {'P', 'E'}};
    
    // Common strings that indicate packing
    Signature packed_strings_1 = {"packed", {'p', 'a', 'c', 'k', 'e', 'd'}};
    Signature packed_strings_2 = {"compressed", {'c', 'o', 'm', 'p', 'r', 'e', 's', 's', 'e', 'd'}};
    
};

} // anonymous namespace

// ============================================================================
// Command Line Interface
// ============================================================================

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [OPTIONS] <FILE>\n\n"
              << "Options:\n"
              << "  -v, --verbose   Show detailed output\n"
              << "  -j, --json      Output as JSON (default)\n"
              << "  -e, --entropy   Calculate and show entropy values\n"
              << "  -h, --help      Show this help message\n\n"
              << "Examples:\n"
              << "  " << program << " file.exe\n"
              << "  " << program << " -v file.exe\n"
              << "  " << program << " -j output.json file.exe\n";
}

int main(int argc, char* argv[]) {
    std::string filepath;
    bool verbose = false;
    bool json_output = true;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if ((arg == "-v" || arg == "--verbose") && i + 1 < argc) {
            verbose = true;
            filepath = argv[++i];
        } else if (arg == "-j" || arg == "--json") {
            json_output = true;
            if (i + 1 < argc) filepath = argv[++i];
        } else if (arg == "-e" || arg == "--entropy") {
            verbose = true; // Entropy implies verbose
            if (i + 1 < argc) filepath = argv[++i];
        } else if (!filepath.empty()) {
            filepath = arg;
        }
    }
    
    if (filepath.empty()) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Initialize engine with default signatures
    PackPeekEngine engine;
    engine.load_signatures();
    
    // Perform analysis
    auto [matches, entropy] = engine.analyze(filepath, verbose);
    
    // Output results
    if (json