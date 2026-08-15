#include <span>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <optional>
#include <stdexcept>
#include <memory>

namespace packpeek {

// ============================================================================
// Constants and Magic Numbers
// ============================================================================

constexpr uint32_t ELF_MAGIC[] = { 0x7f, 'E', 'L', 'F' };
constexpr uint64_t ELF_CLASS_64 = 2;
constexpr uint64_t ELF_CLASS_32 = 1;
constexpr uint64_t ELF_DATA_LITTLE = 1;
constexpr uint64_t ELF_DATA_BIG = 2;

constexpr uint32_t PE_MAGIC[] = { 'M', 'Z' };
constexpr uint32_t PE_NT_SIGNATURE = 0x0000010f;
constexpr uint32_t PE_NT_LITTLE = 0x010b;
constexpr uint364_t PE_NT_BIG = 0x010d;

// ============================================================================
// Utility Functions
// ============================================================================

inline bool is_little_endian(uint8_t const* data) {
    return (data[0] == ELF_MAGIC[0] && 
            data[1] == ELF_MAGIC[1] && 
            data[2] == ELF_MAGIC[2] && 
            data[3] == ELF_MAGIC[3]);
}

inline uint64_t read_u64_le(const uint8_t* ptr) {
    return static_cast<uint64_t>(ptr[0]) |
           (static_cast<uint64_t>(ptr[1]) << 8) |
           (static_cast<uint64_t>(ptr[2]) << 16) |
           (static_cast<uint64_t>(ptr[3]) << 24) |
           (static_cast<uint64_t>(ptr[4]) << 32) |
           (static_cast<uint64_t>(ptr[5]) << 40) |
           (static_cast<uint64_t>(ptr[6]) << 48) |
           (static_cast<uint64_t>(ptr[7]) << 56);
}

inline uint32_t read_u32_le(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

inline uint16_t read_u16_le(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) |
           (static_cast<uint16_t>(ptr[1]) << 8);
}

// ============================================================================
// Entropy Calculation
// ============================================================================

inline double calculate_entropy(std::span<const uint8_t> data) {
    if (data.empty()) return 0.0;

    // Use a sliding window to avoid loading entire file into memory
    constexpr size_t WINDOW_SIZE = 256;
    constexpr size_t STEP = 32;
    
    double total_entropy = 0.0;
    size_t num_windows = (data.size() - WINDOW_SIZE + 1) / STEP;

    for (size_t i = 0; i < num_windows; ++i) {
        std::vector<uint8_t> window(WINDOW_SIZE);
        
        // Copy current window
        for (size_t j = 0; j < WINDOW_SIZE && i * STEP + j < data.size(); ++j) {
            window[j] = data[i * STEP + j];
        }

        // Calculate frequency distribution
        uint32_t freq[256]{};
        for (uint8_t byte : window) {
            freq[byte]++;
        }

        double entropy_sum = 0.0;
        for (int i = 0; i < 256; ++i) {
            if (freq[i] > 0) {
                double p = static_cast<double>(freq[i]) / WINDOW_SIZE;
                entropy_sum -= p * std::log2(p);
            }
        }

        total_entropy += entropy_sum;
    }

    return num_windows > 0 ? total_entropy / num_windows : 0.0;
}

// ============================================================================
// ELF Parser
// ============================================================================

struct ElfHeader {
    bool valid = false;
    uint8_t class_size = 0;
    uint8_t data_encoding = 0;
    uint64_t entry_point = 0;
    std::vector<std::string> sections;
    
    void parse(std::span<const uint8_t> buffer) {
        if (buffer.size() < sizeof(uint32_t)) return;

        // Check magic number
        if (!is_little_endian(buffer.data())) return;

        class_size = read_u16_le(buffer.data());
        data_encoding = read_u16_le(buffer.data() + 4);

        if (class_size != 64 && class_size != 32) {
            valid = false;
            return;
        }

        // Extract entry point
        uint8_t* ehdr_ptr = buffer.data();
        
        if (class_size == 64) {
            // ELF64 header layout
            entry_point = read_u64_le(ehdr_ptr + 0x20);
            
            // Get program headers to find section headers
            uint32_t ph_offset = read_u32_le(ehdr_ptr + 0x1c);
            uint32_t ph_num = read_u32_le(ehdr_ptr + 0x28);
            uint64_t sh_offset = read_u64_le(ehdr_ptr + 0x3a);
            
            if (sh_offset > 0 && buffer.size() >= sh_offset) {
                // Parse section headers
                constexpr size_t ELF64_SH_SIZE = 64;
                for (uint32_t i = 0; i < ph_num; ++i) {
                    uint8_t* sh_ptr = ehdr_ptr + static_cast<size_t>(sh_offset) + 
                                       i * ELF64_SH_SIZE;
                    
                    if (sh_ptr[0] == 1 && sh_ptr[1] == 2) { // SHT_NULL, skip
                        continue;
                    }

                    uint8_t* name_ptr = ehdr_ptr + static_cast<size_t>(sh_ptr[3]);
                    size_t name_len = read_u64_le(sh_ptr + 0x10);
                    
                    if (name_len > 0 && name_ptr) {
                        std::string name;
                        for (size_t j = 0; j < name_len && j < 256; ++j) {
                            name += static_cast<char>(name_ptr[j]);
                        }
                        
                        if (!name.empty()) {
                            sections.push_back(name);
                        }
                    }
                }
            }
        } else {
            // ELF32 header layout
            entry_point = read_u32_le(ehdr_ptr + 0x18);
            
            uint32_t ph_offset = read_u32_le(ehdr_ptr + 0x14);
            uint32_t ph_num = read_u32_le(ehdr_ptr + 0x18);
            uint64_t sh_offset = read_u64_le(ehdr_ptr + 0x2a);
            
            if (sh_offset > 0 && buffer.size() >= sh_offset) {
                constexpr size_t ELF32_SH_SIZE = 40;
                for (uint32_t i = 0; i < ph_num; ++i) {
                    uint8_t* sh_ptr = ehdr_ptr + static_cast<size_t>(sh_offset) + 
                                       i * ELF32_SH_SIZE;
                    
                    if (sh_ptr[0] == 1 && sh_ptr[1] == 2) continue;

                    uint8_t* name_ptr = ehdr_ptr + static_cast<size_t>(sh_ptr[3]);
                    size_t name_len = read_u64_le(sh_ptr + 0x10);
                    
                    if (name_len > 0 && name_ptr) {
                        std::string name;
                        for (size_t j = 0; j < name_len && j < 256; ++j) {
                            name += static_cast<char>(name_ptr[j]);
                        }
                        
                        if (!name.empty()) {
                            sections.push_back(name);
                        }
                    }
                }
            }
        }

        valid = true;
    }
};

// ============================================================================
// PE Parser
// ============================================================================

struct PeHeader {
    bool valid = false;
    uint32_t pe_magic = 0;
    uint64_t entry_point = 0;
    std::vector<std::string> sections;
    
    void parse(std::span<const uint8_t> buffer) {
        if (buffer.size() < 64) return;

        // Check DOS stub magic
        if (!is_little_endian(buffer.data())) return;

        pe_magic = read_u32_le(buffer.data());

        if (pe_magic != 'M' || pe_magic != 'Z') {
            valid = false;
            return;
        }

        // Parse PE header
        uint8_t* pehdr_ptr = buffer.data() + 64;
        
        uint32_t pe_offset = read_u32_le(pehdr_ptr);
        if (pe_offset == 0 || pe_offset > buffer.size()) {
            valid = false;
            return;
        }

        // Check PE signature
        uint8_t* sig_ptr = pehdr_ptr + pe_offset - 64;
        
        if (read_u32_le(sig_ptr) != PE_NT_SIGNATURE) {
            valid = false;
            return;
        }

        // Extract entry point
        uint8_t* opt_hdr = sig_ptr + 0x1c;
        uint32_t opt_size = read_u32_le(opt_hdr);
        
        if (opt_size >= 0x90) {
            uint32_t opt_offset = read_u32_le(opt_hdr + 0x24);
            
            if (opt_offset > 0 && opt_offset < buffer.size()) {
                uint8_t* opt_ptr = sig_ptr + opt_offset - 64;
                
                // Check for PE32+ (x64) vs PE32 (x86)
                uint16_t opt_magic = read_u16_le(opt_ptr);
                
                if (opt_magic == PE_NT_LITTLE || opt_magic == PE_NT_BIG) {
                    entry_point = read_u64_le(opt_ptr + 0x18);
                    
                    // Parse section headers
                    uint32_t sh_offset = read_u32_le(opt_ptr + 0x2c);
                    uint32_t sh_num = read_u32_le(opt_ptr + 0x30);
                    
                    if (sh_offset > 0 && sh_num > 0) {
                        constexpr size_t PE_SH_SIZE = 40;
                        
                        for (uint32_t i = 0; i < sh_num; ++i) {
                            uint8_t* sh_ptr = opt_ptr + static_cast<size_t>(sh_offset) + 
                                               i * PE_SH_SIZE;
                            
                            if (sh_ptr[0] == 1 && sh_ptr[1] == 2) continue;

                            uint8_t* name_ptr = opt_ptr + static_cast<size_t>(sh_ptr[3]);
                            size_t name_len = read_u64_le(sh_ptr + 0x10);
                            
                            if (name_len > 0 && name_ptr) {
                                std::string name;
                                for (size_t j = 0; j < name_len && j < 256; ++j) {
                                    name += static_cast<char>(name_ptr[j]);
                                }
                                
                                if (!name.empty()) {
                                    sections.push_back(name);
                                }
                            }
                        }
                    }
                }
            }
        }

        valid = true;
    }
};

// ============================================================================
// Main Binary Parser
// ============================================================================

struct ParseResult {
    std::string format;
    bool is_valid = false;
    uint64_t entry_point = 0;
    double entropy = 0.0;
    std::vector<std::string> sections;
    std::optional<ElfHeader> elf_header;
    std::optional<PeHeader> pe_header;
};

ParseResult parse_binary(std::span<const uint8_t> buffer) {
    ParseResult result;
    
    if (buffer.empty()) {
        return result;
    }

    // Try ELF first (Linux/Mac/Android)
    ElfHeader elf;
    elf.parse(buffer);
    
    if (elf.valid) {
        result.format = "ELF";
        result.is_valid = true;
        result.entry_point = elf.entry_point;
        result.entropy = calculate_entropy(buffer);
        result.sections = std::move(elf.sections);
        result.elf_header = std::make_optional(std::move(elf));
    }

    // Try PE (Windows) if ELF failed or as fallback
    if (!result.is_valid) {
        PeHeader pe;
        pe.parse(buffer);
        
        if (pe.valid) {
            result.format = "PE";
            result.is_valid = true;
            result.entry_point = pe.entry_point;
            result.entropy = calculate_entropy(buffer);
            result.sections = std::move(pe.sections);
            result.pe_header = std::make_optional(std::move(pe));
        }
    }

    return result;
}

// ============================================================================
// JSON Output (using nlohmann/json)
// ============================================================================

std::string format_json(const ParseResult& result) {
    std::ostringstream oss;
    
    if (!result.is_valid) {
        oss << "{\"format\":\"unknown\",\"valid\":false,\"entry_point\":0,"
            << "\"entropy\":" << std::fixed << std::setprecision(2) 
            << result.entropy << ",\"sections\":[]}";
        return oss.str();
    }

    // Build sections JSON array
    std::vector<std::string> json_sections = result.sections;
    
    oss << "{\"format\":\"" << result.format << "\",\"valid\":" << (result.is_valid ? "true" : "false") 
        << ",\"entry_point\":" << result.entry_point 
        << ",\"entropy\":" << std::fixed << std::setprecision(2) << result.entropy
        << ",\"sections\":[";

    for (size_t i = 0; i < json_sections.size(); ++i) {
        oss << "\"" << json_sections[i] << "\"";
        if (i + 1 < json_sections.size()) oss << ",";
    }

    oss << "]}";
    
    return oss.str();
}

// ============================================================================
// File I/O Wrapper
// ============================================================================

std::optional<std::span<const uint8_t>> load_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    
    if (!file.is_open()) {
        return std::nullopt;
    }

    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    auto buffer = std::make_shared<std::vector<uint8_t>>(size);
    
    if (!file.read(reinterpret_cast<char*>(buffer->data()), size)) {
        return std::nullopt;
    }

    return std::span(buffer->data(), size);
}

// ============================================================================
// Entry Point / Demo
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        // Default: read from stdin
        std::vector<uint8_t> buffer;
        
        uint64_t size = 0;
        while (true) {
            uint32_t chunk_size = 0;
            file.read(reinterpret_cast<char*>(&chunk_size), sizeof(chunk_size));
            
            if (!file || chunk_size == 0) break;
            
            buffer.resize(size + chunk_size);
            file.read(buffer.data() + size, chunk_size);
            size += chunk_size;
        }

        ParseResult result = parse_binary(std::span(buffer));
        std::cout << format_json(result);
    } else {
        // File argument provided
        auto loaded = load_file(argv[1]);
        
        if (!loaded