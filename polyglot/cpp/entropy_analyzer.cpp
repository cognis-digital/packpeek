#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <memory>
#include <filesystem>
#include <numeric>

namespace fs = std::filesystem;

// ============================================================================
// Constants and Type Definitions
// ============================================================================

constexpr uint64_t kMaxFileSizeBytes = 1024 * 1024 * 1024 * 1024ULL; // 1GB max
constexpr double kLog2 = 1.0 / std::log(2.0);
constexpr size_t kDefaultBufferSize = 65536;

// ============================================================================
// Utility: Simple JSON Serializer (No external dependencies)
// ============================================================================

class JsonWriter {
public:
    static std::string escape(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b";  break;
                case '\f': result += "\\f";  break;
                case '\n': result += "\\n";  break;
                case '\r': result += "\\r";  break;
                case '\t': result += "\\t";  break;
                default:   result += c;      break;
            }
        }
        return result;
    }

    static std::string format(double val, int precision = 6) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << val;
        return oss.str();
    }

    static std::string format(uint64_t val) {
        std::ostringstream oss;
        oss << val;
        return oss.str();
    }

    static std::string format(bool val) {
        return val ? "true" : "false";
    }

private:
};

// ============================================================================
// Core: Byte Frequency Counter
// ============================================================================

class ByteFrequencyCounter {
public:
    explicit ByteFrequencyCounter(size_t maxBytes = kMaxFileSizeBytes) 
        : mTotalBytes(maxBytes), mFileOffset(0) {}

    void reset() {
        std::fill(mCounts.begin(), mCounts.end(), 0);
        mTotalBytes = 0;
        mFileOffset = 0;
    }

    size_t readAndCount(const uint8_t* data, size_t len) {
        if (mTotalBytes + len > kMaxFileSizeBytes && !mOverflowed) {
            std::cerr << "Warning: File exceeds maximum size (" 
                      << mTotalBytes << "/" << kMaxFileSizeBytes << " bytes)\n";
            mOverflowed = true;
        }

        for (size_t i = 0; i < len && !mOverflowed; ++i) {
            if (mCounts[data[i]]++ == 0) {
                mNonZeroCount++;
            }
            mTotalBytes++;
        }

        return std::min(mTotalBytes, kMaxFileSizeBytes);
    }

    void setFileOffset(size_t offset) {
        mFileOffset = offset;
    }

    const uint32_t* getCounts() const { return mCounts.data(); }
    size_t getTotalBytes() const { return mTotalBytes; }
    size_t getNonZeroCount() const { return mNonZeroCount; }

private:
    std::array<uint32_t, 256> mCounts{};
    uint64_t mTotalBytes = 0;
    size_t mFileOffset = 0;
    size_t mNonZeroCount = 0;
    bool mOverflowed = false;
};

// ============================================================================
// Core: NIST Entropy Calculator (more robust for small files)
// ============================================================================

class NISTEntropyCalculator {
public:
    static double calculate(const uint32_t* counts, size_t totalBytes) {
        if (totalBytes == 0 || totalBytes > kMaxFileSizeBytes) {
            return -1.0; // Invalid
        }

        double entropy = 0.0;
        for (size_t i = 0; i < 256; ++i) {
            if (counts[i] > 0) {
                double p = static_cast<double>(counts[i]) / totalBytes;
                entropy -= p * std::log(p);
            }
        }

        return entropy;
    }

    // NIST-1: Chi-square test for randomness
    static double chiSquareTest(const uint32_t* counts, size_t totalBytes) {
        if (totalBytes == 0 || totalBytes > kMaxFileSizeBytes) {
            return -1.0;
        }

        double expected = totalBytes / 256.0;
        double chiSquare = 0.0;

        for (size_t i = 0; i < 256; ++i) {
            if (expected > 0) {
                double diff = static_cast<double>(counts[i]) - expected;
                chiSquare += (diff * diff) / expected;
            }
        }

        return chiSquare;
    }

    // NIST-2: Runs test (simplified version)
    static double runsTest(const uint8_t* data, size_t totalBytes) {
        if (totalBytes < 10 || totalBytes > kMaxFileSizeBytes) {
            return -1.0;
        }

        // Count runs and transitions
        int runs = 0;
        bool lastBit = false;
        
        for (size_t i = 0; i < totalBytes && !lastBit; ++i) {
            if ((data[i] & 0x80) != lastBit) {
                runs++;
                lastBit = (data[i] & 0x80);
            }
        }

        // Expected runs for random data
        double expectedRuns = static_cast<double>(totalBytes - 1) / 2.0;
        
        if (expectedRuns > 0) {
            return std::abs(runs - expectedRuns) / expectedRuns;
        }
        return -1.0;
    }

private:
};

// ============================================================================
// Core: Compression Ratio Estimator
// ============================================================================

class CompressionRatioEstimator {
public:
    static double estimate(const uint8_t* data, size_t totalBytes) {
        if (totalBytes == 0 || totalBytes > kMaxFileSizeBytes) {
            return -1.0;
        }

        // Simple Lempel-Ziv-like estimation
        int matches = 0;
        for (size_t i = 256; i < totalBytes && !mOverflowed; ++i) {
            if ((data[i] & 0xFF) == (data[i - 256] & 0xFF)) {
                matches++;
            }
        }

        double compressionRatio = static_cast<double>(matches) / totalBytes;
        return std::min(compressionRatio, 1.0);
    }

private:
    static constexpr size_t kEstimateWindow = 256;
};

// ============================================================================
// Main Analyzer Class
// ============================================================================

class EntropyAnalyzer {
public:
    struct Result {
        std::string filename;
        uint64_t fileSize;
        double shannonEntropy;
        double nistEntropy;
        double chiSquare;
        double runsTest;
        double compressionRatioEstimate;
        size_t nonZeroBytes;
        bool isLikelyPacked;
        
        // Helper: Check if likely packed (entropy > 7.5 and high ratio)
        static bool checkLikelyPacked(double entropy, double chiSquare) {
            return entropy > 7.5 && chiSquare < 100.0;
        }

        Result() : fileSize(0), shannonEntropy(-1.0), nistEntropy(-1.0),
                   chiSquare(-1.0), runsTest(-1.0), compressionRatioEstimate(-1.0),
                   nonZeroBytes(0), isLikelyPacked(false) {}

        Result(const std::string& name, uint64_t size, double ent, 
               double nist, double chiSq, double runs, double compRat)
            : filename(name), fileSize(size), shannonEntropy(ent),
              nistEntropy(nist), chiSquare(chiSq), runsTest(runs),
              compressionRatioEstimate(compRat), isLikelyPacked(false) {}

        void setLikelyPacked(bool val) { isLikelyPacked = val; }
    };

public:
    explicit EntropyAnalyzer(size_t bufferHint = kDefaultBufferSize) 
        : mBuffer(bufferHint), mFileOffset(0) {}

    // Analyze a file (reads in chunks for memory efficiency)
    Result analyze(const fs::path& filepath, size_t bufferSize = 65536);

    // Analyze from raw data buffer
    static Result analyzeFromData(const std::string& name, 
                                  const uint8_t* data, size_t len);

private:
    void readAndAnalyzeFile(const fs::path& filepath, ByteFrequencyCounter& counter);
    
    double calculateShannonEntropy(const uint32_t* counts, size_t totalBytes) {
        if (totalBytes == 0 || totalBytes > kMaxFileSizeBytes) {
            return -1.0;
        }

        double entropy = 0.0;
        for (size_t i = 0; i < 256; ++i) {
            if (counts[i] > 0) {
                double p = static_cast<double>(counts[i]) / totalBytes;
                entropy -= p * std::log(p);
            }
        }

        return entropy;
    }

    void readAndAnalyzeFile(const fs::path& filepath, ByteFrequencyCounter& counter) {
        if (!filepath.exists()) {
            std::cerr << "Error: File not found: " << filepath.string() << "\n";
            return;
        }

        mFileOffset = 0;
        
        // Open file and read in chunks
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file: " << filepath.string() << "\n";
            return;
        }

        uint8_t* chunk = mBuffer.data();
        size_t chunkSize = mBuffer.size();

        while (true) {
            file.read(reinterpret_cast<char*>(chunk), chunkSize);
            auto bytesRead = file.gcount();
            
            if (bytesRead > 0) {
                counter.setFileOffset(mFileOffset + bytesRead - 1);
                counter.readAndCount(chunk, bytesRead);
            }

            mFileOffset += bytesRead;

            if (file.eof() || bytesRead < chunkSize) {
                break;
            }
        }

        file.close();
    }

    static Result analyzeFromData(const std::string& name, 
                                  const uint8_t* data, size_t len) {
        ByteFrequencyCounter counter(len);
        counter.setFileOffset(0);
        
        // Read all at once (small buffer for demo purposes)
        counter.readAndCount(data, len);

        double shannon = calculateShannonEntropy(counter.getCounts(), counter.getTotalBytes());
        double nist = NISTEntropyCalculator::calculate(counter.getCounts(), counter.getTotalBytes());
        double chiSq = NISTEntropyCalculator::chiSquareTest(counter.getCounts(), counter.getTotalBytes());
        double runs = NISTEntropyCalculator::runsTest(data, len);

        Result result(name, counter.getTotalBytes(), shannon, nist, 
                     chiSq, runs, CompressionRatioEstimator::estimate(data, len));

        if (NISTEntropyAnalyzer::checkLikelyPacked(shannon, chiSq)) {
            result.setLikelyPacked(true);
        }

        return result;
    }

private:
    std::array<uint8_t, kDefaultBufferSize> mBuffer{};
    size_t mFileOffset = 0;
};

// ============================================================================
// JSON Output Helper
// ============================================================================

std::string serializeResult(const EntropyAnalyzer::Result& r) {
    std::ostringstream oss;
    
    oss << "{\n";
    oss << "  \"filename\": \"" << JsonWriter::escape(r.filename) << "\",\n";
    oss << "  \"fileSize\": " << JsonWriter::format(r.fileSize) << ",\n";
    oss << "  \"shannonEntropy\": " << JsonWriter::format(r.shannonEntropy, 6) << ",\n";
    oss << "  \"nistEntropy\": " << JsonWriter::format(r.nistEntropy, 6) << ",\n";
    oss << "  \"chiSquare\": " << JsonWriter::format(r.chiSquare, 2) << ",\n";
    oss << "  \"runsTest\": " << JsonWriter::format(r.runsTest, 4) << ",\n";
    oss << "  \"compressionRatioEstimate\": " << JsonWriter::format(r.compressionRatioEstimate, 6) << ",\n";
    oss << "  \"nonZeroBytes\": " << JsonWriter::format(r.nonZeroBytes) << ",\n";
    oss << "  \"isLikelyPacked\": " << JsonWriter::format(r.isLikelyPacked) << "\n";
    oss << "}\n";

    return oss.str();
}

// ============================================================================
// Command Line Interface
// ============================================================================

void printUsage(const char* progName) {
    std::cerr << "Usage: " << progName << " [options] <file>\n\n"
              << "Options:\n"
              << "  -h, --help      Show this help message\n"
              << "  -d, --data      Read from stdin (binary data)\n"
              << "  -o, --output    Output JSON to file instead of stdout\n";
}

int main(int argc, char* argv[]) {
    std::string inputFile;
    bool readFromStdin = false;
    bool outputToFile = false;
    std::string outputFile;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || 
            std::strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]);
            return 0;
        } else if (std::strcmp(argv[i], "-d") == 0 || 
                   std::strcmp(argv[i], "--data") == 0) {
            readFromStdin = true;
        } else if ((std::strcmp(argv[i], "-o") == 0 || 
                   std::strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            outputToFile = true;
            outputFile = argv[++i];
        } else {
            inputFile = argv[i];
        }
    }

    // Process input
    EntropyAnalyzer analyzer;
    EntropyAnalyzer::Result result;

    if (readFromStdin) {
        std::vector<uint8_t> data;
        uint8_t byte;
        
        while (std::cin.get(byte)) {
            data.push_back(byte);
        }

        // Remove null terminator if present
        size_t len = data.size();
        if (len > 0 && data[len - 1] == 0) {
            len--;
        }

        result = EntropyAnalyzer::analyzeFromData("stdin", 
                                                   data.data(), len);
    } else if (!inputFile.empty()) {
        result = analyzer.analyze(inputFile);
    } else {
        std::cerr << "Error: No input file specified\n";
        printUsage(argv[0]);
        return 1;
    }

    // Output results
    std::string output = serializeResult(result);
    
    if (outputToFile) {
        std::ofstream out(outputFile, std::ios::trunc | std::ios::binary);
        if (!out.is_open()) {
            std::cerr << "Error: Could not open output file: " << outputFile << "\n";
            return 1;
        }
        
        // Write as JSON text (not binary)
        out.write(output.c_str(), output.length());
        out.close();
    } else {
        std::cout << output;
    }

    // Print summary