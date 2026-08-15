package polyglot.java;

import java.io.*;
import java.nio.channels.Channels;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Entropy Analyzer for packpeek tool.
 * Calculates Shannon entropy of binary data to detect potential packing/compression.
 */
public class EntropyAnalyzer {

    private static final int DEFAULT_CHUNK_SIZE = 65536;
    private static final double HIGH_ENTROPY_THRESHOLD = 7.5;
    private static final int HEADER_SIZE = 256;

    public record AnalysisResult(
        String fileName,
        long fileSize,
        double totalEntropy,
        double headerEntropy,
        double bodyEntropy,
        boolean likelyPacked,
        Map<String, Object> metadata
    ) {}

    /**
     * Main analysis entry point.
     */
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println("Usage: java polyglot.java.EntropyAnalyzer <file1> [file2 ...]");
            System.out.println("Output: JSON to stdout or file specified as last arg.");
            return;
        }

        String output = null;
        if (args.length > 0 && args[args.length - 1].endsWith(".json")) {
            output = args[args.length - 1];
            Arrays.stream(args).limit(args.length - 1).forEach(EntropyAnalyzer::analyzeFile);
        } else {
            System.out.println("=== PACKPEEK ENTROPY ANALYZER ===\n");
            Arrays.stream(args).forEach(EntropyAnalyzer::analyzeFile);
        }

        if (output != null) {
            Files.writeString(Path.of(output), output);
            System.out.println("JSON written to: " + output);
        } else {
            System.out.println("\n=== JSON OUTPUT ===");
            System.out.println(output);
        }
    }

    /**
     * Analyze a single file and print results.
     */
    public static void analyzeFile(String path) throws IOException {
        Path p = Path.of(path);
        if (!Files.exists(p)) {
            System.err.println("Warning: File not found - " + path);
            return;
        }

        long fileSize = Files.size(p);
        double totalEntropy = calculateEntropy(p, DEFAULT_CHUNK_SIZE);
        double headerEntropy = 0.0;
        double bodyEntropy = 0.0;

        if (fileSize > HEADER_SIZE) {
            byte[] headerBytes = Files.readAllBytes(Paths.get(path).subpath(0, HEADER_SIZE));
            headerEntropy = calculateEntropyFromBytes(headerBytes);
            
            byte[] bodyBytes = Files.readAllBytes(Paths.get(path).subpath(HEADER_SIZE, fileSize));
            bodyEntropy = calculateEntropyFromBytes(bodyBytes);
        } else {
            headerEntropy = totalEntropy;
            bodyEntropy = 0.0;
        }

        boolean likelyPacked = totalEntropy > HIGH_ENTROPY_THRESHOLD || 
                              (fileSize > HEADER_SIZE && Math.abs(totalEntropy - bodyEntropy) > 1.5);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("header_entropy", headerEntropy);
        metadata.put("body_entropy", bodyEntropy);
        metadata.put("entropy_diff", totalEntropy - bodyEntropy);
        metadata.put("likely_packed", likelyPacked);

        System.out.println(String.format(
            "File: %-40s | Size: %12d bytes | Total Entropy: %.4f | Header: %.4f | Body: %.4f | Packed: %s",
            p.getFileName(), fileSize, totalEntropy, headerEntropy, bodyEntropy, likelyPacked
        ));

        AnalysisResult result = new AnalysisResult(
            p.getFileName().toString(),
            fileSize,
            totalEntropy,
            headerEntropy,
            bodyEntropy,
            likelyPacked,
            metadata
        );

        System.out.println(String.format("  JSON: {\"file\":\"%s\",\"size\":%d,\"entropy\":%.4f,\"packed\":%b}",
            result.fileName(), (int)result.fileSize(), Math.round(result.totalEntropy * 100.0) / 100.0, result.likelyPacked()));

        return result;
    }

    /**
     * Calculate Shannon entropy from a byte array.
     */
    public static double calculateEntropyFromBytes(byte[] data) {
        if (data.length == 0) return 0.0;

        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }

        double entropy = 0.0;
        long total = data.length;
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / total;
                entropy -= p * Math.log(p) / Math.log(2);
            }
        }

        return entropy;
    }

    /**
     * Calculate entropy from a file using chunked reading.
     */
    public static double calculateEntropy(Path path, int chunkSize) throws IOException {
        if (!Files.exists(path)) return 0.0;

        long fileSize = Files.size(path);
        if (fileSize == 0) return 0.0;

        int[] freq = new int[256];
        try (InputStream is = Files.newInputStream(path)) {
            byte[] buffer = new byte[chunkSize];
            while (is.read(buffer, 0, chunkSize) > 0) {
                for (byte b : buffer) {
                    freq[b & 0xFF]++;
                }
            }
        }

        double entropy = 0.0;
        long total = fileSize;
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / total;
                entropy -= p * Math.log(p) / Math.log(2);
            }
        }

        return entropy;
    }

    /**
     * Analyze multiple files and aggregate results.
     */
    public static List<AnalysisResult> analyzeBatch(String... paths) throws IOException {
        List<AnalysisResult> results = new ArrayList<>();
        for (String path : paths) {
            try {
                results.add(analyzeFileToResult(Path.of(path)));
            } catch (Exception e) {
                System.err.println("Error analyzing " + path + ": " + e.getMessage());
                AnalysisResult errorResult = new AnalysisResult(
                    path, 0, -1.0, -1.0, -1.0, false,
                    Map.of("error", e.getClass().getSimpleName())
                );
                results.add(errorResult);
            }
        }
        return results;
    }

    /**
     * Analyze a single file and return result object (for JSON serialization).
     */
    public static AnalysisResult analyzeFileToResult(Path path) throws IOException {
        long fileSize = Files.size(path);
        double totalEntropy = calculateEntropy(path, DEFAULT_CHUNK_SIZE);
        
        double headerEntropy = 0.0;
        double bodyEntropy = 0.0;

        if (fileSize > HEADER_SIZE) {
            byte[] headerBytes = Files.readAllBytes(Paths.get(path).subpath(0, HEADER_SIZE));
            headerEntropy = calculateEntropyFromBytes(headerBytes);
            
            byte[] bodyBytes = Files.readAllBytes(Paths.get(path).subpath(HEADER_SIZE, fileSize));
            bodyEntropy = calculateEntropyFromBytes(bodyBytes);
        } else {
            headerEntropy = totalEntropy;
            bodyEntropy = 0.0;
        }

        boolean likelyPacked = totalEntropy > HIGH_ENTROPY_THRESHOLD || 
                              (fileSize > HEADER_SIZE && Math.abs(totalEntropy - bodyEntropy) > 1.5);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("header_entropy", headerEntropy);
        metadata.put("body_entropy", bodyEntropy);
        metadata.put("entropy_diff", totalEntropy - bodyEntropy);
        metadata.put("likely_packed", likelyPacked);

        return new AnalysisResult(
            path.getFileName().toString(),
            fileSize,
            totalEntropy,
            headerEntropy,
            bodyEntropy,
            likelyPacked,
            metadata
        );
    }

    /**
     * Generate a compact JSON string from results.
     */
    public static String toJson(AnalysisResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"file\":\"").append(result.fileName()).append("\",");
        sb.append("\"size\":").append(result.fileSize()).append(",");
        sb.append("\"total_entropy\":").append(String.format("%.4f", result.totalEntropy)).append(",");
        sb.append("\"header_entropy\":").append(String.format("%.4f", result.headerEntropy)).append(",");
        sb.append("\"body_entropy\":").append(String.format("%.4f", result.bodyEntropy)).append(",");
        sb.append("\"likely_packed\":").append(result.likelyPacked()).append(",");
        
        Map<String, Object> meta = result.metadata();
        if (!meta.isEmpty()) {
            sb.append("\"metadata\":{");
            int idx = 0;
            for (Map.Entry<String, Object> e : meta.entrySet()) {
                if (idx > 0) sb.append(",");
                sb.append("\"").append(e.getKey()).append("\":").append(serializeValue(e.getValue()));
                idx++;
            }
            sb.append("}");
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Serialize a value to JSON-compatible string.
     */
    private static String serializeValue(Object value) {
        if (value == null) return "null";
        if (value instanceof Boolean b) return b ? "true" : "false";
        if (value instanceof Number n) return n.toString();
        if (value instanceof String s) return "\"" + escapeJson(s) + "\"";
        if (value instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(serializeValue(list.get(i)));
            }
            sb.append("]");
            return sb.toString();
        }
        if (value instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            int idx = 0;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (idx > 0) sb.append(",");
                String key = escapeJson(e.getKey().toString());
                sb.append("\"").append(key).append("\":").append(serializeValue(e.getValue()));
                idx++;
            }
            sb.append("}");
            return sb.toString();
        }
        return "\"" + escapeJson(value.toString()) + "\"";
    }

    private static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder(s.length() * 2);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Demo with embedded test data.
     */
    public static void runDemo() throws IOException {
        System.out.println("\n=== RUNNING DEMO ===\n");

        // Create test files in memory
        byte[] plainText = "Hello World! This is a plain text file for testing.".getBytes(StandardCharsets.UTF_8);
        byte[] compressed = new java.util.zip.GZIPInputStream(new ByteArrayInputStream(plainText)).readAllBytes();
        
        // Write to temp files
        Path plainPath = Files.createTempFile("demo_plain_", ".txt");
        Path compressedPath = Files.createTempFile("demo_compressed_", ".gz");

        try {
            Files.write(plainPath, plainText);
            Files.write(compressedPath, compressed);

            // Analyze both
            AnalysisResult plain = analyzeFileToResult(plainPath);
            AnalysisResult compressed = analyzeFileToResult(compressedPath);

            System.out.println("Plain text entropy:  " + String.format("%.4f", plain.totalEntropy));
            System.out.println("Compressed entropy:  " + String.format("%.4f", compressed.totalEntropy));
            
            // Output as JSON
            System.out.println("\nJSON Output:");
            System.out.println(toJson(plain) + "\n" + toJson(compressed));

        } finally {
            Files.deleteIfExists(plainPath);
            Files.deleteIfExists(compressedPath);
        }
    }

    /**
     * Main entry point for demo mode.
     */
    public static void mainDemo() throws IOException {
        runDemo();
    }
}