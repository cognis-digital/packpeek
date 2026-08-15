package polyglot.java;

import java.io.*;
import java.nio.*;
import java.nio.channels.Channels;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Binary parser for packpeek tool.
 * Detects packers, calculates entropy, parses PE headers.
 */
public class binary_parser {

    // Magic signatures for common packers
    private static final Map<String, byte[]> PACKER_MAGICS = new HashMap<>();

    static {
        // UPX variants
        PACKER_MAGICS.put("UPX1", new byte[]{0x52, 0x4A}); // "RJ"
        PACKER_MAGICS.put("UPX2", new byte[]{0x4A, 0x52}); // "JR"
        
        // ASPack variants
        PACKER_MAGICS.put("ASPack1", new byte[]{0x53, 0x50, 0x4B, 0x31}); // "SPK1"
        PACKER_MAGICS.put("ASPack2", new byte[]{0x53, 0x50, 0x4B, 0x32}); // "SPK2"
        
        // Themida
        PACKER_MAGICS.put("Themida", new byte[]{0x74, 0x68, 0x6D, 0x69, 0x64, 0x61}); // "themida"
        
        // VMProtect
        PACKER_MAGICS.put("VMProtect", new byte[]{0x56, 0x4D, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74}); // "VMProtect"
        
        // MPRESS
        PACKER_MAGICS.put("MPRESS", new byte[]{0x4D, 0x50, 0x52, 0x45, 0x53, 0x53}); // "MPRESS"
    }

    public static class BinaryMetadata {
        private String fileName;
        private long fileSize;
        private double entropy;
        private List<String> detectedPackers = new ArrayList<>();
        private PEHeader peHeader;
        private byte[] rawBytes;
        
        // Getters
        public String getFileName() { return fileName; }
        public long getFileSize() { return fileSize; }
        public double getEntropy() { return entropy; }
        public List<String> getDetectedPackers() { return detectedPackers; }
        public PEHeader getPEHeader() { return peHeader; }
        public byte[] getRawBytes() { return rawBytes; }

        // Setters
        public void setFileName(String fileName) { this.fileName = fileName; }
        public void setFileSize(long fileSize) { this.fileSize = fileSize; }
        public void setEntropy(double entropy) { this.entropy = entropy; }
        public void addDetectedPacker(String packer) { 
            if (!detectedPackers.contains(packer)) detectedPackers.add(packer); 
        }
        public void setPEHeader(PEHeader peHeader) { this.peHeader = peHeader; }
        public void setRawBytes(byte[] rawBytes) { this.rawBytes = rawBytes; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("BinaryMetadata{\n");
            sb.append("  fileName: ").append(fileName).append("\n");
            sb.append("  fileSize: ").append(fileSize).append("\n");
            sb.append(String.format("  entropy: %.4f\n", entropy));
            sb.append("  detectedPackers: ").append(detectedPackers).append("\n");
            if (peHeader != null) {
                sb.append("  peHeader: ").append(peHeader);
            }
            sb.append("}");
            return sb.toString();
        }
    }

    public static class PEHeader {
        private String dosSignature;
        private int peOffset;
        private int optionalHeaderOffset;
        private long timestamp;
        private int entryPoint;
        private int imageBase;
        private int subsystem;
        
        // Getters
        public String getDosSignature() { return dosSignature; }
        public int getPeOffset() { return peOffset; }
        public int getOptionalHeaderOffset() { return optionalHeaderOffset; }
        public long getTimestamp() { return timestamp; }
        public int getEntryPoint() { return entryPoint; }
        public int getImageBase() { return imageBase; }
        public int getSubsystem() { return subsystem; }

        // Setters
        public void setDosSignature(String dosSignature) { this.dosSignature = dosSignature; }
        public void setPeOffset(int peOffset) { this.peOffset = peOffset; }
        public void setOptionalHeaderOffset(int optionalHeaderOffset) { 
            this.optionalHeaderOffset = optionalHeaderOffset; 
        }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        public void setEntryPoint(int entryPoint) { this.entryPoint = entryPoint; }
        public void setImageBase(int imageBase) { this.imageBase = imageBase; }
        public void setSubsystem(int subsystem) { this.subsystem = subsystem; }

        @Override
        public String toString() {
            return "PEHeader{" +
                    "dosSignature='" + dosSignature + '\'' +
                    ", peOffset=" + peOffset +
                    ", optionalHeaderOffset=" + optionalHeaderOffset +
                    ", timestamp=" + timestamp +
                    ", entryPoint=0x" + Integer.toHexString(entryPoint) +
                    ", imageBase=0x" + Integer.toHexString(imageBase) +
                    ", subsystem=" + subsystem +
                    '}';
        }
    }

    public static class PEHeaderParser {
        
        private static final int DOS_MAGIC = 0x5A4D; // "MZ"
        private static final int PE_SIGNATURE = 0x4550; // "PE"
        private static final int IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32 = 0x10b;
        private static final int IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32PLUS = 0x20b;

        public PEHeader parse(ByteBuffer buffer) {
            if (buffer.remaining() < 64) return null;

            // Check DOS magic
            short dosMagic = buffer.getShort(0);
            if (dosMagic != DOS_MAGIC) return null;

            PEHeader header = new PEHeader();
            
            // Read DOS signature
            byte[] dosSigBytes = new byte[2];
            buffer.position(3);
            dosSigBytes[0] = buffer.get();
            dosSigBytes[1] = buffer.get();
            String dosSignature = new String(dosSigBytes, "ASCII");
            header.setDosSignature(dosSignature);

            // Read PE offset (at 0x3C)
            if (buffer.remaining() >= 68) {
                int peOffset = buffer.getInt(0x3C);
                header.setPeOffset(peOffset);
                
                // Verify PE signature
                if (peOffset + 2 <= buffer.limit()) {
                    short peSig = buffer.getShort(peOffset);
                    if (peSig == PE_SIGNATURE) {
                        header.setDosSignature("MZ");
                        
                        // Read optional header magic
                        int optHeaderMagic = buffer.getInt(peOffset + 60);
                        if (optHeaderMagic == IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32 || 
                            optHeaderMagic == IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32PLUS) {
                            
                            long timestamp = buffer.getLong(peOffset + 72);
                            header.setTimestamp(timestamp);
                            
                            // Entry point (at offset 160 from PE start, or 184 from DOS)
                            int entryPoint = buffer.getInt(peOffset + 160);
                            header.setEntryPoint(entryPoint);
                            
                            // Image base (at offset 128 from PE start, or 152 from DOS)
                            int imageBase = buffer.getInt(peOffset + 128);
                            header.setImageBase(imageBase);
                        }
                    }
                }
            }

            return header;
        }

        public static boolean isPEFile(ByteBuffer buffer) {
            if (buffer.remaining() < 64) return false;
            
            short dosMagic = buffer.getShort(0);
            if (dosMagic != DOS_MAGIC) return false;
            
            int peOffset = buffer.getInt(0x3C);
            if (peOffset + 2 > buffer.limit()) return false;
            
            short peSig = buffer.getShort(peOffset);
            return peSig == PE_SIGNATURE;
        }

        public static boolean isPackedFile(ByteBuffer buffer) {
            // High entropy in first few KB suggests packing
            if (buffer.remaining() < 4096) return false;
            
            byte[] sample = new byte[1024];
            buffer.get(sample);
            
            double entropy = calculateEntropy(sample);
            return entropy > 7.5; // Threshold for packed files
        }

        private static double calculateEntropy(byte[] data) {
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
                    entropy -= p * Math.log(p);
                }
            }
            
            return entropy;
        }

        public static String getDosSignature(ByteBuffer buffer) {
            if (buffer.remaining() < 64) return "Unknown";
            
            byte[] dosSigBytes = new byte[2];
            buffer.position(3);
            dosSigBytes[0] = buffer.get();
            dosSigBytes[1] = buffer.get();
            String result = new String(dosSigBytes, "ASCII");
            
            return result.equals("MZ") ? "DOS/PE" : result;
        }

        public static int getPeOffset(ByteBuffer buffer) {
            if (buffer.remaining() < 64) return -1;
            
            short dosMagic = buffer.getShort(0);
            if (dosMagic != DOS_MAGIC) return -1;
            
            return buffer.getInt(0x3C);
        }

        public static int getOptionalHeaderOffset(ByteBuffer buffer, PEHeader peHeader) {
            if (peHeader == null || peHeader.getPeOffset() < 0) return -1;
            
            // Optional header is at offset 24 from PE signature
            return peHeader.getPeOffset() + 24;
        }

        public static long getTimestamp(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 76) return 0L;
            
            // Timestamp is at offset 72 from PE signature
            return buffer.getLong(peOffset + 72);
        }

        public static int getEntryPoint(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 164) return 0;
            
            // Entry point is at offset 160 from PE signature
            return buffer.getInt(peOffset + 160);
        }

        public static int getImageBase(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 132) return 0;
            
            // Image base is at offset 128 from PE signature
            return buffer.getInt(peOffset + 128);
        }

        public static int getSubsystemType(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 140) return 0;
            
            // Subsystem is at offset 136 from PE signature
            return buffer.getInt(peOffset + 136);
        }

        public static String getSubsystemName(int subsystemType) {
            switch (subsystemType) {
                case 2: return "Windows GUI";
                case 3: return "Windows CUI";
                case 5: return "OS/2 CUI";
                default: return "Unknown (" + subsystemType + ")";
            }
        }

        public static int getNumberOfRvaAndSizes(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 96) return 0;
            
            // RVA and Sizes count is at offset 88 from PE signature
            return buffer.getInt(peOffset + 88);
        }

        public static int getNumberOfSections(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 96) return 0;
            
            // Section count is at offset 92 from PE signature
            return buffer.getInt(peOffset + 92);
        }

        public static String getMachineType(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 68) return "Unknown";
            
            // Machine type is at offset 4 from PE signature
            short machine = buffer.getShort(peOffset + 4);
            
            switch (machine) {
                case 0x14c: return "Intel x86";
                case 0x8664: return "AMD x86-64";
                case 0x1c0: return "ARM";
                case 0xaa64: return "ARM64";
                default: return "Unknown (0x" + Integer.toHexString(machine) + ")";
            }
        }

        public static String getCharacteristics(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 68) return "Unknown";
            
            // Characteristics is at offset 40 from PE signature
            short characteristics = buffer.getShort(peOffset + 40);
            
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            
            if ((characteristics & 0x0001) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_RELOCS_STRIPPED");
                first = false;
            }
            if ((characteristics & 0x0002) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_EXECUTABLE_IMAGE");
                first = false;
            }
            if ((characteristics & 0x0004) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_LINE_NUMS_STRIPPED");
                first = false;
            }
            if ((characteristics & 0x0008) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_LOCAL_SYMS_STRIPPED");
                first = false;
            }
            if ((characteristics & 0x0010) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_32BIT_MACHINE");
                first = false;
            }
            if ((characteristics & 0x0020) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_DEBUG_STRIPPED");
                first = false;
            }
            if ((characteristics & 0x0100) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_LARGE_ADDRESS_AWARE");
                first = false;
            }
            if ((characteristics & 0x0200) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_BYTES_REVERSED_LO");
                first = false;
            }
            if ((characteristics & 0x1000) != 0) {
                if (!first) sb.append(", ");
                sb.append("IMAGE_FILE_32BIT_MACHINE (alt)");
                first = false;
            }
            
            return sb.length() > 0 ? sb.toString() : "Unknown";
        }

        public static int getSubsystem(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 140) return 0;
            
            // Subsystem is at offset 136 from PE signature
            return buffer.getInt(peOffset + 136);
        }

        public static int getNumberOfRvaAndSizes(ByteBuffer buffer, int peOffset) {
            if (peOffset == -1 || buffer.remaining() < peOffset + 96) return 0;
            
            // RVA and Sizes count is at offset 88 from PE signature
            return buffer.getInt(peOffset + 88);
        }

        public