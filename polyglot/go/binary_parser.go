package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// PEHeader represents the complete PE header structure for parsing
type PEHeader struct {
	DOSHeader  DOSHeader
	PESignature uint32
	PEHeader   PEStandardHeader
	Optional    PEOptionalHeader
	Sections    []SectionInfo
}

// DOSHeader is the MZ header at the start of every PE file
type DOSHeader struct {
	Magic     [2]byte
	Offset    uint16 // Offset to PE header (eip)
	Subsystem uint16 // Subsystem type
}

// PEStandardHeader contains the standard PE fields
type PEStandardHeader struct {
	Signature   uint32
	Machine      uint16
	NumberOfSections uint16
	TimeDateStamp  uint32
	PointerToSymbolTable  uint32
	NumberOfSymbols       uint32
	OptionalHeaderSize    uint16
	Characteristics       uint16
}

// PEOptionalHeader contains the optional header fields
type PEOptionalHeader struct {
	Magic              uint16
	MajorLinkerVersion byte
	MinorLinkerVersion byte
	SizeOfCode         uint32
	SizeOfInitializedData  uint32
	SizeOfUninitializedData   uint32
	AddressOfEntryPoint    uint32
	BaseOfCode            uint32
	BaseOfData            uint32
	ImageBase             uint32
	SectionAlignment      uint32
	FileAlignment         uint32
	MajorOSVersion        uint16
	MinorOSVersion        uint16
	MajorImageVersion     uint16
	MinorImageVersion     uint16
	MajorSubsystemVersion  uint16
	MinorSubsystemVersion  uint16
}

// SectionInfo represents a PE section
type SectionInfo struct {
	Name       string
	VirtualSize   uint32
	VirtualAddress uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  uint32
}

// PackerResult is the main result structure containing all analysis data
type PackerResult struct {
	Path           string
	FileName       string
	FileSize       int64
	Magic          [2]byte
	DOSOffset      uint16
	PESignature    uint32
	Machine        uint16
	SectionsCount  uint16
	OptionalMagic   uint16
	Entropy        float64
	ShannonEntropy float64
	IsPacked       bool
	PackersDetected []string
	Resources      ResourceInfo
	Sections       []SectionInfo
}

// ResourceInfo contains UPX resource information if found
type ResourceInfo struct {
	HasUPXResource   bool
	UPXVersion       string
	UPXOffset        uint32
	UPXSize          uint32
	UPXCompression   uint16
}

// Constants for PE headers
const (
	PESignature = 0x4550 // "PE\0\0"
	MZSignature  = 0x5A4D // "MZ"
	IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32     = 0x10b
	IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32PLUS = 0x20b
)

// Constants for UPX resources
const (
	UPX_RESOURCE_DIRECTORY_SIZE = 8
	UPX_VERSION_4_0             = 0x0400
)

// CalculateShannonEntropy computes the Shannon entropy of a byte slice
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[byte]int, 256)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64 = 0.0
	total := float64(len(data))

	for count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// ReadPEHeader reads and parses the PE header from a file
func ReadPEHeader(filePath string) (*PEHeader, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	header := &PEHeader{
		DOSHeader: DOSHeader{
			Magic:  [2]byte{'Z', 'M'}, // Little-endian MZ
		},
		PESignature: PESignature,
	}

	if len(data) < 64 {
		return nil, fmt.Errorf("file too small for PE header")
	}

	// Parse DOS header (little-endian)
	binary.Read(bytes.NewReader(data[0:2]), binary.LittleEndian, &header.DOSHeader.Magic)
	header.DOSOffset = binary.LittleEndian.Uint16(data[48:50])
	header.PESignature = binary.LittleEndian.Uint32(data[60:64])

	// Parse PE standard header
	if len(data) < 64+header.DOSOffset {
		return nil, fmt.Errorf("PE header offset out of bounds")
	}

	binary.Read(bytes.NewReader(data[header.DOSOffset:]), binary.LittleEndian, &header.PESignature)
	binary.Read(bytes.NewReader(data[header.DOSOffset+2:]), binary.LittleEndian, &header.PEHeader)

	// Parse optional header if present
	if len(data) >= int(header.DOSOffset)+int(header.PEHeader.OptionalHeaderSize) {
		optStart := header.DOSOffset + 40 // PE standard header is 40 bytes
		binary.Read(bytes.NewReader(data[optStart:]), binary.LittleEndian, &header.Optional.Magic)
	}

	// Enumerate sections
	header.Sections = EnumerateSections(data, header.PEHeader, header.Optional)

	return header, nil
}

// EnumerateSections extracts all section information from the PE file
func EnumerateSections(data []byte, stdHeader PEStandardHeader, optHeader PEOptionalHeader) []SectionInfo {
	var sections []SectionInfo

	if len(data) < int(stdHeader.PointerToSymbolTable)+int(optHeader.SizeOfCode) {
		return sections
	}

	// Calculate section table offset
	sectionOffset := 64 + stdHeader.OptionalHeaderSize // After DOS + PE standard header

	if len(data) <= int(sectionOffset) {
		return sections
	}

	for i := uint16(0); i < stdHeader.NumberOfSections; i++ {
		nameStart := sectionOffset + (i * 40)
		
		var name [8]byte
		binary.Read(bytes.NewReader(data[nameStart:nameStart+4]), binary.LittleEndian, &name[:4])
		nameStr := string(name[:4])

		if len(nameStr) < 2 {
			continue
		}

		// Pad to 8 bytes for proper display
		for j := 4; j < 8; j++ {
			if name[j] == 0 {
				name[j] = ' '
			}
		}

		sections = append(sections, SectionInfo{
			Name:       strings.TrimSpace(string(name[:])),
			VirtualSize: binary.LittleEndian.Uint32(data[nameStart+4 : nameStart+8]),
			VirtualAddress: binary.LittleEndian.Uint32(data[nameStart+8 : nameStart+12]),
			SizeOfRawData:  binary.LittleEndian.Uint32(data[nameStart+16 : nameStart+20]),
			PointerToRawData: binary.LittleEndian.Uint32(data[nameStart+20 : nameStart+24]),
			Characteristics: binary.LittleEndian.Uint32(data[nameStart+28 : nameStart+32]),
		})
	}

	return sections
}

// DetectUPXResources scans for UPX resource directory
func DetectUPXResources(data []byte) ResourceInfo {
	var res ResourceInfo

	if len(data) < 64 {
		return res
	}

	// Check if file is large enough to have resources
	if len(data) < 256 {
		return res
	}

	// Look for UPX resource directory at offset 0x18 (24 bytes into PE header)
	resourceOffset := 64 + 24 // DOS(64) + PE Standard(24)

	if len(data) < int(resourceOffset)+UPX_RESOURCE_DIRECTORY_SIZE {
		return res
	}

	// Read resource directory header
	resDirStart := resourceOffset
	binary.Read(bytes.NewReader(data[resDirStart:]), binary.LittleEndian, &res.UPXVersion)

	// UPX 4.0 has specific signature at offset 0x18
	if len(data) >= int(resourceOffset)+UPX_RESOURCE_DIRECTORY_SIZE {
		version := binary.LittleEndian.Uint32(data[resourceOffset : resourceOffset+4])
		
		if version == UPX_VERSION_4_0 || version == UPX_VERSION_4_1 {
			res.HasUPXResource = true
			res.UPXVersion = fmt.Sprintf("v%d.%d", byte(version>>8), byte(version&0xFF))
			
			// Extract UPX metadata from resource directory
			res.UPXOffset = binary.LittleEndian.Uint32(data[resourceOffset+4 : resourceOffset+8])
			res.UPXSize = binary.LittleEndian.Uint32(data[resourceOffset+8 : resourceOffset+12])
			res.UPXCompression = binary.LittleEndian.Uint16(data[resourceOffset+12 : resourceOffset+14])
		}
	}

	return res
}

// ScanForPackerSignatures looks for known packer signatures in the file
func ScanForPackerSignatures(data []byte, header *PEHeader) []string {
	var detected []string

	signatures := map[string][]byte{
		"UPX":       {"UPX0", "UPX1"},
		"ASPack":    {"ASPak", "ASPak2"},
		"Themida":   {"ThmD", "ThmD2"},
		"VMProtect": {"VMP_", "VMPr"},
		"MPRESS":    {"MPre", "MPreS"},
	}

	for name, patterns := range signatures {
		for _, pattern := range patterns {
			if len(data) >= 8 && bytes.Contains(data[:8], pattern) {
				detected = append(detected, fmt.Sprintf("%s (signature match)", name))
			}
		}
	}

	return detected
}

// ParseBinaryFile is the main entry point for binary analysis
func ParseBinaryFile(filePath string) (*PackerResult, error) {
	result := &PackerResult{
		Path:     filePath,
		Magic:    [2]byte{'Z', 'M'},
		DOSOffset: 64, // Default MZ offset
		PESignature: PESignature,
	}

	f, err := os.Open(filePath)
	if err != nil {
		return result, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return result, fmt.Errorf("read file: %w", err)
	}

	result.FileSize = int64(len(data))
	result.FileName = filepath.Base(filePath)

	// Parse PE header if present
	if len(data) >= 64 && bytes.Equal(data[0:2], []byte{'Z', 'M'}) {
		header, err := ReadPEHeader(filePath)
		if err == nil {
			result.DOSOffset = header.DOSOffset
			result.PESignature = header.PESignature
			result.Machine = header.PEHeader.Machine
			result.SectionsCount = header.PEHeader.NumberOfSections
			result.OptionalMagic = header.Optional.Magic
			result.Sections = header.Sections

			// Detect packers via signatures
			signatures := ScanForPackerSignatures(data, header)
			if len(signatures) > 0 {
				result.IsPacked = true
				result.PackersDetected = append(result.PackersDetected, signatures...)
			}

			// Check for UPX resources
			resources := DetectUPXResources(data)
			result.Resources = resources
			if resources.HasUPXResource {
				result.IsPacked = true
				result.PackersDetected = append(result.PackersDetected, 
					fmt.Sprintf("UPX %s (resources: offset=%d, size=%d)",
						resources.UPXVersion, resources.UPXOffset, resources.UPXSize))
			}

			// Calculate entropy
			result.ShannonEntropy = CalculateShannonEntropy(data)
			
			// High entropy often indicates packing/compression
			if result.ShannonEntropy > 7.5 {
				result.IsPacked = true
				result.PackersDetected = append(result.PackersDetected, 
					fmt.Sprintf("High entropy: %.2f (possible compression)", result.ShannonEntropy))
			}
		}
	}

	return result, nil
}

// OutputResult formats the PackerResult as JSON
func OutputResult(result *PackerResult) {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
		return
	}

	fmt.Println(string(jsonBytes))
}

func main() {
	// Demo with a sample binary file
	samplePath := "./test_binary.exe"

	if _, err := os.Stat(samplePath); err == nil {
		result, err := ParseBinaryFile(samplePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing: %v\n", err)
			os.Exit(1)
		}

		OutputResult(result)
	} else {
		// Create a minimal PE file for testing if sample doesn't exist
		fmt.Println("Sample binary not found. Creating test file...")
		
		testPE := createMinimalPE()
		err := os.WriteFile("./test_binary.exe", testPE, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating test file: %v\n", err)
			os.Exit(1)
		}

		result, err := ParseBinaryFile("./test_binary.exe")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing test: %v\n", err)
			os.Exit(1)
		}

		OutputResult(result)
	}
}

// createMinimalPE creates a minimal valid PE file for testing
func createMinimalPE() []byte {
	var buf bytes.Buffer

	// DOS Header (64 bytes)
	buf.WriteString("MZ") // Magic
	binary.Write(&buf, binary.LittleEndian, uint16(0x8000)) // eip offset
	binary.Write(&buf, binary.LittleEndian, uint16(2))     // subsystem

	// PE Header (56 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(PESignature))
	binary.Write(&buf, binary.LittleEndian, uint16(0x14c))  // machine (i386)
	binary.Write(&buf, binary.LittleEndian, uint16(1))     // sections
	binary.Write(&buf, binary.LittleEndian, uint32(0x12345678)) // timestamp
	binary.Write(&buf, binary.LittleEndian, uint32(0))      // symbol table
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // symbols
	binary.Write(&buf, binary.LittleEndian, uint16(40))     // optional header size
	binary.Write(&buf, binary.LittleEndian, uint16(0x2202)) // characteristics

	// Optional Header (28 bytes for PE32)