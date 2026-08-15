package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// EntropyResult holds analysis results for a single file
type EntropyResult struct {
	Name        string  `json:"name"`
	Size        int64   `json:"size"`
	Overall     float64 `json:"overall_entropy"`
	Summary     Summary `json:"summary"`
	Sections    []SectionAnalysis `json:"sections,omitempty"`
	PackerHints []PackerHint `json:"packer_hints,omitempty"`
}

// Summary provides high-level findings
type Summary struct {
	AvgEntropy      float64  `json:"avg_entropy"`
	MaxEntropy      float64  `json:"max_entropy"`
	MinEntropy      float64  `json:"min_entropy"`
	PackedLikely    bool     `json:"packed_likely"`
	HighestSection  string   `json:"highest_section,omitempty"`
}

// SectionAnalysis represents entropy for a specific section
type SectionAnalysis struct {
	Name       string  `json:"name"`
	Offset     int64   `json:"offset"`
	Size       int64   `json:"size"`
	Entropy    float64 `json:"entropy"`
	Ratio      float64 `json:"ratio"` // entropy / max possible (0-1)
}

// PackerHint represents a probabilistic packer detection
type PackerHint struct {
	Packer     string  `json:"packer"`
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
	RawScore   float64  `json:"raw_score"`
}

// SARIFResult wraps results in SARIF-compatible format
type SARIFResult struct {
	Version    string        `json:"version"`
	Schema     string        `json:"schema"`
	Runs       []SARIFRun    `json:"runs"`
}

type SARIFRun struct {
	Name      string   `json:"name"`
	Rules     []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	ShortDesc struct {
		Text    string `json:"text"`
		Lang    string `json:"lang"`
	} `json:"shortDescription"`
	Results []SARIFResultItem `json:"results,omitempty"`
}

type SARIFResultItem struct {
	RuleID      string   `json:"ruleId"`
	Name        string   `json:"name"`
	Message     string   `json:"message"`
	Locations   []Location `json:"locations"`
	Properties  Properties `json:"properties,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	AddressFormat string    `json:"addressFormat"`
	Address       int64      `json:"address"`
	Path          string     `json:"path"`
	Segment       *Segment   `json:"segment,omitempty"`
}

type Segment struct {
	Name  string `json:"name"`
	Offset int64  `json:"offset"`
	Size  int64  `json:"size"`
}

type Properties map[string]float64

// Constants for packer detection thresholds
const (
	EntropyMax      = 8.0
	UpxMin          = 7.2
	UpxMax          = 7.5
	AspackMin       = 6.8
	AspackMax       = 7.3
	ThemidaMin      = 7.4
	ThemidaMax      = 7.8
	VMPProtectMin   = 7.5
	VMPProtectMax   = 8.0
	DefaultSectionSize = 16 * 1024 // 16KB for sampling
)

// Default PE section names to analyze (if available)
var defaultPESections = []string{
	".text", ".data", ".rdata", ".idata", ".bss", ".reloc",
}

func main() {
	// Demo: Analyze a sample binary from stdin or file argument
	if len(os.Args) > 1 {
		result, err := analyzeFile(os.Args[1])
		if err != nil {
			log.Fatalf("Error analyzing %s: %v", os.Args[1], err)
		}
		
		// Output JSON to stdout
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonBytes))
	} else {
		// Read from stdin for demo purposes
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Reading stdin: %v", err)
		}
		
		result := &EntropyResult{
			Name: "stdin",
			Size: int64(len(data)),
			Summary: Summary{
				AvgEntropy: 0,
				MaxEntropy: 0,
				MinEntropy: 0,
			},
		}
		
		result.Overall = calculateShannonEntropy(data)
		result.Summary.AvgEntropy = result.Overall
		result.Summary.MaxEntropy = result.Overall
		result.Summary.MinEntropy = result.Overall
		
		if result.Overall > 7.0 {
			result.Summary.PackedLikely = true
			result.Summary.HighestSection = "entire_file"
		}
		
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonBytes))
	}
	
	log.Println("Demo complete. Check output for entropy values and packer hints.")
}

// analyzeFile reads a file and returns full analysis results
func analyzeFile(path string) (*EntropyResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	result := &EntropyResult{
		Name: filepath.Base(path),
		Size: int64(len(data)),
		Summary: Summary{
			AvgEntropy: 0,
			MaxEntropy: 0,
			MinEntropy: 0,
		},
	}

	result.Overall = calculateShannonEntropy(data)

	// Analyze sections if this looks like a PE file (has DOS header + NT headers)
	if len(data) > 64 && isPEFile(data[:64]) {
		result.Sections = analyzePESections(data, path)
		
		// Aggregate summary stats from sections
		for _, sec := range result.Sections {
			if sec.Entropy > result.Summary.MaxEntropy {
				result.Summary.MaxEntropy = sec.Entropy
				result.Summary.HighestSection = sec.Name
			}
			if sec.Entropy < result.Summary.MinEntropy {
				result.Summary.MinEntropy = sec.Entropy
			}
		}
		
		// Calculate average entropy across sections
		if len(result.Sections) > 0 {
			var sum float64
			for _, sec := range result.Sections {
				sum += sec.Entropy
			}
			result.Summary.AvgEntropy = sum / float64(len(result.Sections))
		}
		
		// Detect packers based on section entropy patterns
		result.PackerHints = detectPackers(data, result.Sections)
		
		// If overall high entropy and no clear sections found, flag as packed
		if result.Overall > 7.0 && len(result.Sections) == 0 {
			result.Summary.PackedLikely = true
			result.Summary.HighestSection = "unknown"
		}
	} else if result.Overall > 6.5 {
		// High entropy in non-PE file - likely packed or encrypted
		result.Summary.PackedLikely = true
		result.Summary.HighestSection = "entire_file"
	}

	return result, nil
}

// calculateShannonEntropy computes Shannon entropy for a byte slice
func calculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	frequency := make([]int64, 256)
	for _, b := range data {
		frequency[b]++
	}

	total := float64(len(data))
	var entropy float64
	
	for i := 0; i < 256; i++ {
		if frequency[i] > 0 {
			p := frequency[i] / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// isPEFile checks if data starts with DOS/NT headers indicating a PE file
func isPEFile(header []byte) bool {
	if len(header) < 64 {
		return false
	}

	// Check MZ signature
	if header[0] == 'M' && header[1] == 'z' {
		// Check NT headers offset (e_lfanew at offset 0x3C)
		if len(header) > 64+4 {
			ntOffset := int(int32(header[64])) + 64
			if ntOffset < len(header) && header[ntOffset] == 'P' && header[ntOffset+1] == 'E' {
				return true
			}
		}
	}

	return false
}

// analyzePESections extracts and analyzes PE sections from a PE file
func analyzePESections(data []byte, path string) []SectionAnalysis {
	var sections []SectionAnalysis
	
	if len(data) < 64+20 {
		return sections
	}

	// Get NT headers offset
	ntOffset := int(int32(header[64])) + 64
	if ntOffset >= len(data) {
		return sections
	}

	// Parse Optional Header to get section table location
	var optHeaderStart, sectionTableOffset int
	
	if len(data) > ntOffset+2 {
		machineType := int(uint16(data[ntOffset])) | int(uint16(data[ntOffset+1])<<8)
		
		// PE32: 0x14C (348), PE32+: 0x15C (348 for PE32+)
		if machineType == 0x14C || machineType == 0x15C {
			optHeaderStart = ntOffset + 2
			sectionTableOffset = optHeaderStart + 24 // Offset to section table pointer
		} else if machineType == 0x8664 { // PE32+ (64-bit)
			optHeaderStart = ntOffset + 2
			sectionTableOffset = optHeaderStart + 24
		} else {
			return sections
		}

		if sectionTableOffset >= len(data) {
			return sections
		}

		// Read number of sections (at offset 0x18 within optional header)
		numSections := int(uint32(data[sectionTableOffset])) | 
					int(uint32(data[sectionTableOffset+1])<<8) |
					int(uint32(data[sectionTableOffset+2])<<16) |
					int(uint32(data[sectionTableOffset+3])<<24)

		if numSections == 0 || sectionTableOffset+8 > len(data) {
			return sections
		}

		sectionTableStart := sectionTableOffset + 8
		
		// Analyze each section
		for i := 0; i < numSections && sectionTableStart+i*40 < len(data); i++ {
			nameLen := int(uint32(data[sectionTableStart])) | 
					int(uint32(data[sectionTableStart+1])<<8) |
					int(uint32(data[sectionTableStart+2])<<16) |
					int(uint32(data[sectionTableStart+3])<<24)

			if nameLen == 0 || sectionTableStart+nameLen > len(data) {
				break
			}

			name := string(data[sectionTableStart : sectionTableStart+nameLen])
			
			// Calculate offset and size (relative to optional header start)
			offset := int64(int(uint32(data[sectionTableStart+nameLen])) | 
					int(uint32(data[sectionTableStart+nameLen+1])<<8) |
					int(uint32(data[sectionTableStart+nameLen+2])<<16) |
					int(uint32(data[sectionTableStart+nameLen+3])<<24)) + optHeaderStart
			
			size := int64(int(uint32(data[sectionTableStart+nameLen+4])) | 
					int(uint32(data[sectionTableStart+nameLen+5])<<8) |
					int(uint32(data[sectionTableStart+nameLen+6])<<16) |
					int(uint32(data[sectionTableStart+nameLen+7])<<24))

			// Skip empty or very small sections
			if size == 0 || offset >= int64(len(data)) {
				continue
			}

			sectionSize := int64(math.Min(float64(size), float64(len(data)-offset)))
			
			// Sample the section for entropy calculation (avoid reading beyond file)
			sampleSize := DefaultSectionSize
			if sampleSize > int(sectionSize) {
				sampleSize = int(sectionSize)
			}

			var sectionData []byte
			if offset+sampleSize <= len(data) {
				sectionData = data[offset : offset+sampleSize]
			} else {
				// Wrap around for very large sections (rare but possible)
				sample1 := data[offset:]
				sample2 := data[:offset+sampleSize-len(data)]
				sectionData = append(sample1, sample2...)
			}

			if len(sectionData) == 0 {
				continue
			}

			entropy := calculateShannonEntropy(sectionData)
			
			// Calculate ratio (normalized entropy, max ~8.0 for uniform distribution)
			ratio := entropy / EntropyMax
			
			sections = append(sections, SectionAnalysis{
				Name:    name,
				Offset:  offset,
				Size:    sectionSize,
				Entropy: entropy,
				Ratio:   ratio,
			})

			if name == "" {
				name = fmt.Sprintf("section_%d", i)
			}
		}
	}

	return sections
}

// detectPackers analyzes entropy patterns to suggest possible packers
func detectPackers(data []byte, sections []SectionAnalysis) []PackerHint {
	var hints []PackerHint
	
	if len(sections) == 0 || len(data) < 64 {
		return hints
	}

	// Calculate overall entropy for context
	overallEntropy := calculateShannonEntropy(data)

	// Analyze specific section patterns
	for _, sec := range sections {
		hintScore := 0.0
		
		// UPX detection: very high entropy in data sections, lower in text
		if strings.Contains(strings.ToLower(sec.Name), "data") || 
		   strings.Contains(strings.ToLower(sec.Name), ".rsrc") {
			if sec.Entropy >= UpxMin && sec.Entropy <= UpxMax {
				hintScore += 0.35
			} else if sec.Entropy > UpxMax {
				hintScore += 0.45
			}
			
			// UPX often has a specific entropy range around 7.2-7.4
			if sec.Entropy >= 7.1 && sec.Entropy <= 7.6 {
				hintScore += 0.3
			}
		}

		// ASPack detection: high but slightly lower than UPX
		if strings.Contains(strings.ToLower(sec.Name), "data") || 
		   strings.Contains(strings.ToLower(sec.Name), ".rsrc") {
			if sec.Entropy >= AspackMin && sec.Entropy <= AspackMax {
				hintScore += 0.35
			} else if sec.Entropy > AspackMax {
				hintScore += 0.25
			}
			
			// ASPack typically has entropy around