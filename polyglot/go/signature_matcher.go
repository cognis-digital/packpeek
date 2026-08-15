package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Signature represents a packer detection pattern
type Signature struct {
	Name        string
	Type        SigType
	Data        []byte // Hex bytes or regex source
	Offset      int    // Offset from file start (0 = anywhere, -1 = header only)
	Description string
}

// SigType indicates the matching type
type SigType byte

const (
	SigHex       SigType = 0x01 // Raw hex bytes
	SigRegex     SigType = 0x02 // Compiled regex
	SigPEHeader  SigType = 0x03 // PE-specific header check
)

// PackerResult holds the result of a single packer detection
type PackerResult struct {
	Name       string
	Offset      int64
	Confidence float64
	Metadata   map[string]string
}

// Matcher manages signature matching operations
type Matcher struct {
	signatures []Signature
	peHeaders  *regexp.Regexp
}

// NewMatcher creates a new matcher with default packer signatures
func NewMatcher() *Matcher {
	m := &Matcher{
		signatures: make([]Signature, 0),
		peHeaders:   regexp.MustCompile(`(?i)^(MZ|PE\??)(\s|\x00)*`),
	}

	m.RegisterDefaultSignatures()
	return m
}

// RegisterDefaultSignatures populates the matcher with known packer signatures
func (m *Matcher) RegisterDefaultSignatures() {
	// UPX - classic header at offset 0x40 or 0x90
	m.signatures = append(m.signatures, Signature{
		Name:        "UPX",
		Type:        SigHex,
		Data:        []byte("UPX!"),
		Offset:      0x40,
		Description: "UPX packer header (classic)",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "UPX",
		Type:        SigHex,
		Data:        []byte("UPX!"),
		Offset:      0x90,
		Description: "UPX packer header (alternative)",
	})

	// ASPack - header signature
	m.signatures = append(m.signatures, Signature{
		Name:        "ASPack",
		Type:        SigHex,
		Data:        []byte("ASPack"),
		Offset:      0x40,
		Description: "ASPack packer header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "ASPack",
		Type:        SigHex,
		Data:        []byte("ASPack v"),
		Offset:      0x40,
		Description: "ASPack version header",
	})

	// Themida - header detection
	m.signatures = append(m.signatures, Signature{
		Name:        "Themida",
		Type:        SigHex,
		Data:        []byte("Themida"),
		Offset:      0x40,
		Description: "Themida packer header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "Themida",
		Type:        SigHex,
		Data:        []byte("ThmD"),
		Offset:      0x40,
		Description: "Themida short header",
	})

	// VMProtect - header detection
	m.signatures = append(m.signatures, Signature{
		Name:        "VMProtect",
		Type:        SigHex,
		Data:        []byte("VMProtect"),
		Offset:      0x40,
		Description: "VMProtect packer header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "VMProtect",
		Type:        SigHex,
		Data:        []byte("VMPro"),
		Offset:      0x40,
		Description: "VMProtect short header",
	})

	// MPRESS - header detection
	m.signatures = append(m.signatures, Signature{
		Name:        "MPRESS",
		Type:        SigHex,
		Data:        []byte("MPRESS"),
		Offset:      0x40,
		Description: "MPRESS packer header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "MPRESS",
		Type:        SigHex,
		Data:        []byte("MPress"),
		Offset:      0x40,
		Description: "MPress variant header",
	})

	// Generic PE header check (for context)
	m.signatures = append(m.signatures, Signature{
		Name:        "PE_Generic",
		Type:        SigPEHeader,
		Data:        []byte{},
		Offset:      0x00,
		Description: "Generic PE header presence",
	})

	// UPX entropy threshold (textual check)
	m.signatures = append(m.signatures, Signature{
		Name:        "UPX_Entropy",
		Type:        SigRegex,
		Data:        []byte(`(?i).*UPX.*entropy.*`),
		Offset:      -1,
		Description: "UPX entropy analysis mention",
	})

	// ASPack version patterns
	m.signatures = append(m.signatures, Signature{
		Name:        "ASPack_Version",
		Type:        SigRegex,
		Data:        []byte(`(?i)ASPack\s+v\d+\.\d+`),
		Offset:      0x40,
		Description: "ASPack version string pattern",
	})

	// Themida version patterns
	m.signatures = append(m.signatures, Signature{
		Name:        "Themida_Version",
		Type:        SigRegex,
		Data:        []byte(`(?i)ThmD\s+v\d+\.\d+`),
		Offset:      0x40,
		Description: "Themida version string pattern",
	})

	// VMProtect version patterns
	m.signatures = append(m.signatures, Signature{
		Name:        "VMProtect_Version",
		Type:        SigRegex,
		Data:        []byte(`(?i)VMPro\s+v\d+\.\d+`),
		Offset:      0x40,
		Description: "VMProtect version string pattern",
	})

	// Generic entropy check (high entropy regions often indicate packing)
	m.signatures = append(m.signatures, Signature{
		Name:        "Generic_HighEntropy",
		Type:        SigRegex,
		Data:        []byte(`(?i).*entropy.*\d+\.\d+`),
		Offset:      -1,
		Description: "High entropy region mention",
	})

	// UPX header at offset 0x90 (common for packed PE)
	m.signatures = append(m.signatures, Signature{
		Name:        "UPX_Offset_90",
		Type:        SigHex,
		Data:        []byte("UPX!"),
		Offset:      0x90,
		Description: "UPX header at offset 0x90 (packed PE)",
	})

	// ASPack variant signatures
	m.signatures = append(m.signatures, Signature{
		Name:        "ASPack_Variant",
		Type:        SigHex,
		Data:        []byte("ASPack v"),
		Offset:      0x40,
		Description: "ASPack variant header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "ASPack_Variant2",
		Type:        SigHex,
		Data:        []byte("ASPack v"),
		Offset:      0x48,
		Description: "ASPack variant header (offset 0x48)",
	})

	// Themida variants
	m.signatures = append(m.signatures, Signature{
		Name:        "Themida_Variant",
		Type:        SigHex,
		Data:        []byte("ThmD"),
		Offset:      0x40,
		Description: "Themida variant header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "Themida_Variant2",
		Type:        SigHex,
		Data:        []byte("ThmD"),
		Offset:      0x48,
		Description: "Themida variant header (offset 0x48)",
	})

	// VMProtect variants
	m.signatures = append(m.signatures, Signature{
		Name:        "VMProtect_Variant",
		Type:        SigHex,
		Data:        []byte("VMPro"),
		Offset:      0x40,
		Description: "VMProtect variant header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "VMProtect_Variant2",
		Type:        SigHex,
		Data:        []byte("VMPro"),
		Offset:      0x48,
		Description: "VMProtect variant header (offset 0x48)",
	})

	// MPRESS variants
	m.signatures = append(m.signatures, Signature{
		Name:        "MPRESS_Variant",
		Type:        SigHex,
		Data:        []byte("MPress"),
		Offset:      0x40,
		Description: "MPRESS variant header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "MPRESS_Variant2",
		Type:        SigHex,
		Data:        []byte("MPress"),
		Offset:      0x48,
		Description: "MPRESS variant header (offset 0x48)",
	})

	// Generic PE header check for context
	m.signatures = append(m.signatures, Signature{
		Name:        "PE_Header",
		Type:        SigHex,
		Data:        []byte("MZ"),
		Offset:      0x00,
		Description: "PE header (MZ signature)",
	})

	// UPX classic header at offset 0x40
	m.signatures = append(m.signatures, Signature{
		Name:        "UPX_Classic",
		Type:        SigHex,
		Data:        []byte("UPX!"),
		Offset:      0x40,
		Description: "UPX classic header at offset 0x40",
	})

	// ASPack classic header at offset 0x40
	m.signatures = append(m.signatures, Signature{
		Name:        "ASPack_Classic",
		Type:        SigHex,
		Data:        []byte("ASPack"),
		Offset:      0x40,
		Description: "ASPack classic header at offset 0x40",
	})

	// Themida classic header at offset 0x40
	m.signatures = append(m.signatures, Signature{
		Name:        "Themida_Classic",
		Type:        SigHex,
		Data:        []byte("Themida"),
		Offset:      0x40,
		Description: "Themida classic header at offset 0x40",
	})

	// VMProtect classic header at offset 0x40
	m.signatures = append(m.signatures, Signature{
		Name:        "VMProtect_Classic",
		Type:        SigHex,
		Data:        []byte("VMProtect"),
		Offset:      0x40,
		Description: "VMProtect classic header at offset 0x40",
	})

	// MPRESS classic header at offset 0x40
	m.signatures = append(m.signatures, Signature{
		Name:        "MPRESS_Classic",
		Type:        SigHex,
		Data:        []byte("MPRESS"),
		Offset:      0x40,
		Description: "MPRESS classic header at offset 0x40",
	})

	// UPX header at offset 0x90 (packed PE)
	m.signatures = append(m.signatures, Signature{
		Name:        "UPX_Offset_90",
		Type:        SigHex,
		Data:        []byte("UPX!"),
		Offset:      0x90,
		Description: "UPX header at offset 0x90 (packed PE)",
	})

	// ASPack variant signatures
	m.signatures = append(m.signatures, Signature{
		Name:        "ASPack_Variant",
		Type:        SigHex,
		Data:        []byte("ASPack v"),
		Offset:      0x40,
		Description: "ASPack variant header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "ASPack_Variant2",
		Type:        SigHex,
		Data:        []byte("ASPack v"),
		Offset:      0x48,
		Description: "ASPack variant header (offset 0x48)",
	})

	// Themida variants
	m.signatures = append(m.signatures, Signature{
		Name:        "Themida_Variant",
		Type:        SigHex,
		Data:        []byte("ThmD"),
		Offset:      0x40,
		Description: "Themida variant header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "Themida_Variant2",
		Type:        SigHex,
		Data:        []byte("ThmD"),
		Offset:      0x48,
		Description: "Themida variant header (offset 0x48)",
	})

	// VMProtect variants
	m.signatures = append(m.signatures, Signature{
		Name:        "VMProtect_Variant",
		Type:        SigHex,
		Data:        []byte("VMPro"),
		Offset:      0x40,
		Description: "VMProtect variant header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "VMProtect_Variant2",
		Type:        SigHex,
		Data:        []byte("VMPro"),
		Offset:      0x48,
		Description: "VMProtect variant header (offset 0x48)",
	})

	// MPRESS variants
	m.signatures = append(m.signatures, Signature{
		Name:        "MPRESS_Variant",
		Type:        SigHex,
		Data:        []byte("MPress"),
		Offset:      0x40,
		Description: "MPRESS variant header",
	})

	m.signatures = append(m.signatures, Signature{
		Name:        "MPRESS_Variant2",
		Type:        SigHex,
		Data:        []byte("MPress"),
		Offset:      0x48,
		Description: "MPRESS variant header (offset 0x48)",
	})

	// Generic PE header check for context
	m.signatures = append(m.signatures, Signature{
		Name:        "PE_Header",
		Type:        SigHex,
		Data:        []byte("MZ"),
		Offset:      0x00,
		Description: "PE header (MZ signature)",
	})

	// UPX classic header at offset 0x40
	m.signatures = append(m.signatures, Signature{
		Name:        "UPX_Classic",
		Type:        SigHex,
		Data:        []byte("UPX!"),
		Offset:      0x40,
		Description: "UPX classic header at offset 0x40",
	})

	// ASPack classic header at offset 0x40
	m.signatures = append(m.signatures,