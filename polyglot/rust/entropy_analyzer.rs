use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

// ============================================================================
// PE Header Structures (Minimal but complete for analysis)
// ============================================================================

#[derive(Debug, Clone)]
pub struct PeHeader {
    pub magic: u16,
    pub machine: u16,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_pointer: u32,
    pub characteristics: u32,
}

// ============================================================================
// Entropy Calculation Module
// ============================================================================

/// Calculate Shannon entropy of a byte slice.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }

    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let prob = count as f64 / total as f64;
            entropy -= (prob * prob.ln());
        }
    }

    // Normalize to 8-bit range (max entropy is 8.0 for uniform distribution)
    entropy / 8.0
}

/// Calculate entropy with configurable bit depth (useful for analyzing specific ranges).
pub fn calculate_entropy_range(data: &[u8], min_bit: u32, max_bit: u32) -> f64 {
    if data.is_empty() || min_bit > max_bit {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        // Mask to the relevant bit range
        let masked = byte & ((1 << (max_bit - min_bit + 1)) - 1);
        counts[masked as usize] += 1;
    }

    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }

    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let prob = count as f64 / total as f64;
            entropy -= (prob * prob.ln());
        }
    }

    entropy / 8.0
}

// ============================================================================
// PE File Parser
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct PeSectionInfo {
    pub name: String,
    pub virtual_size: u64,
    pub raw_data_size: u64,
    pub entropy: f64,
    pub compression_ratio: Option<f64>,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeFileAnalysis {
    pub file_path: String,
    pub is_pe: bool,
    pub header: Option<PeHeader>,
    pub sections: Vec<PeSectionInfo>,
    pub overall_entropy: f64,
    pub suspicious_sections: Vec<String>,
}

pub fn parse_pe_header(file: &mut File) -> Result<Option<PeHeader>, String> {
    let mut magic_buf = [0u8; 2];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut magic_buf)?;

    if magic_buf[0] == b'M' && magic_buf[1] == b'Z' {
        // PE32+ (x64)
        let mut header = PeHeader {
            magic: 0x200E,
            machine: 0x8664, // AMD64
            number_of_sections: 0,
            timestamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
        };

        file.seek(SeekFrom::Start(64))?; // Skip to optional header start
        let mut machine_buf = [0u8; 2];
        file.read_exact(&mut machine_buf)?;
        header.machine = u16::from_le_bytes(machine_buf);

        let mut num_sections_buf = [0u8; 2];
        file.read_exact(&mut num_sections_buf)?;
        header.number_of_sections = u16::from_le_bytes(num_sections_buf);

        Ok(Some(header))
    } else if magic_buf[0] == b'M' && magic_buf[1] == b'Z' {
        // PE32 (x86)
        let mut header = PeHeader {
            magic: 0x10b,
            machine: 0x14c, // i386
            number_of_sections: 0,
            timestamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
        };

        file.seek(SeekFrom::Start(64))?;
        let mut machine_buf = [0u8; 2];
        file.read_exact(&mut machine_buf)?;
        header.machine = u16::from_le_bytes(machine_buf);

        let mut num_sections_buf = [0u8; 2];
        file.read_exact(&mut num_sections_buf)?;
        header.number_of_sections = u16::from_le_bytes(num_sections_buf);

        Ok(Some(header))
    } else {
        Ok(None)
    }
}

pub fn parse_pe_sections(file: &mut File, header: &PeHeader) -> Result<Vec<SectionHeader>, String> {
    let section_offset = 64 + header.size_of_optional_header as u64;
    let mut sections = Vec::with_capacity(header.number_of_sections as usize);

    for _ in 0..header.number_of_sections {
        let mut section = SectionHeader {
            name: [0u8; 8],
            virtual_size: 0,
            virtual_address: 0,
            raw_data_size: 0,
            raw_data_pointer: 0,
            characteristics: 0,
        };

        file.seek(SeekFrom::Start(section_offset))?;

        // Read name (null-terminated)
        let mut name_buf = [0u8; 8];
        file.read_exact(&mut name_buf)?;
        
        // Find null terminator and convert to string
        let end = name_buf.iter().position(|&b| b == 0).unwrap_or(7);
        section.name[..end].copy_from_slice(&name_buf[..end]);

        // Read remaining fields (little-endian)
        file.read_u32::<LittleEndian>(&mut section.virtual_size)?;
        file.read_u32::<LittleEndian>(&mut section.virtual_address)?;
        file.read_u32::<LittleEndian>(&mut section.raw_data_size)?;
        file.read_u32::<LittleEndian>(&mut section.raw_data_pointer)?;
        file.read_u32::<LittleEndian>(&mut section.characteristics)?;

        sections.push(section);
        
        // Move to next section (8 bytes padding)
        file.seek(SeekFrom::Current(8))?;
    }

    Ok(sections)
}

// ============================================================================
// Entropy Analyzer Core Logic
// ============================================================================

pub struct EntropyAnalyzer {
    pub threshold: f64,
    pub min_section_size: u32,
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self {
            threshold: 7.0, // High entropy indicates compression/packing
            min_section_size: 1024,
        }
    }
}

impl EntropyAnalyzer {
    pub fn new(threshold: f64) -> Self {
        Self { threshold, ..Default::default() }
    }

    /// Analyze a PE file and return comprehensive entropy analysis.
    pub fn analyze_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<PeFileAnalysis, String> {
        let full_path = path.as_ref().to_string_lossy().to_string();
        
        // Open file for reading
        let mut file = File::open(&full_path).map_err(|e| format!("Failed to open: {}", e))?;

        // Parse PE header
        let header = parse_pe_header(&mut file)?;
        let is_pe = header.is_some();

        if !is_pe {
            return Ok(PeFileAnalysis {
                file_path: full_path,
                is_pe: false,
                header: None,
                sections: Vec::new(),
                overall_entropy: 0.0,
                suspicious_sections: Vec::new(),
            });
        }

        let header = header.unwrap();
        
        // Parse all sections
        let mut sections = parse_pe_sections(&mut file, &header)?;
        
        // Calculate entropy for each section and filter small ones
        let mut analyzed_sections = Vec::with_capacity(sections.len());
        let mut suspicious = Vec::new();

        for (idx, section) in sections.iter().enumerate() {
            if section.raw_data_size < self.min_section_size as u64 {
                continue; // Skip very small sections
            }

            // Seek to raw data and calculate entropy
            file.seek(SeekFrom::Start(section.raw_data_pointer as u64))?;
            
            let mut buffer = Vec::with_capacity(section.raw_data_size as usize);
            if section.raw_data_size > 0 {
                buffer.resize(section.raw_data_size as usize, 0);
                file.read_exact(&mut buffer).ok();
                
                // Calculate entropy
                let entropy = calculate_entropy(&buffer);
                
                // Calculate compression ratio (raw vs virtual)
                let compression_ratio = if section.virtual_size > 0 {
                    Some(section.raw_data_size as f64 / section.virtual_size as f64)
                } else {
                    None
                };

                analyzed_sections.push(PeSectionInfo {
                    name: String::from_utf8_lossy(&section.name[..]).to_string(),
                    virtual_size: section.virtual_size,
                    raw_data_size: section.raw_data_size,
                    entropy,
                    compression_ratio,
                    characteristics: section.characteristics,
                });

                // Flag suspicious sections
                if entropy > self.threshold {
                    suspicious.push(format!("Section {}: entropy {:.2}", idx + 1, entropy));
                }
            } else {
                analyzed_sections.push(PeSectionInfo {
                    name: String::from_utf8_lossy(&section.name[..]).to_string(),
                    virtual_size: section.virtual_size,
                    raw_data_size: 0,
                    entropy: 0.0,
                    compression_ratio: None,
                    characteristics: section.characteristics,
                });
            }
        }

        // Calculate overall entropy (weighted average by size)
        let total_size: u64 = analyzed_sections.iter()
            .filter(|s| s.raw_data_size > 0)
            .map(|s| s.raw_data_size)
            .sum();
        
        let overall_entropy = if total_size > 0 {
            analyzed_sections.iter()
                .filter(|s| s.raw_data_size > 0)
                .map(|s| (s.entropy * s.raw_data_size as f64))
                .sum::<f64>() / total_size as f64
        } else {
            0.0
        };

        Ok(PeFileAnalysis {
            file_path: full_path,
            is_pe: true,
            header: Some(header),
            sections: analyzed_sections,
            overall_entropy,
            suspicious_sections: suspicious,
        });
    }

    /// Analyze multiple files from a directory.
    pub fn analyze_directory<P: AsRef<std::path::Path>>(
        &self,
        dir_path: P,
    ) -> Result<Vec<PeFileAnalysis>, String> {
        let mut results = Vec::new();
        
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                match self.analyze_file(entry.path()) {
                    Ok(result) => results.push(result),
                    Err(e) => eprintln!("Error analyzing {}: {}", entry.path().display(), e),
                }
            }
        }

        Ok(results)
    }
}

// ============================================================================
// Utility: LittleEndian Reader (inline for self-containment)
// ============================================================================

pub trait LittleEndian {
    fn read_u16(&mut self, buf: &mut [u8]) -> std::io::Result<()>;
    fn read_u32(&mut self, buf: &mut [u8]) -> std::io::Result<()>;
}

impl LittleEndian for File {
    fn read_u16(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut temp = [0u8; 2];
        self.read_exact(&mut temp)?;
        buf.copy_from_slice(&temp);
        Ok(())
    }

    fn read_u32(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut temp = [0u8; 4];
        self.read_exact(&mut temp)?;
        buf.copy_from_slice(&temp);
        Ok(())
    }
}

// ============================================================================
// JSON Serialization (using serde - requires `serde_json`)
// ============================================================================

impl PeFileAnalysis {
    pub fn to_json_string(&self) -> Result<String, String> {
        use std::io::Write;
        
        let mut json = String::new();
        write!(json, "{{\n  \"file\": \"{}\",\n", self.file_path)?;
        write!(json, "  \"is_pe\": {},\n", self.is_pe)?;
        
        if let Some(ref h) = self.header {
            write!(json, "  \"header\": {{\n    \"magic\": {:?},\n", h.magic)?;
            write!(json, "    \"machine\": {:?},\n", h.machine)?;
            write!(json, "    \"sections_count\": {}\n", h.number_of_sections)?;
            write!(json, "  }},\n")?;
        }

        let total_size: u64 = self.sections.iter()
            .filter(|s| s.raw_data_size > 0)
            .map(|s| s.raw_data_size)
            .sum();
        
        write!(json, "  \"overall_entropy\": {:.2},\n", self.overall_entropy)?;
        write!(json, "  \"total_analyzed_bytes\": {},\n", total_size)?;

        if !self.suspicious_sections.is_empty() {
            let formatted: Vec<String> = self.suspicious_sections.iter()
                .map(|s| format!("    - {}", s))
                .collect();
            write!(json, "  \"suspicious_sections\": [\n{}\n  ]", 
                   formatted.join(",\n"))?;
        } else {
            write!(json, "  \"suspicious_sections\": []")?;
        }

        write!(json, "\n}}")?;
        
        Ok(json)
    }
}

// ============================================================================
// Demo / Entry Point
// ============================================================================

fn main() -> Result<(), String> {
    println!("=== PackPeek Entropy Analyzer ===\n");

    // Example 1: Analyze a single file (use your own path or sample)
    let analyzer = EntropyAnalyzer::new(7.0);
    
    // Try to analyze the current executable itself as a demo
    let exe_path = std::env::args()
        .next()
        .unwrap_or_else(|| String::from("target/debug/packpeek"))
        .replace('\\', "/");

    println!("Analyzing: {}", exe_path);
    
    match analyzer.analyze_file(&exe_path) {
        Ok(analysis) => {
            if analysis.is_pe {
                println!("\n--- PE Analysis Results ---\n");
                
                println!("Header Info:");
                let h = analysis.header.as