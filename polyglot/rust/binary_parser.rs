use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use serde::{Deserialize, Serialize};

/// Metadata about the scanned binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMetadata {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
}

/// Result of packer detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerResult {
    pub name: Option<String>,
    pub confidence: f32,
    pub signature_offset: u64,
    pub entropy: f32,
    pub is_packed: bool,
}

/// Complete analysis result for a binary file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub metadata: BinaryMetadata,
    pub packer_results: Vec<PackerResult>,
    pub entropy_score: f32,
    pub is_suspicious: bool,
}

/// Thresholds for detection
#[derive(Debug, Clone)]
struct DetectionThresholds {
    /// Minimum entropy to consider as packed (typical range 6.5-7.8)
    min_entropy_packed: f32,
    /// Maximum entropy before considering random data
    max_entropy_random: f32,
}

impl Default for DetectionThresholds {
    fn default() -> Self {
        Self {
            min_entropy_packed: 6.5,
            max_entropy_random: 7.8,
        }
    }
}

/// Calculate Shannon entropy of a binary file
pub fn calculate_entropy<R: Read + Seek>(reader: &mut R) -> Result<f32, std::io::Error> {
    const BYTE_COUNT: usize = 1 << 16; // 65536 bytes for frequency analysis
    
    let mut buffer = [0u8; 256];
    let mut byte_counts = [0usize; 256];
    
    // Read entire file into memory for entropy calculation
    let total_size = reader.seek(SeekFrom::End(0))?;
    if total_size == 0 {
        return Ok(0.0);
    }
    
    reader.seek(SeekFrom::Start(0))?;
    
    // First pass: count byte frequencies
    for _ in 0..BYTE_COUNT {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        for &b in &buffer[..bytes_read] {
            byte_counts[b as usize] += 1;
        }
    }
    
    // Calculate Shannon entropy: H = -Σ p(x) * log2(p(x))
    let mut entropy = 0.0f32;
    for count in &byte_counts {
        if *count > 0 {
            let probability = (*count as f32 / total_size as f32);
            entropy -= probability * (probability.ln() / std::f32::consts::LN_2);
        }
    }
    
    Ok(entropy)
}

/// Check if file has UPX packer signature
pub fn check_upx<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<bool, std::io::Error> {
    const UPX_MAGIC: &[u8; 3] = b"UPX";
    
    let mut buffer = [0u8; 12];
    reader.seek(SeekFrom::Start(offset))?;
    let bytes_read = reader.read(&mut buffer)?;
    
    if bytes_read >= 3 && &buffer[..3] == UPX_MAGIC {
        // Verify with additional signature checks
        const UPX0: &[u8; 4] = b"UPX0";
        const UPX1: &[u8; 4] = b"UPX1";
        const UPX2: &[u8; 4] = b"UPX2";
        
        for &magic in &[UPX0, UPX1, UPX2] {
            if bytes_read >= 4 && &buffer[..4] == magic {
                return Ok(true);
            }
        }
    }
    
    Ok(false)
}

/// Check if file has ASPack signature
pub fn check_aspack<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<bool, std::io::Error> {
    const ASPACK_MAGIC: &[u8; 6] = b"ASPack";
    
    let mut buffer = [0u8; 12];
    reader.seek(SeekFrom::Start(offset))?;
    let bytes_read = reader.read(&mut buffer)?;
    
    if bytes_read >= 6 && &buffer[..6] == ASPACK_MAGIC {
        return Ok(true);
    }
    
    // Check for ASPack header pattern (0x54, 0x41, 0x53, 0x50, 0x6B)
    const HEADER_PATTERN: &[u8; 5] = b"ASPB";
    if bytes_read >= 5 && &buffer[..5] == HEADER_PATTERN {
        return Ok(true);
    }
    
    Ok(false)
}

/// Check if file has Themida signature
pub fn check_themida<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<bool, std::io::Error> {
    const THEMIDA_MAGIC: &[u8; 7] = b"THEMIDA";
    
    let mut buffer = [0u8; 12];
    reader.seek(SeekFrom::Start(offset))?;
    let bytes_read = reader.read(&mut buffer)?;
    
    if bytes_read >= 7 && &buffer[..7] == THEMIDA_MAGIC {
        return Ok(true);
    }
    
    // Check for Themida header pattern
    const HEADER_PATTERN: &[u8; 6] = b"THEM";
    if bytes_read >= 4 && &buffer[..4] == HEADER_PATTERN {
        return Ok(true);
    }
    
    Ok(false)
}

/// Check if file has MPRESS signature
pub fn check_mpress<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<bool, std::io::Error> {
    const MPRESS_MAGIC: &[u8; 6] = b"MPRESS";
    
    let mut buffer = [0u8; 12];
    reader.seek(SeekFrom::Start(offset))?;
    let bytes_read = reader.read(&mut buffer)?;
    
    if bytes_read >= 6 && &buffer[..6] == MPRESS_MAGIC {
        return Ok(true);
    }
    
    // Check for MPRESS header pattern
    const HEADER_PATTERN: &[u8; 5] = b"MPRS";
    if bytes_read >= 4 && &buffer[..4] == HEADER_PATTERN {
        return Ok(true);
    }
    
    Ok(false)
}

/// Check if file has VMProtect signature
pub fn check_vmprotect<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<bool, std::io::Error> {
    const VMPROTECT_MAGIC: &[u8; 10] = b"VMProtect";
    
    let mut buffer = [0u8; 20];
    reader.seek(SeekFrom::Start(offset))?;
    let bytes_read = reader.read(&mut buffer)?;
    
    if bytes_read >= 10 && &buffer[..10] == VMPROTECT_MAGIC {
        return Ok(true);
    }
    
    // Check for VMProtect header pattern
    const HEADER_PATTERN: &[u8; 9] = b"VMProt";
    if bytes_read >= 6 && &buffer[..6] == HEADER_PATTERN {
        return Ok(true);
    }
    
    Ok(false)
}

/// Analyze a single binary file
pub fn analyze_binary<P: AsRef<Path>>(path: P, thresholds: DetectionThresholds) -> AnalysisResult {
    let metadata = get_metadata(path.as_ref());
    
    // Open file for reading
    let mut file = File::open(&metadata.path).expect("Failed to open file");
    let mut reader = BufReader::new(file);
    
    // Calculate entropy
    let entropy = calculate_entropy(&mut reader).unwrap_or(0.0);
    
    // Reset position for signature checking
    reader.seek(SeekFrom::Start(0)).unwrap();
    
    // Check packer signatures at various offsets
    const OFFSETS: &[u64] = &[0, 256, 512, 1024, 2048];
    
    let mut packer_results = Vec::new();
    let mut is_packed = false;
    let mut max_confidence = 0.0f32;
    let mut best_match: Option<&str> = None;
    let mut best_offset: u64 = 0;
    
    for &offset in OFFSETS {
        if offset >= metadata.size {
            break;
        }
        
        // Check each packer at this offset
        let upx_result = check_upx(&mut reader, offset).unwrap_or(false);
        let aspack_result = check_aspack(&mut reader, offset).unwrap_or(false);
        let themida_result = check_themida(&mut reader, offset).unwrap_or(false);
        let mpress_result = check_mpress(&mut reader, offset).unwrap_or(false);
        let vmprotect_result = check_vmprotect(&mut reader, offset).unwrap_or(false);
        
        // Calculate confidence based on entropy and signature match
        let mut confidence = 0.0f32;
        if upx_result {
            best_match = Some("UPX");
            best_offset = offset;
            confidence = std::cmp::max(confidence, 0.95);
            is_packed = true;
        } else if aspack_result {
            best_match = Some("ASPack");
            best_offset = offset;
            confidence = std::cmp::max(confidence, 0.85);
            is_packed = true;
        } else if themida_result {
            best_match = Some("Themida");
            best_offset = offset;
            confidence = std::cmp::max(confidence, 0.90);
            is_packed = true;
        } else if mpress_result {
            best_match = Some("MPRESS");
            best_offset = offset;
            confidence = std::cmp::max(confidence, 0.85);
            is_packed = true;
        } else if vmprotect_result {
            best_match = Some("VMProtect");
            best_offset = offset;
            confidence = std::cmp::max(confidence, 0.92);
            is_packed = true;
        }
        
        // Adjust confidence based on entropy match
        let entropy_confidence = if entropy >= thresholds.min_entropy_packed 
                               && entropy <= thresholds.max_entropy_random {
            1.0
        } else if entropy > thresholds.max_entropy_random {
            0.5
        } else {
            0.3
        };
        
        confidence = (confidence + entropy_confidence) / 2.0;
        max_confidence = std::cmp::max(max_confidence, confidence);
    }
    
    // If no signature found but high entropy, consider suspicious
    if !is_packed && entropy >= thresholds.min_entropy_packed {
        is_packed = true;
        best_match = Some("High Entropy (Possible Packer)");
        max_confidence = std::cmp::min(max_confidence, 0.75);
    }
    
    AnalysisResult {
        metadata,
        packer_results: vec![PackerResult {
            name: best_match.map(|s| s.to_string()),
            confidence,
            signature_offset: best_offset,
            entropy,
            is_packed,
        }],
        entropy_score: entropy,
        is_suspicious: is_packed || entropy > thresholds.max_entropy_random,
    }
}

/// Get file metadata (size, SHA256)
fn get_metadata<P: AsRef<Path>>(path: P) -> BinaryMetadata {
    let path = path.as_ref();
    let size = fs::metadata(path).expect("Failed to get metadata").len();
    
    // Calculate SHA256 for additional verification
    let sha256 = calculate_sha256(&path).unwrap_or_else(|| "unknown".to_string());
    
    BinaryMetadata {
        path: path.to_string_lossy().into_owned(),
        size,
        sha256: if sha256 != "unknown" { Some(sha256) } else { None },
    }
}

/// Calculate SHA256 hash of a file
fn calculate_sha256<P: AsRef<Path>>(path: P) -> Result<String, std::io::Error> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    let mut file = File::open(path)?;
    
    const BUFFER_SIZE: usize = 1 << 16; // 64KB chunks
    
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", hasher.finalize()))
}

/// Main entry point with demo functionality
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Default thresholds
    let thresholds = DetectionThresholds::default();
    
    println!("=== PackPeek Binary Parser Demo ===\n");
    
    // Example: Analyze a sample file (use current executable for demo)
    let sample_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "self".to_string());
    
    println!("Analyzing: {}", sample_path);
    println!();
    
    // Perform analysis
    let result = analyze_binary(&sample_path, thresholds.clone());
    
    // Output results as JSON
    println!("=== Analysis Results (JSON) ===");
    println!("{}", serde_json::to_string_pretty(&result)?);
    println!();
    
    // Human-readable summary
    println!("=== Summary ===");
    println!("File: {}", result.metadata.path);
    println!("Size: {} bytes", result.metadata.size);
    println!("SHA256: {:?}", result.metadata.sha256.as_deref());
    println!("Entropy: {:.4} bits/byte", result.entropy_score);
    println!("Packed: {}", if result.is_suspicious { "Yes" } else { "No" });
    
    if let Some(name) = &result.packer_results[0].name {
        println!("Detected Packer: {}", name);
    }
    
    println!();
    
    // Example: Generate YARA rule snippet
    println!("=== Generated YARA Snippet ===");
    generate_yara_snippet(&result)?;
    
    Ok(())
}

/// Generate a basic YARA rule based on findings
fn generate_yara_snippet(result: &AnalysisResult) -> Result<String, Box<dyn std::error::Error>> {
    let mut yara = String::new();
    
    // Add file metadata hash check
    if let Some(sha256) = &result.metadata.sha256 {
        yara.push_str(&format!(
            "rule PackedFile_{} {{\n",
            sha256
        ));
        yara.push_str("  meta:\n");
        yara.push_str(&format!("    description = \"Packed file detected\"\n"));
        yara.push_str(&format!("    sha256 = \"{sha256}\"\n\n"));
        
        if result.is_suspicious {
            yara.push_str("  strings:\n");
            yara.push_str("    $packed_magic = \"UPX\" ascii\n");