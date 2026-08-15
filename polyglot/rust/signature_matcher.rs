use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Packer signatures database
const PACKER_SIGNATURES: &[(&[u8], &str)] = &[
    // UPX variants
    (b"\x14\x0A\x02\xB7", "UPX!"),
    (b"TXSP", "ASPack"),
    (b"MPRE", "MPRESS"),
    (b"VMPR", "VMProtect"),
    (b"VMPS", "VMProtect"),
    (b"\x54\x68\x6D\x64", "Themida"),
];

/// Result of a signature match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub packer: String,
    pub offset: u64,
    pub size: usize,
    pub data: Vec<u8>,
}

/// Entropy analysis result for a memory region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    pub start_offset: u64,
    pub end_offset: u64,
    pub entropy: f32,
    pub is_obfuscated: bool,
}

/// Complete analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub matches: Vec<SignatureMatch>,
    pub entropy_regions: Vec<EntropyResult>,
    pub overall_entropy: f32,
    pub packed: bool,
    pub yara_rules: String,
    pub sarif_report: String,
}

/// Configuration for the matcher
#[derive(Debug, Clone)]
pub struct MatcherConfig {
    pub scan_sections: bool,
    pub entropy_threshold: f32,
    pub min_match_size: usize,
}

impl Default for MatcherConfig {
    fn default() -> Self {
        Self {
            scan_sections: true,
            entropy_threshold: 7.0,
            min_match_size: 4,
        }
    }
}

/// Calculate Shannon entropy of a byte slice
pub fn calculate_entropy(data: &[u8]) -> f32 {
    let mut freq = [0u64; 256];
    
    for &byte in data {
        freq[byte as usize] += 1;
    }
    
    let len = data.len() as f32;
    if len == 0.0 {
        return 0.0;
    }
    
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count / len;
            entropy -= (p * p.ln()).min(f32::MAX);
        }
    }
    
    entropy
}

/// Scan a binary file for packer signatures
pub fn scan_signatures(
    data: &[u8],
    config: &MatcherConfig,
) -> Vec<SignatureMatch> {
    let mut matches = Vec::new();
    let min_size = config.min_match_size;
    
    // Create a lookup table for faster matching
    let mut sig_table: HashMap<u64, Vec<&[u8]>> = HashMap::new();
    
    for (sig_data, _) in PACKER_SIGNATURES {
        if sig_data.len() < min_size {
            continue;
        }
        
        // Create hash of signature for quick lookup
        let mut hasher = Sha256::new();
        hasher.update(sig_data);
        let hash = hasher.finalize().as_slice()[..8].to_vec();
        
        sig_table.entry(hash).or_insert_with(Vec::new).push(*sig_data);
    }
    
    // Scan for exact signature matches
    for (offset, &byte) in data.iter().enumerate() {
        if offset + min_size > data.len() {
            break;
        }
        
        let chunk = &data[offset..(offset + min_size)];
        let mut hasher = Sha256::new();
        hasher.update(chunk);
        let hash = hasher.finalize().as_slice()[..8].to_vec();
        
        if let Some(sigs) = sig_table.get(&hash) {
            for &sig in sigs {
                if chunk == sig {
                    // Verify full signature match
                    if chunk.len() >= min_size && chunk[..min_size] == sig[..min_size] {
                        matches.push(SignatureMatch {
                            packer: format!("{} (partial)", sig_data.iter().collect::<String>()),
                            offset,
                            size: min_size,
                            data: chunk.to_vec(),
                        });
                    }
                }
            }
        }
    }
    
    // Deduplicate matches
    let mut unique_matches = Vec::new();
    for match_item in matches {
        if !unique_matches.iter().any(|m| m.offset == match_item.offset) {
            unique_matches.push(match_item);
        }
    }
    
    unique_matches.sort_by_key(|m| m.offset);
    unique_matches
}

/// Scan memory regions for entropy anomalies (common in packed binaries)
pub fn scan_entropy_regions(
    data: &[u8],
    config: &MatcherConfig,
) -> Vec<EntropyResult> {
    let threshold = config.entropy_threshold;
    let mut results = Vec::new();
    
    // Scan 4KB chunks for entropy anomalies
    const CHUNK_SIZE: usize = 4096;
    const STEP_SIZE: usize = 1024;
    
    for i in (0..data.len()).step_by(STEP_SIZE) {
        let end = std::cmp::min(i + CHUNK_SIZE, data.len());
        let chunk = &data[i..end];
        
        if chunk.is_empty() {
            continue;
        }
        
        let entropy = calculate_entropy(chunk);
        let is_obfuscated = entropy > threshold || 
                          (chunk.len() >= 1024 && entropy > 6.5);
        
        results.push(EntropyResult {
            start_offset: i as u64,
            end_offset: (end - 1) as u64,
            entropy,
            is_obfuscated,
        });
    }
    
    // Filter to only obfuscated regions
    results.retain(|r| r.is_obfuscated);
    results.sort_by_key(|r| r.start_offset);
    results
}

/// Calculate overall binary entropy
pub fn calculate_overall_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    
    // Sample the middle portion to avoid header/footer bias
    let mid_start = (data.len() / 4).max(1);
    let mid_end = (data.len() * 3) / 4;
    let sample = &data[mid_start..mid_end];
    
    calculate_entropy(sample)
}

/// Generate YARA rules from detected packers
pub fn generate_yara_rules(matches: &[SignatureMatch]) -> String {
    let mut unique_packers: HashSet<String> = HashSet::new();
    
    for match_item in matches.iter() {
        // Extract packer name (first 20 chars max)
        let name = &match_item.packer[..std::cmp::min(20, match_item.packer.len())];
        unique_packers.insert(name.to_string());
    }
    
    let mut rules = String::new();
    rules.push_str("rule PackPeek_Detected_Packers {\n");
    rules.push_str("\tmeta:\n");
    rules.push_str("\t\tdescription = \"Auto-generated by packpeek signature matcher\"\n");
    rules.push_str("\t\tauthor = \"packpeek\"\n");
    rules.push_str("\t\tversion = \"1.0\"\n\n");
    
    for (i, packer) in unique_packers.iter().enumerate() {
        let rule_name = format!("{}_Match", packer.replace('-', "_"));
        
        if i == 0 {
            rules.push_str(&format!(r#"\tstrings:$/{}/"#, packer));
        } else {
            rules.push_str("\n\tstrings:");
        }
        rules.push_str(&format!($/{}"/", packer));
        
        // Add condition for this rule
        if i == 0 {
            rules.push_str(&format!(r#"\n\tcondition:\n\t\t$/{}/"#, packer));
        } else {
            rules.push_str("\n\n");
        }
    }
    
    rules.push('\n');
    rules.push('}');
    rules
    
}

/// Generate SARIF report from analysis results
pub fn generate_sarif_report(result: &AnalysisResult) -> String {
    use serde_json;
    
    let mut sarif = serde_json::json!({
        "version": "2.1",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "packpeek",
                        "version": "signature_matcher",
                        "informationUri": "https://github.com/packpeek/signature_matcher"
                    }
                },
                "results": []
            }
        ]
    });
    
    // Add each match as a result
    for match_item in &result.matches {
        let mut run = sarif["runs"][0]["tool"].as_object_mut().unwrap();
        
        let rule_id = format!("PackPeek_{}", match_item.packer.replace('-', "_"));
        
        let result_obj = serde_json::json!({
            "ruleId": rule_id,
            "level": if match_item.size > 8 { "error" } else { "note" },
            "message": {
                "text": format!("Detected {} signature at offset 0x{:X}", 
                               match_item.packer, match_item.offset)
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "memory",
                            "region": {
                                "startLine": (match_item.offset / 16) as u32 + 1,
                                "sourceLanguage": "C"
                            }
                        },
                        "address": format!("0x{:X}", match_item.offset)
                    }
                }
            ],
            "properties": {
                "offset": match_item.offset.to_string(),
                "size": match_item.size.to_string(),
                "packer_type": match_item.packer.clone()
            }
        });
        
        sarif["runs"][0]["results"].push(result_obj);
    }
    
    // Add entropy results as notes
    for entropy in &result.entropy_regions {
        let result_obj = serde_json::json!({
            "ruleId": "PackPeek_Entropy",
            "level": if entropy.is_obfuscated { "warning" } else { "note" },
            "message": {
                "text": format!("High entropy region: 0x{:X}-0x{:X} (entropy: {:.2})",
                               entropy.start_offset, 
                               entropy.end_offset,
                               entropy.entropy)
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "memory",
                            "region": {
                                "startLine": (entropy.start_offset / 16) as u32 + 1,
                                "sourceLanguage": "C"
                            }
                        },
                        "address": format!("0x{:X}", entropy.start_offset)
                    }
                }
            ],
            "properties": {
                "start_offset": entropy.start_offset.to_string(),
                "end_offset": entropy.end_offset.to_string(),
                "entropy": entropy.entropy.to_string()
            }
        });
        
        sarif["runs"][0]["results"].push(result_obj);
    }
    
    // Convert to string and format nicely
    let json_str = serde_json::to_string_pretty(&sarif).unwrap_or_default();
    json_str
}

/// Main analysis function that orchestrates all detection
pub fn analyze_binary(
    data: &[u8],
    config: &MatcherConfig,
) -> AnalysisResult {
    // Scan for packer signatures
    let matches = scan_signatures(data, config);
    
    // Calculate overall entropy
    let overall_entropy = calculate_overall_entropy(data);
    
    // Determine if binary is likely packed
    let packed = !matches.is_empty() || 
                  (overall_entropy > 7.5 && data.len() > 1024 * 1024) ||
                  (overall_entropy > 6.8 && data.len() > 512 * 1024);
    
    // Scan for entropy anomalies
    let entropy_regions = scan_entropy_regions(data, config);
    
    // Generate reports
    let yara_rules = generate_yara_rules(&matches);
    let sarif_report = generate_sarif_report(&AnalysisResult {
        matches: matches.clone(),
        entropy_regions: entropy_regions.clone(),
        overall_entropy,
        packed,
        yara_rules: String::new(),
        sarif_report: String::new(),
    });
    
    AnalysisResult {
        matches,
        entropy_regions,
        overall_entropy,
        packed,
        yara_rules,
        sarif_report,
    }
}

/// Demo/test harness for the signature matcher
fn main() -> io::Result<()> {
    println!("=== PackPeek Signature Matcher Demo ===\n");
    
    // Test 1: UPX-packed binary (simulated)
    let upx_header = vec![0x14, 0x0A, 0x02, 0xB7];
    println!("Test 1: UPX Header Detection");
    println!("Header bytes: {:02X?}", upx_header);
    
    let mut test_data = vec![];
    // Add some padding
    for _ in 0..512 {
        test_data.push((rand::random::<u8>() & 0xFF) as u8);
    }
    // Insert UPX header
    test_data.extend_from_slice(&upx_header);
    
    let result = analyze_binary(&test_data, &MatcherConfig::default());
    println!("Matches found: {}", result.matches.len());
    for match_item in &result.matches {
        println!("  - {}: offset=0x{:X}, size={}", 
                 match_item.packer, match_item.offset, match_item.size);
    }
    
    // Test 2: High entropy region detection
    println!("\nTest 2: Entropy Analysis");
    let high_entropy_data = vec![0xFF; 1024];
    let entropy = calculate_entropy(&high_entropy_data);
    println!("Entropy of 1KB of 0xFF: {:.2}", entropy);
    
    // Test 3: Mixed content with multiple packers
    println!("\nTest 3: Multi-Packer Detection");
    let mut mixed_data = vec![0x4D; 256]; // MPRESS-like start
    for _ in 0..1024 {
        mixed_data.push((rand::random::<u8>() & 0xFF) as u8);
    }
    
    // Insert ASPack signature
    let aspax_sig = b"TXSP";
    mixed_data.extend_from_slice(aspax_sig);
    
    let result = analyze_binary(&mixed_data, &MatcherConfig::default());
    println!("Total matches: {}", result.matches.len());
    println!("Binary likely packed: {}", result.packed);
    
    // Test 4: YARA generation
    println!("\nTest 4: Generated YARA Rules");
    let yara = generate_yara_rules(&result.matches);
    println!("{}", yara);
    
    // Test 5: SARIF report preview
    println!("\nTest 5: SARIF Report (first 500 chars)");
    let sarif = generate_sarif_report(&result);
    println!("{}...", &sarif[..std::cmp::min(