import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface PackerInfo {
  name: string;
  magic: number[];
  version?: string;
  confidence: number; // 0-100
}

interface EntropyResult {
  totalBits: number;
  entropyPerByte: number;
  isHighEntropy: boolean;
}

interface PEHeaderInfo {
  machine: string;
  numberOfSections: number;
  timestamp: Date | null;
  subsystem: string;
  characteristics: string[];
}

interface AnalysisResult {
  filename: string;
  sizeBytes: number;
  magicNumbers: Map<number, PackerInfo>;
  entropy: EntropyResult;
  peHeader: PEHeaderInfo | null;
  yaraRules: string[];
  sarifResults: SarifResultItem[];
}

interface SarifResultItem {
  id: string;
  ruleId: string;
  level: 'note' | 'warning' | 'error';
  message: string;
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
}

// ============================================================================
// CONSTANTS & MAGIC NUMBERS
// ============================================================================

const PE_MAGIC = 0x4D5A; // "MZ"
const UPX_MAGIC = [0x55, 0x54]; // "UT"
const ASPACK_MAGIC = [0x21, 0x41, 0x53, 0x50]; // "!ASP"
const THEMIDA_MAGIC = [0x74, 0x68, 0x6D, 0x64]; // "thmd"
const VMProtect_MAGIC = [0x56, 0x4D, 0x50, 0x31]; // "VMP1"
const MPRESS_MAGIC = [0x4D, 0x50, 0x52, 0x45]; // "MPRE"

const PE_HEADER_OFFSET = 64;
const PE_MACHINE_OFFSET = 180;
const PE_SUBSYSTEM_OFFSET = 182;

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function readUInt16LE(buffer: Buffer, offset: number): number {
  return (buffer[offset] | buffer[offset + 1] << 8);
}

function readUInt32LE(buffer: Buffer, offset: number): number {
  let result = 0;
  for (let i = 0; i < 4; i++) {
    result |= buffer[offset + i] << (i * 8);
  }
  return result;
}

function readStringLE(buffer: Buffer, offset: number, length: number): string {
  let str = '';
  for (let i = 0; i < length && i < buffer.length - offset; i++) {
    const charCode = buffer[offset + i];
    if (charCode === 0) break;
    str += String.fromCharCode(charCode);
  }
  return str.trim();
}

function calculateEntropy(buffer: Buffer): EntropyResult {
  // Calculate Shannon entropy per byte
  const frequency: number[] = new Array(256).fill(0);
  
  for (let i = 0; i < buffer.length; i++) {
    frequency[buffer[i]]++;
  }

  let totalBits = 0;
  let maxFrequency = 0;

  for (const count of frequency) {
    if (count > 0) {
      const probability = count / buffer.length;
      totalBits += -probability * Math.log2(probability);
      maxFrequency = Math.max(maxFrequency, count);
    }
  }

  // Normalize to bits per byte (max is ~8 for uniform distribution)
  const entropyPerByte = totalBits / 8;

  return {
    totalBits: Math.round(totalBits * 100) / 100,
    entropyPerByte: Math.round(entropyPerByte * 100) / 100,
    isHighEntropy: entropyPerByte > 6.5, // Threshold for packed/encrypted content
  };
}

function detectPEHeader(buffer: Buffer): PEHeaderInfo | null {
  if (buffer.length < PE_HEADER_OFFSET + 2 || readUInt16LE(buffer, 0) !== PE_MAGIC) {
    return null;
  }

  const machine = readUInt16LE(buffer, PE_MACHINE_OFFSET);
  let subsystem: string;
  
  switch (machine) {
    case 0x14c: subsystem = 'Intel x86'; break;
    case 0x8664: subsystem = 'AMD64 / x64'; break;
    case 0xaa: subsystem = 'ARM'; break;
    default: subsystem = `Unknown (${machine.toString(16)})`;
  }

  const timestamp = readUInt32LE(buffer, PE_HEADER_OFFSET + 4);
  const timestampDate = timestamp > 0 ? new Date(timestamp * 1000) : null;

  // Parse characteristics flags
  const characteristics: string[] = [];
  if (readUInt16LE(buffer, PE_HEADER_OFFSET + 2) & 0x0001) {
    characteristics.push('Relocatable');
  }
  if (readUInt16LE(buffer, PE_HEADER_OFFSET + 2) & 0x0002) {
    characteristics.push('ExecutableImage');
  }
  if (readUInt16LE(buffer, PE_HEADER_OFFSET + 2) & 0x0004) {
    characteristics.push('LineNumbers');
  }
  if (readUInt16LE(buffer, PE_HEADER_OFFSET + 2) & 0x0008) {
    characteristics.push('WorkingSet');
  }
  if (readUInt16LE(buffer, PE_HEADER_OFFSET + 2) & 0x0010) {
    characteristics.push('ReadOnlyData');
  }
  if (readUInt16LE(buffer, PE_HEADER_OFFSET + 2) & 0x0020) {
    characteristics.push('SharedLibrary');
  }
  if (readUInt16LE(buffer, PE_HEADER_OFFSET + 2) & 0x0040) {
    characteristics.push('ExecutableCode');
  }

  return {
    machine: subsystem,
    numberOfSections: readUInt16LE(buffer, PE_HEADER_OFFSET),
    timestamp: timestampDate,
    subsystem: 'PE32', // Simplified for this demo
    characteristics,
  };
}

function detectPacker(buffer: Buffer): PackerInfo[] {
  const results: PackerInfo[] = [];

  // Check UPX (UT magic at offset 0x14)
  if (buffer.length >= 0x18 && 
      buffer[0x14] === UPX_MAGIC[0] && 
      buffer[0x15] === UPX_MAGIC[1]) {
    const version = readStringLE(buffer, 0x16, 2);
    results.push({
      name: 'UPX',
      magic: [UPX_MAGIC[0], UPX_MAGIC[1]],
      version: `v${version || 'unknown'}`,
      confidence: 95,
    });
  }

  // Check ASPack
  if (buffer.length >= 4 && 
      buffer[0] === ASPACK_MAGIC[0] &&
      buffer[1] === ASPACK_MAGIC[1] &&
      buffer[2] === ASPACK_MAGIC[2] &&
      buffer[3] === ASPACK_MAGIC[3]) {
    results.push({
      name: 'ASPack',
      magic: [APSPACK_MAGIC[0], ASPACK_MAGIC[1], ASPACK_MAGIC[2], ASPACK_MAGIC[3]],
      confidence: 98,
    });
  }

  // Check Themida
  if (buffer.length >= 4 && 
      buffer[0] === THEMIDA_MAGIC[0] &&
      buffer[1] === THEMIDA_MAGIC[1] &&
      buffer[2] === THEMIDA_MAGIC[2] &&
      buffer[3] === THEMIDA_MAGIC[3]) {
    results.push({
      name: 'Themida',
      magic: [THEMIDA_MAGIC[0], THEMIDA_MAGIC[1], THEMIDA_MAGIC[2], THEMIDA_MAGIC[3]],
      confidence: 96,
    });
  }

  // Check VMProtect
  if (buffer.length >= 4 && 
      buffer[0] === VMProtect_MAGIC[0] &&
      buffer[1] === VMProtect_MAGIC[1] &&
      buffer[2] === VMProtect_MAGIC[2] &&
      buffer[3] === VMProtect_MAGIC[3]) {
    results.push({
      name: 'VMProtect',
      magic: [VMProtect_MAGIC[0], VMProtect_MAGIC[1], VMProtect_MAGIC[2], VMProtect_MAGIC[3]],
      confidence: 97,
    });
  }

  // Check MPRESS
  if (buffer.length >= 4 && 
      buffer[0] === MPRESS_MAGIC[0] &&
      buffer[1] === MPRESS_MAGIC[1] &&
      buffer[2] === MPRESS_MAGIC[2] &&
      buffer[3] === MPRESS_MAGIC[3]) {
    results.push({
      name: 'MPRESS',
      magic: [MPRESS_MAGIC[0], MPRESS_MAGIC[1], MPRESS_MAGIC[2], MPRESS_MAGIC[3]],
      confidence: 94,
    });
  }

  return results;
}

function generateYaraRules(packers: PackerInfo[], entropy: EntropyResult): string[] {
  const rules: string[] = [];

  // UPX rule
  if (packers.some(p => p.name === 'UPX')) {
    rules.push(`
rule UPX_Detector {
  meta:
    author = "PackPeek"
    description = "Detects UPX packing"
    tags = "packing,upx"

  strings:
    $upx_magic = "UT" at offset 0x14 with length 2
    $upx_version = { "UPX!" "UPX0" } of ascii

  condition:
    uint16(0x14) == 0x5554 and 
    any of ($upx_magic, $upx_version)
}
`);
  }

  // ASPack rule
  if (packers.some(p => p.name === 'ASPack')) {
    rules.push(`
rule ASPack_Detector {
  meta:
    author = "PackPeek"
    description = "Detects ASPack packing"
    tags = "packing,aspack"

  strings:
    $aspack_magic = "!ASP" at offset 0x00 with length 4

  condition:
    uint8(0x00) == 0x21 and 
    uint8(0x01) == 0x41 and 
    uint8(0x02) == 0x53 and 
    uint8(0x03) == 0x50
}
`);
  }

  // High entropy rule (potential encryption/VMProtect)
  if (entropy.isHighEntropy) {
    rules.push(`
rule Potential_Virtualization {
  meta:
    author = "PackPeek"
    description = "Detects potentially virtualized or encrypted binary"
    tags = "entropy,virtualization,encryption"

  condition:
    uint16(0x00) == 0x4D5A and 
    float(entropy_per_byte) > 6.5
}
`);
  }

  return rules;
}

function generateSarifResults(filename: string, packers: PackerInfo[], entropy: EntropyResult): SarifResultItem[] {
  const results: SarifResultItem[] = [];

  // Add packer findings as notes
  for (const packer of packers) {
    results.push({
      id: `packer_${packer.name.toLowerCase()}`,
      ruleId: `PackPeek.${packer.name}_DETECTED`,
      level: 'note',
      message: `${packer.name} packing detected with ${Math.round(packer.confidence)}% confidence.`,
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: filename },
        },
      }],
    });
  }

  // Add entropy finding as warning if high
  if (entropy.isHighEntropy) {
    results.push({
      id: 'high_entropy',
      ruleId: 'PackPeek.HIGH_ENTROPY',
      level: 'warning',
      message: `Binary shows high entropy (${entropy.entropyPerByte.toFixed(2)} bits/byte), suggesting encryption or virtualization protection.`,
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: filename },
        },
      }],
    });
  }

  // Add PE header info as note if valid
  const peHeader = detectPEHeader(Buffer.from(filename, 'binary'));
  if (peHeader) {
    results.push({
      id: 'pe_header',
      ruleId: 'PackPeek.PE_HEADER_PARSED',
      level: 'note',
      message: `Valid PE header found. Machine: ${peHeader.machine}, Sections: ${peHeader.numberOfSections}.`,
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: filename },
        },
      }],
    });
  }

  return results;
}

// ============================================================================
// MAIN PARSER CLASS
// ============================================================================

export class BinaryParser {
  private buffer: Buffer;
  private result: AnalysisResult | null = null;

  constructor(buffer: Buffer) {
    this.buffer = buffer;
  }

  analyze(): AnalysisResult {
    if (this.result) return this.result;

    const filename = 'input.bin'; // Default name when no file path provided
    const sizeBytes = this.buffer.length;

    // Detect packers
    const packers = detectPacker(this.buffer);

    // Calculate entropy
    const entropy = calculateEntropy(this.buffer);

    // Parse PE header if present
    let peHeader: PEHeaderInfo | null = null;
    if (readUInt16LE(this.buffer, 0) === PE_MAGIC) {
      peHeader = detectPEHeader(this.buffer);
    }

    // Generate YARA rules
    const yaraRules = generateYaraRules(packers, entropy);

    // Generate SARIF results
    const sarifResults = generateSarifResults(filename, packers, entropy);

    this.result = {
      filename: filename,
      sizeBytes: sizeBytes,
      magicNumbers: new Map(
        packers.map((p) => [p.magic[0], p])
      ),
      entropy: entropy,
      peHeader: peHeader,
      yaraRules: yaraRules,
      sarifResults: sarifResults,
    };

    return this.result;
  }

  getAnalysis(): AnalysisResult {
    if (!this.result) {
      throw new Error('Call analyze() first');
    }
    return this.result;
  }

  reset(): void {
    this.buffer = Buffer.from(this.buffer);
    this.result = null;
  }
}

// ============================================================================
// EXPORTED FUNCTIONS FOR EASE OF USE
// ============================================================================

export function analyzeBinaryFile(filePath: string): AnalysisResult {
  const buffer = fs.readFileSync(filePath);
  return new BinaryParser(buffer).analyze();
}

export function analyzeBuffer(buffer: Buffer): AnalysisResult {
  return new BinaryParser(buffer).analyze();
}

// ============================================================================
// DEMO / RUNNABLE ENTRY POINT
// ============================================================================

function main(): void {
  // Demo with a sample PE file (minimal valid MZ header)
  const demoBuffer = Buffer.from([
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, // MZ header
    0x04, 0x00, 0x0C, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ... rest of minimal PE header
    0x