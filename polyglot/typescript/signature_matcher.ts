import { Readable } from 'node:stream';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export interface FileSignature {
  name: string;
  description: string;
  patterns: HexPattern[];
  entropyMin?: number;
  entropyMax?: number;
  stringsMinLen?: number;
}

export type HexPattern = string | { hex: string; wildcard?: boolean };

export interface ScanResult {
  fileName: string;
  fileSize: number;
  matchedSignatures: MatchedSignature[];
  entropy: number;
  topStrings: string[];
  metadata: Partial<Metadata>;
}

export interface MatchedSignature {
  signatureName: string;
  confidence: number; // 0-1, higher is better
  matchesFound: number;
  matchOffsets: number[];
  entropyMatch?: boolean;
  stringsMatch?: boolean;
}

export interface Metadata {
  upx?: { version: string; flags: string };
  aspack?: { version: string; flags: string };
  themida?: { version: string; flags: string };
  mpress?: { version: string; flags: string };
  vmprotect?: { version: string; flags: string };
}

export interface YARARule {
  name: string;
  rules: string[];
  meta: Record<string, string>;
}

export interface SARIFResult {
  $schema: string;
  version: string;
  runs: [{ tool: { driver: { name: string; informationUri: string }; informationUrl: string }, results: any[] }];
}

// ============================================================================
// CONFIGURATION & DEFAULTS
// ============================================================================

const DEFAULT_ENTROPY_THRESHOLD = 6.5;
const DEFAULT_STRING_MIN_LENGTH = 4;
const DEFAULT_CONFIDENCE_THRESHOLD = 0.7;

// Known packer signatures (hex patterns)
export const KNOWN_SIGNATURES: FileSignature[] = [
  {
    name: 'UPX',
    description: 'Ultimate Packer for eXecutables',
    entropyMin: 5.8,
    entropyMax: 7.9,
    stringsMinLen: 4,
    patterns: [
      { hex: '00000103', wildcard: true }, // UPX header magic
      { hex: 'UPX0!' }, // ASCII string match
    ],
  },
  {
    name: 'ASPack',
    description: 'ASPack PE Compact/Encrypter',
    entropyMin: 5.5,
    entropyMax: 7.2,
    stringsMinLen: 4,
    patterns: [
      { hex: '0103' }, // ASPack header
      { hex: 'ASPack!' },
    ],
  },
  {
    name: 'Themida',
    description: 'Themida Protection System',
    entropyMin: 6.0,
    entropyMax: 7.5,
    stringsMinLen: 4,
    patterns: [
      { hex: '0102' }, // Themida header
      { hex: 'Themida!' },
    ],
  },
  {
    name: 'MPRESS',
    description: 'MPress Packer',
    entropyMin: 5.9,
    entropyMax: 7.3,
    stringsMinLen: 4,
    patterns: [
      { hex: '0102' }, // MPress header
      { hex: 'MPress!' },
    ],
  },
  {
    name: 'VMProtect',
    description: 'VMProtect Virtual Machine Protection',
    entropyMin: 6.2,
    entropyMax: 7.8,
    stringsMinLen: 4,
    patterns: [
      { hex: '0103' }, // VMProtect header
      { hex: 'VMProtect!' },
    ],
  },
];

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Convert a string to its hexadecimal representation.
 */
export function strToHex(str: string): string {
  return Buffer.from(str).toString('hex');
}

/**
 * Convert hex string back to binary data (Buffer).
 */
export function hexToBuffer(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

/**
 * Calculate Shannon entropy of a byte array.
 */
function calculateEntropy(data: Uint8Array): number {
  const freq = new Map<number, number>();
  
  for (const byte of data) {
    freq.set(byte, (freq.get(byte) || 0) + 1);
  }

  let entropy = 0;
  const total = data.length;
  
  for (const [byte, count] of freq.entries()) {
    const p = count / total;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Extract printable strings from binary data.
 */
function extractStrings(data: Uint8Array, minLength: number): string[] {
  const strings: string[] = [];
  let currentString = '';

  for (let i = 0; i < data.length; i++) {
    if (data[i] >= 32 && data[i] <= 126) { // Printable ASCII
      currentString += String.fromCharCode(data[i]);
    } else {
      if (currentString.length >= minLength) {
        strings.push(currentString);
      }
      currentString = '';
    }
  }

  // Don't forget the last string
  if (currentString.length >= minLength) {
    strings.push(currentString);
  }

  return strings;
}

/**
 * Scan binary data for hex patterns.
 */
function scanPatterns(data: Uint8Array, patterns: HexPattern[]): Map<string, number[]> {
  const matches = new Map<string, number[]>();

  for (const pattern of patterns) {
    if (typeof pattern === 'string') {
      // ASCII string pattern
      const str = Buffer.from(pattern);
      let offset = 0;
      
      while ((offset = data.indexOf(str, offset)) !== -1) {
        matches.set(pattern, [...(matches.get(pattern) || []), offset]);
        offset += str.length;
      }
    } else if (pattern.hex) {
      // Hex pattern with optional wildcard
      const hexBytes = Buffer.from(pattern.hex, 'hex');
      
      if (!pattern.wildcard) {
        let offset = 0;
        
        while ((offset = data.indexOf(hexBytes, offset)) !== -1) {
          matches.set(pattern.hex, [...(matches.get(pattern.hex) || []), offset]);
          offset += hexBytes.length;
        }
      } else {
        // Wildcard pattern matching (simplified: match anywhere with partial)
        for (let i = 0; i <= data.length - hexBytes.length; i++) {
          let match = true;
          
          for (let j = 0; j < hexBytes.length; j++) {
            if (hexBytes[j] !== -1 && data[i + j] !== hexBytes[j]) {
              match = false;
              break;
            }
          }
          
          if (match) {
            matches.set(pattern.hex, [...(matches.get(pattern.hex) || []), i]);
          }
        }
      }
    }
  }

  return matches;
}

/**
 * Calculate confidence score for a signature match.
 */
function calculateConfidence(
  entropy: number,
  entropyMin?: number,
  entropyMax?: number,
  patternMatches: Map<string, number[]>,
  stringsMatched: Set<string>
): number {
  let score = 0;
  const maxScore = 1.0;

  // Entropy contribution (up to 30%)
  if (entropyMin && entropyMax) {
    if (entropy >= entropyMin && entropy <= entropyMax) {
      score += 0.3;
    } else if (Math.abs(entropy - ((entropyMin + entropyMax) / 2)) < 0.5) {
      score += 0.15;
    }
  }

  // Pattern matches contribution (up to 40%)
  const totalPatterns = KNOWN_SIGNATURES.reduce((sum, sig) => sum + sig.patterns.length, 0);
  let matchedPatterns = 0;

  for (const [pattern, offsets] of patternMatches.entries()) {
    if (offsets.length > 0) {
      // More matches = higher confidence
      const matchCount = Math.min(offsets.length, 5); // Cap at 5 to avoid saturation
      matchedPatterns++;
      score += (matchCount / 5) * 0.4;
    }
  }

  // Normalize pattern contribution
  if (totalPatterns > 0) {
    score = Math.min(score, 0.4 + (matchedPatterns / totalPatterns) * 0.3);
  }

  // String matches contribution (up to 20%)
  const stringScore = stringsMatched.size > 0 ? 0.15 : 0;
  score += stringScore;

  return Math.min(score, maxScore);
}

/**
 * Check if a signature's entropy range is satisfied.
 */
function checkEntropyRange(entropy: number, min?: number, max?: number): boolean {
  if (!min && !max) return true; // No constraints
  if (min && max) return entropy >= min && entropy <= max;
  if (min) return entropy >= min;
  return entropy <= max || false;
}

/**
 * Check if a signature's string requirements are met.
 */
function checkStringsMatch(
  strings: string[],
  minLength: number,
  matchedSignatures: Set<string>
): boolean {
  // Look for known packer strings in the extracted strings
  const knownStrings = new Set([
    'UPX0!', 'ASPack!', 'Themida!', 'MPress!', 'VMProtect!'
  ]);

  let foundKnown = false;
  
  for (const str of strings) {
    if (knownStrings.has(str)) {
      matchedSignatures.add(str);
      foundKnown = true;
    }
  }

  return foundKnown || strings.length > minLength * 3; // At least 3x min length as bonus
}

// ============================================================================
// SIGNATURE MATCHER CLASS
// ============================================================================

export class SignatureMatcher {
  private signatures: FileSignature[];
  private entropyThreshold: number;
  private stringMinLength: number;
  private confidenceThreshold: number;

  constructor(options?: {
    signatures?: FileSignature[];
    entropyThreshold?: number;
    stringMinLength?: number;
    confidenceThreshold?: number;
  }) {
    this.signatures = options?.signatures || KNOWN_SIGNATURES;
    this.entropyThreshold = options?.entropyThreshold ?? DEFAULT_ENTROPY_THRESHOLD;
    this.stringMinLength = options?.stringMinLength ?? DEFAULT_STRING_MIN_LENGTH;
    this.confidenceThreshold = options?.confidenceThreshold ?? DEFAULT_CONFIDENCE_THRESHOLD;
  }

  /**
   * Scan a file (or buffer) for packer signatures.
   */
  async scan(data: Buffer | Readable, fileName?: string): Promise<ScanResult> {
    const buffer = data instanceof Readable 
      ? await this.readStreamToBuffer(data)
      : data;

    if (!buffer || buffer.length === 0) {
      return this.createEmptyResult(fileName);
    }

    // Calculate entropy
    const entropy = calculateEntropy(buffer);

    // Extract strings
    const allStrings = extractStrings(buffer, this.stringMinLength);
    const uniqueStrings = [...new Set(allStrings)];

    // Scan for patterns
    let patternMatches: Map<string, number[]>;
    
    try {
      patternMatches = scanPatterns(buffer, KNOWN_SIGNATURES.flatMap(s => s.patterns));
    } catch (error) {
      console.error('Pattern scanning error:', error);
      patternMatches = new Map();
    }

    // Match signatures with confidence scores
    const matchedSignatures: MatchedSignature[] = [];
    const matchedStringSet = new Set<string>();

    for (const sig of this.signatures) {
      const entropyMatch = checkEntropyRange(entropy, sig.entropyMin, sig.entropyMax);
      const stringsMatch = checkStringsMatch(allStrings, sig.stringsMinLen || this.stringMinLength, matchedStringSet);
      
      // Calculate confidence
      const patternMatchesForSig: Map<string, number[]> = new Map();
      for (const [pattern, offsets] of patternMatches.entries()) {
        if (sig.patterns.some(p => p.hex === pattern)) {
          patternMatchesForSig.set(pattern, offsets);
        }
      }

      const confidence = calculateConfidence(
        entropy,
        sig.entropyMin,
        sig.entropyMax,
        patternMatchesForSig,
        matchedStringSet
      );

      if (confidence >= this.confidenceThreshold || 
          (sig.patterns.length > 0 && patternMatches.size > 0)) {
        
        const match: MatchedSignature = {
          signatureName: sig.name,
          confidence: Math.round(confidence * 100) / 100,
          matchesFound: patternMatchesForSig.reduce((sum, offsets) => sum + offsets.length, 0),
          matchOffsets: [...patternMatchesForSig.values()].flat().sort((a, b) => a - b),
        };

        if (entropyMatch) {
          match.entropyMatch = true;
        }

        if (stringsMatch) {
          match.stringsMatch = true;
        }

        matchedSignatures.push(match);
      }
    }

    // Sort by confidence descending
    matchedSignatures.sort((a, b) => b.confidence - a.confidence);

    return this.createResult(fileName, buffer, entropy, uniqueStrings, matchedSignatures);
  }

  private readStreamToBuffer(stream: Readable): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Uint8Array[] = [];
      
      stream.on('data', (chunk) => {
        chunks.push(chunk as Uint8Array);
      });

      stream.on('end', () => {
        resolve(Buffer.concat(chunks));
      });

      stream.on('error', reject);
    });
  }

  private createEmptyResult(fileName?: string): ScanResult {
    return {
      fileName: fileName || 'unknown',
      fileSize: 0,
      matchedSignatures: [],
      entropy: 0,
      topStrings: [],
      metadata: {},
    };
  }

  private createResult(
    fileName: string | undefined,
    buffer: Buffer,
    entropy: number,
    uniqueStrings: string[],
    matchedSignatures: MatchedSignature[]
  ): ScanResult {
    return {
      fileName: fileName || 'unknown',
      fileSize: buffer.length,
      matchedSignatures,
      entropy: Math.round(entropy * 10) / 10,
      topStrings: uniqueStrings.slice(0, 50), // Limit to top 50
      metadata: this.extractMetadata(buffer),
    };
  }

  /**
   * Extract additional metadata from the file.
   */
  private extractMetadata(data: Buffer): Partial<Metadata> {
    const metadata: Partial<Metadata> = {};

    // UPX detection
    if (data.slice(0, 4).toString('hex') === '00000103' || 
        data.indexOf(Buffer.from('UPX0!')) !== -1) {
      try {
        const upxVersion = this.extractUPXVersion(data);
        metadata.upx = { version: upxVersion, flags: 'detected' };
      } catch (e) {}
    }

    // ASPack detection
    if (data.slice(0, 4).toString('hex') === '0103' || 
        data.indexOf(Buffer.from('ASPack!')) !== -1) {
      try {
        const aspackVersion = this.extractASPackVersion(data);
        metadata.aspack = { version: aspackVersion, flags: 'detected' };
      } catch (e) {}
    }

    // Themida detection
    if (data.slice(0, 4).toString('hex') === '0102' || 
        data.indexOf(Buffer.from('Themida!')) !== -1) {
      try {
        const themidaVersion = this.extractThemidaVersion(data);
        metadata.themida = { version: themida