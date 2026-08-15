import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// Configuration & Interfaces
// ============================================================================

export interface EntropyConfig {
  windowSize?: number;        // Bytes per window (default: 0x1000)
  stepSize?: number;          // Step between windows (default: 0x200)
  entropyThreshold?: number;  // Min entropy to flag as suspicious (default: 7.5)
  minWindows?: number;        // Minimum windows for valid report (default: 1)
  outputFormat?: 'json' | 'sarif'; // Output format
}

export interface WindowResult {
  offset: number;
  size: number;
  entropy: number;
  isSuspicious: boolean;
  byteDistribution: Map<number, number>;
}

export interface EntropyReport {
  filename: string;
  fileSize: number;
  totalWindows: number;
  avgEntropy: number;
  maxEntropy: number;
  minEntropy: number;
  suspiciousRegions: WindowResult[];
  summary: {
    highEntropyCount: number;
    highEntropyPercentage: number;
    estimatedPacked: boolean;
  };
}

export interface SarifIssue {
  id: string;
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: string;
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
}

// ============================================================================
// Core Entropy Calculation
// ============================================================================

function calculateShannonEntropy(buffer: Buffer): number {
  const byteFreq = new Map<number, number>();
  
  // Count byte frequencies
  for (let i = 0; i < buffer.length; i++) {
    const b = buffer[i];
    byteFreq.set(b, (byteFreq.get(b) || 0) + 1);
  }

  let entropy = 0.0;
  const totalBytes = buffer.length;

  // Shannon formula: H = -Σ(p * log₂(p))
  for (const [byte, count] of byteFreq.entries()) {
    if (count > 0) {
      const p = count / totalBytes;
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

// ============================================================================
// Sliding Window Analysis
// ============================================================================

function analyzeWindows(
  buffer: Buffer, 
  config: EntropyConfig
): WindowResult[] {
  const windowSize = config.windowSize || 0x1000;
  const stepSize = config.stepSize || 0x200;
  
  if (buffer.length < windowSize) {
    return [];
  }

  const results: WindowResult[] = [];
  let offset = 0;

  while (offset + windowSize <= buffer.length) {
    // Extract current window
    const windowBuffer = buffer.slice(offset, offset + windowSize);
    
    // Calculate entropy for this window
    const entropy = calculateShannonEntropy(windowBuffer);
    
    // Determine if suspicious based on threshold
    const isSuspicious = entropy >= (config.entropyThreshold || 7.5);

    results.push({
      offset,
      size: windowSize,
      entropy,
      isSuspicious,
      byteDistribution: new Map([...windowBuffer.entries()]),
    });

    offset += stepSize;
  }

  return results;
}

// ============================================================================
// Report Generation
// ============================================================================

function generateReport(
  filename: string, 
  buffer: Buffer, 
  config: EntropyConfig
): EntropyReport {
  const windowSize = config.windowSize || 0x1000;
  const stepSize = config.stepSize || 0x200;
  
  if (buffer.length < windowSize) {
    return createEmptyReport(filename, buffer.length);
  }

  // Analyze all windows
  const results = analyzeWindows(buffer, config);
  
  // Calculate summary statistics
  let totalEntropy = 0.0;
  let maxEntropy = -Infinity;
  let minEntropy = Infinity;
  let highEntropyCount = 0;

  for (const result of results) {
    totalEntropy += result.entropy;
    if (result.entropy > maxEntropy) maxEntropy = result.entropy;
    if (result.entropy < minEntropy) minEntropy = result.entropy;
    
    if (result.isSuspicious) {
      highEntropyCount++;
    }
  }

  const avgEntropy = results.length > 0 ? totalEntropy / results.length : 0;
  const suspiciousRegions = results.filter(r => r.isSuspicious);
  
  // Estimate if file is packed based on overall entropy profile
  const estimatedPacked = maxEntropy >= (config.entropyThreshold || 7.5) && 
                          highEntropyCount > results.length * 0.1;

  return {
    filename,
    fileSize: buffer.length,
    totalWindows: results.length,
    avgEntropy,
    maxEntropy,
    minEntropy,
    suspiciousRegions,
    summary: {
      highEntropyCount,
      highEntropyPercentage: (highEntropyCount / results.length) * 100,
      estimatedPacked,
    },
  };
}

function createEmptyReport(filename: string, fileSize: number): EntropyReport {
  return {
    filename,
    fileSize,
    totalWindows: 0,
    avgEntropy: 0,
    maxEntropy: 0,
    minEntropy: 0,
    suspiciousRegions: [],
    summary: {
      highEntropyCount: 0,
      highEntropyPercentage: 0,
      estimatedPacked: false,
    },
  };
}

// ============================================================================
// SARIF Output Generation
// ============================================================================

function generateSarif(report: EntropyReport): string {
  const sarifVersion = '2.1.0';
  const toolName = 'EntropyAnalyzer';
  const ruleIdPrefix = 'Ent.';

  // Build issues from suspicious regions
  const issues: SarifIssue[] = report.suspiciousRegions.map((region, index) => ({
    id: `issue-${index + 1}`,
    ruleId: `${ruleIdPrefix}HIGH_ENTROPY`,
    level: 'warning',
    message: `High entropy region detected at offset ${0x${report.filename.length > 0 ? report.filename : ''}}`,
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: report.filename || 'stdin' },
      },
    }],
  }));

  const sarif = {
    $schema: `http://schematics.org/sarif/${sarifVersion}`,
    version: sarifVersion,
    runs: [{
      tool: {
        name: toolName,
        version: '1.0.0',
        rules: [{
          id: `${ruleIdPrefix}HIGH_ENTROPY`,
          name: 'High Entropy Region Detected',
          description: 'Potential packed or encrypted code region',
          shortDescription: { text: 'Suspicious entropy level' },
          fullDescription: { 
            text: `Found ${report.suspiciousRegions.length} regions with entropy >= ${report.summary.estimatedPacked ? '>=' : ''}${(config.entropyThreshold || 7.5).toFixed(2)}`,
            markdown: `Found **${report.suspiciousRegions.length}** suspicious regions.\n\n| Offset | Entropy | Size |\n|--------|---------|------|\n`,
          },
        }],
      },
      results: issues,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

// ============================================================================
// File I/O Helpers
// ============================================================================

function readBufferFromFile(filePath: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, (err, data) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(data);
    });
  });
}

function readBufferFromStdin(): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    
    process.stdin.on('data', (chunk) => {
      chunks.push(chunk);
    });

    process.stdin.on('end', () => {
      resolve(Buffer.concat(chunks));
    });

    process.stdin.on('error', reject);
  });
}

// ============================================================================
// Main Analysis Function
// ============================================================================

export async function analyzeEntropy(
  source: string | Buffer, 
  config?: EntropyConfig
): Promise<Ent