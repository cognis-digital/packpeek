#!/usr/bin/env python3
"""
polyglot/python/entropy_analyzer.py

Entropy analyzer for packer/loader detection.
Calculates Shannon entropy, byte frequency analysis, and N-gram patterns.
Outputs structured JSON compatible with YARA/SARIF pipelines.
"""

import argparse
import json
import math
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional


@dataclass
class EntropyResult:
    """Container for entropy analysis results."""
    
    filename: str
    size_bytes: int
    shannon_entropy: float  # 0.0 to 8.0 (byte range)
    byte_frequency: Dict[int, float]  # normalized counts per byte value
    ngram_entropy_2: float  # 2-gram entropy
    ngram_entropy_3: float  # 3-gram entropy
    unique_bytes: int
    ratio_unique_to_total: float
    
    # Packer-specific metrics
    upx_heuristic_score: float  # 0.0 to 1.0 (higher = more likely UPX)
    aspack_heuristic_score: float  # 0.0 to 1.0
    themida_heuristic_score: float  # 0.0 to 1.0
    
    # Raw data for downstream processing
    raw_bytes: bytes


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte distribution."""
    if not data:
        return 0.0
    
    n = len(data)
    counter = Counter(data)
    
    total_entropy = 0.0
    for count in counter.values():
        probability = count / n
        if probability > 0:
            total_entropy -= probability * math.log2(probability)
    
    return round(total_entropy, 6)


def calculate_ngram_entropy(data: bytes, n: int) -> float:
    """Calculate N-gram entropy for higher-order analysis."""
    if len(data) < n:
        return 0.0
    
    # Pad with null byte to handle boundary conditions
    padded = b'\x00' * (n - 1) + data + b'\x00' * (n - 1)
    
    counter = Counter(padded[i:i+n] for i in range(len(data)))
    total_ngrams = len(counter)
    
    if total_ngrams == 0:
        return 0.0
    
    entropy = 0.0
    for ngram, count in counter.items():
        probability = count / total_ngrams
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    # Normalize by maximum possible entropy (n bytes of randomness)
    max_entropy = n
    normalized = min(entropy / max_entropy, 1.0)
    
    return round(normalized, 6)


def calculate_byte_frequency(data: bytes) -> Dict[int, float]:
    """Calculate normalized byte frequency distribution."""
    if not data:
        return {}
    
    counter = Counter(data)
    total = len(data)
    
    # Return as dict of {byte_value: probability}
    return {int(k): round(v / total, 6) for k, v in sorted(counter.items())}


def calculate_upx_heuristic_score(data: bytes) -> float:
    """
    UPX heuristic scoring.
    
    UPX typically:
    - Uses high compression (high entropy)
    - Has specific header patterns
    - Creates predictable byte distributions
    
    Returns score 0.0-1.0 where higher = more likely UPX.
    """
    if not data:
        return 0.0
    
    # Normalize to 8-bit range for comparison
    normalized = min(data, key=lambda x: x) - 32  # Shift by minimum byte
    
    score = 0.0
    
    # Factor 1: High entropy (UPX compresses heavily)
    shannon_entropy = calculate_shannon_entropy(data)
    entropy_score = min(shannon_entropy / 8.0, 1.0) * 0.35
    
    # Factor 2: Byte distribution similarity to known UPX patterns
    upx_signature_bytes = {
        0x50, 0x55, 0x78, 0x94, 0x6D, 0x78, 0x31, 0xD1, 0xA0, 0x26,
        0x3C, 0x6F, 0x5E, 0x2A, 0x4B, 0x9D, 0xF8, 0x7C, 0x1E, 0xB2
    }
    
    signature_matches = sum(1 for b in data[:64] if b in upx_signature_bytes)
    signature_score = min(signature_matches / 64.0, 1.0) * 0.35
    
    # Factor 3: Compression ratio proxy (UPX heavily compresses)
    unique_ratio = len(set(data)) / len(data)
    compression_proxy = 1.0 - unique_ratio  # Higher for compressed data
    compression_score = min(compression_proxy, 1.0) * 0.25
    
    # Factor 4: Specific UPX header patterns (if present in first 64 bytes)
    upx_header_patterns = [
        b'UPX!',           # Classic UPX signature
        b'\x50\x55',       # "PU" ASCII
        b'\x78\x94',       # Extended UPX variant
    ]
    
    header_score = 0.0
    for pattern in upx_header_patterns:
        if len(pattern) <= 64 and pattern in data[:64]:
            header_score += 0.15
    
    return round(min(entropy_score + signature_score + compression_score + header_score, 1.0), 3)


def calculate_aspack_heuristic_score(data: bytes) -> float:
    """
    ASPack heuristic scoring.
    
    ASPack typically:
    - Uses specific header markers
    - Has characteristic byte distributions
    
    Returns score 0.0-1.0 where higher = more likely ASPack.
    """
    if not data:
        return 0.0
    
    score = 0.0
    
    # Factor 1: ASCII header detection
    aspack_headers = [
        b'ASPack',         # Classic ASPack signature
        b'\x54\x68\x69\x73\x20\x41\x53\x50\x61\x63\x6B',  # "This ASPack"
    ]
    
    header_matches = 0.0
    for header in aspack_headers:
        if header in data[:128]:
            header_matches += 1
    
    header_score = min(header_matches / len(aspack_headers), 1.0) * 0.40
    
    # Factor 2: Byte distribution analysis (ASPack has distinct patterns)
    shannon_entropy = calculate_shannon_entropy(data)
    
    # ASPack tends to have moderate-high entropy due to compression
    entropy_score = min((shannon_entropy - 5.0) / 3.0, 1.0) * 0.25
    
    # Factor 3: Specific byte sequences common in ASPack
    aspack_sequences = [
        b'\x4D\x5A',       # "MZ" (PE header marker that survives compression)
        b'\x90\x90\x90',   # NOP sleds sometimes present
    ]
    
    sequence_matches = sum(1 for seq in aspack_sequences if seq in data[:256])
    sequence_score = min(sequence_matches / len(aspack_sequences), 1.0) * 0.20
    
    return round(min(header_score + entropy_score + sequence_score, 1.0), 3)


def calculate_themida_heuristic_score(data: bytes) -> float:
    """
    Themida heuristic scoring.
    
    Themida typically:
    - Uses specific header patterns
    - Has characteristic entropy profiles
    
    Returns score 0.0-1.0 where higher = more likely Themida.
    """
    if not data:
        return 0.0
    
    score = 0.0
    
    # Factor 1: ASCII header detection
    themida_headers = [
        b'Themida',        # Classic Themida signature
        b'\x54\x68\x65\x6D\x69\x64\x61',  # "Themida" ASCII
    ]
    
    header_matches = 0.0
    for header in themida_headers:
        if header in data[:256]:
            header_matches += 1
    
    header_score = min(header_matches / len(themida_headers), 1.0) * 0.35
    
    # Factor 2: Entropy analysis (Themida has distinct compression profile)
    shannon_entropy = calculate_shannon_entropy(data)
    
    # Themida tends to have very high entropy due to heavy obfuscation
    entropy_score = min((shannon_entropy - 6.0) / 2.0, 1.0) * 0.35
    
    # Factor 3: Specific byte sequences
    themida_sequences = [
        b'\x4D\x5A',       # "MZ" header often preserved
        b'\x90\x90\x90\x90',  # NOP sleds common in Themida
    ]
    
    sequence_matches = sum(1 for seq in themida_sequences if seq in data[:256])
    sequence_score = min(sequence_matches / len(themida_sequences), 1.0) * 0.20
    
    return round(min(header_score + entropy_score + sequence_score, 1.0), 3)


def analyze_file(filepath: str) -> EntropyResult:
    """Analyze a single file and return structured results."""
    path = Path(filepath)
    
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")
    
    # Read entire file into memory (suitable for most binaries < 2GB)
    with open(path, 'rb') as f:
        raw_bytes = f.read()
    
    size = len(raw_bytes)
    
    if size == 0:
        raise ValueError(f"Empty file: {filepath}")
    
    # Calculate all metrics
    shannon_entropy = calculate_shannon_entropy(raw_bytes)
    byte_frequency = calculate_byte_frequency(raw_bytes)
    ngram_2_entropy = calculate_ngram_entropy(raw_bytes, 2)
    ngram_3_entropy = calculate_ngram_entropy(raw_bytes, 3)
    
    unique_count = len(set(raw_bytes))
    ratio_unique_to_total = round(unique_count / size, 6)
    
    # Packer-specific heuristics
    upx_score = calculate_upx_heuristic_score(raw_bytes)
    aspack_score = calculate_aspack_heuristic_score(raw_bytes)
    themida_score = calculate_themida_heuristic_score(raw_bytes)
    
    return EntropyResult(
        filename=str(path),
        size_bytes=size,
        shannon_entropy=shannon_entropy,
        byte_frequency=byte_frequency,
        ngram_entropy_2=ngram_2_entropy,
        ngram_entropy_3=ngram_3_entropy,
        unique_bytes=unique_count,
        ratio_unique_to_total=ratio_unique_to_total,
        upx_heuristic_score=upx_score,
        aspack_heuristic_score=aspack_score,
        themida_heuristic_score=themida_score,
        raw_bytes=raw_bytes,
    )


def format_result_for_sarif(result: EntropyResult) -> Dict[str, Any]:
    """Format result for SARIF output."""
    return {
        "name": result.filename,
        "sizeBytes": result.size_bytes,
        "shannonEntropy": result.shannon_entropy,
        "uniqueByteCount": result.unique_bytes,
        "uniqueRatio": result.ratio_unique_to_total,
        "ngram2Entropy": result.ngram_entropy_2,
        "ngram3Entropy": result.ngram_entropy_3,
        "packerScores": {
            "upx": result.upx_heuristic_score,
            "aspack": result.aspack_heuristic_score,
            "themida": result.themida_heuristic_score,
        },
    }


def format_result_for_json(result: EntropyResult) -> Dict[str, Any]:
    """Format result for general JSON output."""
    return {
        "filename": result.filename,
        "size_bytes": result.size_bytes,
        "shannon_entropy": result.shannon_entropy,
        "byte_frequency": result.byte_frequency,
        "ngram_entropy_2": result.ngram_entropy_2,
        "ngram_entropy_3": result.ngram_entropy_3,
        "unique_bytes": result.unique_bytes,
        "ratio_unique_to_total": result.ratio_unique_to_total,
        "upx_heuristic_score": result.upx_heuristic_score,
        "aspack_heuristic_score": result.aspack_heuristic_score,
        "themida_heuristic_score": result.themida_heuristic_score,
    }


def main() -> int:
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description="Entropy analyzer for packer/loader detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s file.exe                    # Analyze single file
  %(prog)s *.exe                       # Analyze multiple files (glob)
  %(prog)s --format sarif app.exe      # Output SARIF format
  %(prog)s --json output.json          # Output JSON format
        """
    )
    
    parser.add_argument(
        'files',
        nargs='+',
        help='Files to analyze'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'sarif'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--output',
        '-o',
        help='Output file path'
    )
    
    args = parser.parse_args()
    
    results = []
    for filepath in args.files:
        try:
            result = analyze_file(filepath)
            results.append(result)
        except (FileNotFoundError, ValueError) as e:
            print(f"Warning: {e}", file=sys.stderr)
    
    # Format output based on requested format
    if args.format == 'sarif':
        formatted = [format_result_for_sarif(r) for r in results]
    else:
        formatted = [format_result_for_json(r) for r in results]
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(formatted, f, indent=2)
        print(f"Results written to {args.output}")
    else:
        print(json.dumps(formatted, indent=2))
    
    return 0


if __name__ == '__main__':
    sys.exit(main())